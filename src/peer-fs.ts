/**
 * Peer-federated filesystem provider.
 *
 * Mounts other machines' files at `<peerRoot>/<peer>/<absolute-path>` — with the
 * default root that reads `/peers/ze-run/E:/__ai__/project/src/index.ts`. Every
 * model-facing file tool (`read`, `write`, `edit`, …) already goes through
 * `ctx.fs`, so this provider adds peer addressing **without adding a single
 * tool**: the tools keep their schemas and the model keeps its habits.
 *
 * ## Why it extends the sandboxed backend
 *
 * The base bundle installs `fs-sandbox` (`SandboxedFileSystem`), which extends
 * `LocalFileSystem` and overrides only `writeText`/`editText` to add the
 * per-call policy fence — reads pass through untouched. Extending *that* means a
 * local path keeps the deployment's exact containment behaviour, because every
 * non-peer path is delegated with `super`. The fence is deliberately NOT applied
 * to peer targets: a peer URI is not a local path, and the peer's own
 * `maxPermission` ceiling is what confines those writes.
 *
 * ## Scope of this stage (S1)
 *
 * Read paths are implemented: `resolve`, `stat`, `lstat`, `listDir`, `readText`,
 * `streamText`, `readBytes`, `readByteRange`, plus the identity helpers.
 * **Peer writes are refused with a typed error rather than silently attempted**
 * — version-guarded writes and edits arrive with the `fs.write`/`fs.edit` ops.
 *
 * `glob`/`grep` are spawn-backed in this deployment (they shell out to `rg`
 * locally) and never call this provider, so peer paths do not search. That is a
 * known gap with a known fix (a remote rg channel); until then a peer search
 * fails loudly instead of returning an empty result.
 *
 * @module dsh-remote/peer-fs
 */

import type { Context } from '@deepseek-ai/cordis'
import { FsError, FsTargetKey, FsVersion } from '@deepseek-ai/dsh-fs'
import type {
  FsDirEntry,
  FsEditOutcome,
  FsEditRequest,
  FsInfo,
  FsPathInfo,
  FsTarget,
  FsWriteIntent,
  FsWriteOutcome,
} from '@deepseek-ai/dsh-fs'
import { SandboxedFileSystem } from '@deepseek-ai/dsh-fs-sandbox'
import type { Config as LocalConfig } from '@deepseek-ai/dsh-fs-local'
import z from '@deepseek-ai/schemastery'

import { dshHomePath } from './keys.ts'
import { LinkClient } from './link.ts'
import { assertPeerOperation, normalizePermission } from './peers.ts'
import type { PeerRegistry } from './peers.ts'

/** Stable Cordis plugin name. */
export const name = 'dsh-remote-peer-fs'

/** The ceiling a peer starts at until a deployment raises it deliberately. */
export const DEFAULT_MAX_PERMISSION = 1

/** Prefix that marks a peer target key: `peer:<name>:<remotePath>`. */
const PEER_KEY_PREFIX = 'peer:'

/** Read window used when the caller does not bound a read. */
const DEFAULT_READ_WINDOW = 256 * 1024

/** Chunk size for the `streamText` adapter. */
const STREAM_CHUNK = 64 * 1024

/**
 * One reachable peer. Connection fields mirror the client plugin's settings so a
 * deployment writes them the same way in both places.
 */
export interface PeerProfile {
  /** Peer host — whatever address reaches that machine. No default. */
  host?: string
  /** Peer port. No default. */
  port?: number
  /**
   * Ceiling on what this peer may be asked to do, `1 < 2 < 3`:
   * 1 read-only, 2 workspace-write, 3 danger-full-access.
   * Defaults to 1 so a newly declared peer can only be read.
   */
  maxPermission?: number
  /** Boundary a level-2 peer may write inside (empty = the peer decides). */
  workspaceRoot?: string
  /** Inline X25519 private key (PEM / 64 hex / base64); wins over the file. */
  privateKey?: string
  /** File holding this side's private key; also where a generated one lands. */
  privateKeyFile?: string
  /** Generate and persist a keypair when none exists yet (default true). */
  autoGenerateKey?: boolean
  /** Inline pinned X25519 public key of the peer; wins over the file. */
  peerPublicKey?: string
  /** File holding the peer's pinned public key. */
  peerPublicKeyFile?: string
  /** Per-request socket timeout in milliseconds (default 120000). */
  timeoutMs?: number
}

const PeerProfileSchema = z.object({
  host: z.string().default(''),
  port: z.number().default(0),
  maxPermission: z.number().default(DEFAULT_MAX_PERMISSION),
  workspaceRoot: z.string().default(''),
  privateKey: z.string().role('secret').default(''),
  privateKeyFile: z.string().default(dshHomePath('dsh-remote', 'client.key')),
  autoGenerateKey: z.boolean().default(true),
  peerPublicKey: z.string().default(''),
  peerPublicKeyFile: z.string().default(dshHomePath('dsh-remote', 'server.pub')),
  timeoutMs: z.number().default(120_000),
})

/** Plugin config: the local backend's knobs plus the peer mounts. */
export interface Config extends LocalConfig {
  /** Mount point for peer paths. Defaults to `/peers`. */
  peerRoot?: string
  /** Declared peers, keyed by the name used in a path. */
  peers?: Record<string, PeerProfile>
}

export const Config = z.object({
  cwd: z.string().default(process.cwd()),
  diffBasisMaxBytes: z.number().default(10 * 1024 * 1024),
  peerRoot: z.string().default('/peers'),
  peers: z.dict(PeerProfileSchema).default({}),
})

/** A path recognised as peer-addressed. */
export interface ParsedPeerPath {
  /** Declared peer name. */
  peer: string
  /** The peer's own absolute path, verbatim. */
  remote: string
}

/**
 * Recognise `<peerRoot>/<peer>/<absolute-path>`.
 *
 * The peer name is restricted to `[A-Za-z0-9._-]` so the remainder is
 * unambiguously the peer's own path — a Windows `E:/…` keeps its colon.
 *
 * @param path - the model-supplied path.
 * @param peerRoot - the configured mount point, without a trailing slash.
 * @returns the parsed parts, or undefined when this is not a peer path.
 */
export function parsePeerPath(path: string, peerRoot: string): ParsedPeerPath | undefined {
  if (!path.startsWith(`${peerRoot}/`)) return undefined
  const rest = path.slice(peerRoot.length + 1)
  const slash = rest.indexOf('/')
  if (slash <= 0) return undefined
  const peer = rest.slice(0, slash)
  if (!/^[A-Za-z0-9._-]+$/.test(peer)) return undefined
  const remote = rest.slice(slash + 1)
  if (remote === '') return undefined
  return { peer, remote }
}

/** Build the opaque target key for a peer target. */
export function peerTargetKey(peer: string, remote: string): string {
  return `${PEER_KEY_PREFIX}${peer}:${remote}`
}

/**
 * Split a peer target key back into its parts.
 * @param key - a key previously produced by {@link peerTargetKey}.
 * @returns the parts, or undefined when the key is not a peer key.
 */
export function splitPeerTargetKey(key: string): ParsedPeerPath | undefined {
  if (!key.startsWith(PEER_KEY_PREFIX)) return undefined
  const rest = key.slice(PEER_KEY_PREFIX.length)
  const colon = rest.indexOf(':')
  if (colon <= 0) return undefined
  return { peer: rest.slice(0, colon), remote: rest.slice(colon + 1) }
}

/** Synthesize a freshness token from the peer's cheap metadata. */
function peerVersion(peer: string, remote: string, mtime: unknown, size: unknown): FsVersion {
  return FsVersion(`pv1:${peer}:${String(mtime ?? 0)}:${String(size ?? 0)}:${remote}`)
}

/**
 * Wrap the version token the peer reported.
 *
 * The peer must be the authority here: a write guard round-trips this exact
 * string back to it, so anything this side invents could never match.
 * @param reply - the peer's reply.
 * @param parsed - the peer and path, used only for the diagnostic fallback.
 * @returns the version token.
 */
function peerVersionOf(reply: Record<string, unknown>, parsed: ParsedPeerPath): FsVersion {
  const raw = reply.version
  if (typeof raw === 'string' && raw !== '') return FsVersion(raw)
  return peerVersion(parsed.peer, parsed.remote, peerMtime(reply), reply.size)
}

/** Map the peer's `dir` boolean onto the FS type union. */
function peerType(reply: Record<string, unknown>): 'file' | 'directory' | 'other' {
  // The peer plugin reports `isDir`; a test peer may report `dir`. Accept both.
  return (reply.isDir ?? reply.dir) === true ? 'directory' : 'file'
}

/** The peer's mtime in milliseconds, whichever name it used. */
function peerMtime(reply: Record<string, unknown>): unknown {
  return reply.mtimeMs ?? reply.mtime
}

/**
 * The federated provider. Local paths behave exactly as the deployment's
 * sandboxed backend; peer paths are routed over the authenticated link.
 */
export class FederatedFileSystem extends SandboxedFileSystem {
  static override inject = ['sandboxPolicy']

  /** Mount point without a trailing slash. */
  private readonly peerRoot: string
  /**
   * Fallback declarations from this plugin's own config. Normally empty: the
   * deployment declares peers once, in the client plugin, which publishes them
   * through {@link PeerRegistry}. Kept so this provider also works standalone
   * (tests, or a deployment that mounts peers without the client plugin).
   */
  private readonly profiles: Record<string, PeerProfile>
  /** One reusable link per peer, created on first use. */
  private readonly links = new Map<string, LinkClient>()

  constructor(ctx: Context, config: Config) {
    super(ctx, config)
    const raw = String(config.peerRoot ?? '/peers')
    this.peerRoot = raw.replace(/\/+$/, '') === '' ? '/peers' : raw.replace(/\/+$/, '')
    this.profiles = config.peers ?? {}
    const own = Object.keys(this.profiles)
    const shared = this.registry()?.list() ?? []
    const declared = shared.length > 0 ? shared : own
    this.ctx.logger.info(
      declared.length === 0
        ? `${name}: no peers declared — ${this.peerRoot}/* is not mounted`
        : `${name}: mounting ${declared.length} peer(s) at ${this.peerRoot}: ${declared.join(', ')}`
          + (shared.length > 0 ? ' (from the shared registry)' : ' (from this plugin\'s own config)'),
    )
  }

  /** The shared declarations, when the client plugin published them. */
  private registry(): PeerRegistry | undefined {
    return this.ctx.get('dshRemotePeers') as PeerRegistry | undefined
  }

  /**
   * The declaration for a peer. The shared registry wins; this plugin's own
   * config is the fallback, so a deployment never writes an address twice.
   * @param peerName - the name from the path.
   * @returns the profile.
   * @throws FsError when the peer is declared in neither place.
   */
  private profileOf(peerName: string): PeerProfile {
    const shared = this.registry()
    if (shared !== undefined && shared.has(peerName)) return shared.profile(peerName)
    const own = this.profiles[peerName]
    if (own !== undefined) return own
    const declared = [...new Set([...(shared?.list() ?? []), ...Object.keys(this.profiles)])]
    throw new FsError(
      `unknown peer "${peerName}": declare it under peers in the dsh-remote-client settings`
      + (declared.length === 0 ? ' (none are declared)' : ` (declared: ${declared.join(', ')})`),
      'FS_NOT_FOUND',
    )
  }

  /**
   * The reusable link for a peer, created on first use.
   * @param peerName - the name from the path.
   * @returns the link.
   * @throws FsError when the peer is not declared.
   */
  private linkFor(peerName: string): LinkClient {
    const existing = this.links.get(peerName)
    if (existing !== undefined) return existing
    this.profileOf(peerName) // throws for an unknown peer before a link is cached
    const link = new LinkClient(
      // Resolved per dial, so a declaration changed in settings is picked up.
      () => this.profileOf(peerName),
      message => this.ctx.logger.info(message),
      `dsh-remote peer ${peerName}`,
    )
    this.links.set(peerName, link)
    return link
  }

  /** The declared ceiling for a peer, normalized by the shared rule. */
  private ceilingOf(peerName: string): number {
    return normalizePermission(this.profileOf(peerName).maxPermission ?? DEFAULT_MAX_PERMISSION)
  }

  /**
   * Check one operation against a peer's ceiling.
   *
   * The same function the controlled side runs on arrival, so the two ends
   * cannot disagree — and this side refuses before spending a round trip.
   * @param parsed - the peer and the path it targets.
   * @param op - the wire operation name.
   * @throws FsError when the operation exceeds the ceiling.
   */
  private assertPeer(parsed: ParsedPeerPath, op: string): void {
    assertPeerOperation(this.ceilingOf(parsed.peer), op, {
      peer: parsed.peer,
      path: parsed.remote,
      workspaceRoot: String(this.profileOf(parsed.peer).workspaceRoot ?? ''),
    })
  }

  override async resolve(
    path: string,
    opts?: { cwd?: string; signal?: AbortSignal },
  ): Promise<FsTarget> {
    const parsed = parsePeerPath(path, this.peerRoot)
    if (parsed === undefined) return await super.resolve(path, opts)
    if (opts?.signal?.aborted === true) throw new FsError('resolve aborted', 'FS_ABORTED')
    this.profileOf(parsed.peer) // validates the name; no link is created here
    return {
      targetKey: FsTargetKey(peerTargetKey(parsed.peer, parsed.remote)),
      displayPath: path,
    }
  }

  override processPath(target: FsTarget): string {
    const parsed = splitPeerTargetKey(String(target.targetKey))
    if (parsed === undefined) return super.processPath(target)
    // Deliberately NOT a local path: handing a subprocess something that could
    // name a real local file would be worse than handing it an unusable URI.
    return `peer://${parsed.peer}/${parsed.remote}`
  }

  override fileUrl(target: FsTarget): string {
    const parsed = splitPeerTargetKey(String(target.targetKey))
    if (parsed === undefined) return super.fileUrl(target)
    return `peer://${parsed.peer}/${parsed.remote}`
  }

  override contains(parent: FsTarget, child: FsTarget): boolean {
    const a = splitPeerTargetKey(String(parent.targetKey))
    const b = splitPeerTargetKey(String(child.targetKey))
    if (a === undefined || b === undefined) {
      if (a === undefined && b === undefined) return super.contains(parent, child)
      return false // never claim containment across the peer boundary
    }
    if (a.peer !== b.peer) return false
    if (a.remote === b.remote) return true
    const prefix = a.remote.endsWith('/') ? a.remote : `${a.remote}/`
    return b.remote.startsWith(prefix)
  }

  override async stat(target: FsTarget, signal?: AbortSignal): Promise<FsInfo | undefined> {
    const parsed = splitPeerTargetKey(String(target.targetKey))
    if (parsed === undefined) return await super.stat(target, signal)
    if (signal?.aborted === true) throw new FsError('stat aborted', 'FS_ABORTED')
    const reply = await this.linkFor(parsed.peer).request('fs.stat', { path: parsed.remote })
    if (reply.exists !== true) return undefined
    const size = typeof reply.size === 'number' ? reply.size : undefined
    return {
      version: peerVersionOf(reply, parsed),
      type: peerType(reply),
      ...(size === undefined ? {} : { size }),
    }
  }

  override async lstat(
    path: string,
    opts?: { cwd?: string },
    signal?: AbortSignal,
  ): Promise<FsPathInfo | undefined> {
    const parsed = parsePeerPath(path, this.peerRoot)
    if (parsed === undefined) return await super.lstat(path, opts, signal)
    // The peer reports one metadata shape; without a follow/no-follow split the
    // honest answer is the stat result, never a fabricated `symlink`.
    const info = await this.stat(
      { targetKey: FsTargetKey(peerTargetKey(parsed.peer, parsed.remote)), displayPath: path },
      signal,
    )
    if (info === undefined) return undefined
    return {
      version: info.version,
      type: info.type,
      ...(info.size === undefined ? {} : { size: info.size }),
    }
  }

  override async listDir(target: FsTarget, signal?: AbortSignal): Promise<FsDirEntry[]> {
    const parsed = splitPeerTargetKey(String(target.targetKey))
    if (parsed === undefined) return await super.listDir(target, signal)
    if (signal?.aborted === true) throw new FsError('listDir aborted', 'FS_ABORTED')
    const reply = await this.linkFor(parsed.peer).request('fs.list', { path: parsed.remote })
    const entries = Array.isArray(reply.entries) ? reply.entries as Array<Record<string, unknown>> : []
    return entries.map((entry) => {
      const childName = String(entry.name ?? '')
      const childRemote = parsed.remote.endsWith('/')
        ? `${parsed.remote}${childName}`
        : `${parsed.remote}/${childName}`
      const size = typeof entry.size === 'number' ? entry.size : undefined
      return {
        name: childName,
        type: peerType(entry),
        target: {
          targetKey: FsTargetKey(peerTargetKey(parsed.peer, childRemote)),
          displayPath: `${target.displayPath.replace(/\/+$/, '')}/${childName}`,
        },
        version: peerVersion(parsed.peer, childRemote, peerMtime(entry), entry.size),
        ...(size === undefined ? {} : { size }),
      }
    })
  }

  override async readText(target: FsTarget, signal?: AbortSignal): Promise<string> {
    const parsed = splitPeerTargetKey(String(target.targetKey))
    if (parsed === undefined) return await super.readText(target, signal)
    const bytes = await this.readPeerBytes(parsed, { offset: 0, length: Number.MAX_SAFE_INTEGER }, signal)
    return decodePeerText(bytes, target.displayPath)
  }

  override async streamText(
    target: FsTarget,
    signal?: AbortSignal,
  ): Promise<AsyncIterable<string>> {
    const parsed = splitPeerTargetKey(String(target.targetKey))
    if (parsed === undefined) return await super.streamText(target, signal)
    const text = await this.readText(target, signal)
    return (async function* chunks() {
      for (let at = 0; at < text.length; at += STREAM_CHUNK) {
        if (signal?.aborted === true) throw new FsError('stream aborted', 'FS_ABORTED')
        yield text.slice(at, at + STREAM_CHUNK)
      }
    })()
  }

  override async readBytes(
    target: FsTarget,
    signal: AbortSignal | undefined,
    maxBytes: number,
  ): Promise<Uint8Array> {
    const parsed = splitPeerTargetKey(String(target.targetKey))
    if (parsed === undefined) return await super.readBytes(target, signal, maxBytes)
    const info = await this.stat(target, signal)
    if (info === undefined) throw new FsError(`cannot read "${target.displayPath}": not found`, 'FS_NOT_FOUND')
    if (info.type !== 'file') {
      throw new FsError(`cannot read "${target.displayPath}": not a regular file`, 'FS_NOT_REGULAR_FILE')
    }
    if (info.size !== undefined && info.size > maxBytes) {
      throw new FsError(`cannot read "${target.displayPath}": file exceeds ${maxBytes} bytes`, 'FS_TOO_LARGE')
    }
    return await this.readPeerBytes(parsed, { offset: 0, length: maxBytes }, signal)
  }

  override async readByteRange(
    target: FsTarget,
    range: { offset: number; length: number },
    signal?: AbortSignal,
  ): Promise<Uint8Array> {
    const parsed = splitPeerTargetKey(String(target.targetKey))
    if (parsed === undefined) return await super.readByteRange(target, range, signal)
    return await this.readPeerBytes(parsed, range, signal)
  }

  /**
   * One bounded byte read over the link.
   * @param parsed - the peer and its path.
   * @param range - `offset` and the largest `length` to transfer.
   * @param signal - aborts before the request is sent.
   * @returns the window's bytes.
   */
  private async readPeerBytes(
    parsed: ParsedPeerPath,
    range: { offset: number; length: number },
    signal?: AbortSignal,
  ): Promise<Uint8Array> {
    if (signal?.aborted === true) throw new FsError('read aborted', 'FS_ABORTED')
    // Every read funnels through here, so one check covers readText,
    // readBytes and readByteRange alike.
    this.assertPeer(parsed, 'fs.read')
    const length = Math.max(0, Math.min(range.length, Number.MAX_SAFE_INTEGER))
    const reply = await this.linkFor(parsed.peer).request('fs.read', {
      path: parsed.remote,
      offset: range.offset,
      length: length === Number.MAX_SAFE_INTEGER ? DEFAULT_READ_WINDOW : length,
    })
    const encoded = typeof reply.dataB64 === 'string' ? reply.dataB64 : ''
    return Uint8Array.from(Buffer.from(encoded, 'base64'))
  }

  /**
   * One peer request, with the peer's typed failure code preserved.
   * @param parsed - the peer and the path it targets.
   * @param op - the wire operation name.
   * @param args - its arguments.
   * @returns the peer's reply.
   * @throws FsError carrying the peer's own code when it refused.
   */
  private async peerRequest(
    parsed: ParsedPeerPath,
    op: string,
    args: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    try {
      return await this.linkFor(parsed.peer).request(op, args)
    } catch (error) {
      const code = (error as { peerCode?: unknown }).peerCode
      if (typeof code === 'string' && /^FS_[A-Z_]+$/.test(code)) {
        throw new FsError(error instanceof Error ? error.message : String(error), code as never)
      }
      throw error
    }
  }

  override async writeText(
    target: FsTarget,
    content: string,
    expected?: FsWriteIntent,
    signal?: AbortSignal,
  ): Promise<FsWriteOutcome> {
    const parsed = splitPeerTargetKey(String(target.targetKey))
    if (parsed === undefined) return await super.writeText(target, content, expected, signal)
    if (signal?.aborted === true) throw new FsError('write aborted', 'FS_ABORTED')
    this.assertPeer(parsed, 'fs.write')
    const reply = await this.peerRequest(parsed, 'fs.write', {
      path: parsed.remote,
      dataB64: Buffer.from(content, 'utf8').toString('base64'),
      ...(expected?.kind === 'createIfAbsent' ? { createOnly: true } : {}),
      ...(expected?.kind === 'replaceIfVersion' ? { expectedVersion: String(expected.version) } : {}),
    })
    return {
      operation: reply.created === true ? 'create' : 'update',
      version: peerVersionOf(reply, parsed),
      before: typeof reply.before === 'string' ? reply.before : null,
      after: typeof reply.after === 'string' ? reply.after : content,
    }
  }

  override async editText(
    target: FsTarget,
    edit: FsEditRequest,
    expected?: { version: FsVersion },
    signal?: AbortSignal,
  ): Promise<FsEditOutcome> {
    const parsed = splitPeerTargetKey(String(target.targetKey))
    if (parsed === undefined) return await super.editText(target, edit, expected, signal)
    if (signal?.aborted === true) throw new FsError('edit aborted', 'FS_ABORTED')
    this.assertPeer(parsed, 'fs.edit')
    const reply = await this.peerRequest(parsed, 'fs.edit', {
      path: parsed.remote,
      oldString: edit.oldString,
      newString: edit.newString,
      replaceAll: edit.replaceAll === true,
      ...(expected === undefined ? {} : { expectedVersion: String(expected.version) }),
    })
    return {
      version: peerVersionOf(reply, parsed),
      before: String(reply.before ?? ''),
      after: String(reply.after ?? ''),
    }
  }
}

/**
 * Decode peer bytes as UTF-8 text without pretending binary is text.
 * @param bytes - the raw content.
 * @param displayPath - used in the error message.
 * @returns the decoded text.
 * @throws FsError with `FS_NOT_TEXT` when the content is not regular text.
 */
export function decodePeerText(bytes: Uint8Array, displayPath: string): string {
  if (bytes.includes(0)) {
    throw new FsError(`cannot read "${displayPath}": not a text file`, 'FS_NOT_TEXT')
  }
  return Buffer.from(bytes).toString('utf8')
}

export { FederatedFileSystem as default }
