/**
 * Peer declarations and the permission ceiling that **both** ends enforce.
 *
 * One implementation, two call sites: the controlling side checks before it
 * spends a round trip, and the controlled side checks again on arrival. A
 * controller that is compromised, buggy, or simply newer than the peer can
 * therefore never exceed what the peer's own configuration allows — the
 * enforcement does not depend on the controller being well behaved.
 *
 * Levels are ordered `1 < 2 < 3`:
 *
 * | level | name                 | what it admits |
 * |---|---|---|
 * | 1 | read-only            | look: ping, sysinfo, presets, stat/list/read/hash, watch a session |
 * | 2 | workspace-write      | the above plus write/edit, confined to a declared root |
 * | 3 | danger-full-access   | the above plus exec and driving the peer's agent |
 *
 * The default is **1**. A peer that has just been declared can be looked at and
 * nothing more, so forgetting to think about the ceiling fails closed.
 *
 * @module dsh-remote/peers
 */

import { Context, Service } from '@deepseek-ai/cordis'
import { FsError } from '@deepseek-ai/dsh-fs'
import z from '@deepseek-ai/schemastery'

import { dshHomePath } from './keys.ts'
import type { EndpointConfig } from './link.ts'

/** Lowest usable ceiling. */
export const MIN_PERMISSION = 1

/** Highest ceiling: nothing is fenced. */
export const MAX_PERMISSION = 3

/** The level a freshly declared peer starts at. */
export const DEFAULT_PERMISSION = MIN_PERMISSION

/** How a peer may be used. */
export interface PeerProfile extends EndpointConfig {
  /**
   * Ceiling on what this peer may be asked to do, `1 < 2 < 3`.
   * Defaults to {@link DEFAULT_PERMISSION} so a new declaration is read-only.
   */
  maxPermission?: number
  /**
   * Boundary a level-2 peer may write inside. Empty means "the peer decides"
   * (the peer's own configured root, or nothing at level 3).
   */
  workspaceRoot?: string
}

/** Schema for one peer declaration. */
export const PeerProfileSchema = z.object({
  host: z.string().default(''),
  port: z.number().default(0),
  maxPermission: z.number().default(DEFAULT_PERMISSION),
  workspaceRoot: z.string().default(''),
  privateKey: z.string().role('secret').default(''),
  privateKeyFile: z.string().default(dshHomePath('dsh-remote', 'client.key')),
  autoGenerateKey: z.boolean().default(true),
  peerPublicKey: z.string().default(''),
  peerPublicKeyFile: z.string().default(dshHomePath('dsh-remote', 'server.pub')),
  timeoutMs: z.number().default(120_000),
})

/** Operations that need the peer's full trust: they run code or drive its agent. */
const LEVEL_3_OPS = new Set([
  'exec',
  'agent.prompt',
  'agent.ensure',
  'agent.interrupt',
])

/** Operations that change bytes on the peer. */
const LEVEL_2_OPS = new Set([
  'fs.write',
  'fs.edit',
])

/**
 * The level an operation requires.
 *
 * Anything not listed needs level 1: an unknown operation is treated as a read,
 * which is safe precisely because every mutating op above is listed explicitly.
 * That direction is deliberate — the alternative (unknown ⇒ level 3) would make
 * adding an op a breaking change for every peer.
 *
 * @param op - the wire operation name.
 * @returns the minimum ceiling that admits it.
 */
export function requiredLevel(op: string): number {
  if (LEVEL_3_OPS.has(op)) return MAX_PERMISSION
  if (LEVEL_2_OPS.has(op)) return 2
  return MIN_PERMISSION
}

/** Human-readable name for a level, for messages. */
export function levelName(level: number): string {
  if (level >= MAX_PERMISSION) return 'danger-full-access'
  if (level === 2) return 'workspace-write'
  return 'read-only'
}

/**
 * Coerce a configured ceiling into the valid range.
 *
 * A non-finite or sub-1 value becomes the read-only default rather than an
 * accidental grant, and anything above 3 clamps: a typo must not widen access.
 *
 * @param value - the configured value, possibly absent or junk.
 * @returns a level in `[1, 3]`.
 */
export function normalizePermission(value: unknown): number {
  const numeric = Number(value)
  if (!Number.isFinite(numeric)) return DEFAULT_PERMISSION
  const floored = Math.trunc(numeric)
  if (floored < MIN_PERMISSION) return DEFAULT_PERMISSION
  return Math.min(floored, MAX_PERMISSION)
}

/**
 * Compare two peer-side paths for containment.
 *
 * The peer is a different machine, so this is deliberately lexical: separators
 * are unified, case is folded (the peer is likely Windows), and no local file
 * system is consulted. It answers "is this path inside the declared root", not
 * "does this file exist" — the peer decides the latter when it resolves it.
 *
 * @param child - the path the operation targets, on the peer.
 * @param root - the declared root, on the peer. Empty means "no boundary".
 * @returns true when `child` is `root` or under it, or when no root is declared.
 */
export function isRemoteUnder(child: string, root: string): boolean {
  const normalizedRoot = root.trim()
  if (normalizedRoot === '') return true
  const fold = (value: string): string => value.replace(/\\/g, '/').replace(/\/+$/, '').toLowerCase()
  const haystack = fold(child)
  const needle = fold(normalizedRoot)
  if (needle === '') return true
  return haystack === needle || haystack.startsWith(`${needle}/`)
}

/** Context a ceiling check needs beyond the level itself. */
export interface OperationContext {
  /** Peer name, for the message. */
  peer?: string
  /** The peer-side path this operation targets, when it has one. */
  path?: string
  /** The peer's declared write boundary. */
  workspaceRoot?: string
}

/**
 * Refuse an operation that exceeds a ceiling.
 *
 * Called on both ends with the same arguments, so a controller and a peer can
 * never disagree about what a level admits, and the refusal carries the same
 * typed code either way.
 *
 * @param ceiling - the peer's configured ceiling.
 * @param op - the wire operation name.
 * @param context - peer name, target path, and declared root.
 * @throws FsError with `FS_PERMISSION_DENIED` when the operation exceeds the ceiling.
 */
export function assertPeerOperation(
  ceiling: number,
  op: string,
  context: OperationContext = {},
): void {
  const level = normalizePermission(ceiling)
  const needed = requiredLevel(op)
  const who = context.peer === undefined ? 'this peer' : `peer "${context.peer}"`

  if (needed > level) {
    throw new FsError(
      `refusing ${op} on ${who}: it needs permission level ${needed} `
      + `(${levelName(needed)}) but the ceiling is ${level} (${levelName(level)})`,
      'FS_PERMISSION_DENIED',
    )
  }

  // Confinement belongs to level 2 itself, not to level-2 operations: at level 3
  // a write is unconfined even though it still "needs level 2".
  if (level === 2 && needed === 2 && context.path !== undefined
    && !isRemoteUnder(context.path, context.workspaceRoot ?? '')) {
    throw new FsError(
      `refusing ${op} on ${who}: "${context.path}" is outside the declared workspace `
      + `"${context.workspaceRoot ?? ''}" (level 2 is confined)`,
      'FS_PERMISSION_DENIED',
    )
  }
}

/** Plugin config for the registry: the declarations, nothing else. */
export interface PeerRegistryConfig {
  /** Peers by name. */
  peers?: Record<string, PeerProfile>
}

export const PeerRegistryConfig: z<PeerRegistryConfig> = z.object({
  peers: z.dict(PeerProfileSchema).default({}),
})

/**
 * The deployment's peer declarations, shared by the plugins that need them.
 *
 * Publishing this as a service is what keeps one declaration authoritative: the
 * client plugin routes its tools through it, the filesystem provider mounts it,
 * and a deployment never has to write a peer's address twice.
 */
export class PeerRegistry extends Service {
  private readonly peers: Record<string, PeerProfile>

  constructor(ctx: Context, config: PeerRegistryConfig) {
    super(ctx, 'dshRemotePeers')
    this.peers = config.peers ?? {}
  }

  /** Declared peer names, in declaration order. */
  list(): string[] {
    return Object.keys(this.peers)
  }

  /** True when `name` is declared. */
  has(name: string): boolean {
    return Object.hasOwn(this.peers, name)
  }

  /**
   * The declaration for a peer.
   * @param name - the peer name.
   * @returns the profile.
   * @throws FsError when the peer is not declared.
   */
  profile(name: string): PeerProfile {
    const profile = this.peers[name]
    if (profile === undefined) {
      const declared = this.list()
      throw new FsError(
        `unknown peer "${name}"`
        + (declared.length === 0 ? ': no peers are declared' : `: declared peers are ${declared.join(', ')}`),
        'FS_NOT_FOUND',
      )
    }
    return profile
  }

  /** The peer's ceiling, normalized. */
  ceilingOf(name: string): number {
    return normalizePermission(this.profile(name).maxPermission)
  }

  /** The peer's declared write boundary (may be empty). */
  workspaceRootOf(name: string): string {
    return String(this.profile(name).workspaceRoot ?? '')
  }

  /**
   * Check one operation against a peer's ceiling.
   * @param name - the peer name.
   * @param op - the wire operation name.
   * @param path - the peer-side target path, when the operation has one.
   * @throws FsError when the operation exceeds the ceiling.
   */
  assert(name: string, op: string, path?: string): void {
    assertPeerOperation(this.ceilingOf(name), op, {
      peer: name,
      ...(path === undefined ? {} : { path }),
      workspaceRoot: this.workspaceRootOf(name),
    })
  }

  /** A one-line summary of every declaration, for the boot log. */
  describe(): string {
    const declared = this.list()
    if (declared.length === 0) return 'no peers declared'
    return declared
      .map(peerName => `${peerName} (level ${this.ceilingOf(peerName)}/${levelName(this.ceilingOf(peerName))})`)
      .join(', ')
  }
}

export default PeerRegistry
