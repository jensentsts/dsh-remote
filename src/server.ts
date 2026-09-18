/**
 * `dsh-remote-server` — the half that runs on the machine being controlled.
 *
 * It listens on a loopback TCP port (the one a frp tunnel points at) and
 * serves a small RPC surface to a peer holding the pinned client key. Besides
 * plain shell/file operations, it can drive *this* DSH instance's agents: create
 * or resume a session, inject a user message, wait for the turn to settle, and
 * hand back the assistant's reply — which is what lets the peer treat this
 * harness as an agent.
 *
 * Security posture
 * ----------------
 * - Only loopback binds by default; the tunnel is the only way in.
 * - Mutual X25519 authentication with pinned keys; see `protocol.ts`.
 * - Failed handshakes are counted per source address and past a threshold the
 *   source is refused for a cooling-off window, so a public tunnel endpoint
 *   cannot be hammered.
 * - Every accepted operation is appended to an audit log next to the key file.
 *
 * @module dsh-remote/server
 */

import { execFile } from 'node:child_process'
import { createHash } from 'node:crypto'
import { appendFileSync, mkdirSync } from 'node:fs'
import { readFile, readdir, stat, writeFile } from 'node:fs/promises'
import { createServer } from 'node:net'
import type { Server, Socket } from 'node:net'
import { dirname } from 'node:path'

import type { Context } from '@deepseek-ai/cordis'
import z from '@deepseek-ai/schemastery'
import { installModelSelection } from '@deepseek-ai/dsh-agent'
import { createUserMessage } from '@deepseek-ai/dsh-llm'
// Type-only: carries the `ctx.settings` Context merge.
import type {} from '@deepseek-ai/dsh-settings'
import type { SettingsNamespace } from '@deepseek-ai/dsh-settings'
import { SessionId } from '@deepseek-ai/dsh-session'
import type { SessionEvent } from '@deepseek-ai/dsh-session'
// Runtime import also merges `ctx.agentPresets`; presets are what give a
// remotely created session its tool set.
import type {} from '@deepseek-ai/dsh-agent-presets'

import { HandshakeError, HANDSHAKE_TIMEOUT_MS, fingerprint, publicToPem, serverHandshake } from './protocol.ts'
import type { Session } from './protocol.ts'
import {
  describeIdentity,
  dshHomePath,
  resolvePeerPublicKey,
  resolvePrivateKey,
  text,
} from './keys.ts'

/** Stable Cordis plugin name. */
export const name = 'dsh-remote-server'

/** Settings namespace the GUI edits (`settings.yaml` → `dsh-remote-server:`). */
export const DSH_REMOTE_SERVER_SETTINGS_NAMESPACE = 'dsh-remote-server' as SettingsNamespace

/** Advertised to the peer so it can refuse an incompatible build. */
export const SERVER_VERSION = '0.1.0'

/**
 * Bumped on every source change.
 *
 * DSH does not re-import an already-loaded module, so after editing this
 * file the runtime may still be serving the previous build. Shipping the tag
 * in `sysinfo` turns "did my edit take effect?" into one tool call.
 */
export const BUILD = 'r8'

/**
 * Hard dependencies. `agentDefaultModel` matters as much as the registries: a
 * freshly created agent has no model route of its own, and without one its
 * first turn fails immediately with `reason: error`.
 */
export const inject = [
  'agentDefaultModel',
  'agentPresets',
  'agents',
  'sessions',
  // Needed so a remotely created session is owned by a workspace; without
  // that ownership the GUI has nothing to list it under.
  'workspaceRegistry',
]

/** Plugin config; every field has a default, so `{}` is valid. */
export interface Config {
  /** Bind address — keep `127.0.0.1` when frpc runs on this machine. */
  host?: string
  /** Bind port — the frp tunnel's local port. */
  port?: number
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
  /** Agent working directory for sessions created on request. */
  workspace?: string
  /** Default preset for sessions created on request (empty = deployment default). */
  defaultPreset?: string
  /** Refuse handshakes from a source after this many failures (default 8). */
  maxHandshakeFailures?: number
  /** Cooling-off window in seconds after the threshold is hit (default 900). */
  lockoutSeconds?: number
  /** Cap on a single `exec` timeout in milliseconds (default 600000). */
  maxExecTimeoutMs?: number
  /** Audit log path (default `${DSH_HOME}/dsh-remote/server-audit.log`). */
  auditFile?: string
  /** Log every accepted operation (default true). */
  audit?: boolean
}

export const Config: z<Config> = z.object({
  host: z.string().default('127.0.0.1'),
  port: z.number().default(11325),
  // `role('secret')` keeps the value out of settings-GUI wire payloads.
  privateKey: z.string().role('secret').default(''),
  privateKeyFile: z.string().default(dshHomePath('dsh-remote', 'server.key')),
  autoGenerateKey: z.boolean().default(true),
  peerPublicKey: z.string().default(''),
  peerPublicKeyFile: z.string().default(dshHomePath('dsh-remote', 'client.pub')),
  workspace: z.string().default(''),
  defaultPreset: z.string().default(''),
  maxHandshakeFailures: z.number().default(8),
  lockoutSeconds: z.number().default(900),
  maxExecTimeoutMs: z.number().default(600_000),
  auditFile: z.string().default(dshHomePath('dsh-remote', 'server-audit.log')),
  audit: z.boolean().default(true),
})

/** Minimal shapes we read off live session objects; never stringify these. */
type LiveMessage = {
  content?: unknown
}

/** Join the text blocks of a live message without copying the whole object. */
function messageText(message: LiveMessage | undefined): string {
  if (message === undefined) return ''
  const content = (message as { content?: unknown }).content
  const blocks = Array.isArray(content) ? content : content === undefined ? [] : [content]
  let out = ''
  for (const block of blocks) {
    const b = block as { type?: unknown, text?: unknown }
    if (b?.type === 'text' && typeof b.text === 'string') out += b.text
  }
  return out
}

/** True when a tool-result message carries an error. */
function messageIsError(message: LiveMessage | undefined): boolean {
  const content = (message as { content?: unknown } | undefined)?.content
  const blocks = Array.isArray(content) ? content : content === undefined ? [] : [content]
  return blocks.some(block => (block as { isError?: unknown })?.isError === true)
}

/** Aggregate the last assistant text and the turn outcome in one pass. */
function summarize(
  events: readonly SessionEvent[],
  firstSeq: number,
): { text: string, reason: string | null, error: string | null } {
  let started = false
  let out = ''
  let reason: string | null = null
  let error: string | null = null
  for (const event of events) {
    if (event.seq < firstSeq) continue
    if (event.type === 'turn/start') { started = true; continue }
    if (!started) continue
    if (event.type === 'assistant/message') {
      const joined = messageText((event.data as { message?: LiveMessage }).message)
      if (joined !== '') out = joined
    }
    if (event.type === 'turn/end') {
      const why = (event.data as {
        reason?: { kind?: string, error?: { code?: string, message?: string } }
      }).reason
      reason = typeof why?.kind === 'string' ? why.kind : null
      if (why?.error !== undefined) {
        error = `${why.error.code ?? ''}: ${why.error.message ?? ''}`.replace(/^: /, '')
      }
    }
  }
  return { text: out, reason, error }
}

/**
 * Flatten a slice of the session log into plain JSON.
 *
 * The session's own events are live runtime objects, so this deliberately reads
 * only the leaf fields a peer needs for context transfer instead of serializing
 * them wholesale.
 */
function extractEvents(
  events: readonly SessionEvent[],
  fromSeq: number,
  limit: number,
): Array<Record<string, unknown>> {
  const out: Array<Record<string, unknown>> = []
  for (const event of events) {
    if (event.seq < fromSeq) continue
    const base: Record<string, unknown> = { seq: event.seq, type: event.type }
    if (event.type === 'assistant/message' || event.type === 'user/message') {
      base.text = messageText((event.data as { message?: LiveMessage }).message)
    } else if (event.type === 'tool/call') {
      const data = event.data as { name?: unknown, arguments?: unknown }
      base.name = typeof data.name === 'string' ? data.name : ''
      base.arguments = typeof data.arguments === 'string' ? data.arguments.slice(0, 4000) : ''
    } else if (event.type === 'tool/result') {
      base.text = messageText((event.data as { message?: LiveMessage }).message).slice(0, 4000)
      base.isError = messageIsError((event.data as { message?: LiveMessage }).message)
    } else if (event.type === 'turn/end') {
      const why = (event.data as { reason?: { kind?: string } }).reason
      base.reason = typeof why?.kind === 'string' ? why.kind : null
    }
    out.push(base)
    if (out.length >= limit) break
  }
  return out
}

/** One agent handle plus the serial chain that keeps its turns ordered. */
interface SessionState {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  handle: any
  tail: Promise<unknown>
}

/**
 * Mount the listener.
 * @param ctx - the plugin's cordis context.
 * @param config - resolved plugin config; defaults make `{}` valid.
 */
export function apply(ctx: Context, config: Config = {}): void {
  let source: () => Config = () => config
  const read = (): Config => source()

  const identity = resolvePrivateKey(read(), 'server.key')
  ctx.logger.info(`dsh-remote-server: identity ${describeIdentity(identity)}`)
  // Print the public half so the operator can hand it to the peer to pin.
  ctx.logger.info(
    `dsh-remote-server: public key (give this to the client)\n${publicToPem(identity.publicKey)}`,
  )

  const states = new Map<string, SessionState>()
  const failures = new Map<string, number[]>()
  const locked = new Map<string, number>()

  /** Append an audit record; never let logging break a request. */
  const audit = (peer: string, op: string, ok: boolean, extra?: Record<string, unknown>): void => {
    if (read().audit === false) return
    try {
      const file = read().auditFile ?? dshHomePath('dsh-remote', 'server-audit.log')
      mkdirSync(dirname(file), { recursive: true })
      appendFileSync(
        file,
        `${JSON.stringify({ ts: new Date().toISOString(), peer, op, ok, ...(extra ?? {}) })}\n`,
        'utf8',
      )
    } catch {
      // auditing is best effort
    }
  }

  const noteFailure = (peer: string): void => {
    const now = Date.now()
    const window = (failures.get(peer) ?? []).filter(at => now - at < (read().lockoutSeconds ?? 900) * 1000)
    window.push(now)
    failures.set(peer, window)
    const max = read().maxHandshakeFailures ?? 8
    if (window.length >= max) {
      locked.set(peer, now + (read().lockoutSeconds ?? 900) * 1000)
      failures.set(peer, [])
      ctx.logger.warn(`dsh-remote-server: ${peer} refused for ${read().lockoutSeconds}s after ${max} failed handshakes`)
    }
  }

  /** Resolve or create an agent for a session id, reusing a live handle. */
  const ensureAgent = async (
    sessionId: string,
    presetId?: string,
    workspace?: string,
  ): Promise<{ handle: unknown, created: boolean }> => {
    const existing = states.get(sessionId)
    if (existing !== undefined) return { handle: existing.handle, created: false }

    const agents = ctx.get('agents')
    const presets = ctx.get('agentPresets')
    if (agents === undefined) throw new Error('dsh-remote-server: the `agents` service is unavailable')

    const wantedPreset = text(presetId) ?? text(read().defaultPreset)
    const defaults = ctx.get('agentDefaultModel')?.currentSelection()
    const selection = { current: defaults, assembled: undefined }
    const setup = async (agentCtx: Context): Promise<void> => {
      // Without this the new agent has no route and its very first turn
      // returns `reason: error` before doing any work.
      installModelSelection(agentCtx, selection)
      if (presets === undefined) return
      const preset = await presets.resolve(wantedPreset)
      await presets.mount(agentCtx, preset.id)
    }

    // Resolve the directory through the workspace registry: `create()` is
    // create-or-get and yields the canonical path, plus the handle we need to
    // attach the session afterwards. A session made with `agents.create`
    // alone is durable but unowned, and an unowned session never shows up in
    // the GUI sidebar.
    const requested = text(workspace) ?? text(read().workspace) ?? process.cwd()
    const registry = ctx.get('workspaceRegistry')
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    let owner: any
    if (registry !== undefined) {
      try {
        owner = await registry.create(requested)
      } catch (error) {
        ctx.logger.warn(`dsh-remote-server: workspace registry refused ${requested}: ${String(error)}`)
      }
    }
    const cwd: string = typeof owner?.path === 'string' ? owner.path : requested

    let handle: unknown
    let created = false
    try {
      handle = await agents.resume({ resumeSessionId: SessionId(sessionId), setup })
    } catch (error) {
      ctx.logger.debug(`dsh-remote-server: resume ${sessionId} unavailable (${String(error)}); creating`)
      const preset = presets === undefined ? undefined : await presets.resolve(wantedPreset)
      handle = await agents.create({
        sessionId: SessionId(sessionId),
        meta: {
          cwd,
          ...(preset === undefined ? {} : { agentPreset: preset.id }),
        },
        setup,
      })
      created = true
      // Claim the session for the workspace, and give it a findable title.
      try {
        await owner?.attachSession(SessionId(sessionId))
      } catch (attachError) {
        ctx.logger.warn(`dsh-remote-server: attachSession failed: ${String(attachError)}`)
      }
      try {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const session = (handle as any).agent.session
        ctx.get('sessionTitle')?.rename(session, `remote: ${sessionId}`)
      } catch (titleError) {
        ctx.logger.debug(`dsh-remote-server: title rename skipped: ${String(titleError)}`)
      }
    }
    states.set(sessionId, { handle, tail: Promise.resolve() })
    return { handle, created }
  }

  /** Run one prompt on a session, serialized against that session's own chain. */
  const prompt = async (
    sessionId: string,
    promptText: string,
    timeoutMs: number,
    presetId?: string,
    workspace?: string,
  ): Promise<Record<string, unknown>> => {
    const { handle, created } = await ensureAgent(sessionId, presetId, workspace)
    const state = states.get(sessionId) as SessionState
    const resumeOf = state.tail
    let release: () => void = () => {}
    state.tail = new Promise<void>(resolve => { release = resolve })

    await resumeOf
    try {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const agent = (handle as any).agent
      const sessions = ctx.get('sessions')
      const startedAt = Date.now()
      await agent.whenIdle()
      const firstSeq: number = agent.session.seq
      agent.followup(createUserMessage({
        content: [{ type: 'text', text: promptText }],
        source: { kind: 'user' },
      }))
      if (timeoutMs > 0) {
        await Promise.race([
          agent.whenIdle(),
          new Promise((_resolve, reject) => {
            const timer = setTimeout(() => reject(new Error(`prompt timed out after ${timeoutMs} ms`)), timeoutMs)
            timer.unref?.()
          }),
        ])
      } else {
        await agent.whenIdle()
      }
      if (sessions !== undefined) await sessions.flush(agent.session)

      const events: readonly SessionEvent[] = agent.session.snapshotEvents()
      const outcome = summarize(events, firstSeq)
      return {
        sessionId,
        created,
        reply: outcome.text,
        reason: outcome.reason,
        error: outcome.error,
        seq: agent.session.seq,
        durationMs: Date.now() - startedAt,
      }
    } finally {
      release()
    }
  }

  /**
   * Decode a child process's output without guessing wrong.
   *
   * Windows mixes encodings: PowerShell's own cmdlets emit .NET strings in the
   * console encoding, while native tools (`whoami.exe`, `ipconfig.exe`, …) write
   * bytes in the ANSI/OEM code page. Decoding both as UTF-8 turns the native half
   * into U+FFFD. So: strict UTF-8 first, then the Chinese ANSI code page, then a
   * lossy fallback. (The raw bytes are still available to the caller if needed.)
   *
   * @param buf - raw bytes from the child.
   * @returns the best-effort text.
   */
  const decodeOutput = (buf: Buffer): string => {
    if (buf.length === 0) return ''
    try {
      return new TextDecoder('utf-8', { fatal: true }).decode(buf)
    } catch {
      // Not valid UTF-8 — almost always a native tool writing GBK/ANSI.
    }
    for (const encoding of ['gbk', 'big5', 'shift_jis', 'windows-1252']) {
      try {
        return new TextDecoder(encoding).decode(buf)
      } catch {
        // TextDecoder lacks this encoding (Node built without full ICU); try next.
      }
    }
    return buf.toString('utf8')
  }

  /** Execute a shell command and capture both streams. */
  const exec = (
    command: string,
    shell: string,
    timeoutMs: number,
    cwd?: string,
  ): Promise<Record<string, unknown>> => new Promise((resolve, reject) => {
    const cap = read().maxExecTimeoutMs ?? 600_000
    const limit = Math.min(timeoutMs > 0 ? timeoutMs : 120_000, cap)
    const argv = shell === 'cmd'
      ? ['cmd', '/c', command]
      : ['powershell', '-NoProfile', '-NonInteractive', '-Command', `$ErrorActionPreference='Continue';${command}`]
    const startedAt = Date.now()
    execFile(
      argv[0] as string,
      argv.slice(1),
      {
        timeout: limit,
        cwd: text(cwd) ?? undefined,
        windowsHide: true,
        maxBuffer: 64 * 1024 * 1024,
        // Capture raw bytes: the decoder above needs to see them undamaged.
        encoding: 'buffer',
      },
      (error, stdoutRaw, stderrRaw) => {
        const stdout = decodeOutput(stdoutRaw as unknown as Buffer)
        const stderr = decodeOutput(stderrRaw as unknown as Buffer)
        if (error !== null && (error as { killed?: boolean }).killed === true) {
          resolve({
            exit: null,
            timedOut: true,
            stdout,
            stderr: `${stderr}\n[dsh-remote] timed out after ${limit} ms`,
            durationMs: Date.now() - startedAt,
          })
          return
        }
        if (error !== null && typeof (error as { code?: unknown }).code !== 'number') {
          reject(error)
          return
        }
        resolve({
          exit: error === null ? 0 : ((error as { code?: number }).code ?? null),
          timedOut: false,
          stdout,
          stderr,
          durationMs: Date.now() - startedAt,
        })
      },
    )
  })

  const ops: Record<string, (args: Record<string, unknown>) => Promise<Record<string, unknown>>> = {
    ping: async () => ({ pong: true, version: SERVER_VERSION, pid: process.pid }),

    sysinfo: async () => ({
      hostname: process.env.COMPUTERNAME ?? process.env.HOSTNAME ?? '',
      platform: process.platform,
      arch: process.arch,
      node: process.version,
      pid: process.pid,
      cwd: process.cwd(),
      dshHome: dshHomePath(),
      identity: fingerprint(identity.publicKey),
      build: BUILD,
      sessions: [...states.keys()],
    }),

    exec: async args => exec(
      String(args.cmd ?? ''),
      String(args.shell ?? 'powershell'),
      Number(args.timeoutMs ?? 120_000),
      typeof args.cwd === 'string' ? args.cwd : undefined,
    ),

    'fs.read': async args => {
      const path = String(args.path ?? '')
      const data = await readFile(path)
      const offset = Number(args.offset ?? 0)
      const length = Number(args.length ?? data.length)
      const slice = data.subarray(offset, offset + length)
      return {
        size: data.length,
        offset,
        read: slice.length,
        eof: offset + slice.length >= data.length,
        dataB64: slice.toString('base64'),
      }
    },

    'fs.write': async args => {
      const path = String(args.path ?? '')
      const data = Buffer.from(String(args.dataB64 ?? ''), 'base64')
      const offset = Number(args.offset ?? 0)
      mkdirSync(dirname(path), { recursive: true })
      if (offset > 0) {
        const existing = await readFile(path).catch(() => Buffer.alloc(0))
        const merged = Buffer.concat([existing.subarray(0, offset), data])
        await writeFile(path, merged)
      } else {
        await writeFile(path, data)
      }
      return { written: data.length, size: (await stat(path)).size }
    },

    'fs.list': async args => {
      const path = String(args.path ?? '.')
      const entries = await readdir(path, { withFileTypes: true })
      const rows = await Promise.all(entries.map(async (entry) => {
        const info = await stat(`${path}/${entry.name}`).catch(() => undefined)
        return {
          name: entry.name,
          isDir: entry.isDirectory(),
          size: info?.size ?? 0,
          mtimeMs: info?.mtimeMs ?? 0,
        }
      }))
      rows.sort((a, b) => (a.isDir === b.isDir ? a.name.localeCompare(b.name) : a.isDir ? -1 : 1))
      return { path, count: rows.length, entries: rows }
    },

    'fs.stat': async args => {
      const path = String(args.path ?? '')
      try {
        const info = await stat(path)
        return { exists: true, isDir: info.isDirectory(), size: info.size, mtimeMs: info.mtimeMs }
      } catch {
        return { exists: false }
      }
    },

    'fs.hash': async args => {
      const data = await readFile(String(args.path ?? ''))
      return {
        algo: 'sha256',
        hash: createHash('sha256').update(data).digest('hex'),
        bytes: data.length,
      }
    },

    'preset.list': async () => {
      const presets = ctx.get('agentPresets')
      if (presets === undefined) return { available: false, presets: [] }
      const list = await presets.list()
      return {
        available: true,
        defaultId: presets.defaultId,
        presets: list.map((preset: { id: string, name?: string, broken?: string }) => ({
          id: preset.id,
          name: preset.name ?? '',
          broken: preset.broken ?? null,
        })),
      }
    },

    'agent.prompt': async args => {
      const sessionId = String(args.sessionId ?? '')
      if (sessionId === '') throw new Error('agent.prompt: sessionId is required')
      return prompt(
        sessionId,
        String(args.text ?? ''),
        Number(args.timeoutMs ?? 0),
        typeof args.presetId === 'string' ? args.presetId : undefined,
        typeof args.workspace === 'string' ? args.workspace : undefined,
      )
    },

    'agent.ensure': async args => {
      const sessionId = String(args.sessionId ?? '')
      if (sessionId === '') throw new Error('agent.ensure: sessionId is required')
      const { created } = await ensureAgent(
        sessionId,
        typeof args.presetId === 'string' ? args.presetId : undefined,
        typeof args.workspace === 'string' ? args.workspace : undefined,
      )
      return { sessionId, created }
    },

    'agent.interrupt': async args => {
      const sessionId = String(args.sessionId ?? '')
      const state = states.get(sessionId)
      if (state === undefined) return { interrupted: false, reason: 'no live handle for that session' }
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const agent = (state.handle as any).agent
      if (typeof agent.interrupt === 'function') {
        await agent.interrupt()
        return { interrupted: true }
      }
      return { interrupted: false, reason: 'this agent build exposes no interrupt()' }
    },

    'agent.events': async args => {
      const sessionId = String(args.sessionId ?? '')
      const state = states.get(sessionId)
      if (state === undefined) throw new Error(`agent.events: no live handle for ${sessionId}`)
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const session = (state.handle as any).agent.session
      const events: readonly SessionEvent[] = session.snapshotEvents()
      return {
        sessionId,
        seq: session.seq,
        fromSeq: Number(args.fromSeq ?? 0),
        events: extractEvents(events, Number(args.fromSeq ?? 0), Number(args.limit ?? 400)),
      }
    },
  }

  /** Handle one authenticated connection. */
  const serve = async (socket: Socket, peer: string): Promise<void> => {
    const until = locked.get(peer) ?? 0
    if (until > Date.now()) {
      audit(peer, '-', false, { reason: 'locked_out' })
      socket.destroy()
      return
    }

    let session: Session
    try {
      socket.setNoDelay(true)
      session = await serverHandshake(socket, identity.key, resolvePeerPublicKey(read(), 'client.pub'))
      failures.delete(peer)
      ctx.logger.info(`dsh-remote-server: ${peer} authenticated`)
    } catch (error) {
      noteFailure(peer)
      audit(peer, '-', false, {
        reason: error instanceof HandshakeError ? 'handshake_failed' : 'handshake_error',
        detail: error instanceof Error ? error.message : String(error),
      })
      socket.destroy()
      return
    }

    try {
      for (;;) {
        const request = await session.recv()
        if (request === null) break
        const id = request.id
        const op = String(request.op ?? '')
        const handler = ops[op]
        if (handler === undefined) {
          await session.send({ id, ok: false, error: `unknown op ${JSON.stringify(op)}` })
          audit(peer, op, false, { reason: 'unknown_op' })
          continue
        }
        const startedAt = Date.now()
        try {
          const result = await handler(request as Record<string, unknown>)
          await session.send({ id, ok: true, ...result })
          audit(peer, op, true, { ms: Date.now() - startedAt })
        } catch (error) {
          const message = error instanceof Error ? error.message : String(error)
          await session.send({ id, ok: false, error: message })
          audit(peer, op, false, { ms: Date.now() - startedAt, error: message.slice(0, 500) })
        }
      }
    } catch (error) {
      ctx.logger.debug(`dsh-remote-server: ${peer} session ended: ${String(error)}`)
    } finally {
      socket.destroy()
    }
  }

  let listener: Server | undefined
  const stop = (): void => {
    listener?.close()
    listener = undefined
  }

  const start = (): void => {
    stop()
    const current = read()
    const server = createServer((socket: Socket) => {
      const peer = `${socket.remoteAddress ?? '?'}:${socket.remotePort ?? 0}`
      socket.setTimeout(HANDSHAKE_TIMEOUT_MS + 60_000)
      void serve(socket, peer)
    })
    server.on('error', (error: Error) => {
      ctx.logger.error(`dsh-remote-server: listener error: ${error.message}`)
    })
    server.listen(current.port ?? 11325, current.host ?? '127.0.0.1', () => {
      ctx.logger.info(
        `dsh-remote-server: listening on ${current.host ?? '127.0.0.1'}:${current.port ?? 11325}`,
      )
    })
    listener = server
  }

  ctx.inject(['settings'], (settingsCtx: Context) => {
    settingsCtx.settings.installSection(
      ctx,
      DSH_REMOTE_SERVER_SETTINGS_NAMESPACE,
      Config,
      config,
      {
        setSource: (current: () => Config) => { source = current },
        onChange: () => { start() },
      },
    )
  })

  start()
  // Teardown is best effort: on a hot reload the loader may already have
  // deactivated this context, and ctx.effect() throws in that window — which
  // would abort apply() and leave the previous build serving.
  try {
    ctx.effect(() => () => stop(), 'dsh-remote-server: stop listener')
  } catch (error) {
    ctx.logger.warn(`dsh-remote-server: could not register teardown (${String(error)})`)
  }
}
