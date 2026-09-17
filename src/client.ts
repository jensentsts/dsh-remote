/**
 * `dsh-remote-client` — the half that runs on the machine doing the driving.
 *
 * It dials the peer's listener, authenticates with pinned keys, and registers
 * the model-facing tools. The headline tool is `remote_agent_prompt`: it injects
 * a user message into a session on the *peer* harness, waits for the turn to
 * settle, and returns the assistant's reply — so this harness can use the other
 * one as an agent, with itself as that agent's user.
 *
 * One authenticated session is kept open and reused, and it is transparently
 * re-established when the tunnel drops a connection, so a tool call costs a
 * single round trip rather than a handshake per call.
 *
 * @module dsh-remote/client
 */

import type { Context } from '@deepseek-ai/cordis'
import z from '@deepseek-ai/schemastery'
import { defineTool } from '@deepseek-ai/dsh-tools'
import type { JsonValue } from '@deepseek-ai/dsh-tools'
// Type-only: carries the `ctx.settings` and `ctx.tools` Context merges.
import type {} from '@deepseek-ai/dsh-settings'
import type { SettingsNamespace } from '@deepseek-ai/dsh-settings'

import { clientHandshake, fingerprint } from './protocol.ts'
import type { Session } from './protocol.ts'
import {
  describeIdentity,
  dshHomePath,
  resolvePeerPublicKey,
  resolvePrivateKey,
  text,
} from './keys.ts'

/** Stable Cordis plugin name. */
export const name = 'dsh-remote-client'

/** Settings namespace the GUI edits (`settings.yaml` → `dsh-remote-client:`). */
export const DSH_REMOTE_CLIENT_SETTINGS_NAMESPACE = 'dsh-remote-client' as SettingsNamespace

/** Advertised in `remote_ping` results. */
export const CLIENT_VERSION = '0.1.0'

/** Plugin config; every field has a default, so `{}` is valid. */
export interface Config {
  /**
   * Peer host — whatever address actually reaches the other machine
   * (a frp tunnel endpoint, a LAN name, a Tailscale name, …).
   * Required: this plugin ships no default, on purpose.
   */
  host?: string
  /** Peer port. Required, alongside `host`. */
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
  /** Per-request socket timeout in milliseconds (default 120000). */
  timeoutMs?: number
  /** Register the model-facing tools (default true). */
  toolEnabled?: boolean
  /** Default session id prefix used by `remote_agent_prompt` when none is given. */
  sessionPrefix?: string
}

export const Config: z<Config> = z.object({
  // No defaults: the link is a per-deployment fact, not a product constant.
  host: z.string().default(''),
  port: z.number().default(0),
  // `role('secret')` keeps the value out of settings-GUI wire payloads.
  privateKey: z.string().role('secret').default(''),
  privateKeyFile: z.string().default(dshHomePath('dsh-remote', 'client.key')),
  autoGenerateKey: z.boolean().default(true),
  peerPublicKey: z.string().default(''),
  peerPublicKeyFile: z.string().default(dshHomePath('dsh-remote', 'server.pub')),
  timeoutMs: z.number().default(120_000),
  toolEnabled: z.boolean().default(true),
  sessionPrefix: z.string().default('remote'),
})

/**
 * A reusable authenticated link to the peer.
 *
 * A dropped connection is not an error the caller should see: `request()`
 * reconnects once and replays, because a tunnel that idles out is normal.
 */
class LinkClient {
  private session: Session | undefined
  private pending: Promise<Session> | undefined
  private counter = 0

  constructor(
    private readonly read: () => Config,
    private readonly log: (message: string) => void,
  ) {}

  /** Open a fresh authenticated session. */
  private async dial(): Promise<Session> {
    const { connect } = await import('node:net')
    const config = this.read()
    const host = text(config.host)
    const port = config.port ?? 0
    const timeout = config.timeoutMs ?? 120_000
    if (host === undefined || port <= 0) {
      throw new Error(
        'dsh-remote-client: set `host` and `port` to the peer\'s reachable endpoint. '
        + 'Open this plugin\'s settings (dsh-remote-client) and fill them in — for example '
        + 'the host:port your frp tunnel hands out.',
      )
    }

    const socket = connect({ host, port })
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => {
        socket.destroy()
        reject(new Error(`dsh-remote-client: connect to ${host}:${port} timed out after ${timeout} ms`))
      }, timeout)
      socket.once('connect', () => { clearTimeout(timer); resolve() })
      socket.once('error', (error: Error) => { clearTimeout(timer); reject(error) })
    })
    socket.setNoDelay(true)
    socket.setTimeout(0)

    const session = await clientHandshake(
      socket,
      resolvePrivateKey(config, 'client.key').key,
      resolvePeerPublicKey(config, 'server.pub'),
    )
    this.log(`dsh-remote-client: authenticated with ${host}:${port}`)
    return session
  }

  private async ensure(): Promise<Session> {
    if (this.session !== undefined) return this.session
    if (this.pending === undefined) {
      this.pending = this.dial()
        .then((session) => { this.session = session; return session })
        .finally(() => { this.pending = undefined })
    }
    return this.pending
  }

  /** Drop the current session so the next request redials. */
  private drop(): void {
    this.session?.close()
    this.session = undefined
  }

  /**
   * Send one request and return its result, reconnecting once on transport
   * failure.
   * @param op - the server-side operation name.
   * @param args - its arguments.
   * @param timeoutMs - override for the peer-side operation timeout.
   * @returns the peer's result object.
   */
  async request(
    op: string,
    args: Record<string, unknown> = {},
    timeoutMs?: number,
  ): Promise<Record<string, unknown>> {
    const timeout = timeoutMs ?? this.read().timeoutMs ?? 120_000
    let lastError: unknown
    for (let attempt = 1; attempt <= 2; attempt += 1) {
      try {
        const session = await this.ensure()
        this.counter += 1
        await session.send({ id: this.counter, op, ...args })
        const reply = await session.recv(timeout)
        if (reply === null) throw new Error('peer closed the link')
        if (reply.ok !== true) throw new Error(String(reply.error ?? 'peer reported failure'))
        return reply
      } catch (error) {
        lastError = error
        this.drop()
        if (attempt === 2) break
        this.log(`dsh-remote-client: ${op} failed (${error instanceof Error ? error.message : String(error)}); reconnecting`)
      }
    }
    throw lastError instanceof Error ? lastError : new Error(String(lastError))
  }

  /** True while a session is believed live. */
  get connected(): boolean {
    return this.session !== undefined
  }

  /** Close the session and let it die. */
  close(): void {
    this.drop()
  }
}

/** Render a result the way the model should read it. */
function renderText(text: string): Array<{ type: 'text', text: string }> {
  return [{ type: 'text', text }]
}

function fmtBytes(size: number): string {
  if (size < 1024) return `${size} B`
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`
  return `${(size / 1024 / 1024).toFixed(1)} MB`
}

/**
 * Mount the client: register the remote tools and install the settings section.
 * @param ctx - the plugin's cordis context.
 * @param config - resolved plugin config; defaults make `{}` valid.
 */
export function apply(ctx: Context, config: Config = {}): void {
  let source: () => Config = () => config
  const read = (): Config => source()
  const log = (message: string): void => { ctx.logger.info(message) }

  // Report our identity at boot and make sure the peer key is reachable, so a
  // misconfiguration shows up in the log rather than on the first tool call.
  try {
    const identity = resolvePrivateKey(read(), 'client.key')
    log(`dsh-remote-client: identity ${describeIdentity(identity)}`)
    resolvePeerPublicKey(read(), 'server.pub')
  } catch (error) {
    log(`dsh-remote-client: ${error instanceof Error ? error.message : String(error)}`)
  }
  if (text(read().host) === undefined || (read().port ?? 0) <= 0) {
    log(
      'dsh-remote-client: no peer endpoint configured yet — set `host` and `port` in '
      + "this plugin's settings (dsh-remote-client) before calling remote_* tools.",
    )
  }

  const link = new LinkClient(read, log)

  const tools = [
    defineTool({
      name: 'remote_ping',
      description: 'Check the link to the peer harness: version, hostname, live sessions, and this side\'s key fingerprint.',
      parameters: {},
      output: {
        schema: { type: 'json' },
        render: (_args, value) => renderText(JSON.stringify(value, null, 2)),
      },
      async execute(): Promise<JsonValue> {
        const info = await link.request('sysinfo', {}, 30_000)
        return {
          clientVersion: CLIENT_VERSION,
          connected: link.connected,
          ...info,
        } as unknown as JsonValue
      },
    }),

    defineTool({
      name: 'remote_exec',
      description:
        '在远端主机上执行 PowerShell（或 cmd）命令，返回 stdout / stderr / 退出码。'
        + '这是在对端机器上跑命令，不是本机。',
      parameters: {
        command: { type: 'string', required: true, description: '要执行的命令。' },
        shell: { type: 'string', description: 'powershell（默认）或 cmd。' },
        timeout_ms: { type: 'number', description: '超时毫秒数，默认 120000。' },
      },
      output: {
        schema: { type: 'json' },
        render: (_args, value) => {
          const v = value as unknown as { exit: number | null, timedOut: boolean, stdout: string, stderr: string, durationMs: number }
          const parts = [
            `exit_code: ${v.exit === null ? '(none)' : v.exit}${v.timedOut ? '  (TIMED OUT)' : ''}`,
            `duration_ms: ${v.durationMs}`,
          ]
          if (v.stdout.trim() !== '') parts.push('--- stdout ---', v.stdout.trimEnd())
          if (v.stderr.trim() !== '') parts.push('--- stderr ---', v.stderr.trimEnd())
          if (v.stdout.trim() === '' && v.stderr.trim() === '') parts.push('(no output)')
          return renderText(parts.join('\n'))
        },
      },
      async execute(args: { command: string, shell?: string, timeout_ms?: number }): Promise<JsonValue> {
        return await link.request('exec', {
          cmd: args.command,
          shell: args.shell ?? 'powershell',
          timeoutMs: args.timeout_ms ?? 120_000,
        }) as unknown as JsonValue
      },
    }),

    defineTool({
      name: 'remote_agent_prompt',
      description:
        '把一段用户发言交给**对端 harness 的 agent**，等它跑完这一轮，取回回复。'
        + '本机在对端那里扮演"用户"。session_id 相同即续接同一会话（保留上下文）；'
        + '省略 session_id 时按 session_prefix 自动生成一个。'
        + 'preset_id 只在会话首次创建时生效（例如 "cordis" 就是创造模式）。',
      parameters: {
        text: { type: 'string', required: true, description: '交给对端 agent 的用户发言。' },
        session_id: { type: 'string', description: '对端会话 id；相同即续接同一会话。' },
        preset_id: { type: 'string', description: '仅首次创建会话时生效的 preset id，如 cordis。' },
        workspace: { type: 'string', description: '对端会话的工作目录（仅首次创建时生效）。' },
        timeout_ms: { type: 'number', description: '等待这一轮结束的超时毫秒数；0 表示不限。' },
      },
      output: {
        schema: { type: 'json' },
        render: (_args, value) => {
          const v = value as unknown as {
            sessionId: string, reply: string, reason: string | null,
            error?: string | null,
            seq: number, created: boolean, durationMs: number,
          }
          const head = [
            `session: ${v.sessionId}${v.created ? ' (created)' : ''}`,
            `reason : ${v.reason ?? '(none)'}   seq: ${v.seq}   ${v.durationMs} ms`,
          ]
          if (v.error !== null && v.error !== undefined && v.error !== '') {
            head.push(`error  : ${v.error}`)
          }
          head.push('--- reply ---')
          return renderText([...head, v.reply === '' ? '(empty reply)' : v.reply].join('\n'))
        },
      },
      async execute(args: {
        text: string, session_id?: string, preset_id?: string,
        workspace?: string, timeout_ms?: number,
      }): Promise<JsonValue> {
        const sessionId = text(args.session_id)
          ?? `${text(read().sessionPrefix) ?? 'remote'}-${Date.now().toString(36)}`
        return await link.request('agent.prompt', {
          sessionId,
          text: args.text,
          timeoutMs: args.timeout_ms ?? 0,
          ...(text(args.preset_id) === undefined ? {} : { presetId: args.preset_id }),
          ...(text(args.workspace) === undefined ? {} : { workspace: args.workspace }),
        }, Math.max(read().timeoutMs ?? 120_000, (args.timeout_ms ?? 0) + 30_000)) as unknown as JsonValue
      },
    }),

    defineTool({
      name: 'remote_agent_ensure',
      description:
        '在对端 harness 上创建或续接一个 agent 会话，但先不发言。'
        + '用于提前把会话建好（可指定 preset），之后用 remote_agent_prompt 复用同一个 session_id。',
      parameters: {
        session_id: { type: 'string', required: true, description: '对端会话 id。' },
        preset_id: { type: 'string', description: '仅首次创建时生效的 preset id。' },
        workspace: { type: 'string', description: '会话的工作目录（仅首次创建时生效）。' },
      },
      output: {
        schema: { type: 'json' },
        render: (_args, value) => {
          const v = value as unknown as { sessionId: string, created: boolean }
          return renderText(`session ${v.sessionId}: ${v.created ? 'created' : 'resumed'}`)
        },
      },
      async execute(args: { session_id: string, preset_id?: string, workspace?: string }): Promise<JsonValue> {
        return await link.request('agent.ensure', {
          sessionId: args.session_id,
          ...(text(args.preset_id) === undefined ? {} : { presetId: args.preset_id }),
          ...(text(args.workspace) === undefined ? {} : { workspace: args.workspace }),
        }) as unknown as JsonValue
      },
    }),

    defineTool({
      name: 'remote_agent_events',
      description:
        '读取对端某个会话的事件流（只含必要字段：消息文本、工具调用、turn 结束原因）。'
        + '用于把对端上下文取回本机、压缩后再投递回去。'
        + '需要该会话在对端有活动句柄（先 remote_agent_prompt 或 remote_agent_ensure 过）。',
      parameters: {
        session_id: { type: 'string', required: true, description: '对端会话 id。' },
        from_seq: { type: 'number', description: '从该序号开始取，默认 0。' },
        limit: { type: 'number', description: '最多取多少条，默认 400。' },
      },
      output: {
        schema: { type: 'json' },
        render: (_args, value) => {
          const v = value as unknown as {
            sessionId: string, seq: number,
            events: Array<Record<string, unknown>>,
          }
          const lines = [`session ${v.sessionId}  head_seq=${v.seq}  events=${v.events.length}`]
          for (const event of v.events) {
            const body = typeof event.text === 'string' && event.text !== ''
              ? event.text.replace(/\s+/g, ' ').slice(0, 160)
              : typeof event.name === 'string' ? `${event.name} ${String(event.arguments ?? '').slice(0, 120)}`
                : typeof event.reason === 'string' ? event.reason
                  : ''
            lines.push(`${String(event.seq).padStart(5)}  ${String(event.type).padEnd(18)} ${body}`)
          }
          return renderText(lines.join('\n'))
        },
      },
      async execute(args: { session_id: string, from_seq?: number, limit?: number }): Promise<JsonValue> {
        return await link.request('agent.events', {
          sessionId: args.session_id,
          fromSeq: args.from_seq ?? 0,
          limit: args.limit ?? 400,
        }) as unknown as JsonValue
      },
    }),

    defineTool({
      name: 'remote_agent_interrupt',
      description: '打断对端某个会话正在跑的 turn。',
      parameters: {
        session_id: { type: 'string', required: true, description: '对端会话 id。' },
      },
      output: {
        schema: { type: 'json' },
        render: (_args, value) => {
          const v = value as unknown as { interrupted: boolean, reason?: string }
          return renderText(v.interrupted ? 'interrupted' : `not interrupted: ${v.reason ?? 'unknown'}`)
        },
      },
      async execute(args: { session_id: string }): Promise<JsonValue> {
        return await link.request('agent.interrupt', { sessionId: args.session_id }) as unknown as JsonValue
      },
    }),

    defineTool({
      name: 'remote_preset_list',
      description: '列出对端 harness 可用的 agent preset（想知道"创造模式"的 id 就用它）。',
      parameters: {},
      output: {
        schema: { type: 'json' },
        render: (_args, value) => {
          const v = value as unknown as {
            available: boolean, defaultId?: string,
            presets: Array<{ id: string, name: string, broken: string | null }>,
          }
          if (!v.available) return renderText('peer has no agentPresets service mounted')
          const lines = [`default: ${v.defaultId ?? '(none)'}`]
          for (const preset of v.presets) {
            lines.push(`- ${preset.id}${preset.name === '' ? '' : `（${preset.name}）`}${preset.broken === null ? '' : ` ⚠️ ${preset.broken}`}`)
          }
          return renderText(lines.join('\n'))
        },
      },
      async execute(): Promise<JsonValue> {
        return await link.request('preset.list', {}) as unknown as JsonValue
      },
    }),

    defineTool({
      name: 'remote_fs_list',
      description: '列出远端目录内容。',
      parameters: {
        path: { type: 'string', required: true, description: '远端目录路径。' },
      },
      output: {
        schema: { type: 'json' },
        render: (_args, value) => {
          const v = value as unknown as {
            path: string, count: number,
            entries: Array<{ name: string, isDir: boolean, size: number, mtimeMs: number }>,
          }
          const lines = [`${v.path}  (${v.count} entries)`]
          for (const entry of v.entries) {
            const when = entry.mtimeMs === 0 ? '' : new Date(entry.mtimeMs).toISOString().slice(0, 19).replace('T', ' ')
            lines.push(`${entry.isDir ? 'dir ' : 'file'}  ${(entry.isDir ? '' : fmtBytes(entry.size)).padStart(10)}  ${when}  ${entry.name}`)
          }
          return renderText(lines.join('\n'))
        },
      },
      async execute(args: { path: string }): Promise<JsonValue> {
        return await link.request('fs.list', { path: args.path }) as unknown as JsonValue
      },
    }),

    defineTool({
      name: 'remote_fs_write',
      description: '把文本写入远端文件（自动建父目录）。',
      parameters: {
        path: { type: 'string', required: true, description: '远端文件路径。' },
        content: { type: 'string', required: true, description: '要写入的文本。' },
      },
      output: {
        schema: { type: 'json' },
        render: (_args, value) => {
          const v = value as unknown as { written: number, size: number }
          return renderText(`wrote ${v.written} bytes (remote size now ${v.size})`)
        },
      },
      async execute(args: { path: string, content: string }): Promise<JsonValue> {
        return await link.request('fs.write', {
          path: args.path,
          dataB64: Buffer.from(args.content, 'utf8').toString('base64'),
        }) as unknown as JsonValue
      },
    }),
  ]

  ctx.inject(['settings'], (settingsCtx: Context) => {
    settingsCtx.settings.installSection(
      ctx,
      DSH_REMOTE_CLIENT_SETTINGS_NAMESPACE,
      Config,
      config,
      {
        setSource: (current: () => Config) => {
          source = current
          // Endpoint or key changes must not be served by a session built from
          // the old values.
          link.close()
        },
        onChange: () => { link.close() },
      },
    )
  })

  const safeEffect = (fn: () => () => void, label: string): void => {
    // Best effort: a hot reload can hand apply() an already-inactive context,
    // where ctx.effect() throws and would abort the registration below.
    try {
      ctx.effect(fn, label)
    } catch (error) {
      ctx.logger.warn(`dsh-remote-client: could not register teardown (${String(error)})`)
    }
  }

  if (config.toolEnabled === false) {
    safeEffect(() => () => link.close(), 'dsh-remote-client: close link')
    return
  }

  // Lazy wait keeps the plugin loadable in a composition without a tools
  // registry; when `tools` appears the set lands in the global layer.
  ctx.inject(['tools'], (toolsCtx: Context) => {
    for (const tool of tools) toolsCtx.tools.register(tool)
    log(
      `dsh-remote-client: registered ${tools.length} tools `
      + `(peer ${text(read().host) ?? '?'}:${read().port ?? 0}, fingerprint ${fingerprintSafe(read)})`,
    )
  })

  safeEffect(() => () => link.close(), 'dsh-remote-client: close link')
}

/** Best-effort peer fingerprint for the boot log; never throws. */
function fingerprintSafe(read: () => Config): string {
  try {
    return fingerprint(resolvePeerPublicKey(read(), 'server.pub'))
  } catch {
    return '(peer key not configured)'
  }
}

export { LinkClient }
