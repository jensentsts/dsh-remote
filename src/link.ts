/**
 * A reusable authenticated link to one peer endpoint.
 *
 * Extracted from the client plugin so the peer filesystem provider can share the
 * exact same connect / handshake / retry behaviour: a dropped connection is not
 * an error the caller should see — `request()` reconnects once and replays,
 * because a tunnel that idles out is normal.
 *
 * @module dsh-remote/link
 */

import type { Session } from './protocol.ts'
import { clientHandshake } from './protocol.ts'
import { resolvePeerPublicKey, resolvePrivateKey, text } from './keys.ts'

/**
 * Everything needed to reach one peer. The client plugin's `Config` is a
 * superset, so a peer profile and the plugin's own settings share this shape.
 */
export interface EndpointConfig {
  /** Peer host — whatever address reaches the other machine. No default, on purpose. */
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
}

/** One request/response exchange over an authenticated link. */
export class LinkClient {
  private session: Session | undefined
  private pending: Promise<Session> | undefined
  private counter = 0

  /**
   * @param read - live accessor for the endpoint; re-read on every dial so a
   *   settings change takes effect without reloading the module.
   * @param log - one-line logger for connect/failure notices.
   * @param label - prefix used in log messages and errors (usually the plugin
   *   name, or `peer <name>` for a federated endpoint).
   */
  constructor(
    private readonly read: () => EndpointConfig,
    private readonly log: (message: string) => void,
    private readonly label: string = 'dsh-remote',
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
        `${this.label}: set \`host\` and \`port\` to the peer's reachable endpoint. `
        + 'Fill them in — for example the host:port your frp tunnel hands out.',
      )
    }

    const socket = connect({ host, port })
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => {
        socket.destroy()
        reject(new Error(`${this.label}: connect to ${host}:${port} timed out after ${timeout} ms`))
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
    this.log(`${this.label}: authenticated with ${host}:${port}`)
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
        if (reply.ok !== true) {
          // Carry the peer's typed code (FS_STALE_VERSION, ...) so the caller can
          // map it back onto the same FsError the local backend would have raised.
          const failure = new Error(String(reply.error ?? 'peer reported failure'))
          if (typeof reply.code === 'string') {
            (failure as unknown as { peerCode: string }).peerCode = reply.code
          }
          throw failure
        }
        return reply
      } catch (error) {
        lastError = error
        this.drop()
        if (attempt === 2) break
        this.log(`${this.label}: ${op} failed (${error instanceof Error ? error.message : String(error)}); reconnecting`)
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
