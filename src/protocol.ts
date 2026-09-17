/**
 * Wire protocol for the DSH remote link — mutual X25519 + AES-256-GCM.
 *
 * This is a TypeScript port of the Python reference implementation that was
 * already exercised end to end, so the two halves keep the same wire format:
 *
 *   handshake
 *     C -> S  HELLO    magic(5) | c_eph_pub(32) | c_nonce(32)
 *     S -> C  REPLY    magic(5) | s_eph_pub(32) | s_nonce(32) | tag_s(32)
 *     C -> S  CONFIRM  tag_c(32)
 *
 *     ss   = ECDH(c_eph, s_eph) || ECDH(c_eph, s_static) || ECDH(c_static, s_eph)
 *     key  = HKDF-SHA256(ikm = ss, salt = c_nonce || s_nonce, info = "dshr2", 32)
 *     kC2S = HKDF(ikm = key, salt = 0^32, info = "dshr2 c2s", 32)
 *     kS2C = HKDF(ikm = key, salt = 0^32, info = "dshr2 s2c", 32)
 *     transcript = magic || c_eph_pub || s_eph_pub || c_nonce || s_nonce
 *     tag_s = HMAC(key, "dshr2 server" || transcript)
 *     tag_c = HMAC(key, "dshr2 client" || transcript)
 *
 *   frames
 *     uint32 big-endian length | AES-256-GCM ciphertext+tag
 *     nonce = 00000000 || counter(uint64 BE), aad = direction || counter
 *
 * Why the pieces are here:
 *
 * - **Mutual authentication.** Each side holds a static X25519 key and pins the
 *   other's public key. `tag_s` can only be produced by someone holding the
 *   server's static private key (it is required for the ECDH(c_eph, s_static)
 *   leg); `tag_c` proves the same about the client. Comparing them is what makes
 *   an interloper on the tunnel fail instead of silently connecting.
 * - **Forward secrecy.** Session keys come from fresh ephemeral pairs, so a
 *   later static-key compromise does not open recorded sessions.
 * - **Replay/reorder resistance.** The counter is inside the AEAD's additional
 *   data and must advance by exactly one, so a captured frame cannot be replayed
 *   and a dropped one cannot be skipped.
 *
 * Only Node builtins are used, so the package has no install surface.
 *
 * @module dsh-remote/protocol
 */

import { createCipheriv, createDecipheriv, createHash, createHmac, createPrivateKey, createPublicKey, diffieHellman, generateKeyPairSync, randomBytes, timingSafeEqual } from 'node:crypto'
import type { KeyObject } from 'node:crypto'
import type { Socket } from 'node:net'

/** Protocol magic; also the marker that distinguishes these frames from any other listener. */
export const MAGIC = Buffer.from('DSHR2', 'ascii')
const INFO = Buffer.from('dshr2', 'ascii')
const DIR_C2S = Buffer.from('C2S', 'ascii')
const DIR_S2C = Buffer.from('S2C', 'ascii')

/** Bytes of nonce each side contributes to the salt. */
export const NONCE_LEN = 32
/** Bytes of an authentication tag. */
export const TAG_LEN = 32
/** Refuse a declared frame larger than this. */
export const MAX_FRAME = 256 * 1024 * 1024
/** Abort a handshake that stalls. */
export const HANDSHAKE_TIMEOUT_MS = 15_000

const ZERO_SALT = Buffer.alloc(32)

/** Raised when the peer fails to authenticate, or speaks something else. */
export class HandshakeError extends Error {}

// ---------------------------------------------------------------- primitives

function hmac(key: Buffer, data: Buffer): Buffer {
  return createHmac('sha256', key).update(data).digest()
}

/**
 * HKDF-SHA256 (extract then expand), matching the reference implementation
 * byte for byte.
 * @param ikm - input keying material.
 * @param salt - extract salt.
 * @param info - expand context.
 * @param length - output length in bytes.
 * @returns the derived key.
 */
export function hkdf(ikm: Buffer, salt: Buffer, info: Buffer, length: number): Buffer {
  const prk = hmac(salt, ikm)
  const blocks: Buffer[] = []
  let block = Buffer.alloc(0)
  let counter = 1
  let total = 0
  while (total < length) {
    block = hmac(prk, Buffer.concat([block, info, Buffer.from([counter])]))
    blocks.push(block)
    total += block.length
    counter += 1
  }
  return Buffer.concat(blocks).subarray(0, length)
}

function deriveSessionKey(shared: Buffer, cNonce: Buffer, sNonce: Buffer): Buffer {
  return hkdf(shared, Buffer.concat([cNonce, sNonce]), INFO, 32)
}

function handshakeTag(key: Buffer, who: Buffer, transcript: Buffer): Buffer {
  return hmac(key, Buffer.concat([who, transcript]))
}

// ------------------------------------------------------------------ key codec

/**
 * The raw 32-byte public key of an X25519 KeyObject.
 *
 * An X25519 SubjectPublicKeyInfo DER ends with the key itself, which avoids
 * pulling in an ASN.1 dependency just to read it back.
 * @param key - the public key.
 * @returns the 32 raw bytes.
 */
export function rawPublic(key: KeyObject): Buffer {
  const der = key.export({ type: 'spki', format: 'der' })
  return Buffer.from(der.subarray(der.length - 32))
}

/**
 * Wrap 32 raw bytes as an X25519 public KeyObject.
 * @param raw - the 32-byte public key.
 * @returns the key object.
 */
export function publicFromRaw(raw: Buffer): KeyObject {
  if (raw.length !== 32) throw new Error(`x25519 public key must be 32 bytes, got ${raw.length}`)
  const prefix = Buffer.from('302a300506032b656e032100', 'hex')
  return createPublicKey({ key: Buffer.concat([prefix, raw]), format: 'der', type: 'spki' })
}

/**
 * Short, human-checkable fingerprint of a public key.
 * @param key - the public key.
 * @returns colon-separated groups, e.g. `af82:15f1:8232:b695`.
 */
export function fingerprint(key: KeyObject): string {
  const digest = createHash('sha256').update(rawPublic(key)).digest('hex')
  return (digest.match(/.{4}/g) ?? []).slice(0, 4).join(':')
}

/** Generate a fresh X25519 keypair. */
export function generateKeyPair(): { privateKey: KeyObject, publicKey: KeyObject } {
  const { privateKey, publicKey } = generateKeyPairSync('x25519')
  return { privateKey, publicKey }
}

/**
 * Parse a private key from PEM, or from 32 raw bytes given as hex or base64.
 * @param text - the encoded key.
 * @returns the private key object.
 */
export function parsePrivateKey(text: string): KeyObject {
  const trimmed = text.trim()
  if (trimmed.includes('-----BEGIN')) return createPrivateKey(trimmed)
  const raw = decodeRaw(trimmed, 'private')
  const prefix = Buffer.from('302e020100300506032b656e04220420', 'hex')
  return createPrivateKey({ key: Buffer.concat([prefix, raw]), format: 'der', type: 'pkcs8' })
}

/**
 * Parse a public key from PEM, or from 32 raw bytes given as hex or base64.
 * @param text - the encoded key.
 * @returns the public key object.
 */
export function parsePublicKey(text: string): KeyObject {
  const trimmed = text.trim()
  if (trimmed.includes('-----BEGIN')) return createPublicKey(trimmed)
  return publicFromRaw(decodeRaw(trimmed, 'public'))
}

/** Decode 32 raw key bytes from hex or base64. */
function decodeRaw(text: string, what: string): Buffer {
  const compact = text.replace(/\s+/g, '')
  const candidates: Buffer[] = []
  if (/^[0-9a-fA-F]{64}$/.test(compact)) candidates.push(Buffer.from(compact, 'hex'))
  try {
    candidates.push(Buffer.from(compact, 'base64'))
  } catch {
    // not base64; the length check below reports the failure
  }
  const found = candidates.find(candidate => candidate.length === 32)
  if (found === undefined) {
    throw new Error(`x25519 ${what} key must be PEM, 64 hex chars, or base64 of 32 bytes`)
  }
  return found
}

/** Serialize a private key as PKCS#8 PEM. */
export function privateToPem(key: KeyObject): string {
  return key.export({ type: 'pkcs8', format: 'pem' }).toString()
}

/** Serialize a public key as SPKI PEM. */
export function publicToPem(key: KeyObject): string {
  return key.export({ type: 'spki', format: 'pem' }).toString()
}

// ------------------------------------------------------------------ socket i/o

/**
 * Promise-based exact-length reader over a net.Socket.
 *
 * `net.Socket` is push-based, so a session needs its own buffer rather than
 * `read()`, which only returns what a single chunk happened to contain.
 */
export class ByteReader {
  private chunks: Buffer[] = []
  private buffered = 0
  private waiters: Array<() => void> = []
  private ended = false

  constructor(private readonly sock: Socket) {
    sock.on('data', (chunk: Buffer) => {
      this.chunks.push(chunk)
      this.buffered += chunk.length
      this.wake()
    })
    const finish = (): void => { this.ended = true; this.wake() }
    sock.on('end', finish)
    sock.on('close', finish)
    sock.on('error', finish)
  }

  private wake(): void {
    const waiters = this.waiters
    this.waiters = []
    for (const waiter of waiters) waiter()
  }

  /**
   * Read exactly `n` bytes, or return null when the peer closed first.
   * @param n - byte count.
   * @param timeoutMs - abort after this long; 0 disables the deadline.
   * @returns the bytes, or null on a clean end-of-stream.
   */
  async read(n: number, timeoutMs = 0): Promise<Buffer | null> {
    const deadline = timeoutMs > 0 ? Date.now() + timeoutMs : 0
    while (this.buffered < n) {
      if (this.ended) return null
      const remaining = deadline === 0 ? 0 : deadline - Date.now()
      if (deadline !== 0 && remaining <= 0) throw new Error(`socket read timed out after ${timeoutMs} ms`)
      await new Promise<void>((resolve, reject) => {
        this.waiters.push(resolve)
        if (deadline !== 0) {
          const timer = setTimeout(() => reject(new Error(`socket read timed out after ${timeoutMs} ms`)), remaining)
          timer.unref?.()
          this.waiters.push(() => clearTimeout(timer))
        }
      })
    }
    const joined = Buffer.concat(this.chunks)
    this.buffered -= n
    if (joined.length === n) {
      this.chunks = []
    } else {
      this.chunks = [joined.subarray(n)]
    }
    return joined.subarray(0, n)
  }
}

function seal(key: Buffer, counter: number, direction: Buffer, plaintext: Buffer): Buffer {
  const counterBuf = Buffer.alloc(8)
  counterBuf.writeBigUInt64BE(BigInt(counter))
  const nonce = Buffer.concat([Buffer.alloc(4), counterBuf])
  const cipher = createCipheriv('aes-256-gcm', key, nonce)
  cipher.setAAD(Buffer.concat([direction, counterBuf]))
  return Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()])
}

function open(key: Buffer, counter: number, direction: Buffer, body: Buffer): Buffer {
  const counterBuf = Buffer.alloc(8)
  counterBuf.writeBigUInt64BE(BigInt(counter))
  const nonce = Buffer.concat([Buffer.alloc(4), counterBuf])
  const decipher = createDecipheriv('aes-256-gcm', key, nonce)
  decipher.setAAD(Buffer.concat([direction, counterBuf]))
  decipher.setAuthTag(body.subarray(body.length - 16))
  return Buffer.concat([decipher.update(body.subarray(0, body.length - 16)), decipher.final()])
}

/**
 * An authenticated, encrypted, ordered message channel.
 *
 * Both directions carry their own key and their own counter, so the two halves
 * of a conversation can never be confused for one another.
 */
export class Session {
  private sendCounter = 0
  private recvCounter = 0
  private readonly sendKey: Buffer
  private readonly recvKey: Buffer
  private readonly sendDir: Buffer
  private readonly recvDir: Buffer
  /** Bytes successfully moved, for diagnostics. */
  bytesSent = 0
  /** Bytes successfully received, for diagnostics. */
  bytesReceived = 0

  constructor(
    readonly socket: Socket,
    private readonly reader: ByteReader,
    key: Buffer,
    initiator: boolean,
  ) {
    const kC2S = hkdf(key, ZERO_SALT, Buffer.concat([INFO, Buffer.from(' c2s')]), 32)
    const kS2C = hkdf(key, ZERO_SALT, Buffer.concat([INFO, Buffer.from(' s2c')]), 32)
    this.sendKey = initiator ? kC2S : kS2C
    this.recvKey = initiator ? kS2C : kC2S
    this.sendDir = initiator ? DIR_C2S : DIR_S2C
    this.recvDir = initiator ? DIR_S2C : DIR_C2S
  }

  /** Send one JSON message. */
  async send(payload: unknown): Promise<void> {
    this.sendCounter += 1
    const plaintext = Buffer.from(JSON.stringify(payload), 'utf8')
    const body = seal(this.sendKey, this.sendCounter, this.sendDir, plaintext)
    const header = Buffer.alloc(4)
    header.writeUInt32BE(body.length)
    await new Promise<void>((resolve, reject) => {
      this.socket.write(Buffer.concat([header, body]), (error) => {
        if (error) reject(error)
        else resolve()
      })
    })
    this.bytesSent += 4 + body.length
  }

  /** Receive one JSON message, or null when the peer closed cleanly. */
  async recv(timeoutMs = 0): Promise<Record<string, unknown> | null> {
    const header = await this.reader.read(4, timeoutMs)
    if (header === null) return null
    const length = header.readUInt32BE(0)
    if (length <= 16 || length > MAX_FRAME) {
      throw new HandshakeError(`implausible frame length ${length}`)
    }
    const body = await this.reader.read(length, timeoutMs)
    if (body === null) return null
    this.recvCounter += 1
    const plaintext = open(this.recvKey, this.recvCounter, this.recvDir, body)
    this.bytesReceived += 4 + length
    return JSON.parse(plaintext.toString('utf8')) as Record<string, unknown>
  }

  /** Close the underlying socket. */
  close(): void {
    this.socket.destroy()
  }
}

// ------------------------------------------------------------------- handshake

function ecdh(privateKey: KeyObject, publicKey: KeyObject): Buffer {
  return diffieHellman({ privateKey, publicKey })
}

function transcriptOf(cEphPub: Buffer, sEphPub: Buffer, cNonce: Buffer, sNonce: Buffer): Buffer {
  return Buffer.concat([MAGIC, cEphPub, sEphPub, cNonce, sNonce])
}

/**
 * Initiator half of the handshake.
 * @param socket - a connected socket (the raw public key of the client, `c_static`).
 * @param clientKey - this side's static private key.
 * @param serverKey - the pinned static public key of the peer.
 * @returns an established session.
 * @throws HandshakeError when the peer cannot prove it holds the pinned key.
 */
export async function clientHandshake(
  socket: Socket,
  clientKey: KeyObject,
  serverKey: KeyObject,
): Promise<Session> {
  const reader = new ByteReader(socket)
  const eph = generateKeyPair()
  const cEphRaw = rawPublic(eph.publicKey)
  const cNonce = randomBytes(NONCE_LEN)
  socket.write(Buffer.concat([MAGIC, cEphRaw, cNonce]))

  const reply = await reader.read(MAGIC.length + 32 + NONCE_LEN + TAG_LEN, HANDSHAKE_TIMEOUT_MS)
  if (reply === null) throw new HandshakeError('peer closed during handshake')
  if (!reply.subarray(0, MAGIC.length).equals(MAGIC)) {
    throw new HandshakeError('peer did not answer with the protocol magic')
  }
  const sEphRaw = reply.subarray(MAGIC.length, MAGIC.length + 32)
  const sNonce = reply.subarray(MAGIC.length + 32, MAGIC.length + 32 + NONCE_LEN)
  const tagS = reply.subarray(reply.length - TAG_LEN)

  const shared = Buffer.concat([
    ecdh(eph.privateKey, publicFromRaw(sEphRaw)),
    ecdh(eph.privateKey, serverKey),
    ecdh(clientKey, publicFromRaw(sEphRaw)),
  ])
  const key = deriveSessionKey(shared, cNonce, sNonce)
  const transcript = transcriptOf(cEphRaw, sEphRaw, cNonce, sNonce)

  const expected = handshakeTag(key, Buffer.from('dshr2 server'), transcript)
  if (tagS.length !== expected.length || !timingSafeEqual(tagS, expected)) {
    throw new HandshakeError(
      'server authentication FAILED — wrong pinned server key, or a man-in-the-middle on the tunnel',
    )
  }

  socket.write(handshakeTag(key, Buffer.from('dshr2 client'), transcript))
  return new Session(socket, reader, key, true)
}

/**
 * Responder half of the handshake.
 * @param socket - an accepted socket.
 * @param serverKey - this side's static private key.
 * @param clientKey - the pinned static public key of the peer.
 * @returns an established session.
 * @throws HandshakeError when the peer cannot prove it holds the pinned key.
 */
export async function serverHandshake(
  socket: Socket,
  serverKey: KeyObject,
  clientKey: KeyObject,
): Promise<Session> {
  const reader = new ByteReader(socket)
  const hello = await reader.read(MAGIC.length + 32 + NONCE_LEN, HANDSHAKE_TIMEOUT_MS)
  if (hello === null) throw new HandshakeError('peer closed during handshake')
  if (!hello.subarray(0, MAGIC.length).equals(MAGIC)) {
    throw new HandshakeError('peer did not speak the protocol magic')
  }
  const cEphRaw = hello.subarray(MAGIC.length, MAGIC.length + 32)
  const cNonce = hello.subarray(MAGIC.length + 32)

  const eph = generateKeyPair()
  const sEphRaw = rawPublic(eph.publicKey)
  const sNonce = randomBytes(NONCE_LEN)

  const shared = Buffer.concat([
    ecdh(eph.privateKey, publicFromRaw(cEphRaw)),
    ecdh(serverKey, publicFromRaw(cEphRaw)),
    ecdh(eph.privateKey, clientKey),
  ])
  const key = deriveSessionKey(shared, cNonce, sNonce)
  const transcript = transcriptOf(cEphRaw, sEphRaw, cNonce, sNonce)

  socket.write(Buffer.concat([
    MAGIC,
    sEphRaw,
    sNonce,
    handshakeTag(key, Buffer.from('dshr2 server'), transcript),
  ]))

  const tagC = await reader.read(TAG_LEN, HANDSHAKE_TIMEOUT_MS)
  if (tagC === null) throw new HandshakeError('peer closed before confirming')
  const expected = handshakeTag(key, Buffer.from('dshr2 client'), transcript)
  if (!timingSafeEqual(tagC, expected)) {
    throw new HandshakeError('client authentication FAILED — unknown client key')
  }

  return new Session(socket, reader, key, false)
}
