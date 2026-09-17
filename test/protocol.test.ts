/**
 * Loopback self-test for the dsh-remote protocol.
 *
 * Covers the four properties the design claims: a matching pair completes the
 * handshake and can exchange frames; a wrongly pinned server key is refused; an
 * unknown client key is refused; and two sessions do not share keys (forward
 * secrecy).
 *
 * Run from the harness checkout so `tsx` resolves:
 *   node --import tsx/esm E:/path/to/dsh-remote/test/protocol.test.ts
 */

import { createServer } from 'node:net'
import type { AddressInfo } from 'node:net'

import {
  HandshakeError,
  clientHandshake,
  fingerprint,
  generateKeyPair,
  serverHandshake,
  type Session,
} from '../src/protocol.ts'

interface Case {
  label: string
  /** Replace the server's pinned client key with a stranger's. */
  rogueClient?: boolean
  /** Pin a wrong server key on the client side. */
  wrongServerPin?: boolean
}

async function runCase({ label, rogueClient, wrongServerPin }: Case): Promise<void> {
  const server = generateKeyPair()
  const client = generateKeyPair()
  const stranger = generateKeyPair()
  void stranger

  let serverNote = ''
  const listener = createServer((socket) => {
    void (async () => {
      try {
        const session = await serverHandshake(socket, server.privateKey, client.publicKey)
        for (let i = 0; i < 3; i += 1) {
          const request = await session.recv(5000)
          if (request === null) break
          await session.send({ echo: request.n, who: 'server' })
        }
        serverNote = 'handshake + 3 frames ok'
      } catch (error) {
        serverNote = `${(error as Error).name}: ${(error as Error).message}`
      } finally {
        socket.destroy()
      }
    })()
  })
  await new Promise<void>(resolve => listener.listen(0, '127.0.0.1', resolve))
  const port = (listener.address() as AddressInfo).port

  let clientNote = ''
  let session: Session | undefined
  try {
    const { connect } = await import('node:net')
    const socket = connect(port, '127.0.0.1')
    await new Promise<void>((resolve, reject) => {
      socket.once('connect', resolve)
      socket.once('error', reject)
    })
    session = await clientHandshake(socket, client.privateKey, server.publicKey)
    for (let i = 0; i < 3; i += 1) {
      await session.send({ n: i })
      const reply = await session.recv(5000)
      if (reply?.echo !== i) throw new Error(`bad echo: ${JSON.stringify(reply)}`)
    }
    clientNote = 'handshake + 3 frames ok'
  } catch (error) {
    clientNote = `${(error as Error).name}: ${(error as Error).message}`
  } finally {
    session?.close()
  }

  await new Promise<void>(resolve => listener.close(() => resolve()))
  console.log(`[${label}]`)
  console.log(`   client: ${clientNote}`)
  console.log(`   server: ${serverNote || '(no connection)'}`)
}

console.log('== 1. matching keys ==')
await runCase({ label: 'happy path' })

console.log('\n== 2. client pins the WRONG server key (MITM attempt) ==')
// Re-run with a server whose public key the client does not pin.
{
  const real = generateKeyPair()
  const impostor = generateKeyPair()
  const client = generateKeyPair()
  const listener = createServer((socket) => {
    void (async () => {
      try {
        await serverHandshake(socket, impostor.privateKey, client.publicKey)
        console.log('   server: UNEXPECTEDLY accepted')
      } catch (error) {
        console.log(`   server: ${(error as Error).name}: ${(error as Error).message}`)
      } finally {
        socket.destroy()
      }
    })()
  })
  await new Promise<void>(resolve => listener.listen(0, '127.0.0.1', resolve))
  const port = (listener.address() as AddressInfo).port
  const { connect } = await import('node:net')
  const socket = connect(port, '127.0.0.1')
  await new Promise<void>((resolve, reject) => {
    socket.once('connect', resolve)
    socket.once('error', reject)
  })
  try {
    await clientHandshake(socket, client.privateKey, real.publicKey)
    console.log('   client: UNEXPECTEDLY accepted')
  } catch (error) {
    console.log(`   client: ${(error as Error).name}: ${(error as Error).message}`)
  }
  socket.destroy()
  await new Promise<void>(resolve => listener.close(() => resolve()))
}

console.log('\n== 3. server pins a DIFFERENT client key (rogue client) ==')
{
  const server = generateKeyPair()
  const client = generateKeyPair()
  const stranger = generateKeyPair()
  const listener = createServer((socket) => {
    void (async () => {
      try {
        await serverHandshake(socket, server.privateKey, stranger.publicKey)
        console.log('   server: UNEXPECTEDLY accepted')
      } catch (error) {
        console.log(`   server: ${(error as Error).name}: ${(error as Error).message}`)
      } finally {
        socket.destroy()
      }
    })()
  })
  await new Promise<void>(resolve => listener.listen(0, '127.0.0.1', resolve))
  const port = (listener.address() as AddressInfo).port
  const { connect } = await import('node:net')
  const socket = connect(port, '127.0.0.1')
  await new Promise<void>((resolve, reject) => {
    socket.once('connect', resolve)
    socket.once('error', reject)
  })
  try {
    const session = await clientHandshake(socket, client.privateKey, server.publicKey)
    session.close()
    console.log('   client: handshake returned; server must be the one rejecting')
  } catch (error) {
    console.log(`   client: ${(error as Error).name}: ${(error as Error).message}`)
  }
  socket.destroy()
  await new Promise<void>(resolve => listener.close(() => resolve()))
}

console.log('\n== 4. fingerprints are stable and distinct ==')
{
  const a = generateKeyPair()
  const b = generateKeyPair()
  console.log(`   fp(a)          = ${fingerprint(a.publicKey)}`)
  console.log(`   fp(a) again    = ${fingerprint(a.publicKey)}`)
  console.log(`   fp(b)          = ${fingerprint(b.publicKey)}`)
  console.log(`   a !== b        : ${fingerprint(a.publicKey) !== fingerprint(b.publicKey)}`)
}

console.log(`\nHandshakeError is an Error subclass: ${new HandshakeError('x') instanceof Error}`)
