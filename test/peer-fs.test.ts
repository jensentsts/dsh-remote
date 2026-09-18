/**
 * Loopback verification for the peer-federated filesystem provider.
 *
 * The point of this test is that it needs **no real peer machine**: it stands up
 * a minimal server that speaks the same wire protocol and answers the `fs.*`
 * ops from a temp directory. So every claim about peer addressing can be
 * checked here, and only the cross-machine network path is left to an
 * integration run.
 *
 * It asserts the two halves that matter:
 *   1. peer paths read through the mount point, and
 *   2. with no peers declared — and for every local path — the provider behaves
 *      exactly like the backend it extends (the zero-regression requirement).
 *
 * Run from the harness checkout so `tsx` resolves the workspace imports:
 *   node --import tsx/esm E:/path/to/dsh-remote/test/peer-fs.test.ts
 */

import { createServer } from 'node:net'
import type { AddressInfo, Socket } from 'node:net'
import { mkdtempSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { Context, Service } from '@deepseek-ai/cordis'
import { FsError } from '@deepseek-ai/dsh-fs'

import { generateKeyPair, privateToPem, publicToPem, serverHandshake } from '../src/protocol.ts'
import { FederatedFileSystem } from '../src/peer-fs.ts'
import { PeerRegistry } from '../src/peers.ts'

let failures = 0
let checks = 0

function check(label: string, condition: boolean, detail = ''): void {
  checks += 1
  if (condition) {
    console.log(`  ok   ${label}`)
  } else {
    failures += 1
    console.log(`  FAIL ${label}${detail === '' ? '' : ` — ${detail}`}`)
  }
}

function section(title: string): void {
  console.log(`\n== ${title} ==`)
}

/** Minimal `ctx.sandboxPolicy` stand-in: the fence is not what this test probes. */
class StubSandboxPolicy extends Service {
  readonly defaultMode = 'danger-full-access' as const
  constructor(ctx: Context) {
    super(ctx, 'sandboxPolicy')
  }

  resolve(): { mode: 'danger-full-access' } {
    return { mode: 'danger-full-access' }
  }
}

/**
 * A tiny wire-protocol server answering the read-side `fs.*` ops from a real
 * directory. Deliberately not the full server plugin: this test is about the
 * provider, and a small peer keeps the failure surface small too.
 */
function startFakePeer(
  agentPrivate: ReturnType<typeof generateKeyPair>['privateKey'],
  clientPublic: ReturnType<typeof generateKeyPair>['publicKey'],
): Promise<{ port: number, close: () => void, ops: string[] }> {
  const ops: string[] = []
  const server = createServer((socket: Socket) => {
    void (async () => {
      try {
        const session = await serverHandshake(socket, agentPrivate, clientPublic)
        for (;;) {
          const request = await session.recv(30_000)
          if (request === null) break
          const op = String(request.op)
          ops.push(op)
          const result = answer(op, String(request.path ?? ''), request)
          await session.send(
            result.__fail === true
              ? { id: request.id, ok: false, error: String(result.error), code: String(result.code) }
              : { id: request.id, ok: true, ...result },
          )
        }
      } catch {
        // The client closing between requests is the normal end of this loop.
      } finally {
        socket.destroy()
      }
    })()
  })
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address() as AddressInfo
      resolve({ port, close: () => server.close(), ops })
    })
  })
}

/** Answer one `fs.*` op from the real filesystem, in the server plugin's shape. */
function answer(op: string, path: string, request: Record<string, unknown>): Record<string, unknown> {
  const nativePath = path.replace(/\//g, '\\')
  if (op === 'fs.stat') {
    try {
      const stat = statSyncSafe(nativePath)
      if (stat === undefined) return { exists: false }
      return {
        exists: true,
        isDir: stat.isDirectory(),
        size: stat.size,
        mtimeMs: Math.floor(stat.mtimeMs),
        version: `${Math.floor(stat.mtimeMs)}:${stat.size}`,
      }
    } catch {
      return { exists: false }
    }
  }
  if (op === 'fs.list') {
    const entries = readdirSync(nativePath, { withFileTypes: true }).map(entry => {
      const stat = statSyncSafe(join(nativePath, entry.name))
      return { name: entry.name, isDir: entry.isDirectory(), size: stat?.size ?? null, mtimeMs: Math.floor(stat?.mtimeMs ?? 0) }
    })
    return { path: nativePath, count: entries.length, entries }
  }
  if (op === 'fs.read') {
    const offset = Number(request.offset ?? 0)
    const length = Number(request.length ?? 256 * 1024)
    const buf = readFileSync(nativePath)
    const window = buf.subarray(offset, offset + length)
    return {
      path: nativePath,
      offset,
      size: buf.length,
      bytes: window.length,
      eof: offset + window.length >= buf.length,
      dataB64: window.toString('base64'),
      text: window.toString('utf8'),
    }
  }
  const versionOf = (target: string): string | undefined => {
    const info = statSyncSafe(target)
    return info === undefined ? undefined : `${Math.floor(info.mtimeMs)}:${info.size}`
  }
  const fail = (error: string, code: string): Record<string, unknown> => ({ __fail: true, error, code })

  if (op === 'fs.write') {
    const exists = statSyncSafe(nativePath) !== undefined
    if (request.createOnly === true && exists) {
      return fail('cannot overwrite existing without reading it first', 'FS_NOT_OBSERVED')
    }
    if (typeof request.expectedVersion === 'string') {
      if (!exists) return fail('file no longer exists', 'FS_STALE_VERSION')
      if (versionOf(nativePath) !== request.expectedVersion) {
        return fail('file changed since it was read', 'FS_STALE_VERSION')
      }
    }
    const before = exists ? readFileSync(nativePath, 'utf8') : null
    writeFileSync(nativePath, Buffer.from(String(request.dataB64 ?? ''), 'base64'))
    return { size: statSyncSafe(nativePath)?.size ?? 0, version: versionOf(nativePath), created: !exists, before }
  }
  if (op === 'fs.edit') {
    if (statSyncSafe(nativePath) === undefined) return fail('file changed since it was read', 'FS_STALE_VERSION')
    if (typeof request.expectedVersion === 'string' && versionOf(nativePath) !== request.expectedVersion) {
      return fail('file changed since it was read', 'FS_STALE_VERSION')
    }
    const text = readFileSync(nativePath, 'utf8')
    const oldString = String(request.oldString ?? '')
    const count = oldString === '' ? 0 : text.split(oldString).length - 1
    if (count === 0) return fail('the text to replace was not found', 'FS_EDIT_NOT_FOUND')
    if (count > 1 && request.replaceAll !== true) {
      return fail(`the text to replace appears ${count} times`, 'FS_AMBIGUOUS_EDIT')
    }
    const after = request.replaceAll === true
      ? text.split(oldString).join(String(request.newString ?? ''))
      : text.replace(oldString, String(request.newString ?? ''))
    writeFileSync(nativePath, after, 'utf8')
    return { version: versionOf(nativePath), before: text, after }
  }

  return fail(`unsupported op ${op}`, 'FS_IO_ERROR')
}

function statSyncSafe(path: string): { isDirectory: () => boolean, size: number, mtimeMs: number } | undefined {
  try {
    return statSync(path)
  } catch {
    return undefined
  }
}

async function main(): Promise<void> {
  const workspace = mkdtempSync(join(tmpdir(), 'peer-fs-'))
  mkdirSync(join(workspace, 'sub'))
  writeFileSync(join(workspace, 'hello.txt'), 'hello from the peer\nsecond line\n', 'utf8')
  writeFileSync(join(workspace, 'sub', 'nested.txt'), 'nested\n', 'utf8')
  const remoteRoot = workspace.replace(/\\/g, '/')

  const clientKeys = generateKeyPair()
  const agentKeys = generateKeyPair()
  const peer = await startFakePeer(agentKeys.privateKey, clientKeys.publicKey)

  const peerProfile = {
    host: '127.0.0.1',
    port: peer.port,
    maxPermission: 1,
    privateKey: privateToPem(clientKeys.privateKey),
    peerPublicKey: publicToPem(agentKeys.publicKey),
    timeoutMs: 20_000,
  }

  // ---------------------------------------------------------------- with a peer
  section('with a peer declared')
  const ctx = new Context()
  await ctx.plugin(StubSandboxPolicy)
  await ctx.plugin(FederatedFileSystem, { cwd: process.cwd(), peers: { p: peerProfile } } as never)
  const fs = ctx.fs as FederatedFileSystem

  const peerFile = `/peers/p/${remoteRoot}/hello.txt`
  const parsed = await fs.resolve(peerFile)
  check('resolve maps the path onto a peer key',
    String(parsed.targetKey) === `peer:p:${remoteRoot}/hello.txt`,
    String(parsed.targetKey))

  const info = await fs.stat(parsed)
  check('stat reports a regular file', info?.type === 'file', JSON.stringify(info))
  check('stat reports the peer size', info?.size === 32, String(info?.size))

  const text = await fs.readText(parsed)
  check('readText returns the peer content', text.startsWith('hello from the peer'), JSON.stringify(text))

  const window = await fs.readByteRange(parsed, { offset: 0, length: 5 })
  check('readByteRange returns the exact window', Buffer.from(window).toString('utf8') === 'hello')

  const dirTarget = await fs.resolve(`/peers/p/${remoteRoot}`)
  const entries = await fs.listDir(dirTarget)
  const names = entries.map(e => e.name).sort()
  check('listDir returns both children', JSON.stringify(names) === '["hello.txt","sub"]', JSON.stringify(names))
  const sub = entries.find(e => e.name === 'sub')
  check('listDir child targets carry peer keys',
    String(sub?.target.targetKey).startsWith('peer:p:'), String(sub?.target.targetKey))
  check('listDir types the directory', sub?.type === 'directory', String(sub?.type))

  const nested = await fs.readText(await fs.resolve(`/peers/p/${remoteRoot}/sub/nested.txt`))
  check('a nested path reads too', nested === 'nested\n', JSON.stringify(nested))

  const missing = await fs.stat(await fs.resolve(`/peers/p/${remoteRoot}/nope.txt`))
  check('an absent peer file stats to undefined', missing === undefined)

  let unknownPeer = ''
  try {
    await fs.resolve('/peers/not-declared/E:/x.txt')
  } catch (error) {
    unknownPeer = error instanceof FsError ? error.code : String(error)
  }
  check('an undeclared peer is refused', unknownPeer === 'FS_NOT_FOUND', unknownPeer)

  let writeRefusal = ''
  let writeRefusalMessage = ''
  try {
    await fs.writeText(parsed, 'nope')
  } catch (error) {
    writeRefusal = error instanceof FsError ? error.code : String(error)
    writeRefusalMessage = error instanceof Error ? error.message : String(error)
  }
  check('peer writes are refused, not silently attempted',
    writeRefusal === 'FS_PERMISSION_DENIED', writeRefusal)

  // -------------------------------------------------- ceiling wiring (S2)
  section('what refuses the write, and why')
  check('a read-only peer is stopped by the ceiling, and the message says so',
    writeRefusalMessage.includes('ceiling') && writeRefusalMessage.includes('level 2'),
    writeRefusalMessage)

  const full = new Context()
  await full.plugin(StubSandboxPolicy)
  await full.plugin(FederatedFileSystem, {
    cwd: process.cwd(),
    peers: { p: { ...peerProfile, maxPermission: 3 } },
  } as never)
  const fullFs = full.fs as FederatedFileSystem
  // A dedicated probe file: writing through a peer must not disturb the fixture
  // the read-side checks later in this file depend on.
  const probeFile = `/peers/p/${remoteRoot}/write-probe.txt`
  let level3Message = ''
  try {
    await fullFs.writeText(await fullFs.resolve(probeFile), 'nope')
  } catch (error) {
    level3Message = error instanceof Error ? error.message : String(error)
  }
  check('a level-3 peer clears the ceiling and the write lands',
    readFileSync(join(workspace, 'write-probe.txt'), 'utf8') === 'nope', level3Message)

  const confined = new Context()
  await confined.plugin(StubSandboxPolicy)
  await confined.plugin(FederatedFileSystem, {
    cwd: process.cwd(),
    peers: { p: { ...peerProfile, maxPermission: 2, workspaceRoot: 'E:/somewhere-else' } },
  } as never)
  const confinedFs = confined.fs as FederatedFileSystem
  let outsideMessage = ''
  try {
    await confinedFs.writeText(await confinedFs.resolve(peerFile), 'nope')
  } catch (error) {
    outsideMessage = error instanceof Error ? error.message : String(error)
  }
  check('a level-2 peer writing outside its declared root is refused for containment',
    outsideMessage.includes('outside the declared workspace'), outsideMessage)

  check('peer processPath is not a local path',
    fs.processPath(parsed).startsWith('peer://'), fs.processPath(parsed))
  check('contains() stays inside one peer',
    fs.contains(dirTarget, parsed) && !fs.contains(dirTarget, await fs.resolve('/peers/p/E:/other.txt')))

  // ------------------------------------------------------ local paths untouched
  section('local paths (zero regression)')
  const localTarget = await fs.resolve(join(workspace, 'hello.txt'))
  check('a local path still resolves locally', !String(localTarget.targetKey).startsWith('peer:'),
    String(localTarget.targetKey))
  check('a local read still works',
    (await fs.readText(localTarget)).startsWith('hello from the peer'))
  const localDir = await fs.resolve(workspace)
  const localNames = (await fs.listDir(localDir)).map(e => e.name)
  check('a local listing still works',
    localNames.includes('hello.txt') && localNames.includes('sub'), localNames.join(','))
  check('local containment still holds', fs.contains(localDir, localTarget))

  // ------------------------------------------------------------- with no peers
  section('with no peers declared')
  const bare = new Context()
  await bare.plugin(StubSandboxPolicy)
  await bare.plugin(FederatedFileSystem, { cwd: process.cwd() } as never)
  const bareFs = bare.fs as FederatedFileSystem
  check('local reads still work', (await bareFs.readText(await bareFs.resolve(join(workspace, 'hello.txt')))).length > 0)
  let unmounted = ''
  try {
    await bareFs.resolve('/peers/p/E:/x.txt')
  } catch (error) {
    unmounted = error instanceof FsError ? error.code : String(error)
  }
  check('the mount point is inert when nothing is declared', unmounted === 'FS_NOT_FOUND', unmounted)

  // ------------------------------------------- shared declarations (S2 finish)
  section('the shared registry is the single source of truth')
  const shared = new Context()
  await shared.plugin(StubSandboxPolicy)
  await shared.plugin(PeerRegistry, { peers: { p: { ...peerProfile, maxPermission: 3 } } } as never)
  // Deliberately no `peers` of its own: the mount must come from the registry.
  await shared.plugin(FederatedFileSystem, { cwd: process.cwd() } as never)
  const sharedFs = shared.fs as FederatedFileSystem
  const sharedText = await sharedFs.readText(await sharedFs.resolve(peerFile))
  check('a peer declared only in the registry is mounted and readable',
    sharedText.startsWith('hello from the peer'), JSON.stringify(sharedText.slice(0, 20)))
  let sharedWrite = ''
  try {
    await sharedFs.writeText(await sharedFs.resolve(probeFile), 'nope')
  } catch (error) {
    sharedWrite = error instanceof Error ? error.message : String(error)
  }
  check('the registry\'s ceiling is the one enforced (level 3 lets the write through)',
    readFileSync(join(workspace, 'write-probe.txt'), 'utf8') === 'nope', sharedWrite || '(no throw)')

  const conflicting = new Context()
  await conflicting.plugin(StubSandboxPolicy)
  await conflicting.plugin(PeerRegistry, { peers: { p: { ...peerProfile, maxPermission: 3 } } } as never)
  await conflicting.plugin(FederatedFileSystem, {
    cwd: process.cwd(),
    peers: { p: { ...peerProfile, maxPermission: 1 } },
  } as never)
  const conflictingFs = conflicting.fs as FederatedFileSystem
  let conflictMessage = ''
  try {
    await conflictingFs.writeText(await conflictingFs.resolve(probeFile), 'nope')
  } catch (error) {
    conflictMessage = error instanceof Error ? error.message : String(error)
  }
  check('when both declare, the registry wins (level 3 writes; the config said level 1)',
    conflictMessage === '', conflictMessage)

  // --------------------------------------------------- the version guard (S3)
  section('a stale write is refused, not silently applied')
  writeFileSync(join(workspace, 'hello.txt'), 'hello from the peer\nsecond line\n', 'utf8')
  const guardCtx = new Context()
  await guardCtx.plugin(StubSandboxPolicy)
  await guardCtx.plugin(FederatedFileSystem, {
    cwd: process.cwd(),
    peers: { p: { ...peerProfile, maxPermission: 3 } },
  } as never)
  const guardFs = guardCtx.fs as FederatedFileSystem
  const guardTarget = await guardFs.resolve(peerFile)
  const observed = await guardFs.stat(guardTarget)
  check('the peer supplies the version token', typeof observed?.version === 'string' && String(observed.version).includes(':'),
    String(observed?.version))

  // Someone else changes the file after we observed it.
  writeFileSync(join(workspace, 'hello.txt'), 'changed underneath, a different length\n', 'utf8')
  let staleCode = ''
  try {
    await guardFs.writeText(guardTarget, 'should not land', { kind: 'replaceIfVersion', version: observed!.version })
  } catch (error) {
    staleCode = error instanceof FsError ? error.code : String(error)
  }
  check('a guarded write against a changed file is FS_STALE_VERSION', staleCode === 'FS_STALE_VERSION', staleCode)
  check('and the file was left untouched',
    readFileSync(join(workspace, 'hello.txt'), 'utf8') === 'changed underneath, a different length\n')

  const fresh = await guardFs.stat(guardTarget)
  const written = await guardFs.writeText(guardTarget, 'guarded write landed\n', { kind: 'replaceIfVersion', version: fresh!.version })
  check('a guarded write against the current version lands', written.operation === 'update'
    && readFileSync(join(workspace, 'hello.txt'), 'utf8') === 'guarded write landed\n')

  const edited = await guardFs.editText(guardTarget, { oldString: 'guarded write', newString: 'edited text', replaceAll: false })
  check('a peer edit applies the literal replacement',
    edited.after === 'edited text landed\n' && readFileSync(join(workspace, 'hello.txt'), 'utf8') === 'edited text landed\n',
    JSON.stringify(edited.after))

  let ambiguous = ''
  try {
    await guardFs.editText(guardTarget, { oldString: 'e', newString: 'X', replaceAll: false })
  } catch (error) {
    ambiguous = error instanceof FsError ? error.code : String(error)
  }
  check('an ambiguous edit is refused', ambiguous === 'FS_AMBIGUOUS_EDIT', ambiguous)

  let missingEdit = ''
  try {
    await guardFs.editText(guardTarget, { oldString: 'no such text', newString: 'x', replaceAll: false })
  } catch (error) {
    missingEdit = error instanceof FsError ? error.code : String(error)
  }
  check('a non-matching edit is refused', missingEdit === 'FS_EDIT_NOT_FOUND', missingEdit)

  peer.close()
  console.log(`\n${checks - failures}/${checks} checks passed`)
  console.log('peer ops exercised:', [...new Set(peer.ops)].join(', '))
  if (failures > 0) process.exitCode = 1
  await new Promise<void>((resolve) => { setTimeout(resolve, 50) })
}

await main()
