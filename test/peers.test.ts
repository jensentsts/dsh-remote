/**
 * Verification for the peer permission ceiling.
 *
 * This is the piece that has to be right in both directions, so the checks are
 * deliberately hostile: they probe the fail-closed default, the clamping of
 * out-of-range values, the containment edge where a sibling directory shares a
 * prefix, and the exact typed refusal each level produces.
 *
 * Run from the harness checkout so `tsx` resolves the workspace imports:
 *   node --import tsx/esm E:/path/to/dsh-remote/test/peers.test.ts
 */

import { Context } from '@deepseek-ai/cordis'
import { FsError } from '@deepseek-ai/dsh-fs'

import {
  DEFAULT_PERMISSION,
  PeerRegistry,
  assertPeerOperation,
  isRemoteUnder,
  levelName,
  normalizePermission,
  requiredLevel,
} from '../src/peers.ts'

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

/** Run an operation and report the error code it raised, or 'no-throw'. */
function codeOf(fn: () => void): string {
  try {
    fn()
    return 'no-throw'
  } catch (error) {
    return error instanceof FsError ? error.code : `other:${String(error)}`
  }
}

function messageOf(fn: () => void): string {
  try {
    fn()
    return ''
  } catch (error) {
    return error instanceof Error ? error.message : String(error)
  }
}

async function main(): Promise<void> {
  // ------------------------------------------------------------------ mapping
  section('operation → required level')
  for (const op of ['ping', 'sysinfo', 'preset.list', 'fs.stat', 'fs.list', 'fs.read', 'fs.hash', 'agent.events']) {
    check(`${op} is a read`, requiredLevel(op) === 1, String(requiredLevel(op)))
  }
  for (const op of ['fs.write', 'fs.edit']) {
    check(`${op} needs level 2`, requiredLevel(op) === 2, String(requiredLevel(op)))
  }
  for (const op of ['exec', 'agent.prompt', 'agent.ensure', 'agent.interrupt']) {
    check(`${op} needs level 3`, requiredLevel(op) === 3, String(requiredLevel(op)))
  }
  check('an unknown op is treated as a read (new ops must not silently need level 3)',
    requiredLevel('fs.something-new') === 1, String(requiredLevel('fs.something-new')))

  // ----------------------------------------------------------------- clamping
  section('ceiling normalization fails closed')
  check('absent → read-only default', normalizePermission(undefined) === DEFAULT_PERMISSION)
  check('NaN → read-only default', normalizePermission(Number.NaN) === DEFAULT_PERMISSION)
  check('0 → read-only default', normalizePermission(0) === DEFAULT_PERMISSION)
  check('negative → read-only default', normalizePermission(-5) === DEFAULT_PERMISSION)
  check("'2' coerces", normalizePermission('2') === 2)
  check('2.9 truncates to 2', normalizePermission(2.9) === 2)
  check('4 clamps to 3, never above', normalizePermission(4) === 3, String(normalizePermission(4)))
  check('1/2/3 pass through',
    normalizePermission(1) === 1 && normalizePermission(2) === 2 && normalizePermission(3) === 3)
  check('level names', `${levelName(1)}/${levelName(2)}/${levelName(3)}` === 'read-only/workspace-write/danger-full-access')

  // --------------------------------------------------------------- containment
  section('remote path containment is lexical')
  check('no declared root means no boundary', isRemoteUnder('E:/anything', ''))
  check('exact match', isRemoteUnder('E:/work', 'E:/work'))
  check('nested', isRemoteUnder('E:/work/src/a.ts', 'E:/work'))
  check('backslashes fold', isRemoteUnder('E:\\work\\src', 'E:/work'))
  check('case folds', isRemoteUnder('e:/WORK/src', 'E:/work'))
  check('trailing slash on the root', isRemoteUnder('E:/work/src', 'E:/work/'))
  check('a sibling sharing a prefix is NOT inside', !isRemoteUnder('E:/workshop/x', 'E:/work'))
  check('a parent is not inside its child', !isRemoteUnder('E:/work', 'E:/work/src'))

  // ------------------------------------------------------------------ refusals
  section('level 1 (read-only)')
  check('reads pass', codeOf(() => assertPeerOperation(1, 'fs.read', { peer: 'p' })) === 'no-throw')
  check('writes are refused', codeOf(() => assertPeerOperation(1, 'fs.write', { peer: 'p', path: 'E:/w/a' })) === 'FS_PERMISSION_DENIED')
  check('exec is refused', codeOf(() => assertPeerOperation(1, 'exec', { peer: 'p' })) === 'FS_PERMISSION_DENIED')
  check('the message names the peer and both levels',
    messageOf(() => assertPeerOperation(1, 'exec', { peer: 'ze-run' }))
      .includes('ze-run') && messageOf(() => assertPeerOperation(1, 'exec', { peer: 'ze-run' })).includes('level 3'))

  section('level 2 (workspace-write)')
  const within = { peer: 'p', workspaceRoot: 'E:/work' }
  check('reads pass', codeOf(() => assertPeerOperation(2, 'fs.read', { peer: 'p' })) === 'no-throw')
  check('a write inside the root passes',
    codeOf(() => assertPeerOperation(2, 'fs.write', { ...within, path: 'E:/work/src/a.ts' })) === 'no-throw')
  check('a write at the root passes',
    codeOf(() => assertPeerOperation(2, 'fs.write', { ...within, path: 'E:/work' })) === 'no-throw')
  check('a write outside the root is refused',
    codeOf(() => assertPeerOperation(2, 'fs.write', { ...within, path: 'E:/elsewhere/a.ts' })) === 'FS_PERMISSION_DENIED')
  check('a sibling prefix is refused',
    codeOf(() => assertPeerOperation(2, 'fs.write', { ...within, path: 'E:/workshop/a.ts' })) === 'FS_PERMISSION_DENIED')
  check('exec is still refused at level 2',
    codeOf(() => assertPeerOperation(2, 'exec', { peer: 'p' })) === 'FS_PERMISSION_DENIED')
  check('an empty root lets the peer decide',
    codeOf(() => assertPeerOperation(2, 'fs.write', { peer: 'p', path: 'E:/anywhere/a.ts' })) === 'no-throw')

  section('level 3 (danger-full-access)')
  check('writes pass anywhere',
    codeOf(() => assertPeerOperation(3, 'fs.write', { peer: 'p', workspaceRoot: 'E:/work', path: 'E:/elsewhere/a.ts' })) === 'no-throw')
  check('exec passes', codeOf(() => assertPeerOperation(3, 'exec', { peer: 'p' })) === 'no-throw')
  check('driving the peer agent passes', codeOf(() => assertPeerOperation(3, 'agent.prompt', { peer: 'p' })) === 'no-throw')

  // ------------------------------------------------------------------ registry
  section('registry')
  const ctx = new Context()
  await ctx.plugin(PeerRegistry, {
    peers: {
      'read-only-peer': { host: 'h', port: 1 },
      confined: { host: 'h', port: 2, maxPermission: 2, workspaceRoot: 'E:/work' },
      full: { host: 'h', port: 3, maxPermission: 3 },
      junk: { host: 'h', port: 4, maxPermission: 99 },
    },
  } as never)
  const registry = ctx.dshRemotePeers as PeerRegistry

  check('declared peers are listed', registry.list().join(',') === 'read-only-peer,confined,full,junk', registry.list().join(','))
  check('a peer without maxPermission defaults to read-only', registry.ceilingOf('read-only-peer') === 1)
  check('an out-of-range ceiling clamps', registry.ceilingOf('junk') === 3)
  check('unknown peer is FS_NOT_FOUND', codeOf(() => registry.profile('nope')) === 'FS_NOT_FOUND')
  check('the unknown-peer message lists what exists',
    messageOf(() => registry.profile('nope')).includes('read-only-peer'))
  check('assert() uses the peer ceiling',
    codeOf(() => registry.assert('confined', 'fs.write', 'E:/work/a')) === 'no-throw'
    && codeOf(() => registry.assert('confined', 'fs.write', 'E:/out/a')) === 'FS_PERMISSION_DENIED')
  check('assert() on a read-only peer refuses a write',
    codeOf(() => registry.assert('read-only-peer', 'fs.write', 'E:/work/a')) === 'FS_PERMISSION_DENIED')
  check('describe() summarises levels',
    registry.describe().includes('read-only-peer (level 1/read-only)'), registry.describe())

  const empty = new Context()
  await empty.plugin(PeerRegistry, {} as never)
  const bare = empty.dshRemotePeers as PeerRegistry
  check('an empty registry says so', bare.describe() === 'no peers declared', bare.describe())
  check('an empty registry refuses every peer lookup', codeOf(() => bare.profile('any')) === 'FS_NOT_FOUND')

  console.log(`\n${checks - failures}/${checks} checks passed`)
  if (failures > 0) process.exitCode = 1
}

await main()
