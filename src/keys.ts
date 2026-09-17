/**
 * Key material resolution for the remote link, deliberately shaped like the
 * other DSH plugins' key settings so the two feel identical to use:
 *
 *   - `privateKey` / `peerPublicKey` take an inline value (PEM, 64 hex chars, or
 *     base64 of 32 bytes) and win when present; the private one is `role('secret')`
 *     so the settings GUI never echoes it back over the wire;
 *   - `privateKeyFile` / `peerPublicKeyFile` name a file, defaulting to a path
 *     under `${DSH_HOME}/dsh-remote/`;
 *   - `autoGenerateKey` generates and persists this side's keypair the first
 *     time, so a fresh install is usable after one click.
 *
 * @module dsh-remote/keys
 */

import { createPublicKey } from 'node:crypto'
import type { KeyObject } from 'node:crypto'
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { dirname, isAbsolute, join, resolve } from 'node:path'

import {
  fingerprint,
  generateKeyPair,
  parsePrivateKey,
  parsePublicKey,
  privateToPem,
  publicToPem,
  rawPublic,
} from './protocol.ts'

/** Key-material fields every config in this package shares. */
export interface KeySettings {
  /** Inline X25519 private key (PEM / 64 hex / base64); wins over the file. */
  privateKey?: string
  /** File holding this side's private key; also where a generated one lands. */
  privateKeyFile?: string
  /** Generate and persist a keypair when none exists yet. */
  autoGenerateKey?: boolean
  /** Inline pinned X25519 public key of the peer; wins over the file. */
  peerPublicKey?: string
  /** File holding the peer's pinned public key. */
  peerPublicKeyFile?: string
}

/** This side's resolved identity plus where it came from. */
export interface ResolvedPrivateKey {
  key: KeyObject
  /** Public half, for logging the fingerprint. */
  publicKey: KeyObject
  /** The PEM actually in use, so a caller can print it for the peer to pin. */
  pem: string
  /** True when this call created the key. */
  generated: boolean
  /** File path when the key lives on disk. */
  file?: string
}

/** Treat an empty or blank optional string as absent. */
export function text(value: string | undefined): string | undefined {
  return value === undefined || value.trim() === '' ? undefined : value
}

/**
 * A path under the harness home, so generated state lives with the rest of the
 * deployment instead of in whatever cwd dsh happened to start in.
 * @param segments - path segments below the home.
 * @returns the absolute path.
 */
export function dshHomePath(...segments: string[]): string {
  const home = text(process.env.DSH_HOME) ?? join(homedir(), '.dsh')
  return join(home, ...segments)
}

function absolute(path: string): string {
  return isAbsolute(path) ? path : resolve(process.cwd(), path)
}

/** Restrict a private-key file to its owner (best effort). */
function harden(path: string): void {
  try {
    chmodSync(path, 0o600)
  } catch {
    // Windows has no POSIX mode; the profile directory ACL already covers this.
  }
}

/**
 * Resolve this side's static private key, generating and persisting one when
 * the config allows it and no key exists yet.
 * @param settings - the key fields of the plugin's resolved config.
 * @param defaultFileName - file name used under `${DSH_HOME}/dsh-remote/`.
 * @returns the resolved key material.
 * @throws Error when no key is configured and generation is disabled.
 */
export function resolvePrivateKey(
  settings: KeySettings,
  defaultFileName: string,
): ResolvedPrivateKey {
  const inline = text(settings.privateKey)
  if (inline !== undefined) {
    const key = parsePrivateKey(inline)
    return {
      key,
      publicKey: createPublicKey(key),
      pem: privateToPem(key),
      generated: false,
    }
  }

  const file = absolute(
    text(settings.privateKeyFile) ?? dshHomePath('dsh-remote', defaultFileName),
  )
  if (existsSync(file)) {
    const key = parsePrivateKey(readFileSync(file, 'utf8'))
    return {
      key,
      publicKey: createPublicKey(key),
      pem: privateToPem(key),
      generated: false,
      file,
    }
  }

  if (settings.autoGenerateKey === false) {
    throw new Error(
      `dsh-remote: no private key configured and autoGenerateKey is off (looked for ${file})`,
    )
  }

  const { privateKey } = generateKeyPair()
  const pem = privateToPem(privateKey)
  mkdirSync(dirname(file), { recursive: true })
  writeFileSync(file, pem, { encoding: 'utf8', mode: 0o600 })
  harden(file)
  return { key: privateKey, publicKey: createPublicKey(privateKey), pem, generated: true, file }
}

/**
 * Resolve the peer's pinned public key.
 * @param settings - the key fields of the plugin's resolved config.
 * @param defaultFileName - file name used under `${DSH_HOME}/dsh-remote/`.
 * @returns the peer's public key.
 * @throws Error when no peer key is configured.
 */
export function resolvePeerPublicKey(
  settings: KeySettings,
  defaultFileName: string,
): KeyObject {
  const inline = text(settings.peerPublicKey)
  if (inline !== undefined) return parsePublicKey(inline)

  const file = absolute(
    text(settings.peerPublicKeyFile) ?? dshHomePath('dsh-remote', defaultFileName),
  )
  if (existsSync(file)) return parsePublicKey(readFileSync(file, 'utf8'))

  throw new Error(
    `dsh-remote: no peer public key configured (looked for ${file}). `
    + "Copy the peer's public key there, or paste it into the peerPublicKey setting.",
  )
}

/** A one-line identity summary for logging: fingerprint plus where the key came from. */
export function describeIdentity(resolved: ResolvedPrivateKey): string {
  const where = resolved.file === undefined ? 'inline setting' : resolved.file
  return `fingerprint ${fingerprint(resolved.publicKey)} from ${where}`
    + (resolved.generated ? ' (generated just now)' : '')
}

export { fingerprint, parsePublicKey, publicToPem, rawPublic }
