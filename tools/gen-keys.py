#!/usr/bin/env python3
"""Generate (or reuse) the dsh-remote keypair.

The plugin package deliberately ships **no** keys — key material is a setting.
This script exists so starting fresh is one command, and so a working pair can be
frozen for later reuse.

It is self-contained: X25519 is implemented here (RFC 7748) on top of the
standard library only. An earlier revision imported a helper module through a
hardcoded absolute `sys.path` entry, which made the script useless on any other
machine; there is nothing to point at now.

Formats written are exactly what the plugins' own parsers accept:

    private key   PKCS#8 PEM   -----BEGIN PRIVATE KEY-----   (48-byte DER)
    public key    SPKI   PEM   -----BEGIN PUBLIC KEY-----    (44-byte DER)

Layout — one *active* set, snapshots opt-in. (An earlier version keyed the folder
by today's date; it then failed to find yesterday's good pair, silently generated
a new one, and installed it over the runtime keys. A single stable "active" path
cannot drift like that.)

    keys/active/{server-side,client-side}/   the working pair, reused every run
    keys/archive-<name>/…                    frozen copies made with --archive

The four active files are also installed into `${DSH_HOME}/dsh-remote/`, where
both plugins look by default — that is what makes a single-machine loopback test
work with no further configuration.

Usage:
    python tools/gen-keys.py                      # reuse keys/active when present
    python tools/gen-keys.py --force              # generate a fresh pair
    python tools/gen-keys.py --archive my-laptop  # freeze the current pair
    python tools/gen-keys.py --no-install         # don't touch ${DSH_HOME}
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import os
import secrets
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
KEYS = os.path.join(os.path.dirname(HERE), "keys")
ACTIVE = os.path.join(KEYS, "active")
DSH_HOME = os.environ.get("DSH_HOME") or os.path.join(os.path.expanduser("~"), ".dsh")
RUNTIME = os.path.join(DSH_HOME, "dsh-remote")

# Which files each side needs. `server.pub` and `client.pub` are the same two
# files seen from opposite ends.
LAYOUT = {
    "server-side": ("server.key", "client.pub"),
    "client-side": ("client.key", "server.pub"),
}


# --------------------------------------------------------------------------- #
# X25519 (RFC 7748), standard library only
# --------------------------------------------------------------------------- #

P = 2 ** 255 - 19
A24 = 121665
BASE_POINT = (9).to_bytes(32, "little")


def x25519(private: bytes, public: bytes) -> bytes:
    """Scalar multiplication on Curve25519.

    @param private: 32-byte scalar (clamped here).
    @param public: 32-byte u-coordinate.
    @returns: the 32-byte u-coordinate of the result.
    """
    if len(private) != 32 or len(public) != 32:
        raise ValueError("x25519 takes 32-byte inputs")

    scalar = bytearray(private)
    scalar[0] &= 248
    scalar[31] &= 127
    scalar[31] |= 64
    k = int.from_bytes(bytes(scalar), "little")
    x1 = int.from_bytes(public, "little") & ((1 << 255) - 1)

    x2, z2, x3, z3 = 1, 0, x1, 1
    swap = 0
    for bit in reversed(range(255)):
        kt = (k >> bit) & 1
        swap ^= kt
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = kt

        a = (x2 + z2) % P
        aa = a * a % P
        b = (x2 - z2) % P
        bb = b * b % P
        e = (aa - bb) % P
        c = (x3 + z3) % P
        d = (x3 - z3) % P
        da = d * a % P
        cb = c * b % P

        x3 = (da + cb) % P
        x3 = x3 * x3 % P
        z3 = (da - cb) % P
        z3 = z3 * z3 % P * x1 % P
        x2 = aa * bb % P
        z2 = e * ((aa + A24 * e) % P) % P

    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    return (x2 * pow(z2, P - 2, P) % P).to_bytes(32, "little")


def generate_keypair() -> tuple[bytes, bytes]:
    """@returns: (32-byte private scalar, 32-byte public key)."""
    private = secrets.token_bytes(32)
    return private, x25519(private, BASE_POINT)


def public_from_private(private: bytes) -> bytes:
    """@returns: the public key for a private scalar."""
    return x25519(private, BASE_POINT)


# --------------------------------------------------------------------------- #
# PEM codec — fixed-prefix DER, which is all X25519 needs
# --------------------------------------------------------------------------- #

PRIVATE_PREFIX = bytes.fromhex("302e020100300506032b656e04220420")
PUBLIC_PREFIX = bytes.fromhex("302a300506032b656e032100")


def _pem(label: str, der: bytes) -> str:
    body = base64.b64encode(der).decode("ascii")
    lines = [body[i:i + 64] for i in range(0, len(body), 64)]
    return f"-----BEGIN {label}-----\n" + "\n".join(lines) + f"\n-----END {label}-----\n"


def private_to_pem(raw: bytes) -> str:
    """@returns: this side's private key as PKCS#8 PEM."""
    return _pem("PRIVATE KEY", PRIVATE_PREFIX + raw)


def public_to_pem(raw: bytes) -> str:
    """@returns: a public key as SPKI PEM."""
    return _pem("PUBLIC KEY", PUBLIC_PREFIX + raw)


def load_private(path: str) -> bytes:
    """Read a private key file (PKCS#8 PEM, 64 hex chars, or base64).

    @param path: the file to read.
    @returns: the 32-byte scalar.
    @throws ValueError: when the file holds none of the accepted encodings.
    """
    text = open(path, encoding="utf8").read()
    if "-----BEGIN" in text:
        body = text.split("-----BEGIN", 1)[1]
        body = body.split("-----", 1)[1]
        body = body.split("-----END", 1)[0]
        der = base64.b64decode("".join(body.split()))
        if len(der) != 48 or not der.startswith(PRIVATE_PREFIX):
            raise ValueError(f"{path}: not a 48-byte X25519 PKCS#8 key")
        return der[16:]
    compact = "".join(text.split())
    try:
        raw = bytes.fromhex(compact)
    except ValueError:
        raw = base64.b64decode(compact)
    if len(raw) != 32:
        raise ValueError(f"{path}: expected 32 raw bytes, got {len(raw)}")
    return raw


def fingerprint(raw_public: bytes) -> str:
    """Short, human-checkable identity — matches `fingerprint()` in protocol.ts.

    @param raw_public: the 32-byte public key.
    @returns: colon-separated groups, e.g. `af82:15f1:8232:b695`.
    """
    digest = hashlib.sha256(raw_public).hexdigest()
    return ":".join(digest[i:i + 4] for i in range(0, 16, 4))


# --------------------------------------------------------------------------- #
# Layout
# --------------------------------------------------------------------------- #

def side_path(side: str, name: str, root: str = ACTIVE) -> str:
    """@returns: the path of one key file inside a side folder."""
    return os.path.join(root, side, name)


def write_private(path: str, raw: bytes) -> None:
    """Write a private key with owner-only permissions where the OS supports it."""
    with open(path, "w", encoding="utf8", newline="\n") as handle:
        handle.write(private_to_pem(raw))
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate or reuse the dsh-remote keypair.")
    ap.add_argument("--force", action="store_true", help="regenerate even if a key exists")
    ap.add_argument("--archive", default=None,
                    help="copy the resulting pair to keys/archive-<name>")
    ap.add_argument("--no-install", action="store_true",
                    help=f"do not copy the four files into {RUNTIME}")
    args = ap.parse_args()

    for side in LAYOUT:
        os.makedirs(os.path.join(ACTIVE, side), exist_ok=True)

    fingerprints: dict[str, str] = {}
    for role, side in (("server", "server-side"), ("client", "client-side")):
        key_path = side_path(side, f"{role}.key")
        if os.path.exists(key_path) and not args.force:
            priv = load_private(key_path)
            print(f"[keys] reusing existing {role} key ({key_path})")
        else:
            priv, _ = generate_keypair()
            write_private(key_path, priv)
            print(f"[keys] generated {role} key -> {key_path}")
        pub = public_from_private(priv)
        # The peer's public key is written into the *other* side's folder.
        peer_side = "client-side" if side == "server-side" else "server-side"
        with open(side_path(peer_side, f"{role}.pub"), "w", encoding="utf8", newline="\n") as fh:
            fh.write(public_to_pem(pub))
        fingerprints[role] = fingerprint(pub)

    install = (
        ("server.key", side_path("server-side", "server.key")),
        ("client.pub", side_path("server-side", "client.pub")),
        ("client.key", side_path("client-side", "client.key")),
        ("server.pub", side_path("client-side", "server.pub")),
    )
    if args.no_install:
        print("[keys] --no-install: skipped installing into the harness home")
    else:
        os.makedirs(RUNTIME, exist_ok=True)
        for name, path in install:
            shutil.copyfile(path, os.path.join(RUNTIME, name))
        print(f"[keys] installed 4 files into {RUNTIME}")

    if args.archive:
        dest = os.path.join(KEYS, f"archive-{args.archive}")
        for side, names in LAYOUT.items():
            os.makedirs(os.path.join(dest, side), exist_ok=True)
            for name in names:
                shutil.copyfile(side_path(side, name), os.path.join(dest, side, name))
        print(f"[keys] archived to {dest}")

    print("\n[keys] fingerprints")
    print(f"  server  {fingerprints['server']}   (the controlled machine holds server.key)")
    print(f"  client  {fingerprints['client']}   (the driving machine holds client.key)")
    print("\n[keys] hand out one folder per machine — never both to the same one:")
    print("  controlled machine:  keys/active/server-side/  (server.key + client.pub)")
    print("  driving machine:     keys/active/client-side/  (client.key + server.pub)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
