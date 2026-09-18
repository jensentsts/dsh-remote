#!/usr/bin/env python3
"""usbctl — 两台机器之间一条经过认证的、加密的命令通道。

用途：本机（主控端）向被控端发送终端命令并取回输出。被控端不需要装 DSH、
不需要装任何第三方服务，只要有一个 Python 3.8+ 和 `cryptography`。

它只认一个 **TCP 地址**，所以链路可以是：

    * 局域网 / Wi-Fi           usbctl agent --host 0.0.0.0 --port 11330
    * USB4 / 雷电直连          插上线后 Windows 会多出一块网卡，地址填那块网卡的 IP
    * frp 之类的隧道           把隧道指到 agent 的端口即可
    * 反向连接（被控端主动拨出，不需要在被控端开防火墙）
                              usbctl run --listen 0.0.0.0:11331 --command "..."   （主控端）
                              usbctl agent --connect 192.168.1.117:11331           （被控端）

> 说明：**普通 USB-C 数据线（C2C）在两台主机之间不会产生任何链路**——USB 是
> "主机↔设备"协议。要"用线连两台电脑"，线必须是 USB4 / 雷电 3/4；那样系统会生成
> 一块虚拟网卡，本工具在这块网卡上跑 TCP，跟在局域网上没有区别。

安全模型（与 dsh-remote 插件同一套设计）：

    * 两端各持一个 X25519 静态密钥对，并 pin 住对方公钥 —— 双向认证，没有 CA
    * 每次连接新生成临时密钥对 —— 前向保密
    * HKDF-SHA256 派生方向密钥，AES-256-GCM 逐帧加密
    * 每帧严格递增计数器绑进 AAD —— 抗重放/乱序
    * 认证完成前不回应任何业务内容

子命令：

    keygen   生成 agent/client 两对密钥，打印指纹
    agent    被控端：监听（或反向拨出），执行命令
    run      主控端：发一条命令，取回结果
    ping     主控端：探活 + 看被控端信息
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import socket
import struct
import subprocess
import sys
import threading
import time
import traceback

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey,
        X25519PublicKey,
    )
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
except ImportError:  # pragma: no cover
    sys.exit("缺少 cryptography：请先 `pip install cryptography`")

MAGIC = b"usbctl"
VERSION = "1.0.0"
HKDF_INFO = b"usbctl-v1"
TAG_RESPONDER = b"usbctl responder"
TAG_INITIATOR = b"usbctl initiator"
DIR_A2B = b"\x01"
DIR_B2A = b"\x02"
MAX_FRAME = 64 * 1024 * 1024
HANDSHAKE_TIMEOUT = 20.0


# --------------------------------------------------------------------------- #
# 密钥
# --------------------------------------------------------------------------- #

def private_to_pem(key: X25519PrivateKey) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def public_to_pem(key: X25519PublicKey) -> bytes:
    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def load_private(path: str) -> X25519PrivateKey:
    with open(path, "rb") as handle:
        return serialization.load_pem_private_key(handle.read(), password=None)


def load_public(path: str) -> X25519PublicKey:
    with open(path, "rb") as handle:
        return serialization.load_pem_public_key(handle.read())


def raw_public(key: X25519PublicKey) -> bytes:
    return key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def fingerprint(key: X25519PublicKey) -> str:
    digest = hashlib.sha256(raw_public(key)).hexdigest()
    return ":".join(digest[i:i + 4] for i in range(0, 16, 4))


def write_private(path: str, key: X25519PrivateKey) -> None:
    with open(path, "wb") as handle:
        handle.write(private_to_pem(key))
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def write_public(path: str, key: X25519PublicKey) -> None:
    with open(path, "wb") as handle:
        handle.write(public_to_pem(key))


# --------------------------------------------------------------------------- #
# 握手与会话
# --------------------------------------------------------------------------- #

class LinkError(RuntimeError):
    """握手或帧校验失败。"""


def _recv_exact(sock: socket.socket, count: int) -> bytes:
    buf = bytearray()
    while len(buf) < count:
        chunk = sock.recv(count - len(buf))
        if not chunk:
            raise LinkError("对端关闭了连接")
        buf += chunk
    return bytes(buf)


def _hkdf(ikm: bytes, salt: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(ikm)


class Session:
    """一条已认证的会话：双向独立密钥 + 独立计数器。"""

    def __init__(self, sock: socket.socket, key: bytes, initiator: bool) -> None:
        self.sock = sock
        self.key = key
        self.initiator = initiator
        self.send_key = _hkdf(key, b"", b"usbctl a2b" if initiator else b"usbctl b2a")
        self.recv_key = _hkdf(key, b"", b"usbctl b2a" if initiator else b"usbctl a2b")
        self.send_dir = DIR_A2B if initiator else DIR_B2A
        self.recv_dir = DIR_B2A if initiator else DIR_A2B
        self.send_counter = 0
        self.recv_counter = 0
        self._lock = threading.Lock()

    def send(self, obj: dict) -> None:
        payload = json.dumps(obj, ensure_ascii=False).encode("utf8")
        with self._lock:
            self.send_counter += 1
            counter = self.send_counter
            aad = self.send_dir + counter.to_bytes(8, "big")
            nonce = b"\x00\x00\x00\x00" + counter.to_bytes(8, "big")
            frame = AESGCM(self.send_key).encrypt(nonce, payload, aad)
            self.sock.sendall(struct.pack(">I", len(frame)) + frame)

    def recv(self, timeout: float | None = None) -> dict:
        if timeout is not None:
            self.sock.settimeout(timeout)
        try:
            header = _recv_exact(self.sock, 4)
        finally:
            if timeout is not None:
                self.sock.settimeout(None)
        size = struct.unpack(">I", header)[0]
        if size <= 0 or size > MAX_FRAME:
            raise LinkError(f"帧长度非法：{size}")
        frame = _recv_exact(self.sock, size)
        self.recv_counter += 1
        counter = self.recv_counter
        aad = self.recv_dir + counter.to_bytes(8, "big")
        nonce = b"\x00\x00\x00\x00" + counter.to_bytes(8, "big")
        try:
            payload = AESGCM(self.recv_key).decrypt(nonce, frame, aad)
        except Exception as exc:  # noqa: BLE001
            raise LinkError(f"帧校验失败（重放/篡改/计数器不同步）：{exc}") from exc
        return json.loads(payload.decode("utf8"))

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


def handshake_initiator(
    sock: socket.socket,
    my_private: X25519PrivateKey,
    peer_public: X25519PublicKey,
) -> Session:
    """发起方：A -> B。"""
    sock.settimeout(HANDSHAKE_TIMEOUT)
    ephemeral = X25519PrivateKey.generate()
    eph_pub = raw_public(ephemeral.public_key())
    nonce_a = os.urandom(32)
    sock.sendall(MAGIC + eph_pub + nonce_a)

    reply = _recv_exact(sock, 32 + 32 + 32)
    eph_b, nonce_b, tag_b = reply[:32], reply[32:64], reply[64:96]

    ss = (
        ephemeral.exchange(X25519PublicKey.from_public_bytes(eph_b))
        + ephemeral.exchange(peer_public)
        + my_private.exchange(X25519PublicKey.from_public_bytes(eph_b))
    )
    key = _hkdf(ss, nonce_a + nonce_b, HKDF_INFO)
    transcript = MAGIC + eph_pub + eph_b + nonce_a + nonce_b
    expected = hmac.new(key, TAG_RESPONDER + transcript, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, tag_b):
        raise LinkError("对端身份校验失败——公钥不匹配，或链路上有中间人")

    tag_a = hmac.new(key, TAG_INITIATOR + transcript, hashlib.sha256).digest()
    sock.sendall(tag_a)
    sock.settimeout(None)
    return Session(sock, key, initiator=True)


def handshake_responder(
    sock: socket.socket,
    my_private: X25519PrivateKey,
    peer_public: X25519PublicKey,
) -> Session:
    """响应方：B <- A。"""
    sock.settimeout(HANDSHAKE_TIMEOUT)
    hello = _recv_exact(sock, len(MAGIC) + 32 + 32)
    if hello[:len(MAGIC)] != MAGIC:
        raise LinkError("不是 usbctl 协议（magic 不符）")
    eph_a, nonce_a = hello[len(MAGIC):len(MAGIC) + 32], hello[len(MAGIC) + 32:]

    ephemeral = X25519PrivateKey.generate()
    eph_pub = raw_public(ephemeral.public_key())
    nonce_b = os.urandom(32)
    ss = (
        ephemeral.exchange(X25519PublicKey.from_public_bytes(eph_a))
        + my_private.exchange(X25519PublicKey.from_public_bytes(eph_a))
        + ephemeral.exchange(peer_public)
    )
    key = _hkdf(ss, nonce_a + nonce_b, HKDF_INFO)
    transcript = MAGIC + eph_a + eph_pub + nonce_a + nonce_b
    tag_b = hmac.new(key, TAG_RESPONDER + transcript, hashlib.sha256).digest()
    sock.sendall(eph_pub + nonce_b + tag_b)

    tag_a = _recv_exact(sock, 32)
    expected = hmac.new(key, TAG_INITIATOR + transcript, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, tag_a):
        raise LinkError("对端身份校验失败——客户端公钥不匹配")
    sock.settimeout(None)
    return Session(sock, key, initiator=False)


# --------------------------------------------------------------------------- #
# 被控端：op 实现
# --------------------------------------------------------------------------- #

def _decode(data: bytes) -> str:
    return data.decode("utf8", errors="replace")


def _decode_smart(raw: bytes) -> str:
    """把命令输出的原始字节解成文本，不猜错。

    为什么不能直接 utf8：Windows 上 PowerShell 自己的 cmdlet 输出和 `hostname.exe`
    这类原生程序的输出走的编码**不是同一个**。强行统一成哪一种都会让另一种烂掉
    （原生程序按 GBK 吐字节，按 UTF-8 解就变成一串 U+FFFD）。

    所以这里按 utf-8 → gbk → cp936 依次严格尝试，全失败才退回 replace。
    原始字节另外用 base64 一并带回，保证无损。
    """
    if not raw:
        return ""
    for encoding in ("utf-8", "gbk", "cp936"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")


def op_exec(args: dict) -> dict:
    command = str(args.get("cmd", ""))
    shell = str(args.get("shell", "powershell")).lower()
    timeout = float(args.get("timeout", 120) or 120)
    cwd = args.get("cwd")
    if command.strip() == "":
        raise ValueError("cmd 不能为空")

    if shell == "cmd":
        argv = ["cmd", "/c", command]
    else:
        argv = [
            "powershell", "-NoProfile", "-NonInteractive", "-Command",
            "$ErrorActionPreference='Continue';" + command,
        ]

    started = time.time()
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            timeout=timeout,
            cwd=cwd if isinstance(cwd, str) and cwd else None,
        )
        timed_out = False
        stdout, stderr, code = proc.stdout, proc.stderr, proc.returncode
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        stdout = exc.stdout or b""
        stderr = (exc.stderr or b"") + f"\n[usbctl] 超时（{timeout}s）已终止".encode()
        code = None
    return {
        "exit": code,
        "timedOut": timed_out,
        "durationMs": int((time.time() - started) * 1000),
        "stdout": _decode_smart(stdout),
        "stderr": _decode_smart(stderr),
        # 无损：调用方发现文本不解时，可以自己从这两项还原
        "stdoutB64": base64.b64encode(stdout).decode("ascii"),
        "stderrB64": base64.b64encode(stderr).decode("ascii"),
    }


def op_read(args: dict) -> dict:
    path = str(args["path"])
    offset = int(args.get("offset", 0) or 0)
    length = int(args.get("length", 256 * 1024) or 256 * 1024)
    with open(path, "rb") as handle:
        handle.seek(offset)
        data = handle.read(length)
        size = os.fstat(handle.fileno()).st_size
    return {
        "path": path,
        "offset": offset,
        "size": size,
        "bytes": len(data),
        "eof": offset + len(data) >= size,
        "dataB64": base64.b64encode(data).decode("ascii"),
        "text": _decode(data),
    }


def op_write(args: dict) -> dict:
    path = str(args["path"])
    raw = base64.b64decode(str(args.get("dataB64", "")))
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "wb") as handle:
        handle.write(raw)
    return {"path": path, "written": len(raw), "size": os.path.getsize(path)}


def op_list(args: dict) -> dict:
    path = str(args.get("path", ".") or ".")
    entries = []
    with os.scandir(path) as it:
        for entry in it:
            try:
                stat = entry.stat()
                size = stat.st_size
                mtime = int(stat.st_mtime)
            except OSError:
                size, mtime = None, None
            entries.append({
                "name": entry.name,
                "dir": entry.is_dir(),
                "size": size,
                "mtime": mtime,
            })
    entries.sort(key=lambda e: (not e["dir"], e["name"].lower()))
    return {"path": os.path.abspath(path), "count": len(entries), "entries": entries}


def op_stat(args: dict) -> dict:
    path = str(args["path"])
    if not os.path.exists(path):
        return {"path": path, "exists": False}
    stat = os.stat(path)
    return {
        "path": os.path.abspath(path),
        "exists": True,
        "dir": os.path.isdir(path),
        "size": stat.st_size,
        "mtime": int(stat.st_mtime),
    }


def op_ping(_args: dict) -> dict:
    import getpass
    import platform

    return {
        "version": VERSION,
        "hostname": socket.gethostname(),
        "user": getpass.getuser(),
        "cwd": os.getcwd(),
        "pid": os.getpid(),
        "platform": platform.platform(),
        "python": sys.version.split()[0],
        "time": int(time.time()),
    }


OPS = {
    "ping": op_ping,
    "exec": op_exec,
    "read": op_read,
    "write": op_write,
    "list": op_list,
    "stat": op_stat,
}


def serve_session(session: Session, peer: str, log) -> None:
    try:
        while True:
            request = session.recv()
            ident = request.get("id")
            op = str(request.get("op", ""))
            handler = OPS.get(op)
            started = time.time()
            if handler is None:
                reply = {"id": ident, "ok": False, "error": f"未知 op：{op}"}
            else:
                try:
                    result = handler(request)
                    reply = {"id": ident, "ok": True, **result}
                except Exception as exc:  # noqa: BLE001
                    reply = {
                        "id": ident,
                        "ok": False,
                        "error": f"{type(exc).__name__}: {exc}",
                        "traceback": traceback.format_exc()[-2000:],
                    }
            session.send(reply)
            log(f"{peer}  op={op:<6} ok={reply['ok']}  {int((time.time() - started) * 1000)}ms")
    except LinkError as exc:
        log(f"{peer}  会话结束：{exc}")
    except (OSError, ValueError) as exc:
        log(f"{peer}  传输错误：{exc}")
    finally:
        session.close()


# --------------------------------------------------------------------------- #
# 子命令
# --------------------------------------------------------------------------- #

def cmd_keygen(args: argparse.Namespace) -> int:
    directory = os.path.abspath(args.dir)
    os.makedirs(directory, exist_ok=True)
    agent_private = X25519PrivateKey.generate()
    client_private = X25519PrivateKey.generate()
    write_private(os.path.join(directory, "agent.key"), agent_private)
    write_public(os.path.join(directory, "agent.pub"), agent_private.public_key())
    write_private(os.path.join(directory, "client.key"), client_private)
    write_public(os.path.join(directory, "client.pub"), client_private.public_key())
    print(f"密钥写入 {directory}")
    print(f"  agent  指纹 {fingerprint(agent_private.public_key())}")
    print(f"  client 指纹 {fingerprint(client_private.public_key())}")
    print("\n分发（永远不要两台机器拿到同一侧的两把）：")
    print("  被控端：usbctl.py + agent.key + client.pub")
    print("  主控端：usbctl.py + client.key + agent.pub")
    return 0


def cmd_agent(args: argparse.Namespace) -> int:
    log_path = os.path.abspath(args.log)
    log_lock = threading.Lock()

    def log(message: str) -> None:
        line = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {message}"
        with log_lock:
            print(line, flush=True)
            try:
                with open(log_path, "a", encoding="utf8") as handle:
                    handle.write(line + "\n")
            except OSError:
                pass

    my_private = load_private(args.key)
    peer_public = load_public(args.peer)
    log(f"usbctl {VERSION} agent 启动")
    log(f"  本机身份指纹 {fingerprint(my_private.public_key())}  ({args.key})")
    log(f"  固定对端指纹 {fingerprint(peer_public)}  ({args.peer})")

    def handle(sock: socket.socket, peer: str, initiator: bool) -> None:
        try:
            session = (
                handshake_initiator(sock, my_private, peer_public)
                if initiator
                else handshake_responder(sock, my_private, peer_public)
            )
        except (LinkError, OSError) as exc:
            log(f"{peer}  握手失败：{exc}")
            try:
                sock.close()
            except OSError:
                pass
            return
        log(f"{peer}  认证通过")
        serve_session(session, peer, log)

    if args.connect:
        host, _, port = args.connect.rpartition(":")
        host = host or "127.0.0.1"
        log(f"反向模式：拨向 {host}:{port}")
        while True:
            try:
                sock = socket.create_connection((host, int(port)), timeout=15)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                if args.allow_peer:
                    allowed = sock.getpeername()[0]
                    if allowed not in args.allow_peer:
                        log(f"拒绝来源 {allowed}（不在 --allow-peer 里）")
                        sock.close()
                        continue
                handle(sock, f"{host}:{port}", initiator=True)
            except (OSError, LinkError) as exc:
                log(f"连接失败：{exc}")
            if args.once:
                break
            time.sleep(args.retry)
        return 0

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((args.host, args.port))
    server.listen(16)
    log(f"监听 {args.host}:{args.port}")

    if args.once:
        sock, addr = server.accept()
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        handle(sock, f"{addr[0]}:{addr[1]}", initiator=False)
        return 0

    while True:
        try:
            sock, addr = server.accept()
        except OSError as exc:
            log(f"accept 失败：{exc}")
            break
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if args.allow_peer and addr[0] not in args.allow_peer:
            log(f"拒绝来源 {addr[0]}（不在 --allow-peer 里）")
            sock.close()
            continue
        thread = threading.Thread(
            target=handle,
            args=(sock, f"{addr[0]}:{addr[1]}", False),
            daemon=True,
        )
        thread.start()
    return 0


def _request(args: argparse.Namespace) -> dict:
    my_private = load_private(args.key)
    peer_public = load_public(args.peer)

    if args.listen:
        host, _, port = args.listen.rpartition(":")
        host = host or "0.0.0.0"
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, int(port)))
        server.listen(4)
        print(f"反向模式：等待被控端拨入 {host}:{port} …", file=sys.stderr, flush=True)
        sock, addr = server.accept()
        print(f"来自 {addr[0]}:{addr[1]}，握手…", file=sys.stderr, flush=True)
        session = handshake_responder(sock, my_private, peer_public)
    else:
        host, _, port = args.target.rpartition(":")
        sock = socket.create_connection((host or "127.0.0.1", int(port)), timeout=15)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        print(f"已连接 {host}:{port}，握手…", file=sys.stderr, flush=True)
        session = handshake_initiator(sock, my_private, peer_public)

    print(
        f"认证通过（本机 {fingerprint(my_private.public_key())} / 对端 {fingerprint(peer_public)}）",
        file=sys.stderr,
        flush=True,
    )
    try:
        session.send({"id": 1, "op": args.op, **args.payload})
        reply = session.recv(timeout=args.timeout + 30 if args.timeout else None)
    finally:
        session.close()
    return reply


def _payload(args: argparse.Namespace) -> dict:
    command = args.command
    if args.command_file:
        with open(args.command_file, encoding="utf8") as handle:
            command = handle.read()
    elif command == "-":
        # 显式要求才读 stdin：自动化环境里 stdin 不是 tty，隐式读会直接挂住
        command = sys.stdin.read()
    if command is None:
        raise SystemExit("必须给 --command、--command-file，或用 `--command -` 从 stdin 读")
    return {
        "cmd": command,
        "shell": args.shell,
        "timeout": args.timeout,
        "cwd": args.cwd,
    }


def cmd_run(args: argparse.Namespace) -> int:
    args.payload = _payload(args)
    args.timeout = args.timeout
    reply = _request(args)
    if args.out:
        with open(args.out, "w", encoding="utf8") as handle:
            json.dump(reply, handle, ensure_ascii=False, indent=2)
        print(f"结果写入 {args.out}", file=sys.stderr)
    if not reply.get("ok"):
        print(f"失败：{reply.get('error')}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(reply, ensure_ascii=False, indent=2))
    else:
        if reply.get("stdout"):
            print(reply["stdout"], end="" if reply["stdout"].endswith("\n") else "\n")
        if reply.get("stderr"):
            print("--- stderr ---", file=sys.stderr)
            print(reply["stderr"], end="" if reply["stderr"].endswith("\n") else "\n", file=sys.stderr)
        print(
            f"[exit {reply.get('exit')}  {reply.get('durationMs')}ms"
            f"{'  TIMED OUT' if reply.get('timedOut') else ''}]",
            file=sys.stderr,
        )
    return 0 if reply.get("exit") in (0, None) else 1


def cmd_call(args: argparse.Namespace) -> int:
    """直接调用某个 op，参数走 JSON 文件（避免命令行转义地狱）。"""
    payload = {}
    if args.args_file:
        with open(args.args_file, encoding="utf8") as handle:
            payload = json.load(handle)
    args.op = args.op
    args.payload = payload
    reply = _request(args)
    if args.out:
        with open(args.out, "w", encoding="utf8") as handle:
            json.dump(reply, handle, ensure_ascii=False, indent=2)
        print(f"结果写入 {args.out}", file=sys.stderr)
    print(json.dumps(reply, ensure_ascii=False, indent=2))
    return 0 if reply.get("ok") else 1


def cmd_ping(args: argparse.Namespace) -> int:
    args.op = "ping"
    args.payload = {}
    args.timeout = args.timeout
    reply = _request(args)
    print(json.dumps(reply, ensure_ascii=False, indent=2))
    return 0 if reply.get("ok") else 1


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="usbctl",
        description="两台机器之间一条经认证加密的命令通道（局域网 / USB4 直连 / 隧道 均可）",
    )
    parser.add_argument("--version", action="version", version=f"usbctl {VERSION}")
    sub = parser.add_subparsers(dest="command", required=True)

    keygen = sub.add_parser("keygen", help="生成 agent/client 两对密钥")
    keygen.add_argument("--dir", default="keys", help="输出目录（默认 keys）")
    keygen.set_defaults(func=cmd_keygen)

    agent = sub.add_parser("agent", help="被控端：监听并执行命令")
    agent.add_argument("--host", default="0.0.0.0", help="监听地址（默认 0.0.0.0）")
    agent.add_argument("--port", type=int, default=11330, help="监听端口（默认 11330）")
    agent.add_argument("--connect", help="反向模式：主动拨向 host:port")
    agent.add_argument("--retry", type=float, default=5.0, help="反向模式重连间隔秒")
    agent.add_argument("--once", action="store_true", help="只服务一次就退出")
    agent.add_argument("--allow-peer", action="append", default=[], help="只接受这些来源 IP")
    agent.add_argument("--key", default="agent.key", help="本侧私钥（默认 agent.key）")
    agent.add_argument("--peer", default="client.pub", help="固定对端公钥（默认 client.pub）")
    agent.add_argument("--log", default="usbctl-agent.log", help="日志文件")
    agent.set_defaults(func=cmd_agent)

    run = sub.add_parser("run", help="主控端：执行一条命令并取回结果")
    run.add_argument("--target", default="127.0.0.1:11330", help="被控端 host:port")
    run.add_argument("--listen", help="反向模式：监听并等待被控端拨入 host:port")
    run.add_argument("--command", "-c", help="要执行的命令")
    run.add_argument("--command-file", help="从文件读命令（避免命令行转义问题，推荐）")
    run.add_argument("--shell", default="powershell", choices=["powershell", "cmd"])
    run.add_argument("--timeout", type=float, default=120.0, help="被控端执行超时秒")
    run.add_argument("--cwd", help="在被控端的哪个目录执行")
    run.add_argument("--json", action="store_true", help="输出完整 JSON")
    run.add_argument("--out", help="把完整 JSON 结果写到文件")
    run.add_argument("--key", default="client.key", help="本侧私钥（默认 client.key）")
    run.add_argument("--peer", default="agent.pub", help="固定对端公钥（默认 agent.pub）")
    run.set_defaults(func=cmd_run, op="exec")

    call = sub.add_parser("call", help="主控端：直接调用某个 op（参数走 JSON 文件）")
    call.add_argument("--target", default="127.0.0.1:11330", help="被控端 host:port")
    call.add_argument("--listen", help="反向模式：监听并等待被控端拨入 host:port")
    call.add_argument("--op", required=True, help="ping/exec/read/write/list/stat")
    call.add_argument("--args-file", help="op 参数的 JSON 文件")
    call.add_argument("--timeout", type=float, default=60.0)
    call.add_argument("--out", help="把完整 JSON 结果写到文件")
    call.add_argument("--key", default="client.key", help="本侧私钥（默认 client.key）")
    call.add_argument("--peer", default="agent.pub", help="固定对端公钥（默认 agent.pub）")
    call.set_defaults(func=cmd_call)

    ping = sub.add_parser("ping", help="主控端：探活并看被控端信息")
    ping.add_argument("--target", default="127.0.0.1:11330")
    ping.add_argument("--listen", help="反向模式：监听并等待被控端拨入 host:port")
    ping.add_argument("--timeout", type=float, default=20.0)
    ping.add_argument("--key", default="client.key")
    ping.add_argument("--peer", default="agent.pub")
    ping.set_defaults(func=cmd_ping)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        return args.func(args)
    except LinkError as exc:
        print(f"链路错误：{exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\n已中断", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
