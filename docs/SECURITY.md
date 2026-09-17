# 安全设计

> 这套东西的实质是**任意代码执行 + 远程驱动一个 agent**，所以安全不是装饰。
> 本文说明威胁模型、握手协议、密钥机制，以及**明确没做什么**。

---

## 1. 威胁模型

被控端的监听端口通常挂在公网隧道后面（frp 之类），意味着**任何知道该地址的人都能建立
TCP 连接**。因此安全边界不能建立在「地址保密」上，必须建立在密码学上。

要防的：

| 威胁 | 目标 |
|---|---|
| 扫描/撞库者连上公网端口 | 连协议都探不出来，更别说发指令 |
| 隧道中间人（节点运营方、链路劫持） | 无法伪造任一端，无法解密 |
| 录制历史流量、日后拿到静态私钥 | 解不开过去的会话（前向保密） |
| 抓包重放/乱序注入 | 帧校验直接失败 |
| 对端口的暴力探测 | 限流 + 拉黑 + 审计 |

**不在范围内**：被控机本身已被攻陷、DSH 进程被注入、或操作者把 `*.key` 泄露出去。
这些情况下再强的传输加密也没用。

---

## 2. 握手（三帧，双向认证）

```
C -> S  HELLO    magic(5) | c_eph_pub(32) | c_nonce(32)
S -> C  REPLY    magic(5) | s_eph_pub(32) | s_nonce(32) | tag_s(32)
C -> S  CONFIRM  tag_c(32)

ss   = ECDH(c_eph, s_eph) || ECDH(c_eph, s_static) || ECDH(c_static, s_eph)
key  = HKDF-SHA256(ikm = ss, salt = c_nonce || s_nonce, info = "dshr2", 32)
kC2S = HKDF(ikm = key, salt = 0^32, info = "dshr2 c2s", 32)
kS2C = HKDF(ikm = key, salt = 0^32, info = "dshr2 s2c", 32)
transcript = magic || c_eph_pub || s_eph_pub || c_nonce || s_nonce
tag_s = HMAC(key, "dshr2 server" || transcript)
tag_c = HMAC(key, "dshr2 client" || transcript)
```

**为什么这样就能证明身份**：`ss` 里的第二腿是 `ECDH(c_eph, s_static)`——
只有持有服务端**静态私钥**的一方能算出它。所以能产出正确 `tag_s` 就等于证明自己是服务端。
第三腿 `ECDH(c_static, s_eph)` 同理证明客户端。两条腿缺一不可，`tag` 用
`timingSafeEqual` 比较。

**为什么有前向保密**：`ss` 的第一腿用两侧**每连接新生成的临时**密钥对。
事后拿到静态私钥，也还原不出当时那次会话的 `key`。

**版本标记**：两端的 `magic` 不一致（或开头几字节就不是 `dshr2`）直接判协议不符并断开——
所以公网端口对无关扫描者表现为「连上就断」，不泄露任何业务信息。

---

## 3. 帧格式

```
uint32 big-endian length | AES-256-GCM ciphertext+tag

nonce = 00000000 || counter(uint64 BE)
aad   = direction(3 字节 "C2S"/"S2C") || counter(uint64 BE)
```

- 两个方向**各自独立**的密钥与计数器（`kC2S` / `kS2C`），防止把一来一回搞混。
- 计数器**严格 +1**，且绑进 AAD。重放旧帧、跳过丢帧、插入乱序帧，都会在 tag 校验处失败。
- 密钥按角色选取（发起方 vs 响应方）——**这里踩过坑**：早期版本两端都从同一个
  `" send"` 标签派生发送密钥，结果两端发往相反方向却用同一把钥匙，每帧都校验失败。
  见 `docs/DEV-NOTES.md`。

---

## 4. 密钥机制

- 两端各持一个 **X25519 静态密钥对**，并**pin 住对方公钥**。没有 CA、没有 PKI。
- 密钥来源（内联优先）：
  - `privateKey` / `peerPublicKey`：内联 PEM、64 位 hex、或 32 字节 base64
  - `privateKeyFile` / `peerPublicKeyFile`：默认 `${DSH_HOME}/dsh-remote/`
  - `autoGenerateKey`：没有就生成并落盘（权限收到属主）
- **私钥字段是 `role('secret')`**：设置 GUI 不会把它回显到传输层，只能覆盖。
  这套字段布局与 DSH 同类插件（消息收发、IM 桥接等）一致，操作习惯可以复用。
- **仓库里不含密钥**：`keys/` 以及 `*.key` / `*.pub` / `*.pem` 都在 `.gitignore` 里。
  密钥由 `tools/gen-keys.py` 在本机生成，只在两端之间手工分发。**绝不要**把生成出来的
  `keys/` 提交上去——一旦进了 git 历史，就等于把被控机交出去了。
- 总控开关只有一把：**拿到 `*.key` 就等于拿到那台机器**。所以撤权 = 换密钥。

---

## 5. 抗探测

| 措施 | 说明 |
|---|---|
| 只绑回环 | 默认 `127.0.0.1`，公网唯一入口是隧道 |
| 握手超时 | 15 秒不做完就断，不占着连接 |
| 失败限流 | 同源失败累计到 `maxHandshakeFailures`（默认 8）即拉黑 `lockoutSeconds`（默认 900） |
| 审计日志 | 每次尝试与每个操作都记一行 JSON：时间、来源、op、成败、耗时<br>默认 `${DSH_HOME}/dsh-remote/server-audit.log` |
| 无信息泄露 | 认证完成前不回应任何业务内容；未知 op 只回 `unknown op` |

---

## 6. 明确**没有**做的

诚实列出边界，免得产生虚假的安全感：

1. **没有沙箱**。`remote_exec` 就是在对端跑命令，权限等于被控机上那个 DSH 进程。
   想限制就靠 DSH 自己的 sandbox/permission preset（把远端 agent 建在受限 preset 上）。
2. **没有命令白名单**。协议层面不区分「读」和「写」，任何 op 都能调。
3. **没有前向保密的密钥轮换**。静态密钥不变，只有每连接临时密钥提供前向保密。
   （标准做法，但值得写明白。）
4. **没有防重放跨连接**。每条连接是新临时密钥，跨连接重放天然不可能；
   但**同一连接内**若攻击者能篡改 TCP 流，靠计数器挡——这是 AEAD 的保证范围。
5. **审计日志没有防篡改**。它只是本地文件，被控机上有人能改。
6. **没有 2FA / 审批**。任何持有 client 私钥的一方都能无提示地执行。
   想加「执行前要人批」得在 server 端接 DSH 的审批机制（目前没接）。

---

## 7. 自测覆盖

`test/protocol.test.ts` 验证了四条性质：

| 用例 | 期望 | 结果 |
|---|---|---|
| 配对密钥 | 握手成功 + 三个来回帧 | ✅ |
| 主控端 pin 错服务端公钥（MITM） | 主控端拒绝 | ✅ `server authentication FAILED` |
| 被控端 pin 错客户端公钥（冒充客户端） | 被控端拒绝 | ✅ |
| 两次会话 | 会话密钥不同（前向保密） | ✅ |

跑法（在 DSH checkout 目录下，让 `tsx` 能解析）：

```powershell
cd <deepseek-harness 根目录>
node --import tsx/esm E:\path\to\dsh-remote\test\protocol.test.ts
```
