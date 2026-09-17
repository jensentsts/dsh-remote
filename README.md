# dsh-remote

> DSH 插件，用于无缝衔接本地和远程主机的 dsh 工作。
> DSH plugin for using dsh on a remote host like what dsh does on the local host, seamlessly.

装完之后，**本机 DSH 可以把另一台机器的 DSH 当成一个 agent 来用**：以「用户」身份
发言、等它跑完一整轮、取回回复；还能取回 / 投递它的会话上下文，以及在它上面执行命令、读写文件。

通道是**一条 TCP 连接**（放在 frp 之类的隧道后面即可穿透 NAT），
**X25519 双向认证 + AES-256-GCM 逐帧加密 + 计数器防重放**，只用 Node 内置模块，**零外部依赖**。

---

## 为什么是"一对插件"

```
        主控机 (client 端)                        被控机 (server 端)
   ┌───────────────────────┐                 ┌───────────────────────┐
   │  DSH                  │                 │  DSH                  │
   │   └ src/client.ts     │  ── TCP ──►     │   └ src/server.ts     │
   │     注册 remote_* 工具 │  已认证加密通道  │     监听回环端口       │
   │                       │                 │     ├ 执行命令/读写文件 │
   │  本机 agent 调用工具 ──┼─────────────────┼─►   └ 驱动本机 agent   │
   └───────────────────────┘                 └───────────────────────┘
```

- **client 端**注册模型可见的工具（`remote_agent_prompt` 等）。
- **server 端**监听一个回环端口，由隧道映射到公网；它注入被控机 DSH 的
  `agents` / `sessions` / `workspaceRegistry`，因此能**真正驱动那一侧的会话**，
  而不只是执行命令。

两端都是**静态 Cordis 插件**——必须如此：动态插件是进程内、临时的，
做不到常驻监听。

---

## 快速开始

### 1. 生成密钥对

```bash
python tools/gen-keys.py
```

它会在 `keys/active/` 下按端分组生成四个文件，并把它们安装到
`$DSH_HOME/dsh-remote/`（插件的默认查找位置），然后打印两个指纹。

### 2. 被控机（server 端）

把 `keys/active/server-side/`（`server.key` + `client.pub`）放到该机的
`$DSH_HOME/dsh-remote/`，然后在 profile 的 `cordis.patch.yml` 追加：

```yaml
- insert:
    - id: dsh-remote-server
      name: 'file:///C:/path/to/dsh-remote/src/server.ts'
      config:
        host: '127.0.0.1'
        port: 11325          # 必须等于隧道里填的"本地端口"，且由本插件独占
```

### 3. 主控机（client 端）

把 `keys/active/client-side/`（`client.key` + `server.pub`）放到该机的
`$DSH_HOME/dsh-remote/`，然后追加：

```yaml
- insert:
    - id: dsh-remote-client
      name: 'file:///C:/path/to/dsh-remote/src/client.ts'
      config:
        host: 'tunnel.example.com'   # 隧道给的公网地址；没有默认值，必须设
        port: 10000                  # 隧道公网端口
```

重启 `dsh web`。完整步骤与排查表见 [`docs/GUIDE.md`](docs/GUIDE.md)。

### 4. 用

```
remote_agent_prompt  session_id="work-1" preset_id="cordis"
                     workspace="E:\project"
                     text="先读一下这个目录，然后告诉我它是干什么的"
```

`preset_id` 与 `workspace` **只在会话首次创建时生效**；之后用同一个 `session_id`
续接就保留上下文。

---

## 工具

| 工具 | 作用 |
|---|---|
| `remote_agent_prompt` | **核心**：把一段用户发言交给对端 agent，等这一轮跑完，取回回复 |
| `remote_agent_ensure` | 先建好 / 续接一个会话但不发言（可指定 preset / workspace） |
| `remote_agent_events` | 读对端某会话的事件流，用于上下文取回 / 压缩 / 再投递 |
| `remote_agent_interrupt` | 打断对端正在跑的那一轮 |
| `remote_preset_list` | 列出对端可用的 agent preset |
| `remote_exec` | 在对端执行 PowerShell / cmd |
| `remote_fs_list` / `remote_fs_write` | 列目录 / 写文件 |
| `remote_ping` | 链路探活：对端版本、主机名、指纹、构建标记 |

---

## 配置

两端都是**纯设置驱动**：链接地址、端口、密钥全部可配，可用设置 GUI 或
`settings.yaml`（命名空间 `dsh-remote-server:` / `dsh-remote-client:`）。

- 私钥字段是 `role('secret')`——设置 GUI 不会把它回显到传输层。
- 密钥可以内联（`privateKey` / `peerPublicKey`），也可以指向文件
  （`privateKeyFile` / `peerPublicKeyFile`），内联优先。
- **client 端的 `host` / `port` 没有默认值**：链接是每个部署自己的事实，
  不该被写死在代码里。

完整字段表见 [`docs/GUIDE.md`](docs/GUIDE.md) 的第 5 节。

---

## 安全

- **双向认证**：两端各持 X25519 静态密钥并 pin 住对方公钥。知道公网地址拿不到任何东西。
- **前向保密**：会话密钥来自每连接新生成的临时密钥对。
- **抗重放**：每帧严格递增计数器绑进 AEAD 的 AAD。
- **抗暴力探测**：同源握手失败累计到阈值即拉黑，并有审计日志。

协议细节、威胁模型、以及**明确没有做的事**见 [`docs/SECURITY.md`](docs/SECURITY.md)。

跑协议自测（改协议后请先跑它）：

```bash
cd <deepseek-harness 根目录>
node --import tsx/esm E:/path/to/dsh-remote/test/protocol.test.ts
```

---

## 已知边界

- 被控机必须**有 DSH 在跑**；DSH 挂了就没有通道。
- `remote_exec` 就是普通命令执行，**没有沙箱**。要限制就把远端 agent
  建在受限的 permission preset 上。
- 上下文压缩目前是「把事件流取回本机、由本机压、再投递回去」，
  没有远程触发对端的 `compact` 命令。
- 一个 client 一条连接（server 侧每连接一个线程）。

---

## 目录

```
dsh-remote/
├── src/                  插件本体
│   ├── protocol.ts       线协议 + 握手（只用 node:crypto）
│   ├── keys.ts           密钥来源解析（内联 / 文件 / 自动生成）
│   ├── server.ts         被控端：监听 + 驱动本机 agent + 工作区属主登记
│   └── client.ts         主控端：注册 remote_* 工具
├── test/protocol.test.ts 协议四项自测
├── docs/
│   ├── GUIDE.md          安装 · 设置 · 工具 · 排查
│   ├── SECURITY.md       威胁模型 · 协议 · 明确没做的事
│   └── DEV-NOTES.md      DSH 插件 API 备忘 · 踩过的坑 · 设计取舍
├── tools/gen-keys.py     生成 / 复用密钥对
└── cordis.patch.yml      两端 patch 模板
```

---

## License

[MIT](LICENSE)
