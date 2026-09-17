# dsh-remote —— 插件安装与设置参考

> **一句话**：装完之后，本机的 DSH 可以把**另一台机器的 DSH 当成一个 agent**来用——
> 以"用户"身份对它发言、等它跑完一整轮、取回回复；还能取回/投递它的会话上下文，
> 以及在它上面执行命令、读写文件。
>
> 通道是**单一 TCP 长连接**（典型是 frp 隧道），
> **双向 X25519 认证 + AES-256-GCM 逐帧加密 + 计数器防重放**。

---

本文件只讲**安装与设置**；总览看 [`../README.md`](../README.md)，
协议与威胁模型看 [`SECURITY.md`](SECURITY.md)，内部设计与踩坑看 [`DEV-NOTES.md`](DEV-NOTES.md)。

---

## 1. 插件包内容

```
dsh-remote/                   ← 把整个仓库复制到目标机器（不含任何密钥）
├── package.json
├── cordis.patch.yml          ← 两端 patch 模板，照抄进目标 profile
├── src/
│   ├── protocol.ts           ← 线协议 + 握手（只用 node:crypto，零依赖）
│   ├── keys.ts               ← 密钥解析（内联 / 文件 / 自动生成）
│   ├── server.ts             ← 被控端插件：监听 + 驱动本机 agent + 工作区属主登记
│   └── client.ts             ← 主控端插件：注册 remote_* 工具
├── test/protocol.test.ts     ← 协议四项自测
├── tools/gen-keys.py         ← 生成 / 复用密钥对（纯标准库）
└── docs/                     ← 安装指南 / 安全设计 / 开发信息

keys/                         ← 密钥，由 gen-keys.py 生成，**不进 git**
├── active/
│   ├── server-side/          ← 装到【被控机】: server.key + client.pub
│   └── client-side/          ← 装到【主控机】: client.key + server.pub
└── archive-<name>/           ← 用 --archive 冻结的快照
```

**零外部依赖**：只用 Node 内置模块，不需要 `pnpm add`。
用一个 `file:///` 的 patch 行指到 `src/server.ts` / `src/client.ts` 就能加载
（profile 的 `cordis.patch.yml` 支持直接指向 TS 源码，由运行中的 checkout 转译）。

---

## 2. 装【server 端】（被控机）

### 2.1 放密钥

把 `../keys/active/server-side/` 里的两个文件放到运行端的 DSH 家目录：

```powershell
$dst = "$env:USERPROFILE\.dsh\dsh-remote"
New-Item -ItemType Directory -Force -Path $dst | Out-Null
Copy-Item ..\keys\active\server-side\server.key  $dst\server.key
Copy-Item ..\keys\active\server-side\client.pub  $dst\client.pub
```

> 插件默认就去这里找：`${DSH_HOME}/dsh-remote/server.key` 与 `client.pub`。
> 想换位置见第 5 节的设置项。

### 2.2 加 patch 行

编辑 `%USERPROFILE%\.dsh\profiles\<你的 profile>\cordis.patch.yml`，在**文件末尾**追加：

```yaml
- insert:
    - id: dsh-remote-server
      name: 'file:///C:/Users/<you>/dsh-remote/src/server.ts'
      config:
        host: '127.0.0.1'
        port: 11325
```

> - `name` 里的路径请改成**你实际复制的目录**（注意是 `file:///` 三条斜杠 + 正斜杠）。
> - `port: 11325` 必须和 frp 那条隧道里填的**本地端口**一致。
> - **这个端口必须是这个插件独占的**：如果之前测试用的别的东西还占着 11325，
>   先把它停掉，否则插件会报监听失败。

### 2.3 重启 DSH

```powershell
# 停掉当前的 dsh web，然后重新起
pnpm dsh web
```

启动日志里应该能看到两行：

```
dsh-remote-server: identity fingerprint <xxxx:xxxx:xxxx:xxxx> from C:\Users\<you>\.dsh\dsh-remote\server.key
dsh-remote-server: listening on 127.0.0.1:11325
```

并且会打印它自己的**公钥 PEM**——那一整段（含 `BEGIN PUBLIC KEY` / `END PUBLIC KEY`）
就是主控机要 pin 的东西，贴进 client 的 `peerPublicKey`，或存成文件。

### 2.4 验证监听

```powershell
Get-NetTCPConnection -State Listen -LocalPort 11325
```

看得到 `127.0.0.1  11325` 并且属主是 node 就对了。

---

## 3. 装【client 端】（主控机）

同一份包，装法一样，只是换成另一半密钥、换成 client 行：

```powershell
$dst = "$env:USERPROFILE\.dsh\dsh-remote"
New-Item -ItemType Directory -Force -Path $dst | Out-Null
Copy-Item ..\keys\active\client-side\client.key  $dst\client.key
Copy-Item ..\keys\active\client-side\server.pub  $dst\server.pub
```

```yaml
- insert:
    - id: dsh-remote-client
      name: 'file:///C:/Users/<you>/dsh-remote/src/client.ts'
      config:
        host: 'tunnel.example.com'      # 对端可达地址（隧道给的公网地址、局域网名、Tailscale 名…）
        port: 10000              # 对应端口
        # 注意：这两项**没有默认值**，必须显式设置；
        # 不设时插件启动会打印提示、调用工具会报一条明确的错。
```

client 端**不需要** `--new-session` 之类的东西，它懒连接：
第一次调用工具时才拨号，之后复用同一条已认证会话；隧道断了自己重连。

---

## 4. 工具清单（client 端注册给模型的）

| 工具 | 作用 |
|---|---|
| `remote_ping` | 链路探活：对端版本、主机名、活跃会话、本侧指纹 |
| `remote_exec` | 在对端机器上跑 PowerShell/cmd，回传 stdout/stderr/退出码 |
| `remote_agent_prompt` | **核心**：把一段用户发言交给对端 agent，等这一轮跑完，取回回复。`session_id` 相同即续接同一会话（保留上下文）；`preset_id` 与 `workspace` 只在会话首次创建时生效 |
| `remote_agent_ensure` | 先建好/续接一个会话但不发言（可指定 preset） |
| `remote_agent_events` | 读对端某会话的事件流（只含必要字段），用于**上下文取回/压缩/再投递** |
| `remote_agent_interrupt` | 打断对端正在跑的那一轮 |
| `remote_preset_list` | 列出对端可用 preset（找"创造模式"的 id） |
| `remote_fs_list` / `remote_fs_write` | 列目录 / 写文件 |

典型用法：

```
remote_agent_ensure  session_id="job-1" preset_id="cordis"
remote_agent_prompt  session_id="job-1" text="读一下这个目录，然后告诉我它是干什么的" \
                     workspace='E:\work\job'
remote_agent_events  session_id="job-1" from_seq=0     # 把中间过程取回来
```

> `workspace` / `preset_id` **只在会话首次创建时生效**；会话一旦建好就固定了。
> 想换工作目录就换一个新的 `session_id`。
>
> 小坑：如果只改 patch 行里的 `config`，**不会**让已加载的插件重新 `apply`，
> 所以改 `workspace` 更推荐用「每次调用传参」，或者直接改 `settings.yaml`
> 里 `dsh-remote-server:` 那一段（设置层是热生效的）。

---

## 5. 设置项（GUI 里可改，`settings.yaml` 落盘）

两个插件各自注册一个设置区，命名空间分别是 `dsh-remote-server` 和
`dsh-remote-client`；字段按下面的表来（GUI 里能改，落盘到 `settings.yaml`）：

**server（`dsh-remote-server:`）**

| 字段 | 默认 | 说明 |
|---|---|---|
| `host` | `127.0.0.1` | 绑定地址；frpc 在同一台机器时保持回环 |
| `port` | `11325` | 绑定端口 = 隧道本地端口 |
| `privateKey` | 空 | 内联私钥（PEM / 64 hex / base64），**secret**，优先于文件 |
| `privateKeyFile` | `${DSH_HOME}/dsh-remote/server.key` | 私钥文件；自动生成时也写这里 |
| `autoGenerateKey` | `true` | 没有密钥时自动生成并落盘 |
| `peerPublicKey` | 空 | 内联对端公钥，优先于文件 |
| `peerPublicKeyFile` | `${DSH_HOME}/dsh-remote/client.pub` | 固定的对端公钥 |
| `workspace` | 空（用进程 cwd） | 远端被创建会话的工作目录 |
| `defaultPreset` | 空（用部署默认） | 远端新会话默认 preset |
| `maxHandshakeFailures` | `8` | 同一来源握手失败多少次后拉黑 |
| `lockoutSeconds` | `900` | 拉黑时长 |
| `maxExecTimeoutMs` | `600000` | 单条 `exec` 的超时上限 |
| `audit` / `auditFile` | `true` / `${DSH_HOME}/dsh-remote/server-audit.log` | 审计日志 |

**client（`dsh-remote-client:`）**

| 字段 | 默认 | 说明 |
|---|---|---|
| `host` / `port` | **无默认值** | 对端可达地址（隧道公网地址）；不设则启动时告警、调用时报错 |
| `privateKey` / `privateKeyFile` | 空 / `${DSH_HOME}/dsh-remote/client.key` | 本侧私钥，**secret** |
| `peerPublicKey` / `peerPublicKeyFile` | 空 / `${DSH_HOME}/dsh-remote/server.pub` | 固定的对端公钥 |
| `autoGenerateKey` | `true` | 自动生成落盘 |
| `timeoutMs` | `120000` | 单次请求超时 |
| `toolEnabled` | `true` | 关掉就只留服务、不注册工具 |
| `sessionPrefix` | `remote` | 不指定 `session_id` 时自动生成的会话前缀 |

---

## 6. 安全设计（为什么这套可以直接挂在公网端口上）

| 性质 | 怎么实现的 |
|---|---|
| **双向身份认证** | 两端各持 X25519 静态密钥对并 pin 住对方公钥。`tag_s` 只有持有服务端私钥才能算出（`ECDH(c_eph, s_static)` 那一腿），`tag_c` 同理。**知道公网地址拿不到任何东西** |
| **前向保密** | 会话密钥来自每连接新生成的临时密钥对；日后静态密钥泄露也解不开录制下来的历史会话 |
| **抗重放 / 抗乱序** | 每帧带严格递增计数器，计数器绑进 AEAD 的 AAD；重放或丢帧都会直接校验失败 |
| **抗暴力探测** | 同一来源握手失败累计到阈值即拉黑一段时间；每次尝试都进审计日志 |
| **面最小** | 只绑定回环地址（默认），公网唯一的入口是隧道；协议在认证完成前不回应任何业务信息 |
| **密钥不落地明文外** | 私钥字段是 `role('secret')`，设置 GUI 不会把它回显；私钥文件权限收紧到属主 |

已用自动化测试验证过的四条（`test/protocol.test.ts`）：
① 正常配对可通 ② pin 错服务端公钥 → 客户端拒绝（MITM） ③ pin 错客户端公钥 → 拒绝 ④ 两次会话密钥不同（前向保密）。

---

## 7. 排查

| 现象 | 先查 |
|---|---|
| 服务端日志没有 `listening` | 端口被占（`Get-NetTCPConnection -State Listen -LocalPort 11325`）；`host`/`port` 设置 |
| client 报 `server authentication FAILED` | 两侧密钥不配对。服务端日志里的指纹和 client 的 `server.pub` 是否一致 |
| client 报 `no peer public key configured` | `server.pub` 没放到 `${DSH_HOME}/dsh-remote/` |
| 隧道通但连不上 | frp 隧道是否指向了**这台机器**的 `127.0.0.1:11325`（隧道归属冲突是常见坑） |
| `remote_agent_prompt` 回 `reason: error` | 对端新会话没有模型路由。本插件已 `installModelSelection`；若仍复现，看工具返回里的 `error:` 一行 |
| 改了 `src/*.ts` 但行为没变 | DSH 不会重载已 import 的模块。要么重启 `dsh web`，要么给 patch 行里的 URL 加个 `?v=N`（ESM 视为不同模块） |

---

## 8. 已知边界

- 动态 Cordis 插件（创造模式的 `cordis_define`）是**进程内、临时**的，所以**本插件必须是静态插件**——
  它要常驻、要跟着 DSH 启动。创造模式用来做的是"把某个工具插件化"，不是用来装这个监听器的。
- `remote_agent_events` 只暴露必要字段（消息文本、工具名与参数、turn 结束原因），
  不会把会话的活对象整体序列化——那是运行时对象，不能当业务数据处理。
- 被控机必须有 DSH 在跑。DSH 挂了就没有通道了——本插件驱动的是对端的
  `agents` / `sessions` / `workspaceRegistry` 服务，没有 DSH 就无从谈起。
- 上下文压缩目前是"把事件流取回本机、由本机来压、再投递回去"，用的是本机 agent 的能力；
  对端自己的 `command-compact` 没有被远程触发（需要时可以加一个 op）。
