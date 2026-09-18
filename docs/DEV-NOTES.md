# 开发信息

> 这份是给**以后回来改这个插件的人**（多半是未来的我）看的。
> 记的是「怎么想出来的」「API 长什么样」「踩过哪些坑」，不是使用说明。
> 使用说明见 [`GUIDE.md`](GUIDE.md)，协议与威胁模型见 [`SECURITY.md`](SECURITY.md)。

---

## 1. 为什么要做成"静态插件对"，而不是别的形态

| 形态 | 为什么不行 |
|---|---|
| 让远端跑一个独立进程（Python 代理） | 能跑，但**拿不到 DSH 的 agent 能力**——只能执行命令，没法以「用户」身份驱动一个会话 |
| 用创造模式的动态插件（`cordis_define`） | 官方文档明确：**Dynamic Plugins are temporary and process-local**。监听器要常驻、要跟 DSH 一起启动，动态插件做不到 |
| 只做一半（本地 MCP 工具 + 远端裸进程） | 远端那半还是拿不到 agent；而且 MCP 不是「成对插件」的形态 |
| **静态插件对（本方案）** | 两半都是真插件：server 端能注入 `agents`/`sessions`/`workspaceRegistry`，client 端能 `ctx.tools.register`。零外部依赖，一个 `file:///` patch 行就能装 |

**关键判据**：需要 `ctx.*` 服务的能力必须住在插件里；只需要文件/进程的能力才可以用裸进程。

---

## 2. DSH 插件 API 备忘

> 这一节是从**能跑通的实现**里总结的：同类 DSH 插件（消息收发、IM 桥接等）的源码，
> 以及 checkout 里的 `packages/webhook/`。
> 官方生成的 API 目录在 `docs/config-catalog.md` 与 `docs/subsystems/*.md`。

### 插件骨架

```ts
export const name = 'my-plugin'
export const inject = ['agents', 'sessions']        // 硬依赖，缺失则等待
export interface Config { /* … */ }
export const Config: z<Config> = z.object({          // @deepseek-ai/schemastery
  secret: z.string().role('secret').default(''),     // 不回显到设置传输层
  port: z.number().default(11325),
})
export function apply(ctx: Context, config: Config = {}): void { /* … */ }
```

装载（profile 的 `cordis.patch.yml`），TS 源码直接加载，无需构建：

```yaml
- insert:
    - id: my-plugin
      name: 'file:///C:/path/to/src/index.ts'
      config: { port: 11325 }
```

### 设置区（GUI 可改，`settings.yaml` 落盘）

```ts
ctx.inject(['settings'], (settingsCtx) => {
  settingsCtx.settings.installSection(ctx, NAMESPACE, Config, config, {
    // 存**取值函数**而不是值：之后设置一改，read() 立刻看到新值
    setSource: (current) => { source = current },
    onChange: () => { /* 需要重建的东西（监听器、连接）在这里重启 */ },
    validate: (value) => { /* 提交时的跨字段校验 */ },
  })
})
const read = () => source()
```

**要点**：`setSource` 拿到的是**活取值函数**。存下来、每次用的时候调 `read()`，
设置改动就热生效——不需要重载模块。这是本插件让 `workspace` 可远程改的原理。

### 驱动一个 agent 会话（本插件的核心）

```ts
const handle = await agents.resume({ resumeSessionId: SessionId(id), setup })
// 或者对不存在的会话：
const handle = await agents.create({
  sessionId: SessionId(id),
  meta: { cwd, agentPreset: presetId },
  setup: async (agentCtx) => {
    installModelSelection(agentCtx, { current: defaults, assembled: undefined })  // ← 必须
    await ctx.agentPresets.mount(agentCtx, presetId)
  },
})

const agent = handle.agent
await agent.whenIdle()
const firstSeq = agent.session.seq
agent.followup(createUserMessage({
  content: [{ type: 'text', text }],
  source: { kind: 'user' },
}))
await agent.whenIdle()
await ctx.sessions.flush(agent.session)
const outcome = summarize(agent.session.snapshotEvents(), firstSeq)
```

- `agent.session.snapshotEvents()` 给完整事件流；`{seq, type, data}`。
- `turn/end` 的 `data.reason` 形如 `{ kind: 'completed' | 'error', error?: { code, message } }`。
- **注意**：`reason.kind === 'error'` 时 `reply` 可能是空的，必须把 `reason.error` 也带出来，
  否则排查时只看到一句 `reason: error`。

### 注册模型可见的工具

```ts
import { defineTool } from '@deepseek-ai/dsh-tools'

ctx.inject(['tools'], (toolsCtx) => {
  toolsCtx.tools.register(defineTool({
    name: 'my_tool',
    description: '…',
    parameters: { x: { type: 'string', required: true, description: '…' } },
    output: {
      schema: { type: 'json' },
      render: (_args, value) => [{ type: 'text', text: String(value) }],
    },
    async execute(args) { return { /* JsonValue */ } as unknown as JsonValue },
  }))
})
```

`ctx.inject(['tools'])` 是**惰性等待**：composition 里没有 tools 注册表时插件仍能加载。

### 会话要在 GUI 里可见，必须登记工作区属主

```ts
const workspace = await ctx.workspaceRegistry.create(path)   // create-or-get，返回规范路径
const handle = await ctx.agents.create({ sessionId, meta: { cwd: workspace.path, … }, setup })
await workspace.attachSession(sessionId)                     // ← 漏了就"磁盘上有、界面上没有"
ctx.get('sessionTitle')?.rename(handle.agent.session, 'remote: …')   // 可选，便于识别
```

`packages/webhook/webhook/src/session.ts` 是「从 Web 之外创建会话」的权威范例，
本插件的 server 端就是照它写的。

### 服务清单（这个部署里可用的）

| 服务 | 用途 |
|---|---|
| `agents` | `resume` / `create` → `AgentHandle` |
| `sessions` | `flush(session)` 落盘 |
| `agentPresets` | `list` / `resolve(id)` / `mount(agentCtx, id)` / `defaultId` |
| `agentDefaultModel` | `currentSelection()` —— 新会话的模型路由来源 |
| `workspaceRegistry` | `create(path)` / `list()` → `Workspace.attachSession` |
| `sessionTitle` | `rename(session, title)` |
| `permissionPresets` | `resolve` / `set(session, preset)` |
| `settings` | `installSection` |
| `tools` | `register(tool)` |
| `loader` | `await()` —— 等整个应用装配完再动 agent |

### 内置 preset（本部署实测）

`standard`（默认）/ `ptc` / `minimal` / **`cordis`（创造模式）**
（各个部署还可能加上自己的 preset；**实际有哪些用 `remote_preset_list` 问对端**）

创造模式 = 标准模式的全部能力 + `cordis_*` 工具族（运行时读接口、定义/运行/停止动态插件）
+ 两个 skill（`cordis-plugin-development`、`editing-cordis-compositions`）。
定义在 `packages/preset/agent-presets/presets/cordis/`。

---

## 3. 踩过的坑

> 全部是实测撞出来的，不是推测。按"症状 → 根因 → 处理"记。

### 3.1 新会话第一轮瞬间 `reason: error`

- **症状**：`remote_agent_prompt` 建会话成功，但 130 ms 就结束、`reply` 空。
- **根因**：新会话没有**模型路由**。`agents.create` 不会自动继承部署默认模型。
- **处理**：`setup` 里必须 `installModelSelection(agentCtx, {current: ctx.get('agentDefaultModel')?.currentSelection(), assembled: undefined})`。
- **教训**：同类插件（IM 桥接那类）里都有这一行，一开始没意识到它是必需的，只当是"切换模型"用的。

### 3.2 会话在磁盘上有，GUI 里看不见

- **症状**：`example-session.json` 确实躺在 `storages/session_projcache/sessions/`，
  但侧边栏没有。
- **根因**：`agents.create` 建的会话**无工作区属主**。GUI 渲染的是
  「工作区 + 它的 `sessionIds`」，而这张表只由 Web 自己的建会话路径维护。
- **处理**：`workspaceRegistry.create` + `agents.create({meta:{cwd: workspace.path}})` + `workspace.attachSession(sessionId)`。
- **教训**：「落盘」和「可见」是两件事。

### 3.3 改了 `src/*.ts` 行为不变

- **根因**：DSH **不会重新 import 已加载的模块**。
- **处理**：① 重启 `dsh web`（最干净）；② 给 patch 行的 `file:///` URL 加 `?v=N`——
  ESM 把带不同查询串的 URL 视为不同模块，于是真的会重新加载。
- **配套**：`server.ts` 里加了 `BUILD` 常量并放进 `sysinfo`，
  这样「加载的是哪一版」变成一次 `remote_ping` 就能确认的事实。
  **没有这个标记时，我在这件事上浪费了好几轮。**

### 3.4 热重载之后 `sysinfo` 正常、所有 agent op 报错

- **症状**：`cannot create effect on inactive context`。
- **根因**：loader 在热重载时**把旧 context 置为失活**，但旧模块的监听 socket 还活着并继续服务。
  于是不需要 `ctx` 的 op（`sysinfo`）正常，需要 `ctx` 的 op（`agents.create` / `presets.mount`
  都要在 context 上建 effect）全挂。
- **处理**：
  - 短期：换一个新端口 + 新 URL，让新模块在**全新 context** 上绑一个新 socket（绕过僵死的那个）。
  - 长期：**重启 `dsh web`**。
  - 代码侧：把 `ctx.effect(...)` 包进 try/catch——它在失活 context 上会抛，
    而抛在 `apply` 里会让整个插件注册不上。
- **教训**：`ctx.effect()` 不是"注册个清理函数"那么无害，它是个可能失败的操作。

### 3.5 两端发送密钥用了同一把

- **症状**：握手看起来成功，第一帧解密就 `InvalidTag`，服务端静默关连接
  （客户端只看到"agent closed the connection"，非常误导）。
- **根因**：`Session` 构造里两端都从**同一个** `" send"` 标签派生发送密钥，
  但两端是往**相反方向**发的。
- **处理**：改成方向密钥 `kC2S` / `kS2C`，再按角色选：
  发起方 send 用 `kC2S`，响应方 send 用 `kS2C`。
- **教训**：先写 `test/protocol.test.ts` 的本地回环自测就对了——
  这个 bug 在隧道上排查会痛苦十倍。

### 3.6 `?v=3`/`?v=4` 重载把运行实例弄成半死状态

- 见 3.4。追加一条操作经验：**一旦发现 context 失活，别再连续试重载**，
  直接换端口（或重启）。连续重载会叠加僵死 socket，把排查彻底搅浑。

### 3.7 指纹算法两端不一致

- **症状**：Python 密钥生成器算 `server = aa11:bb22:cc33:dd44`，
  插件报 `server = 1f3c:9d80:5ba7:0e12`。两者都**稳定但互不相同**，
  于是「两端指纹对不上」的排查步骤永远失败。
- **根因**：Python 用 `sha256(pub)`，TS 用了 `HMAC-SHA256(空密钥, pub)`。
- **处理**：TS 改成 `createHash('sha256')`（r7）。
- **教训**：跨语言实现一个"校验和"式的小函数，也要**先对齐定义**再各写各的。

### 3.8 patch 行的 `config` 改了但没生效

- **根因**：改 `config` 不会让已加载模块重新 `apply`，闭包里捕获的还是旧 config 对象。
- **处理**：
  - 真正的热路径是**设置层**（`settings.yaml` / GUI）——`setSource` 会推新的取值函数。
  - 所以把「每次调用会变的东西」（workspace）做成**调用参数**，
    把「部署级不变的东西」（端口、密钥）留在 `config`。
- **教训**：分清楚哪些配置是"装配期"的、哪些是"运行期"的。

### 3.9 环境侧的两个大坑（不在插件里，但会伪装成插件故障）

| 坑 | 症状 | 真相 |
|---|---|---|
| **frp 隧道归属冲突** | 隧道"通"，但连到的是**本机**自己的服务 | 隧道 ID 是**独占槽位**，两台机器配置同源就变成"谁先连上谁占用" |
| **DNS 污染** | `frpc 登录节点失败 … EOF`，而 TCP 连通性测试却正常 | 远端把**隧道节点的域名**解析成了 `.com` 顶级域根服务器地址。用 hosts 锁死真实 IP 解决 |

### 3.10 命令输出被按错误编码解码（中文变 U+FFFD）

- **症状**：`remote_exec` 跑 `whoami` / `ipconfig`，中文全变成 `����`；
  但 `remote_ping` 返回的 `hostname`（读的是 `$env:COMPUTERNAME`）却是好的。
- **根因**：Windows 上**两种编码混在同一个管道里**——PowerShell 自己的 cmdlet 输出是 .NET 字符串
  （按控制台编码写出），而 `whoami.exe` / `ipconfig.exe` 这类**原生程序**按 ANSI/OEM 代码页
  直接写字节。原实现把子进程输出**无条件按 UTF-8 解码**，原生那一半就烂了。
  另一种"想当然的修法"（在 PowerShell 里强制 `[Console]::OutputEncoding=UTF8`）**更糟**：
  它让 PowerShell 把原生程序的 GBK 字节当 UTF-8 解，信息在插件看到之前就已经丢了。
- **处理**：用 `encoding: 'buffer'` 收**原始字节**，然后
  **utf-8 严格 → gbk → big5 → shift_jis → windows-1252 → 有损回退** 依次尝试。
  cmdlet 输出是合法 UTF-8，命中第一档；原生输出命中 GBK 档。
- **教训**：`hostname.exe` 是**另一个**坑——它是 ANSI 程序，系统非 Unicode 代码页表示不出中文机名，
  所以远端 `hostname` 永远输出垃圾，换个算法也救不回来。**要机名就读 `$env:COMPUTERNAME`**。
- **验证**：远端 `remote_exec` 一次跑 cmdlet 中文 / `whoami` / `ipconfig` / `cmd` 四路中文，
  全部正确（远端 `build: r8`）。

---

## 4. 版本历史

| 版本 | 改了什么 | 触发原因 |
|---|---|---|
| r1 | 初版：协议 + 两端插件 + 密钥生成 | — |
| r2 | `installModelSelection` | 3.1 |
| r4 | `BUILD` 标记、`workspace`/`preset_id` 改为每次调用可传、`ctx.effect` 容错 | 3.3 / 3.4 / 3.8 |
| r6 | `workspaceRegistry.create` + `attachSession` + 标题 | 3.2 |
| r7 | 指纹改回 `sha256`（与密钥生成器一致） | 3.7 |
| r8 | `exec` 按原始字节 + 多编码回退解码（修中文乱码） | 3.10 |

> **热重载会留下僵死 socket**：每次换 `?v=` 都会新建一个监听，旧的不会自己关。
> 自测时换一个干净端口，或用 `Get-NetTCPConnection -State Listen -LocalPort <port>`
> 确认谁在听；正式部署重启 `dsh web` 清干净。

---

## 5. 调试手法（都不依赖看日志）

这套东西最烦的是**看不到 DSH 的 stdout**。所以把关键事实做成"可以被工具观测"的：

1. **`BUILD` 常量进 `sysinfo`** → `remote_ping` 直接告诉你运行时是哪一版。
2. **监听端口** → `Get-NetTCPConnection -State Listen -LocalPort <port>` 证明插件真的起来了。
3. **`workspace.json`** → 直接看 `sessionIds` 数组成员，判断会话有没有被登记。
4. **会话文件** → `storages/session_projcache/sessions/<id>.json` 判断有没有落盘。
5. **审计日志** → `${DSH_HOME}/dsh-remote/server-audit.log`（JSON 行，含来源/op/成败/耗时）。
6. **本地协议自测** → `test/protocol.test.ts`，改协议后先跑它，别上隧道试。

---

## 6. 没做 / 可做

按价值排序：

1. **远程自举一个"能改插件"的会话**：现在靠 `preset_id: "cordis"` 显式指定，
   可以再加一个 op：先探测对端有哪些 preset，再挑一个带 `cordis_*` 工具的建会话。
2. **远程触发对端压缩**：加一个 op 包一下 `command-compact`，
   现在上下文压缩是"拉回本机压"。
3. **文件批量同步**：现在只有单文件 `fs.read/write`；可以做成带清单+增量+校验的同步。
4. **执行审批**：在 server 端接 DSH 的审批机制，让敏感 op 需要人批（见 `SECURITY.md` §6.6）。
5. **连接复用与多路**：现在一个 client 一条连接，多个客户端会各连一条（server 是每连接一线程）。
6. **给 `remote_agent_prompt` 加流式**：现在要等整轮结束才返回，
   长任务期间看不到进展（临时办法：同 session 调 `remote_agent_events` 偷看）。

---

## 7. 文件地图

| 文件 | 干什么的 | 什么时候改它 |
|---|---|---|
| `src/protocol.ts` | 握手 + 帧 + 密钥编解码 | 改协议时（**先改 `test/protocol.test.ts`**） |
| `src/keys.ts` | 密钥来源解析（内联/文件/自动生成） | 改密钥设定语义时 |
| `src/server.ts` | 监听 + op 表 + agent 驱动 + 工作区登记 + 审计 + 限流 | 加 op、改 agent 行为时。**记得推 `BUILD`** |
| `src/client.ts` | `remote_*` 工具 + 连接复用 | 加工具、改参数时 |
| `cordis.patch.yml` | 两端 patch 模板 | 改默认配置时 |
| `tools/gen-keys.py` | 生成/安装密钥对 | 改密钥存放约定时 |
