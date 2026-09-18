# usbctl 部署说明

> 一条**独立于 DSH、独立于 frp、独立于 UU** 的命令通道。
> 被控端只要有个 Python 3.8+ 和 `cryptography`，不需要装别的东西。
>
> 主控端目录（本机）：`E:\__ai__\demo\ds_harness_test\usbctl\`
> 被控端目录（远端）：`C:\Users\thinkpad\usbctl\`

---

## 0. 关于"用 Type-C 连接两台电脑"

先把这件事说清楚，免得白折腾：

| 线 | 结果 |
|---|---|
| **普通 USB-C 数据线**（C2C 充电线 / USB 3.x 线） | **不会有任何链路**。USB 是"主机↔设备"协议，两台主机之间不会枚举出设备，设备管理器里什么都不出现 |
| **USB4 / 雷电 3/4 线** | **可以**。链路会协商出 PCIe 隧道，Windows 生成一块"雷电 / USB4 网络"虚拟网卡，两端各拿到一个 `169.254.x.x`，**之后就是普通 TCP/IP** |
| USB 对拷线（中间带芯片） | 靠厂商驱动，表现为专用设备而不是网卡，跑不了标准 TCP |

本机确认有 USB4 硬件（`USB4(TM) 主机路由器`）。**远端有没有 USB4/雷电口，需要你插上线之后看**：

```powershell
Get-NetAdapter | Format-Table Name, InterfaceDescription, Status, LinkSpeed
```

看到类似 `Thunderbolt Networking` / `USB4` 的一块，就说明线通了，把它的 IP 当成 `--target` 用即可。

**但既然两台机器在同一张 Wi-Fi 里（本机 `192.168.1.117`、远端 `192.168.1.116`），
现在就可以直接用，不用等线。** 这个工具只认一个 TCP 地址，链路是 Wi-Fi、USB4 还是隧道，它不关心。

---

## 1. 要拷什么（只拷这三个文件）

从 `E:\__ai__\demo\ds_harness_test\usbctl\`：

| 文件 | 拷到远端哪里 |
|---|---|
| `usbctl.py` | `C:\Users\thinkpad\usbctl\usbctl.py` |
| `keys\agent.key` | `C:\Users\thinkpad\usbctl\agent.key` |
| `keys\client.pub` | `C:\Users\thinkpad\usbctl\client.pub` |

**注意**：只给远端 `agent.key` + `client.pub`。**千万不要**把 `client.key` 或 `agent.pub` 也拷过去
——那等于把主控端的身份也交出去了，双向认证就没意义了。

身份指纹（部署后核对用）：

| 角色 | 指纹 |
|---|---|
| agent（远端持有 `agent.key`） | `e58f:5a57:41aa:1175` |
| client（本机持有 `client.key`） | `cf9c:04c8:048b:bba0` |

---

## 2. 远端：先确认 Python 和依赖

```powershell
cd C:\Users\thinkpad\usbctl
python -V
python -c "import cryptography; print('cryptography', cryptography.__version__)"
```

- 有版本号 → 直接进第 3 步。
- 报 `ModuleNotFoundError` → `python -m pip install cryptography`
  （别用别的 Python：旧的 Python 代理在跑，说明它用的那个解释器一定有这个库。
  可以 `where python` 看一下有没有多个。）

---

## 3. 远端：启动 agent（正向模式，推荐）

```powershell
cd C:\Users\thinkpad\usbctl
python usbctl.py agent --host 0.0.0.0 --port 11330 --allow-peer 192.168.1.117
```

应该看到：

```
[2026-09-18 ...] usbctl 1.0.0 agent 启动
[2026-09-18 ...]   本机身份指纹 e58f:5a57:41aa:1175  (agent.key)
[2026-09-18 ...]   固定对端指纹 cf9c:04c8:048b:bba0  (client.pub)
[2026-09-18 ...] 监听 0.0.0.0:11330
```

**这个窗口别关**，agent 就跑在里面（关了就断了）。日志同时写到 `usbctl-agent.log`。

想让它不占窗口、开机自启，另开一个**管理员** PowerShell 跑：

```powershell
$py = (Get-Command python).Source
$act = New-ScheduledTaskAction -Execute $py -Argument 'usbctl.py agent --host 0.0.0.0 --port 11330 --allow-peer 192.168.1.117' -WorkingDirectory 'C:\Users\thinkpad\usbctl'
Register-ScheduledTask -TaskName 'usbctl-agent' -Action $act -Trigger (New-ScheduledTaskTrigger -AtStartup) -RunLevel Highest -Force
Start-ScheduledTask -TaskName 'usbctl-agent'
```

（**可选，不装也行**。而且注意：之前的旧 Python 代理就是被这类自启项坑过，所以装了记得
`Unregister-ScheduledTask -TaskName 'usbctl-agent'` 能干净撤掉。）

---

## 4. 远端：放行入站 11330（**管理员** PowerShell）

```powershell
New-NetFirewallRule -DisplayName 'usbctl 11330' -Direction Inbound -Action Allow `
  -Protocol TCP -LocalPort 11330 -Profile Any
```

**必须做**：这台机器的网络位置是 `Public`，Public 配置下 Windows 默认挡入站。
远端多半也是 Public。如果远端还装了第三方安全软件，也要在里面放行。

自检：

```powershell
Get-NetTCPConnection -State Listen -LocalPort 11330
# 期望： 0.0.0.0   11330
```

---

## 5. 主控端（我这边）

你做完第 3、4 步说一声，我就跑：

```powershell
cd E:\__ai__\demo\ds_harness_test\usbctl
python usbctl.py ping --target 192.168.1.116:11330 --key keys\client.key --peer keys\agent.pub
```

期望返回远端的 `hostname` / `user` / `cwd` / `pid`。通了之后我就能：

1. **远程改远端 DSH 的绑定**：把 `dsh-remote-server` 的 `host` 改成 `0.0.0.0`，
   顺便把 11325 的防火墙规则加上 → **dsh-remote 那条链路也就活了**
2. 直接读写远端文件、看日志、排查 UU/frp
3. 往后被控端出任何问题，我都能自己修，不用每次都来问你

---

## 6. 备选：反向模式（远端开不了防火墙时用）

正向模式需要**远端**开入站。如果远端拿不到管理员权限、或者安全软件不让你放行，
就用反向：**让远端主动拨出来**，出站默认是放行的，远端什么都不用改。

- 我这边先起监听（我是本机管理员，本机防火墙我自己放行）：

  ```powershell
  python usbctl.py run --listen 0.0.0.0:11331 `
    --key keys\client.key --peer keys\agent.pub `
    --command-file <命令文件>
  ```

- 远端：

  ```powershell
  cd C:\Users\thinkpad\usbctl
  python usbctl.py agent --connect 192.168.1.117:11331
  ```

  它会一直重连（每 5 秒一次），我那边每起一次监听就执行一条命令。
  加 `--once` 则只服务一次就退出。

反向模式的缺点是**必须有我在监听**，所以它适合"一次性修东西"，不适合常驻。

---

## 7. 命令速查

全部子命令都在 `usbctl.py` 里，`python usbctl.py --help` 可看。

| 子命令 | 作用 |
|---|---|
| `keygen --dir keys` | 生成 agent/client 两对密钥，打印指纹 |
| `agent [--host] [--port] [--connect] [--allow-peer] [--once]` | 被控端 |
| `run --target <host:port> --command-file <文件>` | 执行一条命令（`--command` 直接给命令，`--out` 存 JSON） |
| `ping --target <host:port>` | 探活 + 看被控端信息 |
| `call --target <host:port> --op read/write/list/stat --args-file <JSON>` | 文件读写与列目录 |

被控端支持的 op：`ping` / `exec` / `read` / `write` / `list` / `stat`。

`exec` 的输出是 UTF-8 解码的（agent 会先给 PowerShell 设好 `[Console]::OutputEncoding`），
所以中文不会乱码；**退出码、是否超时、耗时**都会带回来，stderr 和 stdout 分开。

### 命令行转义的建议

从 PowerShell 调 `--command` 传含引号/中文/反斜杠的命令很容易被转义吃掉。
**推荐把命令写进文件，用 `--command-file`**；写文件的内容用 `write` op（base64）传，
不要用命令行拼。主控端目录里的 `_mkargs.py` 就是干这个的：

```powershell
python _mkargs.py --op write --path "C:\Users\thinkpad\x.yaml" --from-file "本地文件" --out args.json
python usbctl.py call --target 192.168.1.116:11330 --key keys\client.key --peer keys\agent.pub --op write --args-file args.json
```

---

## 8. 安全说明

- 两端各持一个 X25519 静态密钥对，并 **pin 住对方公钥** —— 双向认证，没有 CA。
- 每次连接新生成临时密钥对 → **前向保密**（事后拿到静态私钥也解不开历史流量）。
- HKDF-SHA256 派生方向密钥，**AES-256-GCM** 逐帧加密；每帧严格递增计数器绑进 AAD，**抗重放/乱序**。
- 认证完成前不回应任何业务内容；magic 不符直接断开 → 公网/局域网扫描者探不出东西。
- **私钥等于那台机器**。撤权 = 换密钥（`keygen` 重新生成，两端换文件）。

已在本机做过完整回环自测：

| 用例 | 结果 |
|---|---|
| ping | ✅ 主机名/用户/cwd/pid 正确 |
| exec 中文 + stderr 分离 | ✅ `中文编码测试 ok`，stderr 单独带回 |
| write → read 逐字节比对 | ✅ 255 字节完全一致（中文 + 反斜杠路径 + CRLF） |
| list | ✅ |
| 正向（被控端监听） | ✅ |
| 反向（被控端拨出） | ✅ |
| **公钥不匹配必须拒绝** | ✅ `对端身份校验失败`，连接被拒 |

---

## 9. 排错

| 现象 | 先查 |
|---|---|
| 主控端 `ECONNREFUSED` | agent 没跑 / 端口不对 / 远端防火墙没放行（第 4 步）|
| 主控端连不上但 agent 显示在监听 | 远端网络位置是不是 Public 且没放行；换个端口试 |
| `对端身份校验失败` | 密钥拿错了：远端该拿 `agent.key`+`client.pub`，本机该拿 `client.key`+`agent.pub`。核对第 1 步的两个指纹 |
| `不是 usbctl 协议（magic 不符）` | 连到了别的服务（比如 msg-recv、远端 DSH 插件）。确认端口 |
| 中文乱码 | 用 `--command-file` 而不是 `--command`；agent 侧已强制 UTF-8 |
| `ModuleNotFoundError: cryptography` | 第 2 步 |
