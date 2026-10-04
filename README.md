# WhoRead

**Which app read my SSH keys?** WhoRead tells you which process opened or modified your sensitive
files, when, and who started it. It can also block access you did not allow. It runs entirely on
your Mac.

[中文说明见下方](#whoread-中文)

> **Status:** in development. The core, storage, daemon, eslogger backend and CLI are built and
> tested (336 tests, two adversarial review rounds). The SwiftUI app, the native Endpoint Security client and enforcement are
> written but not yet compiled on a Mac. See [docs/STATUS.md](docs/STATUS.md).

## Why

macOS privacy prompts (TCC) cover Desktop, Documents, Downloads and a few other places.
`~/.ssh`, `~/.aws`, `~/.config/gh`, browser cookies and shell history are not covered: any
process running as you can read them silently. That includes the AI coding agent in your
terminal and every tool it spawns.

## What it does

- **Records** every open (read/write), modifying close, rename, clone, copyfile, link, unlink and
  truncate on sensitive paths. For each one it keeps the time, pid, executable, signing ID, team
  ID, platform-binary flag, the full parent chain and the **responsible app**, for example
  `Claude Code → zsh → cat → ~/.aws/credentials`.
- **Built-in catalog** of 44 categories, editable: SSH, cloud and developer credentials (AWS,
  gcloud, Azure, kube, Docker, npm, PyPI, netrc, git, gh, GnuPG), keychains, browser profiles,
  password managers, chats (Messages, WeChat, Telegram, Signal…), Mail/Contacts/Calendar/Photos,
  shell history, cloud drives, iPhone backups, external volumes, the transcripts of Claude Code,
  Codex CLI, Gemini CLI, Cursor and opencode (one category each), and `.env`/`*.pem`/`*.key`
  inside the project folders you add (Settings, or `whoread settings set project-root-add PATH`).
  Categories that do not exist on your Mac are shown as "not detected".
- **Attribution** charges helpers to their `.app`, and interpreters or CLI tools to the app or AI
  agent that started them. Recognised agents: Claude Code, Codex CLI, Gemini CLI, opencode,
  aider, Cursor, the Claude and ChatGPT desktop apps.
- **Quiet by default.** It learns for 7 days and then alerts only on a new (app, category,
  access) combination. Critical files touched by an unexpected process alert even while
  learning. Repeats within 10 minutes merge into one alert with a count. Spotlight, Time Machine,
  iCloud, Quick Look and XProtect are folded away.
- **Optional blocking.** Rules (deny / allow / alert) can target a category, a severity or a path,
  and apply to a signed program, an unsigned program, an app, "anything that isn't an expected
  owner" or **"anything started by an AI agent"**. Off by default. Fail-open. Three instant kill
  switches (turning enforcement off needs `sudo` or the app, so an agent cannot simply switch
  off its own guard; a sustained flood that makes AUTH answers slow does trip it, by design).
- **Menu bar app** with seven tabs (Live, Alerts, Apps, Files, Agents, Rules, Settings),
  notifications with actions ("Allow once · Always allow · Keep blocking"), English and
  Simplified Chinese.
- **`whoread` CLI** for status, queries, daily aggregates, JSON/CSV export, catalog edits,
  enforcement on/off and the kill switch.
- **Private.** It never reads file contents, never uses the network, and has no telemetry and no
  LLM calls. Command lines are redacted before they are stored.

## Install

Release builds (Developer ID, notarized) are not published yet. For now, see
[docs/DEVELOPMENT.md](docs/DEVELOPMENT.md). On a Mac, the monitor-only eslogger backend works
without any Apple entitlement:

```bash
swift build -c release
sudo scripts/install-dev-daemon.sh eslogger
# grant Full Disk Access to /usr/local/libexec/whoreadd, then:
sudo launchctl kickstart -k system/com.whoread.daemon
whoread status
whoread events --since 1h
whoread alerts
whoread daily --since 30d
whoread export --format csv --since 7d --output accesses.csv
whoread export --aggregates --format json --since 30d
```

Times without an offset (`--since "2026-10-01 09:00"`) are local time. The daemon reads the team
IDs of installed apps with `codesign -dv` at start, so apps are recognised as the expected owners
of their data (restart the daemon after installing an owner app). To see what it finds:

```bash
sudo whoread catalog resolve-owners
```

Catalog edits (`whoread catalog add-path|remove-path|add-category|remove-category|set-severity|
enable|disable|import`) and anything else that weakens protection need `sudo` or the signed app;
`whoread catalog show|export` are plain reads. With a release build, link the bundled CLI once:
`sudo mkdir -p /usr/local/bin && sudo ln -sf /Applications/WhoRead.app/Contents/Helpers/whoread /usr/local/bin/whoread`.
To use the signed app with the dev daemon, see "M3: the signed app against the dev daemon" in
[docs/DEVELOPMENT.md](docs/DEVELOPMENT.md).

## Permissions, and why

| Permission | Why |
|---|---|
| Full Disk Access (for the daemon / extension) | macOS requires it of every Endpoint Security client, eslogger included. |
| Root (daemon only) | Endpoint Security clients run as root. The app and the CLI run as you. |
| System extension approval | The release build monitors through an Endpoint Security system extension. |
| Endpoint Security entitlement | Granted by Apple to the developer; needed for the native client and for blocking. |
| Notifications (app, optional) | Alerts with Allow once / Always allow / Keep blocking actions. |
| Administrator password (app, occasionally) | Only when the UI creates or removes the kill-switch file because the daemon refused. |

## Screenshots

Pending: the app has not been run on a Mac yet (M7).

## Docs

[Architecture](docs/ARCHITECTURE.md) · [Threat model](docs/THREAT_MODEL.md) ·
[Development & VM setup](docs/DEVELOPMENT.md) · [Distribution](docs/DISTRIBUTION.md) ·
[Research notes](docs/RESEARCH.md) · [Status](docs/STATUS.md)

---

# WhoRead 中文

**谁读了我的 SSH 密钥？** WhoRead 告诉你：哪个 app、哪个进程，在什么时候，读或写了你的哪个敏感文件，又是谁启动了它；并且可以按规则拦截。所有数据都只留在这台 Mac 上。

> **状态：** 开发中。
> - 已完成并通过测试（336 个测试，经过两轮对抗性审查）：核心逻辑、存储、守护进程、eslogger 后端、CLI。
> - 代码已写完，但还没在 Mac 上编译：SwiftUI 应用、原生 Endpoint Security 客户端、拦截功能。
>
> 详见 [docs/STATUS.md](docs/STATUS.md)。

## 为什么需要它

macOS 的隐私弹窗（TCC）只保护桌面、文稿、下载等少数位置。`~/.ssh`、`~/.aws`、`~/.config/gh`、浏览器 Cookie、shell 历史都不受保护，任何以你的身份运行的进程都能静默读取，包括终端里的 AI coding agent 和它启动的每一个工具。

## 功能

- **记录**：对敏感路径的 open（读/写）、修改后的 close、rename、clone、copyfile、link、unlink、truncate。每条记录包含时间、pid、可执行文件、signing ID、team ID、是否 platform binary、完整父进程链，以及归因后的**负责 app**，例如 `Claude Code → zsh → cat → ~/.aws/credentials`。
- **内置 44 个类别**，可增删改：
  - SSH；
  - 开发与云凭证：AWS、gcloud、Azure、kube、Docker、npm、PyPI、netrc、git、gh、GnuPG；
  - 钥匙串、浏览器资料、密码管理器；
  - 聊天记录：信息、微信、Telegram、Signal 等；
  - 邮件、通讯录、日历、照片；
  - shell 历史、云盘、iPhone 备份、外接卷，以及 Claude Code、Codex CLI、Gemini CLI、Cursor、opencode 各自的会话记录（每个一个类别）；
  - 你添加的项目目录下的 `.env`、`*.pem`、`*.key`（在设置中添加，或 `whoread settings set project-root-add PATH`）。

  本机不存在的类别标记为「未检测到」。
- **归因**：helper 归到外层 `.app`；解释器和命令行工具归到启动它们的 app 或 AI agent。能识别的 agent：Claude Code、Codex CLI、Gemini CLI、opencode、aider、Cursor、Claude 桌面版、ChatGPT 桌面版。
- **降噪**：
  - 先学习 7 天，之后只对新的（app、类别、读/写）组合告警；
  - critical 文件被非预期进程访问时，学习期内也会告警；
  - 同一 app 对同一类别 10 分钟内的重复访问，合并成一条告警并附上次数；
  - 聚焦、时间机器、iCloud、快速查看、XProtect 的访问默认折叠。
- **可选拦截**：
  - 规则动作：拦截、允许或告警；
  - 保护对象：类别、严重程度或路径；
  - 适用对象：已签名程序、未签名程序、某个 app、「任意非 owner 进程」，或**「祖先链中包含 AI agent 的任意进程」**；
  - 默认关闭，出错时放行（fail-open），有三种立即生效的 kill switch（关闭拦截需要 `sudo` 或应用本身，agent 不能直接关掉；但持续制造大量访问、让 AUTH 响应变慢，会按设计触发自动关闭）。
- **菜单栏应用**：实时、告警、应用、文件、AI agent、规则、设置七个页签。通知带操作按钮（「允许一次 · 始终允许 · 保持拦截」）。界面提供中英文。
- **`whoread` 命令行**：查看状态、查询、按天汇总、导出 JSON/CSV、编辑类别、开关拦截、kill switch。
- **隐私**：从不读取文件内容，不联网，没有遥测，不调用任何 LLM。命令行参数在存储前会脱敏。

## 安装（开发版）

正式版（Developer ID 签名并公证）还没有发布，目前请参考 [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md)。在 Mac 上，只监控的 eslogger 后端不需要任何 Apple entitlement：

```bash
swift build -c release
sudo scripts/install-dev-daemon.sh eslogger
```

然后给 `/usr/local/libexec/whoreadd` 授予完全磁盘访问权限，再重启守护进程：

```bash
sudo launchctl kickstart -k system/com.whoread.daemon
```

之后就可以查询了：

```bash
whoread status
whoread events --since 1h --lang zh-Hans
whoread alerts --lang zh-Hans
whoread daily --since 30d
```

不带时区的时间（如 `--since "2026-10-01 09:00"`）按本地时间理解。守护进程每次启动时会用 `codesign -dv` 读取已安装 app 的 team ID，从而把它们识别为自己数据的预期 owner（安装新的 owner app 后请重启守护进程）。查看识别结果（不会写入任何文件）：

```bash
sudo whoread catalog resolve-owners
```

编辑类别（`whoread catalog add-path|remove-path|add-category|remove-category|set-severity|enable|disable|import`）以及其他任何削弱保护的操作，都需要 `sudo` 或已签名的应用；`whoread catalog show|export` 只是读取，不需要。

## 权限说明

| 权限 | 原因 |
|---|---|
| 完全磁盘访问（守护进程或扩展） | macOS 要求所有 Endpoint Security 客户端（包括 eslogger）都拥有它 |
| root（仅守护进程） | Endpoint Security 客户端必须以 root 运行；应用和 CLI 以你的身份运行 |
| 批准系统扩展 | 正式版通过 Endpoint Security 系统扩展监控 |
| Endpoint Security entitlement | 由 Apple 授予开发者；原生客户端和拦截功能需要它 |
| 通知（应用，可选） | 告警通知，带「允许一次 · 始终允许 · 保持拦截」操作 |
| 管理员密码（应用，偶尔） | 仅当守护进程拒绝、需要由界面创建或删除 kill switch 文件时 |

## 文档

[架构](docs/ARCHITECTURE.md) · [威胁模型](docs/THREAT_MODEL.md) · [开发与虚拟机](docs/DEVELOPMENT.md) · [分发](docs/DISTRIBUTION.md) · [调研记录](docs/RESEARCH.md) · [计划](docs/STATUS.md) · [进度](docs/STATUS.md)
