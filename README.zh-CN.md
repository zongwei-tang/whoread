# WhoRead

**看清 Mac 上是哪个 app、哪个 AI agent 在读你的密钥，并且拦住它。**

WhoRead 盯住存放凭证和隐私数据的文件：SSH 密钥、云服务和开发工具的令牌、浏览器 Cookie、密码管理器、聊天记录等。每一次访问，它都会告诉你是哪个程序、由哪个 app 或 AI agent 启动、发生在什么时候。程序第一次碰这些文件时，它可以先问你；你说不行，它就拦下。

所有数据只留在你的 Mac 上。WhoRead 从不读取文件内容，也从不联网。

[English](README.md)

```
Claude Code → zsh → cat   读取   ~/.aws/credentials   （AWS 凭证，严重）
```

## 为什么需要它

macOS 会在 app 打开桌面、文稿、下载文件夹之前询问你，但读取 `~/.ssh`、`~/.aws`、`~/.config/gh`、浏览器 Cookie 或 shell 历史时不会。任何以你的身份运行的程序都能悄悄读到它们，包括终端里的 AI 编程助手，以及它启动的每一个工具。

## 功能

- **谁、读了什么、什么时候。** 每次访问敏感文件都会记录：程序本身、它的代码签名、启动它的完整进程链，以及要为它负责的 app 或 AI agent。
- **内置 44 个类别**，可以修改：SSH、AWS、gcloud、Azure、Kubernetes、Docker、npm、PyPI、git 和 GitHub 凭证、GnuPG、钥匙串、浏览器资料、密码管理器、信息、微信、Telegram、Signal、邮件、通讯录、日历、照片、shell 历史、云盘、iPhone 备份、外接磁盘、各 AI 编程工具的会话记录，以及你添加的项目文件夹里的 `.env`、`*.pem`、`*.key`。也可以添加自己的路径和类别。
- **认识 AI agent。** 能识别 Claude Code、Codex CLI、Gemini CLI、opencode、aider、Cursor，以及 Claude 和 ChatGPT 桌面版，包括它们启动的所有程序。
- **先问你。** 开启拦截后，程序第一次碰受保护的文件、又没有规则能决定时，这次访问会先等着，同时弹出通知：*允许一次*、*始终允许*、*拒绝*、*始终拒绝*。你的选择会存成规则。来不及回答就当作拒绝。
- **正常的使用者不打扰。** `ssh` 读 SSH 密钥、Chrome 读自己的 Cookie 属于正常情况，不会问你，除非是 AI agent 启动的。聚焦、时间机器、iCloud 等系统服务永远不会被问。
- **规则**可以对某个类别、某个严重级别或某个路径执行允许、拒绝或提醒，作用于某个程序、某个 app、所有非正常使用者，或者**所有由 AI agent 启动的程序**。
- **AI agent 关不掉自己的看门狗。** 关闭拦截、允许访问、放宽规则都需要你的密码或 WhoRead app。拦截永远不会被自动关闭。
- **菜单栏 app**：实时动态、提醒、应用、文件、AI agent、规则、设置，提供中英文界面；另有 `whoread` 命令行工具。

## 系统要求

- macOS 14 Sonoma 或更新版本。
- 安装后台服务需要管理员权限。
- 拦截功能依靠 Endpoint Security 系统扩展，只能在签名发布版里运行。签名发布版暂未推出，在那之前 WhoRead 以**只监控模式**运行：记录和提醒，但不拦截。

## 开始使用

编译并安装后台服务（只监控模式，使用 macOS 自带的 `eslogger`）：

```bash
git clone https://github.com/zongwei-tang/whoread.git
cd whoread
swift build -c release
sudo scripts/install-dev-daemon.sh eslogger
```

然后给后台服务完全磁盘访问权限：**系统设置 → 隐私与安全性 → 完全磁盘访问权限 → + → ⌘⇧G →** `/usr/local/libexec/whoreadd`，再重启它：

```bash
sudo launchctl kickstart -k system/com.whoread.daemon
whoread status
```

## 常用命令

```bash
whoread status                          # 是否在运行，在监控什么
sudo whoread events --since 1h          # 最近对受保护文件的访问
sudo whoread events --agents-only       # 只看 AI agent 碰过的
sudo whoread alerts                     # 首次和异常访问的提醒
sudo whoread apps                       # 哪些 app 碰了什么
sudo whoread export --format csv --since 7d --output accesses.csv
whoread catalog show                    # 受保护的内容
sudo whoread catalog add-path ssh ~/keys/   # 再保护一个文件夹
```

读取历史记录需要 `sudo`（或 WhoRead app），所以以你身份运行的程序（包括 AI agent）读不到。加 `--lang zh-Hans` 输出中文，加 `--json` 输出 JSON。

开启拦截后，用 `whoread asks` 查看等待回答的询问，用 `whoread ask 编号 deny`、`block`、`allow-once` 或 `allow` 回答（允许需要 `sudo`）。

立即停止拦截：`sudo whoread enforcement off`，或 `sudo whoread kill-switch engage`。

## 隐私

- 从不读取文件内容。
- 不联网，没有遥测，没有统计，不调用任何 AI 服务。
- 命令行里的密码、令牌、密钥在存储前会被脱敏。
- 历史记录存放在 `/Library/Application Support/WhoRead`，只有 root 能读。

## 权限说明

| 权限 | 原因 |
|---|---|
| 完全磁盘访问权限（后台服务） | macOS 要求所有 Endpoint Security 客户端都有它，`eslogger` 也一样。 |
| 管理员权限 | 后台服务以 root 运行；app 和命令行工具以你的身份运行。 |
| 通知（app） | 用于询问和提醒。不允许通知的话，询问只出现在菜单栏里，超时就会被拒绝。 |
| 批准系统扩展（签名发布版） | 拦截功能运行在 Endpoint Security 系统扩展里。 |

## 卸载

```bash
sudo scripts/uninstall-dev-daemon.sh          # 保留历史记录
sudo scripts/uninstall-dev-daemon.sh --purge  # 连历史记录一起删除
```

## 文档

- [询问模式如何工作](docs/ASK_MODE.md)
- [威胁模型与局限](docs/THREAT_MODEL.md)
- [架构](docs/ARCHITECTURE.md)
- [编译、测试与参与开发](docs/DEVELOPMENT.md)
- [签名发布](docs/DISTRIBUTION.md)
- [调研记录](docs/RESEARCH.md)

WhoRead 仍是预发布软件，1.0 之前可能还会有改动。
