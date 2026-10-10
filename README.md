# WhoRead

**See which app or AI agent reads your secrets on your Mac, and stop it.**

WhoRead watches the files that hold your credentials and private data: SSH keys, cloud and
developer tokens, browser cookies, password managers, chat histories and more. For every access it
tells you which program it was, which app or AI agent started it, and when. It can ask you before
a program touches those files for the first time, and block it if you say no.

Everything stays on your Mac. WhoRead never reads file contents and never uses the network.

[简体中文](README.zh-CN.md)

```
Claude Code → zsh → cat   read   ~/.aws/credentials   (AWS credentials, critical)
```

## Why

macOS asks before apps open your Desktop, Documents or Downloads folders, but not before they read
`~/.ssh`, `~/.aws`, `~/.config/gh`, your browser cookies or your shell history. Any program running
as you can read them silently, including an AI coding agent in your terminal and every tool it
starts.

## Features

- **Who, what, when.** Each access to a sensitive file is recorded with the program, its code
  signature, the full chain of processes that started it, and the app or AI agent responsible for
  it.
- **44 built-in categories**, editable: SSH, AWS, gcloud, Azure, Kubernetes, Docker, npm, PyPI,
  git and GitHub credentials, GnuPG, keychains, browser profiles, password managers, Messages,
  WeChat, Telegram, Signal, Mail, Contacts, Calendar, Photos, shell history, cloud drives, iPhone
  backups, external volumes, the transcripts of AI coding tools, and `.env`, `*.pem` and `*.key`
  files in the project folders you add. You can add your own paths and categories.
- **Knows AI agents.** Claude Code, Codex CLI, Gemini CLI, opencode, aider, Cursor and the Claude
  and ChatGPT desktop apps are recognised, including everything they start.
- **Asks first.** With blocking on, the first time a program touches a protected file and no rule
  covers it, the access waits and you get a notification: *Allow once*, *Always allow*, *Deny* or
  *Always deny*. Your answer becomes a rule. No answer in time means denied.
- **Expected owners are left alone.** `ssh` reading your SSH keys or Chrome reading its own cookies
  is normal and raises no question, unless an AI agent started it. System services such as
  Spotlight, Time Machine and iCloud are never asked about.
- **Rules** allow, deny or alert on a category, a severity or a path, for one program, one app,
  anything that is not an expected owner, or **anything started by an AI agent**.
- **An agent cannot switch off its own guard.** Turning blocking off, allowing access or weakening
  a rule needs your password or the WhoRead app. Blocking is never turned off automatically.
- **Menu bar app** with live activity, alerts, apps, files, agents, rules and settings, in English
  and Simplified Chinese, plus a `whoread` command line tool.

## Requirements

- macOS 14 Sonoma or later.
- Administrator rights to install the background service.
- Blocking uses an Endpoint Security system extension, which only runs from a signed release.
  Signed releases are not published yet; until then WhoRead runs in **monitor-only mode**, which
  records and alerts but does not block.

## Getting started

Build and install the background service (monitor-only mode, using Apple's built-in `eslogger`):

```bash
git clone https://github.com/zongwei-tang/whoread.git
cd whoread
swift build -c release
sudo scripts/install-dev-daemon.sh eslogger
```

Then give the service Full Disk Access: **System Settings → Privacy & Security → Full Disk
Access → + → ⌘⇧G →** `/usr/local/libexec/whoreadd`, and restart it:

```bash
sudo launchctl kickstart -k system/com.whoread.daemon
whoread status
```

## Usage

```bash
whoread status                          # is it running, what is it watching
sudo whoread events --since 1h          # recent accesses to protected files
sudo whoread events --agents-only       # only what AI agents touched
sudo whoread alerts                     # first-time and unusual accesses
sudo whoread apps                       # which apps touched what
sudo whoread export --format csv --since 7d --output accesses.csv
whoread catalog show                    # what is protected
sudo whoread catalog add-path ssh ~/keys/   # protect another folder
```

Reading the recorded history needs `sudo` (or the WhoRead app), so a program running as you,
an AI agent included, cannot read it. Add `--lang zh-Hans` for Chinese output, or `--json`.

When blocking is on, open questions are listed with `whoread asks` and answered with
`whoread ask ID deny`, `block`, `allow-once` or `allow` (allowing needs `sudo`).

To stop blocking at once: `sudo whoread enforcement off`, or `sudo whoread kill-switch engage`.

## Privacy

- Never reads the contents of your files.
- No network access, no telemetry, no analytics, no AI services.
- Secrets in command lines (passwords, tokens, keys) are redacted before anything is stored.
- The history lives in `/Library/Application Support/WhoRead`, readable only by root.

## Permissions

| Permission | Why |
|---|---|
| Full Disk Access (the background service) | macOS requires it of every Endpoint Security client, including `eslogger`. |
| Administrator rights | The background service runs as root; the app and the CLI run as you. |
| Notifications (app) | Questions and alerts. Without them, questions only appear in the menu bar and are denied when their time runs out. |
| System extension approval (signed releases) | Blocking runs in an Endpoint Security system extension. |

## Uninstall

```bash
sudo scripts/uninstall-dev-daemon.sh          # keeps the history
sudo scripts/uninstall-dev-daemon.sh --purge  # also deletes it
```

## Documentation

- [How ask mode works](docs/ASK_MODE.md)
- [Threat model and limits](docs/THREAT_MODEL.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Building, testing and contributing](docs/DEVELOPMENT.md)
- [Signed releases](docs/DISTRIBUTION.md)
- [Research notes](docs/RESEARCH.md)

WhoRead is pre-release software: expect changes before 1.0.
