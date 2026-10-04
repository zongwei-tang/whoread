#!/usr/bin/env python3
"""Generates Data/catalog.json, Data/agents.json and Data/benign.json.

The JSON files are the source of truth that ships and that users edit; this script only exists so
the defaults are written consistently. Signing IDs / team IDs are deliberately left out: they are
filled from `codesign -dv` on the user's Mac by `whoread catalog resolve-owners`.
"""
import json, os, sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def L(en, zh): return {"en": en, "zh-Hans": zh}

def platform(label, *names, under=("/System/**", "/usr/**", "/bin/**", "/sbin/**", "/Library/Apple/**")):
    """Apple platform binaries by name under system locations."""
    exes = [f"{base}/{n}" if not base.endswith("**") else f"{base}/{n}" for base in under for n in names]
    return {"label": label, "executables": exes, "platformBinary": True}

def app(label, *bundles):
    return {"label": label, "bundles": list(bundles)}

def cli(label, executables=None, argvGlobs=None, names=None, platformBinary=None):
    d = {"label": label}
    if executables: d["executables"] = executables
    if names: d["names"] = names
    if argvGlobs: d["argvGlobs"] = argvGlobs
    if platformBinary is not None: d["platformBinary"] = platformBinary
    return d

def brew(*names):
    """Homebrew (arm64 + Intel) cellar paths. Path-only identity: weak, user-writable."""
    out = []
    for n in names:
        out += [f"/opt/homebrew/Cellar/*/*/bin/{n}", f"/usr/local/Cellar/*/*/bin/{n}"]
    return out

SSH_OWNERS = [
    platform("OpenSSH (Apple)", "ssh", "ssh-agent", "ssh-add", "ssh-keygen", "ssh-keyscan", "scp", "sftp",
             "sshd", "sshd-session", "ssh-keysign", "ssh-sk-helper", "ssh-pkcs11-helper"),
    cli("OpenSSH (Homebrew)", executables=brew("ssh", "ssh-agent", "ssh-add", "ssh-keygen", "scp", "sftp")),
    platform("git (Apple)", "git", "git-remote-http", "git-remote-https"),
    cli("git (Xcode / CLT)", executables=["/Library/Developer/CommandLineTools/usr/bin/git",
                                          "/Library/Developer/CommandLineTools/usr/libexec/git-core/*",
                                          "/Applications/Xcode*.app/Contents/Developer/usr/bin/git",
                                          "/Applications/Xcode*.app/Contents/Developer/usr/libexec/git-core/*"],
        platformBinary=True),
    cli("git (Homebrew)", executables=brew("git") + ["/opt/homebrew/Cellar/git/*/libexec/git-core/*",
                                                     "/usr/local/Cellar/git/*/libexec/git-core/*"]),
]

BROWSER_PATTERNS = [
    {"glob": "Cache/**", "exclude": True},
    {"glob": "*/Cache/**", "exclude": True},
    {"glob": "*/Code Cache/**", "exclude": True},
    {"glob": "*/GPUCache/**", "exclude": True},
    {"glob": "*/Service Worker/CacheStorage/**", "exclude": True},
    {"glob": "Cookies", "severity": "critical"},
    {"glob": "Cookies-journal", "severity": "critical"},
    {"glob": "Login Data*", "severity": "critical"},
    {"glob": "Web Data*", "severity": "critical"},
    {"glob": "Local State", "severity": "high"},
    {"glob": "History*", "severity": "high"},
    {"glob": "*", "severity": "medium"},
]

def chromium(id_, en, zh, paths, bundles):
    return {
        "id": id_, "name": L(en, zh), "group": "browser", "severity": "high",
        "paths": paths, "patterns": BROWSER_PATTERNS,
        "owners": [app(en, *bundles)],
    }

def pm(id_, en, zh, paths, bundles):
    return {"id": id_, "name": L(en, zh), "group": "password-manager", "severity": "critical",
            "paths": paths, "owners": [app(en, *bundles)]}

def chat(id_, en, zh, paths, owners):
    return {"id": id_, "name": L(en, zh), "group": "chat", "severity": "high", "paths": paths, "owners": owners}

categories = [
    {
        "id": "ssh", "name": L("SSH keys", "SSH 密钥"), "group": "ssh", "severity": "critical",
        "description": L("Private keys are critical; config, known_hosts and public keys are medium.",
                         "私钥为 critical；config、known_hosts 和公钥为 medium。"),
        "paths": ["~/.ssh/"],
        "patterns": [
            {"glob": "*.pub", "severity": "medium"},
            {"glob": "config", "severity": "medium"},
            {"glob": "config.d/**", "severity": "medium"},
            {"glob": "known_hosts*", "severity": "medium"},
            {"glob": "authorized_keys*", "severity": "medium"},
        ],
        "owners": SSH_OWNERS,
    },
    {
        "id": "aws", "name": L("AWS credentials", "AWS 凭证"), "group": "dev-credentials", "severity": "critical",
        "paths": ["~/.aws/"],
        "owners": [
            cli("AWS CLI v2 (installer)", executables=["/usr/local/aws-cli/aws", "/usr/local/aws-cli/aws_completer"]),
            cli("AWS CLI (Homebrew / pip)", argvGlobs=["**/bin/aws", "**/awscli/__main__.py"]),
            cli("Terraform / OpenTofu", names=["terraform", "tofu"]),
            cli("aws-vault / granted", names=["aws-vault", "assume", "granted"]),
        ],
    },
    {
        "id": "gcloud", "name": L("Google Cloud credentials", "Google Cloud 凭证"), "group": "dev-credentials",
        "severity": "critical", "paths": ["~/.config/gcloud/"],
        "owners": [cli("Google Cloud SDK", argvGlobs=["**/google-cloud-sdk/lib/gcloud.py", "**/google-cloud-sdk/bin/*",
                                                      "**/bin/gcloud", "**/bin/gsutil", "**/bin/bq"])],
    },
    {
        "id": "azure", "name": L("Azure credentials", "Azure 凭证"), "group": "dev-credentials", "severity": "critical",
        "paths": ["~/.azure/"],
        "owners": [cli("Azure CLI", argvGlobs=["**/bin/az", "**/azure/cli/__main__.py", "azure.cli"])],
    },
    {
        "id": "kube", "name": L("Kubernetes config", "Kubernetes 配置"), "group": "dev-credentials", "severity": "critical",
        "paths": ["~/.kube/"],
        "owners": [cli("kubectl & friends", names=["kubectl", "kubectl.docker", "k9s", "helm", "kubectx", "kubens", "kind", "minikube", "kustomize"]),
                   app("Docker Desktop", "/Applications/Docker.app"),
                   app("OrbStack", "/Applications/OrbStack.app"),
                   app("Lens", "/Applications/Lens.app")],
    },
    {
        "id": "docker", "name": L("Docker credentials", "Docker 凭证"), "group": "dev-credentials", "severity": "critical",
        "paths": ["~/.docker/config.json"],
        "owners": [cli("docker CLI", names=["docker", "docker-credential-desktop", "docker-credential-osxkeychain", "docker-compose", "colima", "lima", "limactl"]),
                   app("Docker Desktop", "/Applications/Docker.app"),
                   app("OrbStack", "/Applications/OrbStack.app")],
    },
    {
        "id": "npm", "name": L("npm token", "npm 令牌"), "group": "dev-credentials", "severity": "critical",
        "paths": ["~/.npmrc"],
        "owners": [cli("npm / npx / yarn / pnpm", argvGlobs=["**/npm-cli.js", "**/npx-cli.js", "**/bin/npm", "**/bin/npx",
                                                              "**/yarn.js", "**/bin/yarn", "**/pnpm.cjs", "**/bin/pnpm"]),
                   cli("bun", names=["bun"])],
    },
    {
        "id": "pypi", "name": L("PyPI token", "PyPI 令牌"), "group": "dev-credentials", "severity": "critical",
        "paths": ["~/.pypirc"],
        "owners": [cli("twine / poetry / hatch / flit / uv", argvGlobs=["**/bin/twine", "**/bin/poetry", "**/bin/hatch", "**/bin/flit"]),
                   cli("uv", names=["uv"])],
    },
    {
        "id": "netrc", "name": L(".netrc", ".netrc 凭证"), "group": "dev-credentials", "severity": "critical",
        "paths": ["~/.netrc"],
        "owners": [platform("curl / ftp (Apple)", "curl", "ftp"),
                   platform("git HTTP transport (Apple)", "git-remote-http", "git-remote-https"),
                   cli("git HTTP transport (Xcode / CLT / Homebrew)", executables=[
                       "/Library/Developer/CommandLineTools/usr/libexec/git-core/git-remote-http*",
                       "/Applications/Xcode*.app/Contents/Developer/usr/libexec/git-core/git-remote-http*",
                       "/opt/homebrew/Cellar/git/*/libexec/git-core/git-remote-http*",
                       "/usr/local/Cellar/git/*/libexec/git-core/git-remote-http*"]),
                   cli("curl / wget (Homebrew)", executables=brew("curl", "wget"))],
    },
    {
        "id": "git-credentials", "name": L("Git credential store", "Git 凭证存储"), "group": "dev-credentials",
        "severity": "critical", "paths": ["~/.git-credentials", "~/.config/git/credentials"],
        "owners": SSH_OWNERS[2:],
    },
    {
        "id": "gh", "name": L("GitHub CLI token", "GitHub CLI 令牌"), "group": "dev-credentials", "severity": "critical",
        "paths": ["~/.config/gh/"],
        "patterns": [{"glob": "config.yml", "severity": "medium"}],
        "owners": [cli("gh", names=["gh"])],
    },
    {
        "id": "gnupg", "name": L("GnuPG keyring", "GnuPG 密钥环"), "group": "dev-credentials", "severity": "critical",
        "paths": ["~/.gnupg/"],
        "patterns": [{"glob": "S.*", "exclude": True}, {"glob": "*.conf", "severity": "medium"}],
        "owners": [cli("GnuPG", names=["gpg", "gpg2", "gpg-agent", "gpgsm", "gpgconf", "dirmngr", "scdaemon", "keyboxd",
                                       "pinentry", "pinentry-mac", "pinentry-curses", "gpg-connect-agent"])],
    },
    {
        "id": "keychain", "name": L("Keychains", "钥匙串"), "group": "keychain", "severity": "critical",
        "paths": ["~/Library/Keychains/"],
        "owners": [platform("Security daemons", "securityd", "secd", "trustd", "security", "SecurityAgent", "authd",
                            "ctkd", "keychainsharingmessagingd", "accountsd", "cloudd", "akd", "keychain-circle-notification"),
                   {"label": "Keychain Access", "bundles": ["**/Keychain Access.app"], "platformBinary": True}],
    },
    chromium("chrome", "Google Chrome profile", "Google Chrome 资料",
             ["~/Library/Application Support/Google/Chrome/", "~/Library/Application Support/Google/Chrome Beta/",
              "~/Library/Application Support/Google/Chrome Canary/"],
             ["/Applications/Google Chrome.app", "/Applications/Google Chrome Beta.app", "/Applications/Google Chrome Canary.app"]),
    chromium("brave", "Brave profile", "Brave 资料",
             ["~/Library/Application Support/BraveSoftware/Brave-Browser/"], ["/Applications/Brave Browser.app"]),
    chromium("edge", "Microsoft Edge profile", "Microsoft Edge 资料",
             ["~/Library/Application Support/Microsoft Edge/"], ["/Applications/Microsoft Edge.app"]),
    chromium("arc", "Arc profile", "Arc 资料",
             ["~/Library/Application Support/Arc/User Data/"], ["/Applications/Arc.app"]),
    {
        "id": "firefox", "name": L("Firefox profile", "Firefox 资料"), "group": "browser", "severity": "high",
        "paths": ["~/Library/Application Support/Firefox/Profiles/"],
        "patterns": [
            {"glob": "*/cache2/**", "exclude": True},
            {"glob": "cookies.sqlite*", "severity": "critical"},
            {"glob": "logins.json", "severity": "critical"},
            {"glob": "logins-backup.json", "severity": "critical"},
            {"glob": "key4.db", "severity": "critical"},
            {"glob": "formhistory.sqlite*", "severity": "critical"},
            {"glob": "places.sqlite*", "severity": "high"},
            {"glob": "*", "severity": "medium"},
        ],
        "owners": [app("Firefox", "/Applications/Firefox.app", "/Applications/Firefox Developer Edition.app", "/Applications/Firefox Nightly.app")],
    },
    {
        "id": "safari", "name": L("Safari data", "Safari 数据"), "group": "browser", "severity": "high",
        "paths": ["~/Library/Safari/", "~/Library/Containers/com.apple.Safari/Data/Library/Cookies/", "~/Library/Cookies/"],
        "patterns": [
            {"glob": "*.binarycookies", "severity": "critical"},
            {"glob": "History.db*", "severity": "high"},
            {"glob": "*", "severity": "medium"},
        ],
        "owners": [{"label": "Safari", "bundles": ["**/Safari.app", "**/Safari Technology Preview.app"]},
                   platform("WebKit / Safari services", "com.apple.WebKit.Networking", "com.apple.WebKit.WebContent",
                            "com.apple.Safari.History", "SafariBookmarksSyncAgent", "com.apple.Safari.SafeBrowsing.Service",
                            "SafariLaunchAgent", "SafariNotificationAgent", "nsurlsessiond", "cookied")],
    },
    pm("1password", "1Password data", "1Password 数据",
       ["~/Library/Group Containers/2BUA8C4S2C.com.1password/", "~/Library/Containers/com.1password.1password/",
        "~/Library/Group Containers/2BUA8C4S2C.com.agilebits/"],
       ["/Applications/1Password.app", "/Applications/1Password 7.app"]),
    pm("bitwarden", "Bitwarden data", "Bitwarden 数据",
       ["~/Library/Application Support/Bitwarden/", "~/Library/Containers/com.bitwarden.desktop/"],
       ["/Applications/Bitwarden.app"]),
    pm("proton-pass", "Proton Pass data", "Proton Pass 数据",
       ["~/Library/Application Support/Proton Pass/"], ["/Applications/Proton Pass.app"]),
    chat("messages", "Messages", "信息（iMessage）", ["~/Library/Messages/"],
         [{"label": "Messages", "bundles": ["**/Messages.app"], "platformBinary": True},
          platform("Messages daemons", "imagent", "IMDPersistenceAgent", "IMTransferAgent", "imtranscoderagent",
                   "identityservicesd", "IMAutomaticHistoryDeletionAgent", "BlastDoor", "MessagesBlastDoorService")]),
    chat("wechat", "WeChat", "微信", ["~/Library/Containers/com.tencent.xinWeChat/"],
         [app("WeChat", "/Applications/WeChat.app")]),
    chat("telegram", "Telegram", "Telegram",
         ["~/Library/Group Containers/6N38VWS5BX.ru.keepcoder.Telegram/", "~/Library/Application Support/Telegram Desktop/"],
         [app("Telegram", "/Applications/Telegram.app", "/Applications/Telegram Desktop.app")]),
    chat("signal", "Signal", "Signal", ["~/Library/Application Support/Signal/"],
         [app("Signal", "/Applications/Signal.app")]),
    chat("simplex", "SimpleX Chat", "SimpleX Chat", ["~/Library/Application Support/SimpleX/"],
         [app("SimpleX", "/Applications/SimpleX.app", "/Applications/SimpleX Chat.app")]),
    chat("whatsapp", "WhatsApp", "WhatsApp", ["~/Library/Group Containers/group.net.whatsapp.WhatsApp.shared/",
                                              "~/Library/Containers/net.whatsapp.WhatsApp/"],
         [app("WhatsApp", "/Applications/WhatsApp.app")]),
    {
        "id": "mail", "name": L("Mail", "邮件"), "group": "personal", "severity": "high",
        "paths": ["~/Library/Mail/"],
        "owners": [{"label": "Mail", "bundles": ["**/Mail.app"], "platformBinary": True},
                   platform("Mail services", "maild", "MailCacheDelete", "com.apple.MailServiceAgent", "mailq")],
    },
    {
        "id": "contacts", "name": L("Contacts", "通讯录"), "group": "personal", "severity": "high",
        "paths": ["~/Library/Application Support/AddressBook/"],
        "owners": [{"label": "Contacts", "bundles": ["**/Contacts.app"], "platformBinary": True},
                   platform("Contacts services", "contactsd", "AddressBookSourceSync", "AddressBookManager", "ContactsAgent",
                            "com.apple.AddressBook.ContactsAccountsService", "AddressBookSync")],
    },
    {
        "id": "calendar", "name": L("Calendar", "日历"), "group": "personal", "severity": "high",
        "paths": ["~/Library/Calendars/", "~/Library/Group Containers/group.com.apple.calendar/"],
        "owners": [{"label": "Calendar", "bundles": ["**/Calendar.app"], "platformBinary": True},
                   platform("Calendar services", "CalendarAgent", "calaccessd", "remindd", "CalendarWidgetExtension")],
    },
    {
        "id": "photos", "name": L("Photos library", "照片图库"), "group": "personal", "severity": "high",
        "paths": ["~/Pictures/Photos Library.photoslibrary/"],
        "owners": [{"label": "Photos", "bundles": ["**/Photos.app"], "platformBinary": True},
                   platform("Photos services", "photolibraryd", "photoanalysisd", "mediaanalysisd", "cloudphotod",
                            "com.apple.photos.ImageConversionService", "PhotosReliveWidget", "assetsd")],
    },
    {
        "id": "shell-history", "name": L("Shell & REPL history", "Shell 与 REPL 历史"), "group": "history", "severity": "high",
        "paths": ["~/.zsh_history", "~/.zsh_sessions/", "~/.bash_history", "~/.bash_sessions/",
                  "~/.local/share/fish/fish_history", "~/.python_history", "~/.node_repl_history",
                  "~/.psql_history", "~/.mysql_history", "~/.sqlite_history", "~/.irb_history", "~/.lesshst",
                  "~/Library/Application Support/iTerm2/SavedState/"],
        "owners": [platform("Apple shells", "zsh", "bash", "sh"),
                   cli("Homebrew shells", executables=brew("zsh", "bash", "fish")),
                   {"label": "Terminal", "bundles": ["**/Terminal.app"], "platformBinary": True},
                   app("iTerm2", "/Applications/iTerm.app")],
    },
    {
        "id": "cloud-storage", "name": L("Cloud drives", "云盘同步目录"), "group": "cloud", "severity": "high",
        "paths": ["~/Library/CloudStorage/", "~/Library/Mobile Documents/"],
        "owners": [platform("iCloud / File Provider", "bird", "cloudd", "fileproviderd"),
                   app("Dropbox", "/Applications/Dropbox.app"),
                   app("Google Drive", "/Applications/Google Drive.app"),
                   app("OneDrive", "/Applications/OneDrive.app"),
                   app("Box", "/Applications/Box.app")],
    },
    {
        "id": "iphone-backup", "name": L("iPhone backups", "iPhone 备份"), "group": "personal", "severity": "critical",
        "paths": ["~/Library/Application Support/MobileSync/Backup/"],
        "owners": [platform("Device sync", "AMPDevicesAgent", "AMPDeviceDiscoveryAgent", "AMPLibraryAgent",
                            "MobileDeviceUpdater", "AppleMobileDeviceHelper", "AppleMobileBackup"),
                   {"label": "Finder", "bundles": ["**/Finder.app"], "platformBinary": True}],
    },
    {
        "id": "volumes", "name": L("External & decrypted volumes", "外接卷与解密挂载点"), "group": "volumes", "severity": "high",
        "description": L("Includes Cryptomator / VeraCrypt mounts under /Volumes. Add other mount points here.",
                         "包含挂载在 /Volumes 下的 Cryptomator、VeraCrypt 等解密卷；其他挂载点请自行添加。"),
        "paths": ["/Volumes/"],
        "patterns": [{"glob": "*/.Spotlight-V100/**", "exclude": True}, {"glob": "*/.fseventsd/**", "exclude": True},
                     {"glob": "*/.Trashes/**", "exclude": True}],
        "owners": [],
    },
    {
        "id": "ai-sessions", "name": L("AI agent transcripts", "AI agent 会话记录"), "group": "ai", "severity": "high",
        "description": L("Plain-text copies of everything the agent has seen.", "存着 agent 看过的所有内容的明文副本。"),
        "paths": ["~/.claude/projects/", "~/.codex/sessions/", "~/.gemini/tmp/",
                  "~/Library/Application Support/Cursor/User/workspaceStorage/", "~/Library/Application Support/Cursor/User/globalStorage/",
                  "~/.cursor/", "~/.local/share/opencode/"],
        "owners": [
            cli("Claude Code (native)", executables=["**/.local/share/claude/versions/*", "**/Caskroom/claude-code/**"]),
            cli("Claude Code (npm)", argvGlobs=["**/@anthropic-ai/claude-code/cli.js", "**/bin/claude"]),
            cli("Codex CLI", names=["codex"]),
            cli("Codex CLI (npm)", argvGlobs=["**/@openai/codex/bin/codex.js", "**/bin/codex"]),
            cli("Gemini CLI (npm)", argvGlobs=["**/@google/gemini-cli/**", "**/bin/gemini"]),
            app("Cursor", "/Applications/Cursor.app"),
            cli("cursor-agent", names=["cursor-agent"]),
            cli("opencode", names=["opencode"]),
        ],
    },
    {
        "id": "test-vault", "name": L("WhoRead test vault", "WhoRead 测试保险库"), "kind": "test", "group": "test",
        "severity": "critical",
        "description": L("Fake keys and credentials used by automated tests. Never real secrets.",
                         "自动化测试使用的假私钥和假凭证，绝不放真实凭证。"),
        "paths": ["~/WhoReadTestVault/"],
        "patterns": [
            {"glob": "ssh/*.pub", "severity": "medium"},
            {"glob": "ssh/config", "severity": "medium"},
            {"glob": "ssh/known_hosts*", "severity": "medium"},
            {"glob": "notes/**", "severity": "medium"},
        ],
        "owners": SSH_OWNERS[:2],
    },
    {
        "id": "project-secrets", "name": L("Project secrets", "项目密钥文件"), "kind": "projectRoots", "group": "projects",
        "severity": "high",
        "description": L("Only inside your configured project roots: .env*, *.pem, *.key.",
                         "仅在你配置的 project roots 内匹配 .env*、*.pem、*.key。"),
        "paths": [],
        "patterns": [
            {"glob": "**/node_modules/**", "exclude": True},
            {"glob": "**/.git/**", "exclude": True},
            {"glob": ".env.example", "exclude": True},
            {"glob": ".env.sample", "exclude": True},
            {"glob": ".env.template", "exclude": True},
            {"glob": "*.pem", "severity": "critical"},
            {"glob": "*.key", "severity": "critical"},
            {"glob": ".env*", "severity": "high"},
        ],
        "matchOnlyPatterns": True,
        "owners": [],
    },
    {
        "id": "custom", "name": L("Custom", "用户自定义"), "kind": "custom", "group": "custom", "severity": "high",
        "description": L("Add your own paths.", "在这里添加你自己的路径。"),
        "paths": [], "owners": [],
    },
]

catalog = {"version": 1, "categories": categories}

# ---------------------------------------------------------------- agents
NODE = ["node", "bun", "deno"]
agents = {"version": 1, "agents": [
    {"id": "claude-code", "name": L("Claude Code", "Claude Code"), "kind": "cli", "match": [
        {"executableGlobs": ["**/.local/share/claude/versions/*", "**/Caskroom/claude-code/**"]},
        {"executableNames": NODE, "argvContains": ["@anthropic-ai/claude-code"]},
        {"executableNames": NODE, "argvBasenames": ["claude"]},
        {"argv0Names": ["claude"]},
    ]},
    {"id": "codex", "name": L("Codex CLI", "Codex CLI"), "kind": "cli", "match": [
        {"executableNames": ["codex", "codex-aarch64-apple-darwin", "codex-x86_64-apple-darwin"]},
        {"executableNames": NODE, "argvContains": ["@openai/codex"]},
        {"executableNames": NODE, "argvBasenames": ["codex"]},
    ]},
    {"id": "gemini-cli", "name": L("Gemini CLI", "Gemini CLI"), "kind": "cli", "match": [
        {"executableNames": NODE, "argvContains": ["@google/gemini-cli"]},
        {"executableNames": NODE, "argvBasenames": ["gemini"]},
        {"executableNames": ["gemini"]},
    ]},
    {"id": "opencode", "name": L("opencode", "opencode"), "kind": "cli", "match": [
        {"executableNames": ["opencode"]},
        {"executableNames": NODE, "argvContains": ["opencode-ai"]},
        {"executableNames": NODE, "argvBasenames": ["opencode"]},
    ]},
    {"id": "aider", "name": L("aider", "aider"), "kind": "cli", "match": [
        {"executableGlobs": ["**/python*", "**/Python"], "argvBasenames": ["aider"]},
        {"executableGlobs": ["**/python*", "**/Python"], "argvContains": ["aider.main"]},
        {"executableNames": ["aider"]},
    ]},
    {"id": "cursor", "name": L("Cursor", "Cursor"), "kind": "app", "match": [
        {"bundleNames": ["Cursor.app"]},
        {"executableNames": ["cursor-agent"]},
        {"executableNames": NODE, "argvBasenames": ["cursor-agent"]},
    ]},
    {"id": "claude-desktop", "name": L("Claude (desktop app)", "Claude 桌面版"), "kind": "app", "match": [
        {"bundleNames": ["Claude.app"]},
    ]},
    {"id": "chatgpt-desktop", "name": L("ChatGPT (desktop app)", "ChatGPT 桌面版"), "kind": "app", "match": [
        {"bundleNames": ["ChatGPT.app"]},
    ]},
]}

# App agents first: their bundle-name clauses are the most specific (the Claude desktop app's
# executable is also called "Claude", which the Claude Code argv0 clause would otherwise claim).
agents["agents"].sort(key=lambda a: 0 if a["kind"] == "app" else 1)

# ---------------------------------------------------------------- benign services
def sysbin(*names, roots=("/System/**", "/usr/libexec/**", "/usr/sbin/**", "/Library/Apple/**")):
    return {"executables": [f"{r}/{n}" for r in roots for n in names], "platformBinary": True}

benign = {"version": 1, "services": [
    {"id": "spotlight", "group": "spotlight", "name": L("Spotlight", "聚焦（Spotlight）"),
     "identity": sysbin("mds", "mds_stores", "mdworker", "mdworker_shared", "mdsync", "mdbulkimport", "corespotlightd",
                        "Spotlight", "spotlightknowledged")},
    {"id": "timemachine", "group": "timemachine", "name": L("Time Machine", "时间机器"),
     "identity": sysbin("backupd", "backupd-helper", "TMHelperAgent")},
    {"id": "icloud", "group": "icloud", "name": L("iCloud & File Provider", "iCloud 与 File Provider"),
     "identity": sysbin("bird", "cloudd", "fileproviderd", "FileProvider", "com.apple.CloudDocs.iCloudDriveFileProvider",
                        "CloudDocsFileProvider", "iCloudDriveFileProvider")},
    {"id": "quicklook", "group": "quicklook", "name": L("Quick Look", "快速查看（Quick Look）"),
     "identity": sysbin("com.apple.quicklook.ThumbnailsAgent", "QuickLookUIService", "quicklookd",
                        "ExternalQuickLookSatellite*", "QuickLookSatellite*", "ThumbnailExtension*")},
    {"id": "xprotect", "group": "xprotect", "name": L("XProtect", "XProtect"),
     "identity": {"executables": ["/Library/Apple/System/Library/CoreServices/XProtect.app/**",
                                  "/System/**/XprotectService", "/System/**/XProtectPluginService",
                                  "/usr/libexec/XProtect*", "/System/**/MRT"], "platformBinary": True}},
    {"id": "fsevents", "group": "system", "name": L("File system services", "文件系统服务"),
     "identity": sysbin("fseventsd", "revisiond", "filecoordinationd", "diskarbitrationd", "deleted", "cachedeleted")},
]}

def write(name, obj):
    path = os.path.join(ROOT, "Data", name)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)
        f.write("\n")
    print("wrote", path)

write("catalog.json", catalog)
write("agents.json", agents)
write("benign.json", benign)
