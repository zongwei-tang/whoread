#!/usr/bin/env python3
"""Generates Data/catalog.json, Data/agents.json and Data/benign.json.

The JSON files are the source of truth that ships and that users edit; this script only exists so
the defaults are written consistently. Signing IDs / team IDs are deliberately left out: the daemon
fills them in memory from `codesign -dv` of the apps installed on the user's Mac, at every start
(`whoread catalog resolve-owners` only shows them).
"""
import json, os, sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def L(en, zh): return {"en": en, "zh-Hans": zh}

# Root-owned system locations. A copied Apple binary keeps its platform flag (the flag follows the
# signature, not the path), so platform owners are only trusted here (IdentitySpec enforces the same).
SYSTEM_ROOTS = ("/System/**", "/usr/bin", "/usr/sbin", "/usr/libexec/**", "/bin", "/sbin", "/Library/Apple/**")

def platform(label, *names, under=SYSTEM_ROOTS):
    """Apple platform binaries by name under root-owned system locations."""
    return {"label": label, "executables": [f"{base}/{n}" for base in under for n in names], "platformBinary": True}

def apple_app(label, *names):
    """An Apple app bundle shipped in /System (Safari's cryptex path also starts with /System)."""
    return {"label": label, "bundles": [f"/System/**/{n}.app" for n in names], "platformBinary": True}

def app(label, *bundles):
    """A third-party app. Only trusted once the daemon resolved its team ID with codesign."""
    return {"label": label, "bundles": list(bundles)}

def cli(label, executables=None, argvGlobs=None, names=None, platformBinary=None):
    d = {"label": label}
    if executables: d["executables"] = executables
    if names: d["names"] = names
    if argvGlobs: d["argvGlobs"] = argvGlobs
    if platformBinary is not None: d["platformBinary"] = platformBinary
    return d

PREFIXES = ("/opt/homebrew", "/usr/local")  # Homebrew on Apple silicon / Intel. User-owned: weak.

def cellar(formula, *names, sub="bin"):
    """Executables of one Homebrew formula (the resolved path ES reports, not the bin/ symlink)."""
    return [f"{p}/Cellar/{formula}/*/{sub}/{n}" for p in PREFIXES for n in (names or (formula,))]

def cask(token, *rel):
    """Files inside one Homebrew cask."""
    return [f"{p}/Caskroom/{token}/*/{r}" for p in PREFIXES for r in rel]

def onpath(*names):
    """The paths a shell passes as argv[1] when it runs a script found on PATH (shebang)."""
    return [f"{p}/bin/{n}" for p in PREFIXES for n in names] + \
           [f"/Users/*/.local/bin/{n}" for n in names]

# Interpreters, for owners that are scripts (`python3 /opt/homebrew/bin/aws`). Both the interpreter
# location and the script position must match. Paths below are install locations as documented by
# Homebrew, python.org, nvm & co. — see RESEARCH.md (pending verification on a Mac).
PYTHONS = [
    *[f"{p}/Cellar/python@*/*/Frameworks/Python.framework/Versions/*/bin/python3*" for p in PREFIXES],
    *[f"{p}/Cellar/python@*/*/Frameworks/Python.framework/Versions/*/Resources/Python.app/Contents/MacOS/Python" for p in PREFIXES],
    *[f"{p}/Cellar/python@*/*/bin/python3*" for p in PREFIXES],
    "/Library/Frameworks/Python.framework/Versions/*/bin/python3*",
    "/Library/Frameworks/Python.framework/Versions/*/Resources/Python.app/Contents/MacOS/Python",
    "/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/*/bin/python3*",
    "/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/*/Resources/Python.app/Contents/MacOS/Python",
    "/Applications/Xcode.app/Contents/Developer/Library/Frameworks/Python3.framework/Versions/*/bin/python3*",
    "/Applications/Xcode.app/Contents/Developer/Library/Frameworks/Python3.framework/Versions/*/Resources/Python.app/Contents/MacOS/Python",
    "/Users/*/.pyenv/versions/*/bin/python3*",
    "/Users/*/.local/share/uv/python/*/bin/python3*",
]
NODES = [
    *[f"{p}/Cellar/node*/*/bin/node" for p in PREFIXES],
    "/usr/local/bin/node",  # nodejs.org installer (a real file there, not a symlink)
    "/Users/*/.nvm/versions/node/*/bin/node",
    "/Users/*/.volta/tools/image/node/*/bin/node",
    "/Users/*/.local/share/fnm/node-versions/*/installation/bin/node",
    "/Users/*/Library/Application Support/fnm/node-versions/*/installation/bin/node",
    "/Users/*/.asdf/installs/nodejs/*/bin/node",
    "/Users/*/.local/share/mise/installs/node/*/bin/node",
    *[f"{p}/Cellar/bun/*/bin/bun" for p in PREFIXES],
    "/Users/*/.bun/bin/bun",
]
# Global npm package directories (Homebrew node, nodejs.org, nvm, npm prefix ~/.npm-global).
NODE_MODULES = [*[f"{p}/lib/node_modules" for p in PREFIXES],
                "/Users/*/.nvm/versions/node/*/lib/node_modules", "/Users/*/.npm-global/lib/node_modules",
                "/Users/*/.volta/tools/image/packages/*/lib/node_modules"]
NODE_BINS = [*[f"{p}/bin" for p in PREFIXES], "/Users/*/.nvm/versions/node/*/bin", "/Users/*/.npm-global/bin",
             "/Users/*/.volta/bin", "/Users/*/.bun/bin"]

def npm_package(label, package, entries, *bins):
    """A CLI installed with `npm -g`: node runs the bin symlink (as invoked) or the package entry."""
    entries = [entries] if isinstance(entries, str) else entries
    argv = [f"{m}/{package}/{e}" for m in NODE_MODULES for e in entries] + [f"{b}/{n}" for b in NODE_BINS for n in bins]
    return cli(label, executables=NODES, argvGlobs=argv)

def py_script(label, argv):
    return cli(label, executables=PYTHONS, argvGlobs=argv)

OPENSSH = platform("OpenSSH (Apple)", "ssh", "ssh-agent", "ssh-add", "ssh-keygen", "ssh-keyscan", "scp", "sftp",
                   "sshd", "sshd-session", "ssh-keysign", "ssh-sk-helper", "ssh-pkcs11-helper")
OPENSSH_BREW = cli("OpenSSH (Homebrew)", executables=cellar("openssh", "ssh", "ssh-agent", "ssh-add", "ssh-keygen", "scp", "sftp")
                   + cellar("openssh", "ssh-sk-helper", "ssh-pkcs11-helper", "ssh-keysign", sub="libexec"))
# git itself never reads ~/.ssh (it runs ssh), so it is not an SSH owner.
SSH_OWNERS = [OPENSSH, OPENSSH_BREW]
GIT_OWNERS = [
    platform("git (Apple)", "git", "git-remote-http", "git-remote-https", "git-credential-osxkeychain"),
    # Command Line Tools live under a root-owned path in IdentitySpec's system locations.
    cli("git (Command Line Tools)", executables=["/Library/Developer/CommandLineTools/usr/bin/git",
                                                 "/Library/Developer/CommandLineTools/usr/libexec/git-core/*"],
        platformBinary=True),
    # Xcode is admin-writable: trusted only once the daemon pinned the signing ID from codesign. Only a
    # spec of literal paths can be pinned (OwnerResolver), so git's helpers (a glob) are not owners.
    cli("git (Xcode)", executables=["/Applications/Xcode.app/Contents/Developer/usr/bin/git"], platformBinary=True),
    cli("git (Homebrew)", executables=cellar("git", "git", "git-credential-osxkeychain")
        + [f"{p}/Cellar/git/*/libexec/git-core/*" for p in PREFIXES]),
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
    {"glob": "Account Web Data*", "severity": "critical"},
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
            # The AWS pkg installs a self-contained binary in a root-owned directory.
            cli("AWS CLI v2 (installer)", executables=["/usr/local/aws-cli/aws", "/usr/local/aws-cli/aws_completer"]),
            py_script("AWS CLI (Homebrew / pip / pipx)", onpath("aws")
                      + [f"{p}/Cellar/awscli/*/libexec/bin/aws" for p in PREFIXES]
                      + ["/Users/*/Library/Python/*/bin/aws", "/Users/*/.local/pipx/venvs/awscli/bin/aws"]),
            cli("Terraform / OpenTofu", executables=cellar("terraform") + cellar("opentofu", "tofu") + ["/usr/local/bin/terraform"]),
            cli("aws-vault / granted", executables=cask("aws-vault", "aws-vault") + cellar("aws-vault")
                + cellar("granted", "granted", "assumego")),
        ],
    },
    {
        "id": "gcloud", "name": L("Google Cloud credentials", "Google Cloud 凭证"), "group": "dev-credentials",
        "severity": "critical", "paths": ["~/.config/gcloud/"],
        "owners": [cli("Google Cloud SDK",
                       # Its own bundled Python, or any of the usual ones.
                       executables=PYTHONS + cask("*", "google-cloud-sdk/platform/bundledpythonunix/bin/python3*")
                       + ["/Users/*/google-cloud-sdk/platform/bundledpythonunix/bin/python3*"],
                       argvGlobs=[f"{root}/{script}"
                                  for root in [*[f"{p}/Caskroom/*/*/google-cloud-sdk" for p in PREFIXES],
                                               *[f"{p}/share/google-cloud-sdk" for p in PREFIXES], "/Users/*/google-cloud-sdk"]
                                  for script in ["lib/gcloud.py", "bin/bootstrapping/*.py", "platform/gsutil/gsutil"]])],
    },
    {
        "id": "azure", "name": L("Azure credentials", "Azure 凭证"), "group": "dev-credentials", "severity": "critical",
        "paths": ["~/.azure/"],
        # Homebrew's and pip's `az` both run `python -Im azure.cli`.
        "owners": [py_script("Azure CLI", ["azure.cli"]
                             + [f"{p}/Cellar/azure-cli/*/libexec/lib/python*/site-packages/azure/cli/__main__.py" for p in PREFIXES])],
    },
    {
        "id": "kube", "name": L("Kubernetes config", "Kubernetes 配置"), "group": "dev-credentials", "severity": "critical",
        "paths": ["~/.kube/"],
        "owners": [cli("kubectl & friends", executables=cellar("kubernetes-cli", "kubectl") + cellar("k9s") + cellar("helm")
                       + cellar("kubectx", "kubectx", "kubens") + cellar("kind") + cellar("minikube") + cellar("kustomize")
                       + ["/usr/local/bin/kubectl"]),
                   app("Docker Desktop", "/Applications/Docker.app"),
                   app("OrbStack", "/Applications/OrbStack.app"),
                   app("Lens", "/Applications/Lens.app")],
    },
    {
        "id": "docker", "name": L("Docker credentials", "Docker 凭证"), "group": "dev-credentials", "severity": "critical",
        "paths": ["~/.docker/config.json"],
        "owners": [cli("docker CLI (Homebrew)", executables=cellar("docker") + cellar("docker-compose")
                       + cellar("docker-credential-helper", "docker-credential-osxkeychain") + cellar("colima")
                       + cellar("lima", "limactl")),
                   app("Docker Desktop", "/Applications/Docker.app"),
                   app("OrbStack", "/Applications/OrbStack.app")],
    },
    {
        "id": "npm", "name": L("npm token", "npm 令牌"), "group": "dev-credentials", "severity": "critical",
        "paths": ["~/.npmrc"],
        "owners": [npm_package("npm / npx", "npm", ["bin/npm-cli.js", "bin/npx-cli.js"], "npm", "npx"),
                   cli("npm (bundled with Homebrew node)", executables=NODES,
                       argvGlobs=[f"{p}/Cellar/node*/*/lib/node_modules/npm/bin/{n}-cli.js" for p in PREFIXES for n in ("npm", "npx")]),
                   npm_package("yarn", "yarn", "bin/yarn.js", "yarn"),
                   cli("yarn (Homebrew)", executables=NODES, argvGlobs=[f"{p}/Cellar/yarn/*/libexec/bin/yarn.js" for p in PREFIXES]),
                   npm_package("pnpm", "pnpm", "bin/pnpm.cjs", "pnpm"),
                   cli("pnpm (Homebrew / standalone)", executables=cellar("pnpm") + ["/Users/*/Library/pnpm/pnpm"]),
                   cli("bun", executables=cellar("bun") + ["/Users/*/.bun/bin/bun"])],
    },
    {
        "id": "pypi", "name": L("PyPI token", "PyPI 令牌"), "group": "dev-credentials", "severity": "critical",
        "paths": ["~/.pypirc"],
        "owners": [py_script("twine / poetry / hatch / flit", onpath("twine", "poetry", "hatch", "flit")
                             + [f"{p}/Cellar/{f}/*/libexec/bin/{f}" for p in PREFIXES for f in ("poetry", "hatch", "twine")]
                             + [f"/Users/*/Library/Python/*/bin/{f}" for f in ("twine", "poetry", "hatch", "flit")]),
                   cli("uv", executables=cellar("uv") + ["/Users/*/.local/bin/uv", "/Users/*/.cargo/bin/uv"])],
    },
    {
        "id": "netrc", "name": L(".netrc", ".netrc 凭证"), "group": "dev-credentials", "severity": "critical",
        "paths": ["~/.netrc"],
        # curl is not an owner: `curl -T ~/.netrc https://…` uploads it. Its first read is learned instead.
        "owners": [platform("git HTTP transport (Apple)", "git-remote-http", "git-remote-https"),
                   cli("git HTTP transport (Command Line Tools)", platformBinary=True, executables=[
                       "/Library/Developer/CommandLineTools/usr/libexec/git-core/git-remote-http*"]),
                   # Literal paths: only those can get pinned signing IDs (OwnerResolver), and an unpinned
                   # platform spec outside the system locations never matches.
                   cli("git HTTP transport (Xcode)", platformBinary=True, executables=[
                       "/Applications/Xcode.app/Contents/Developer/usr/libexec/git-core/git-remote-http",
                       "/Applications/Xcode.app/Contents/Developer/usr/libexec/git-core/git-remote-https"]),
                   cli("git HTTP transport (Homebrew)", executables=[
                       f"{p}/Cellar/git/*/libexec/git-core/git-remote-http*" for p in PREFIXES])],
    },
    {
        "id": "git-credentials", "name": L("Git credential store", "Git 凭证存储"), "group": "dev-credentials",
        "severity": "critical", "paths": ["~/.git-credentials", "~/.config/git/credentials"],
        "owners": GIT_OWNERS,
    },
    {
        "id": "gh", "name": L("GitHub CLI token", "GitHub CLI 令牌"), "group": "dev-credentials", "severity": "critical",
        "paths": ["~/.config/gh/"],
        "patterns": [{"glob": "config.yml", "severity": "medium"}],
        "owners": [cli("GitHub CLI", executables=cellar("gh") + ["/usr/local/bin/gh"])],
    },
    {
        "id": "gnupg", "name": L("GnuPG keyring", "GnuPG 密钥环"), "group": "dev-credentials", "severity": "critical",
        "paths": ["~/.gnupg/"],
        "patterns": [{"glob": "S.*", "exclude": True}, {"glob": "*.conf", "severity": "medium"}],
        "owners": [cli("GnuPG (Homebrew)", executables=cellar("gnupg", "gpg", "gpg2", "gpg-agent", "gpgsm", "gpgconf", "dirmngr",
                                                         "gpg-connect-agent")
                       + cellar("gnupg", "scdaemon", "keyboxd", "gpg-check-pattern", "gpg-preset-passphrase", sub="libexec")
                       + cellar("pinentry", "pinentry", "pinentry-curses", "pinentry-tty")
                       + [f"{p}/Cellar/pinentry-mac/*/pinentry-mac.app/Contents/MacOS/pinentry-mac" for p in PREFIXES]),
                   # GPG Suite installs into a root-owned directory.
                   cli("GPG Suite (MacGPG2)", executables=["/usr/local/MacGPG2/bin/*", "/usr/local/MacGPG2/libexec/*",
                                                          "/usr/local/MacGPG2/libexec/pinentry-mac.app/Contents/MacOS/pinentry-mac"])],
    },
    {
        "id": "keychain", "name": L("Keychains", "钥匙串"), "group": "keychain", "severity": "critical",
        "paths": ["~/Library/Keychains/"],
        "owners": [platform("Security daemons", "securityd", "secd", "trustd", "security", "SecurityAgent", "authd",
                            "ctkd", "keychainsharingmessagingd", "accountsd", "cloudd", "akd", "keychain-circle-notification"),
                   apple_app("Keychain Access", "Keychain Access")],
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
        "owners": [apple_app("Safari", "Safari"),
                   app("Safari Technology Preview", "/Applications/Safari Technology Preview.app"),
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
         [apple_app("Messages", "Messages"),
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
        "owners": [apple_app("Mail", "Mail"),
                   platform("Mail services", "maild", "MailCacheDelete", "com.apple.MailServiceAgent", "mailq")],
    },
    {
        "id": "contacts", "name": L("Contacts", "通讯录"), "group": "personal", "severity": "high",
        "paths": ["~/Library/Application Support/AddressBook/"],
        "owners": [apple_app("Contacts", "Contacts"),
                   platform("Contacts services", "contactsd", "AddressBookSourceSync", "AddressBookManager", "ContactsAgent",
                            "com.apple.AddressBook.ContactsAccountsService", "AddressBookSync")],
    },
    {
        "id": "calendar", "name": L("Calendar", "日历"), "group": "personal", "severity": "high",
        "paths": ["~/Library/Calendars/", "~/Library/Group Containers/group.com.apple.calendar/"],
        "owners": [apple_app("Calendar", "Calendar"),
                   platform("Calendar services", "CalendarAgent", "calaccessd", "remindd", "CalendarWidgetExtension")],
    },
    {
        "id": "photos", "name": L("Photos library", "照片图库"), "group": "personal", "severity": "high",
        "paths": ["~/Pictures/Photos Library.photoslibrary/"],
        "owners": [apple_app("Photos", "Photos"),
                   platform("Photos services", "photolibraryd", "photoanalysisd", "mediaanalysisd", "cloudphotod",
                            "com.apple.photos.ImageConversionService", "PhotosReliveWidget", "assetsd")],
    },
    {
        "id": "shell-history", "name": L("Shell & REPL history", "Shell 与 REPL 历史"), "group": "history", "severity": "high",
        "description": L("iTerm2 session logs are written to the folder chosen in Profiles → Session → Automatically log; "
                         "add that folder as a custom path. Shells are not owners: an agent's `zsh -c 'fc -l'` must stay visible.",
                         "iTerm2 会话日志写在 Profiles → Session → Automatically log 里选择的文件夹，请把它加为自定义路径。"
                         "Shell 不算 owner：agent 用 `zsh -c 'fc -l'` 读取历史时必须能被看到。"),
        "paths": ["~/.zsh_history", "~/.zsh_sessions/", "~/.bash_history", "~/.bash_sessions/",
                  "~/.local/share/fish/fish_history", "~/.python_history", "~/.node_repl_history",
                  "~/.psql_history", "~/.mysql_history", "~/.sqlite_history", "~/.irb_history", "~/.lesshst",
                  "~/Library/Application Support/iTerm2/SavedState/"],
        "owners": [apple_app("Terminal", "Terminal"),
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
                   apple_app("Finder", "Finder")],
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
    # One category per agent: an agent reading another agent's transcripts is exactly what to surface.
    *[{
        "id": id_, "name": L(en, zh), "group": "ai", "severity": "high",
        "description": L("Plain-text copies of everything the agent has seen.", "存着 agent 看过的所有内容的明文副本。"),
        "paths": paths, "owners": owners,
    } for id_, en, zh, paths, owners in [
        ("claude-sessions", "Claude Code transcripts", "Claude Code 会话记录", ["~/.claude/projects/"], [
            cli("Claude Code (native)", executables=["/Users/*/.local/share/claude/versions/*"]
                + cask("claude-code", "claude")),
            npm_package("Claude Code (npm)", "@anthropic-ai/claude-code", "cli.js", "claude"),
            cli("Claude Code (local install)", executables=NODES,
                argvGlobs=["/Users/*/.claude/local/node_modules/@anthropic-ai/claude-code/cli.js",
                           "/Users/*/.claude/local/node_modules/.bin/claude"]),
        ]),
        ("codex-sessions", "Codex CLI transcripts", "Codex CLI 会话记录", ["~/.codex/sessions/"], [
            # The npm package runs a bundled native binary from its vendor directory.
            cli("Codex CLI (native)", executables=[f"{m}/@openai/codex/vendor/*/codex/codex" for m in NODE_MODULES]
                + cask("codex", "codex*") + cellar("codex")),
            npm_package("Codex CLI (npm)", "@openai/codex", "bin/codex.js", "codex"),
        ]),
        ("gemini-sessions", "Gemini CLI transcripts", "Gemini CLI 会话记录", ["~/.gemini/tmp/"], [
            npm_package("Gemini CLI (npm)", "@google/gemini-cli", "dist/index.js", "gemini"),
            cli("Gemini CLI (Homebrew)", executables=NODES,
                argvGlobs=[f"{p}/Cellar/gemini-cli/*/libexec/lib/node_modules/@google/gemini-cli/dist/index.js" for p in PREFIXES]
                + [f"{p}/Cellar/gemini-cli/*/bin/gemini" for p in PREFIXES]),
        ]),
        ("cursor-data", "Cursor workspace data", "Cursor 工作区数据",
         ["~/Library/Application Support/Cursor/User/workspaceStorage/", "~/Library/Application Support/Cursor/User/globalStorage/",
          "~/.cursor/"], [
            app("Cursor", "/Applications/Cursor.app"),
            cli("cursor-agent", executables=["/Users/*/.local/share/cursor-agent/versions/*/*"]),
        ]),
        ("opencode-data", "opencode data", "opencode 数据", ["~/.local/share/opencode/"], [
            cli("opencode (native)", executables=cellar("opencode") + ["/Users/*/.opencode/bin/opencode"]
                + [f"{m}/opencode-ai/node_modules/opencode-darwin-*/bin/opencode" for m in NODE_MODULES]
                + [f"{m}/opencode-darwin-*/bin/opencode" for m in NODE_MODULES]),
            npm_package("opencode (npm)", "opencode-ai", "bin/opencode", "opencode"),
        ]),
    ]],
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
        "owners": SSH_OWNERS,
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
