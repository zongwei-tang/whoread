#!/usr/bin/env python3
"""Generates synthetic eslogger fixtures for parser and replay tests.

These are NOT captures. Their shape copies real eslogger output found in public sources
(see Tests/Fixtures/eslogger/README.md): message version 7 (2023, macOS 13.3+) and message
version 10 (macOS 26, single-line output with "\\/" escaping and unordered keys). A third file
fakes a future schema_version 2 to exercise tolerance. Real captures from the user's Mac go to
Tests/Fixtures/eslogger/captured/ after `whoread fixture sanitize`.

The scenario mirrors the M2 acceptance test against ~/WhoReadTestVault.
"""
import json, os, random

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
OUT = os.path.join(ROOT, "Tests", "Fixtures", "eslogger")
HOME = "/Users/alice"
VAULT = HOME + "/WhoReadTestVault"

BASE_T = 1760000000  # 2025-10-09T08:53:20Z

def ts(sec, digits=9):
    import datetime
    whole = int(sec)
    frac = sec - whole
    d = datetime.datetime.fromtimestamp(whole, datetime.timezone.utc)
    return d.strftime("%Y-%m-%dT%H:%M:%S") + ("." + str(int(round(frac * 10**digits))).zfill(digits) if digits else "") + "Z"

def stat(ino):
    return {"st_dev": 16777230, "st_mode": 33188, "st_nlink": 1, "st_ino": ino, "st_uid": 501, "st_gid": 20,
            "st_rdev": 0, "st_atimespec": ts(BASE_T - 100), "st_mtimespec": ts(BASE_T - 100),
            "st_ctimespec": ts(BASE_T - 100), "st_birthtimespec": ts(BASE_T - 1000), "st_size": 411,
            "st_blocks": 8, "st_blksize": 4096, "st_flags": 0, "st_gen": 0}

INO = [1152921500312082960]
def f(path):
    INO[0] += 1
    return {"path": path, "path_truncated": False, "stat": stat(INO[0])}

def token(pid, pv, uid=501):
    return {"asid": 100017, "pidversion": pv, "ruid": uid, "euid": uid, "rgid": 20, "auid": uid, "egid": 20, "pid": pid}

class P:
    def __init__(self, pid, pv, ppid, path, start, signing_id, team_id=None, platform=False, original_ppid=None, uid=501):
        self.pid, self.pv, self.ppid, self.path, self.start = pid, pv, ppid, path, start
        self.signing_id, self.team_id, self.platform = signing_id, team_id, platform
        self.original_ppid = original_ppid if original_ppid is not None else ppid
        self.uid = uid

    def json(self, msgv):
        d = {
            "audit_token": token(self.pid, self.pv, self.uid),
            "ppid": self.ppid,
            "original_ppid": self.original_ppid,
            "group_id": self.pid,
            "session_id": 400,
            "codesigning_flags": 570522385 if self.platform else 570506001,
            "is_platform_binary": self.platform,
            "is_es_client": False,
            "cdhash": "".join(random.choice("0123456789ABCDEF") for _ in range(40)),
            "signing_id": self.signing_id,
            "team_id": self.team_id,
            "executable": f(self.path),
            "tty": None,
            "start_time": ts(self.start, 6),
            "responsible_audit_token": token(self.pid, self.pv, self.uid),
            "parent_audit_token": token(self.ppid, 1, self.uid),
        }
        if msgv >= 10:
            d["cs_validation_category"] = 1 if self.platform else 3
        return d

    def exec_image(self, path, signing_id, team_id=None, platform=False):
        return P(self.pid, self.pv + 1, self.ppid, path, self.start, signing_id, team_id, platform, self.original_ppid, self.uid)

    def forked(self, pid, start):
        return P(pid, self.pv + 1000 + pid, self.pid, self.path, start, self.signing_id, self.team_id, self.platform, self.pid, self.uid)

EVENT_TYPES = {"exec": 9, "open": 10, "fork": 11, "close": 12, "create": 13, "exchangedata": 14, "exit": 15,
               "link": 19, "rename": 25, "unlink": 32, "truncate": 41, "clone": 61, "readdir": 68, "copyfile": 110}

class Gen:
    def __init__(self, msgv, schema=1):
        self.msgv, self.schema, self.seq, self.lines = msgv, schema, 1000, []

    def emit(self, t, proc, kind, body):
        self.seq += 1
        action = {"result": {"result": {"flags": 4294967295}, "result_type": 1}} if kind == "open" else \
                 {"result": {"result": {"auth": 0}, "result_type": 0}}
        msg = {
            "schema_version": self.schema,
            "mach_time": 99000000000 + self.seq * 1000,
            "event_type": EVENT_TYPES[kind],
            "thread": {"thread_id": 77000 + self.seq},
            "version": self.msgv,
            "seq_num": self.seq,
            "global_seq_num": self.seq,
            "process": proc.json(self.msgv),
            "action_type": 1,
            "action": action,
            "event": {kind: body},
            "time": ts(BASE_T + t),
        }
        self.lines.append(msg)

    def exec(self, t, old, new, args):
        body = {"target": new.json(self.msgv), "args": args, "env": ["PATH=/usr/bin:/bin", "SECRET_TOKEN=do-not-store"],
                "script": None, "cwd": f(HOME), "last_fd": 2, "fds": [{"fd": 0, "fdtype": 1}],
                "image_cputype": 16777228, "image_cpusubtype": 2}
        if self.msgv >= 7:
            body["dyld_exec_path"] = new.path
        self.emit(t, old, "exec", body)
        return new

    def fork(self, t, parent, child):
        self.emit(t, parent, "fork", {"child": child.json(self.msgv)})
        return child

    def spawn(self, t, parent, pid, path, signing_id, args, team_id=None, platform=False):
        child = self.fork(t, parent, parent.forked(pid, BASE_T + t))
        return self.exec(t + 0.001, child, child.exec_image(path, signing_id, team_id, platform), args)

    def open(self, t, p, path, fflag=1):
        self.emit(t, p, "open", {"fflag": fflag, "file": f(path)})

    def close(self, t, p, path, modified):
        body = {"modified": modified, "target": f(path)}
        if self.msgv >= 6:
            body["was_mapped_writable"] = False
        self.emit(t, p, "close", body)

    def exit(self, t, p, stat=0):
        self.emit(t, p, "exit", {"stat": stat})

    def render(self, style):
        out = []
        for m in self.lines:
            if style == "v10":
                # macOS 26 style: hash-ordered keys, "\/" escaped slashes.
                keys = list(m.keys())
                rnd = random.Random(m["seq_num"])
                rnd.shuffle(keys)
                keys.remove("schema_version")
                m = {"schema_version": m["schema_version"], **{k: m[k] for k in keys}}
                s = json.dumps(m, separators=(",", ":"), ensure_ascii=False).replace("/", "\\/")
            else:
                s = json.dumps(m, separators=(",", ":"), ensure_ascii=False)
            out.append(s)
        return "\n".join(out) + "\n"

def scenario(g):
    random.seed(42)
    launchd = P(1, 1, 0, "/sbin/launchd", BASE_T - 86400, "com.apple.xpc.launchd", platform=True, uid=0)
    terminal = P(400, 900, 1, "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal", BASE_T - 3600,
                 "com.apple.Terminal", platform=True)
    zsh = g.spawn(0.0, terminal, 500, "/bin/zsh", "com.apple.zsh", ["-zsh"], platform=True)

    # 1. cat reads the fake private key.
    cat = g.spawn(1.0, zsh, 501, "/bin/cat", "com.apple.cat", ["cat", VAULT + "/ssh/id_ed25519"], platform=True)
    g.open(1.01, cat, "/usr/lib/libSystem.B.dylib")           # not sensitive, filtered
    g.open(1.02, cat, VAULT + "/ssh/id_ed25519")
    g.close(1.03, cat, VAULT + "/ssh/id_ed25519", False)      # unmodified close, dropped
    g.exit(1.04, cat)

    # 2. python3 reads fake AWS credentials.
    py = g.spawn(2.0, zsh, 502, "/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/3.9/Resources/Python.app/Contents/MacOS/Python",
                 "com.apple.python3", ["/usr/bin/python3", "-c", "open('" + VAULT + "/aws/credentials').read()"], platform=True)
    g.open(2.01, py, VAULT + "/aws/credentials")
    g.exit(2.02, py)

    # 3. node reads the key (homebrew node: not a platform binary, ad-hoc signed).
    node = g.spawn(3.0, zsh, 503, "/opt/homebrew/Cellar/node/22.9.0/bin/node", "node-55554944a5b5a1c0d4d7e1a0b8d9c3f2",
                   ["node", "-e", "require('fs').readFileSync('" + VAULT + "/ssh/id_ed25519')"])
    g.open(3.01, node, VAULT + "/ssh/id_ed25519")
    g.exit(3.02, node)

    # 4. Claude Code (npm install) → zsh → cat reads credentials.
    claude = g.spawn(4.0, zsh, 600, "/opt/homebrew/Cellar/node/22.9.0/bin/node", "node-55554944a5b5a1c0d4d7e1a0b8d9c3f2",
                     ["node", "/opt/homebrew/bin/claude", "--print", "hi"])
    sh = g.spawn(4.1, claude, 601, "/bin/zsh", "com.apple.zsh", ["/bin/zsh", "-c", "cat ~/WhoReadTestVault/aws/credentials"], platform=True)
    cat2 = g.spawn(4.2, sh, 602, "/bin/cat", "com.apple.cat", ["cat", VAULT + "/aws/credentials"], platform=True)
    g.open(4.21, cat2, VAULT + "/aws/credentials")
    g.exit(4.22, cat2)

    # 5. The shell exits first; a background child is reparented to launchd but keeps original_ppid.
    bg = g.spawn(5.0, sh, 603, "/bin/cat", "com.apple.cat", ["cat", VAULT + "/ssh/id_ed25519"], platform=True)
    g.exit(5.01, sh)
    orphan = P(bg.pid, bg.pv, 1, bg.path, bg.start, bg.signing_id, bg.team_id, bg.platform, original_ppid=601)
    g.open(5.02, orphan, VAULT + "/ssh/id_ed25519")
    g.exit(5.03, orphan)

    # 6. Spotlight indexes a vault note: benign, folded.
    mdw = P(700, 4000, 1, "/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/Metadata.framework/Versions/A/Support/mdworker_shared",
            BASE_T + 5.5, "com.apple.mdworker_shared", platform=True, uid=501)
    g.open(6.0, mdw, VAULT + "/notes/todo.txt")

    # 7. Exfil without open: rename, clone, copyfile, link out of the vault; write ops.
    mv = g.spawn(7.0, zsh, 510, "/bin/mv", "com.apple.mv", ["mv", VAULT + "/ssh/id_rsa", "/private/tmp/x"], platform=True)
    g.emit(7.01, mv, "rename", {"source": f(VAULT + "/ssh/id_rsa"), "destination_type": 1,
                                "destination": {"new_path": {"dir": f("/private/tmp"), "filename": "x"}}})
    cp = g.spawn(7.1, zsh, 511, "/bin/cp", "com.apple.cp", ["cp", "-c", VAULT + "/aws/credentials", "/private/tmp/c"], platform=True)
    g.emit(7.11, cp, "clone", {"source": f(VAULT + "/aws/credentials"), "target_dir": f("/private/tmp"), "target_name": "c"})
    g.emit(7.12, cp, "copyfile", {"source": f(VAULT + "/aws/credentials"), "target_file": None, "target_dir": f("/private/tmp"),
                                  "target_name": "c2", "mode": 420, "flags": 0})
    ln = g.spawn(7.2, zsh, 512, "/bin/ln", "com.apple.ln", ["ln", VAULT + "/ssh/id_ed25519", "/private/tmp/l"], platform=True)
    g.emit(7.21, ln, "link", {"source": f(VAULT + "/ssh/id_ed25519"), "target_dir": f("/private/tmp"), "target_filename": "l"})
    g.emit(7.3, zsh, "truncate", {"target": f(VAULT + "/notes/todo.txt")})
    g.emit(7.4, zsh, "unlink", {"target": f(VAULT + "/notes/old.txt"), "parent_dir": f(VAULT + "/notes")})
    g.close(7.5, zsh, VAULT + "/notes/todo.txt", True)
    # Firmlinked spelling of the same vault file.
    g.open(7.6, zsh, "/System/Volumes/Data" + VAULT + "/ssh/id_ed25519")
    # Rename an existing file over a vault file (destination is sensitive).
    g.emit(7.7, mv, "rename", {"source": f("/private/tmp/new"), "destination_type": 0,
                               "destination": {"existing_file": f(VAULT + "/ssh/config")}})

def write(name, text):
    d = os.path.join(OUT, name)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "scenario.jsonl"), "w", encoding="utf-8") as fh:
        fh.write(text)
    print("wrote", os.path.join(d, "scenario.jsonl"), len(text.splitlines()), "lines")

g7 = Gen(msgv=7); scenario(g7); write("schema-v1-msgv7", g7.render("v7"))
g10 = Gen(msgv=10); scenario(g10); write("schema-v1-msgv10", g10.render("v10"))

# Hypothetical future schema: version bump, dropped optional fields, renamed extras, junk lines.
g2 = Gen(msgv=12, schema=2); scenario(g2)
for m in g2.lines:
    p = m["process"]
    p.pop("original_ppid", None)
    p.pop("start_time", None)
    p["new_field_from_the_future"] = {"x": 1}
    m["deadline"] = 0
text = g2.render("v7")
text = "not json at all\n" + text + "{\"schema_version\":2,\"event\":{\"open\":{}}}\n\n"
write("schema-v2-synthetic", text)
