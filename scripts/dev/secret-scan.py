#!/usr/bin/env python3
"""Scans every blob reachable from any ref (or only the working tree with --worktree) for things
that must not be published: private keys, real-looking tokens, URL credentials, local user paths,
e-mail addresses. Known fake values used by the redaction tests are allowed. Exit 1 on findings.

Usage: scripts/dev/secret-scan.py [--worktree]
"""
import re, subprocess, sys

ALLOWED = {
    # Documented example or obviously fake values used by tests and docs.
    'AKIAIOSFODNN7EXAMPLE', 'ghs_16C7e42F292c6912E7710c838347Ae178B4a',
    'ghp_abcdefghijklmnopqrstuvwxyz0123', 'ghp_abcdefghijklmnopqrstuvwxyz0123456789',
    'ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'sk-abcdefghijklmnopqrstuvwx',
    'glpat-AbCdEf1234567890xyz',
}
ALLOWED_EMAIL = re.compile(r'(example\.(com|org)$|@github\.com$|@gitlab\.com$|noreply|^hunter2\w*@)', re.I)
ALLOWED_HOME = re.compile(r'^/(Users|home)/(a|u\d*|new|alice|alicex|bob|carol|erin|link|gone|nobody\d*|zongwei|you|user|runner|admin|test|me|x)\.?$', re.I)
PATTERNS = {
    'private key': re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----'),
    'aws key': re.compile(r'\b(AKIA|ASIA)[0-9A-Z]{16}\b'),
    'github token': re.compile(r'\b(gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{20,})'),
    'slack token': re.compile(r'\bxox[baprs]-[A-Za-z0-9-]{10,}'),
    'openai/anthropic key': re.compile(r'\bsk-(ant-)?[A-Za-z0-9_-]{20,}'),
    'google key': re.compile(r'\bAIza[0-9A-Za-z_-]{35}\b'),
    'gitlab token': re.compile(r'\bglpat-[A-Za-z0-9_-]{16,}'),
    'url credentials': re.compile(r'https?://[^/\s:@\'"]+:([^/\s@\'"\\(‹]{6,})@'),
    'email': re.compile(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'),
    'local home path': re.compile(r'/(?:Users|home)/[A-Za-z][A-Za-z0-9._-]*'),
}

def blobs(worktree):
    if worktree:
        for f in subprocess.run(['git', 'ls-files', '-co', '--exclude-standard'], capture_output=True, text=True).stdout.splitlines():
            try:
                yield f, open(f, 'rb').read()
            except OSError:
                pass
        return
    seen = set()
    for line in subprocess.run(['git', 'rev-list', '--all', '--objects'], capture_output=True, text=True).stdout.splitlines():
        sha, _, name = line.partition(' ')
        if sha in seen or not name:
            continue
        seen.add(sha)
        if subprocess.run(['git', 'cat-file', '-t', sha], capture_output=True, text=True).stdout.strip() != 'blob':
            continue
        yield name, subprocess.run(['git', 'cat-file', '-p', sha], capture_output=True).stdout

def main():
    worktree = '--worktree' in sys.argv
    findings = []
    for name, data in blobs(worktree):
        if name.endswith('secret-scan.py'):
            continue
        text = data.decode('utf-8', 'replace')
        for kind, rx in PATTERNS.items():
            for m in rx.finditer(text):
                v = m.group(0)
                if v in ALLOWED or any(a in v for a in ALLOWED):
                    continue
                if kind == 'email' and ALLOWED_EMAIL.search(v):
                    continue
                if kind == 'local home path' and ALLOWED_HOME.match(v):
                    continue
                if kind == 'url credentials' and re.search(r'(user:token|user:pw|u:pass1234|alice:hunter2pass|x-access-token:\$\{)', v):
                    continue
                findings.append((name, kind, v[:80]))
    for f in sorted(set(findings)):
        print('%s: %s: %s' % f)
    print('secret-scan: %d finding(s)' % len(set(findings)))
    return 1 if findings else 0

sys.exit(main())
