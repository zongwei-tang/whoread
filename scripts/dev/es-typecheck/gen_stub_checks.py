#!/usr/bin/env python3
"""Generates a Swift program that checks the EndpointSecurity stub against the real macOS SDK.

The stub (Sources/EndpointSecurity/Stub.swift) only compiles on Linux. This reads its declarations
and writes Swift that checks each one against the SDK's declaration, to be compiled and run on a
Mac against the real SDK (check-stub.sh does both). Types must be IDENTICAL, not just convertible:
the SDK's declaration is bound to a `var` with no contextual type and passed `inout` together with
the stub's type (`_exact`), so no implicit conversion (Optional promotion, mutable to immutable
pointer, implicit unwrap of a `T!` field) can make a different stub type pass. A stub that is
looser or stricter than the SDK would let the Linux type-check accept code the Mac rejects, or
the reverse.
- every stored field: `\\Root.path.to.field` is a `WritableKeyPath<Root, StubType>` (fields of the
  anonymous unions and structs are reached from the top-level type, whose nested type names are
  not compared; a `T!` field is `T?` here, as Swift imports it);
- every function: the SDK function's type is the stub's parameter and result types;
- every typealias: names the stub's type;
- every enum-like struct: the initializers and protocols the stub declares;
- every global constant: has the stub's type; an ALL_CAPS one also has the stub's value, checked
  when the program runs.
A declaration under `@available(macOS X, *)` is checked inside a function with the same
availability, so a missing annotation in the stub fails too. The program is built for macOS 14
(the deployment target): anything the SDK makes newer than that needs the annotation.

The parser knows exactly the forms the stub uses and stops with an error on anything else, so a new
kind of declaration cannot go unchecked silently.

Usage: gen_stub_checks.py STUB_SWIFT > main.swift
"""
import re
import sys


class ParseError(Exception):
    pass


def strip_comments(text):
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


def balanced(text, i, open_ch, close_ch):
    """Index just past the bracket that closes the one at text[i]."""
    assert text[i] == open_ch
    depth = 0
    for j in range(i, len(text)):
        if text[j] == open_ch:
            depth += 1
        elif text[j] == close_ch:
            depth -= 1
            if depth == 0:
                return j + 1
    raise ParseError("unbalanced %s at offset %d" % (open_ch, i))


def read_type(text, i, stops):
    """A type expression starting at i, up to the first stop character outside (), <> and []."""
    depth = 0
    j = i
    while j < len(text):
        c = text[j]
        if c in "(<[":
            depth += 1
        elif c in ")>]":
            if c == ">" and j > 0 and text[j - 1] == "-":  # the arrow of a function type
                j += 1
                continue
            depth -= 1
        elif depth == 0 and c in stops:
            break
        j += 1
    return " ".join(text[i:j].split()), j


def split_top(s, sep=","):
    parts, depth, cur = [], 0, ""
    for k, c in enumerate(s):
        if c in "(<[":
            depth += 1
        elif c in ")>]" and not (c == ">" and k > 0 and s[k - 1] == "-"):
            depth -= 1
        if c == sep and depth == 0:
            parts.append(cur)
            cur = ""
        else:
            cur += c
    if cur.strip():
        parts.append(cur)
    return [p.strip() for p in parts]


def optional_type(t):
    """An implicitly unwrapped type as a plain type: `T!` is `T?` outside declarations."""
    return t[:-1] + "?" if t.endswith("!") else t


class Struct:
    def __init__(self, name, parent, conformances, avail):
        self.name = name
        self.parent = parent
        self.conformances = conformances
        self.avail = avail
        self.fields = []  # (name, type, avail)
        self.inits = []  # parameter lists as written
        self.children = {}


def parse(text):
    text = strip_comments(text)
    structs, consts, aliases, funcs = [], [], [], []
    stack = []
    pending = None
    i, n = 0, len(text)
    while i < n:
        if text[i].isspace() or text[i] == ";":
            i += 1
            continue
        rest = text[i:]
        if rest.startswith("#") or rest.startswith("import "):
            i = text.find("\n", i)
            i = n if i < 0 else i
            continue
        if rest.startswith("@available"):
            end = balanced(text, i + len("@available"), "(", ")")
            pending = text[i:end]
            i = end
            continue
        if text[i] == "}":
            if not stack:
                raise ParseError("unmatched } at offset %d" % i)
            stack.pop()
            i += 1
            continue
        m = re.match(r"public\s+struct\s+(\w+)\s*(?::\s*([^{]*))?\{", rest)
        if m:
            conf = [c.strip() for c in (m.group(2) or "").split(",") if c.strip()]
            s = Struct(m.group(1), stack[-1] if stack else None, conf, pending)
            if stack:
                stack[-1].children[s.name] = s
            else:
                structs.append(s)
            stack.append(s)
            pending = None
            i += m.end()
            continue
        m = re.match(r"public\s+typealias\s+(\w+)\s*=\s*", rest)
        if m:
            t, j = read_type(text, i + m.end(), "\n;}")
            if stack:
                raise ParseError("typealias %s inside a struct" % m.group(1))
            aliases.append((m.group(1), t, pending))
            pending = None
            i = j
            continue
        m = re.match(r"public\s+var\s+(\w+)\s*:\s*", rest)
        if m:
            name = m.group(1)
            t, j = read_type(text, i + m.end(), "\n;{}=")
            if j < n and text[j] == "=":  # default value of a stored field
                _, j = read_type(text, j + 1, "\n;}")
            if j < n and text[j] == "{":  # computed: a global constant
                end = balanced(text, j, "{", "}")
                body = " ".join(text[j + 1:end - 1].split())
                if stack:
                    raise ParseError("computed property %s inside a struct" % name)
                consts.append((name, t, body, pending))
                j = end
            elif stack:
                stack[-1].fields.append((name, t, pending))
            else:
                raise ParseError("global stored var %s" % name)
            pending = None
            i = j
            continue
        m = re.match(r"public\s+init\s*\(", rest)
        if m:
            p_open = i + m.end() - 1
            p_end = balanced(text, p_open, "(", ")")
            if not stack:
                raise ParseError("init outside a struct")
            stack[-1].inits.append(" ".join(text[p_open + 1:p_end - 1].split()))
            j = text.index("{", p_end)
            i = balanced(text, j, "{", "}")
            pending = None
            continue
        m = re.match(r"public\s+func\s+(\w+)\s*\(", rest)
        if m:
            p_open = i + m.end() - 1
            p_end = balanced(text, p_open, "(", ")")
            params = split_top(text[p_open + 1:p_end - 1])
            ret, j = "Void", p_end
            r = re.match(r"\s*->\s*", text[j:])
            if r:
                ret, j = read_type(text, j + r.end(), "{")
            j = text.index("{", j)
            if stack:
                raise ParseError("func %s inside a struct" % m.group(1))
            funcs.append((m.group(1), params, ret, pending))
            i = balanced(text, j, "{", "}")
            pending = None
            continue
        line = text.count("\n", 0, i) + 1
        raise ParseError("unrecognized declaration near line %d of the comment-stripped stub: %r" % (line, rest[:60]))
    if stack:
        raise ParseError("unclosed struct %s" % stack[-1].name)
    return structs, consts, aliases, funcs


def param_type(p):
    """`_ name: Type` -> Type (the stub labels every parameter `_`, as C imports do)."""
    m = re.match(r"_\s+\w+\s*:\s*(.*)$", p, flags=re.S)
    if not m:
        raise ParseError("parameter without an `_` label: %r" % p)
    return optional_type(m.group(1).strip())


def avail_key(a):
    return a or ""


def generate(structs, consts, aliases, funcs):
    groups = {}  # availability -> lines

    def add(avail, line):
        groups.setdefault(avail_key(avail), []).append(line)

    def exact(avail, expr, stub_type):
        # `var` infers the SDK declaration's own type; `inout` then admits no conversion to the stub's.
        add(avail, "do { var x = %s; _exact(&x, (%s).self) }" % (expr, stub_type))

    def walk(root, s, path, avail):
        for fname, ftype, favail in s.fields:
            a = favail or avail
            if ftype in s.children:  # anonymous union / struct: compare its members, not its name
                walk(root, s.children[ftype], path + [fname], a)
            else:
                exact(a, "\\%s.%s" % (root, ".".join(path + [fname])),
                      "WritableKeyPath<%s, %s>" % (root, optional_type(ftype)))

    for s in structs:
        if "RawRepresentable" in s.conformances:
            for proto in s.conformances:
                add(s.avail, "_is%s(%s.self)" % (proto, s.name))
            for params in s.inits:
                ps = split_top(params)
                labels = "".join("%s:" % p.split(":", 1)[0].split()[0] for p in ps)
                types = ", ".join(optional_type(p.split(":", 1)[1].strip()) for p in ps)
                exact(s.avail, "%s.init(%s)" % (s.name, labels), "(%s) -> %s" % (types, s.name))
        elif any(p == "" for p in s.inits):
            add(s.avail, "_ = %s()" % s.name)
        walk(s.name, s, [], s.avail)
    for name, t, avail in aliases:
        add(avail, "do { var x: Optional<%s> = nil; _exact(&x, Optional<%s>.self) }" % (name, optional_type(t)))
    values = []
    for name, t, body, avail in consts:
        exact(avail, name, optional_type(t))
        if re.fullmatch(r"[A-Z][A-Z0-9_]*", name):
            m = re.fullmatch(r"\.init\((?:rawValue:\s*)?(-?\d+)\)|(-?\d+)", body)
            if not m:
                raise ParseError("constant %s: cannot read a value from { %s }" % (name, body))
            v = m.group(1) or m.group(2)
            expr = "%s.rawValue" % name if m.group(1) else name
            values.append((avail, "_expect(\"%s\", Int64(%s), %s)" % (name, expr, v)))
    for name, params, ret, avail in funcs:
        types = [param_type(p) for p in params]
        exact(avail, name, "(%s) -> %s" % (", ".join(types), optional_type(ret)))

    out = []
    out.append("// Generated by scripts/dev/es-typecheck/gen_stub_checks.py from Stub.swift. Do not edit.")
    out.append("import Darwin")
    out.append("import EndpointSecurity")
    out.append("")
    out.append("func _exact<T>(_: inout T, _: T.Type) {}")
    out.append("func _isEquatable<T: Equatable>(_: T.Type) {}")
    out.append("func _isHashable<T: Hashable>(_: T.Type) {}")
    out.append("func _isSendable<T: Sendable>(_: T.Type) {}")
    out.append("func _isRawRepresentable<T: RawRepresentable>(_: T.Type) where T.RawValue == UInt32 {}")
    out.append("var _failures = 0")
    out.append("func _expect(_ name: String, _ actual: Int64, _ stub: Int64) {")
    out.append("    if actual != stub {")
    out.append("        print(\"MISMATCH \\(name): SDK \\(actual), stub \\(stub)\")")
    out.append("        _failures += 1")
    out.append("    }")
    out.append("}")
    out.append("")
    calls = []
    for k, (avail, lines) in enumerate(sorted(groups.items())):
        fn = "_checks%d" % k
        if avail:
            out.append(avail)
        out.append("func %s() {" % fn)
        out.extend("    " + l for l in lines)
        out.append("}")
        calls.append((avail, fn))
    vgroups = {}
    for avail, line in values:
        vgroups.setdefault(avail_key(avail), []).append(line)
    for k, (avail, lines) in enumerate(sorted(vgroups.items())):
        fn = "_values%d" % k
        if avail:
            out.append(avail)
        out.append("func %s() {" % fn)
        out.extend("    " + l for l in lines)
        out.append("}")
        calls.append((avail, fn))
    out.append("")
    out.append("// Type checks only need to compile; the value checks run.")
    out.append("if CommandLine.arguments.count > 99 {")
    for avail, fn in calls:
        if fn.startswith("_checks"):
            out.append("    " + call(avail, fn))
    out.append("}")
    for avail, fn in calls:
        if fn.startswith("_values"):
            out.append(call(avail, fn, unavailable="print(\"SKIPPED %s: needs a newer OS to run\"); _failures += 1" % fn))
    n_checks = sum(len(v) for v in groups.values())
    out.append("print(\"stub check: %d declarations type-checked, %d raw values compared, \\(_failures) mismatches\")"
               % (n_checks, len(values)))
    out.append("exit(_failures == 0 ? 0 : 1)")
    return "\n".join(out) + "\n"


def call(avail, fn, unavailable=None):
    if not avail:
        return "%s()" % fn
    m = re.match(r"@available\((.*)\)$", avail)
    cond = m.group(1)
    if unavailable:
        return "if #available(%s) { %s() } else { %s }" % (cond, fn, unavailable)
    return "if #available(%s) { %s() }" % (cond, fn)


def main():
    if len(sys.argv) != 2:
        sys.stderr.write("usage: gen_stub_checks.py STUB_SWIFT\n")
        return 2
    with open(sys.argv[1], encoding="utf-8") as f:
        text = f.read()
    try:
        sys.stdout.write(generate(*parse(text)))
    except ParseError as e:
        sys.stderr.write("gen_stub_checks.py: %s\n" % e)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
