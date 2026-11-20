"""Find the CSP headers a host would send for a given URL path.

Supported: Netlify / Cloudflare Pages `_headers` files and the `headers` array
in `vercel.json`. Both are matched against every URL a file can be served at.
"""

import json
import re

CSP = "content-security-policy"
CSP_RO = "content-security-policy-report-only"


class HeaderRule:
    def __init__(self, pattern, regex, headers, removes, origin):
        self.pattern = pattern
        self.regex = regex
        self.headers = headers  # list of (lower name, value)
        self.removes = removes  # lower names detached with "! Name"
        self.origin = origin  # "file:line" for the report

    def matches(self, path):
        return bool(self.regex.match(path))


def _netlify_regex(pattern):
    out = []
    for piece in re.split(r"(\*|:[A-Za-z_][A-Za-z0-9_]*)", pattern):
        if piece == "*":
            out.append(".*")
        elif piece.startswith(":") and len(piece) > 1:
            out.append("[^/]+")
        else:
            out.append(re.escape(piece))
    return re.compile("^" + "".join(out) + "$")


def parse_headers_file(text, name="_headers"):
    rules = []
    current = None
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not raw[:1].isspace():
            pattern = line.strip()
            if "://" in pattern:  # absolute-URL rules (Cloudflare) are matched on their path
                pattern = "/" + pattern.split("://", 1)[1].split("/", 1)[-1] if "/" in pattern.split("://", 1)[1] else "/*"
            current = HeaderRule(line.strip(), _netlify_regex(pattern), [], set(), f"{name}:{n}")
            rules.append(current)
            continue
        if current is None:
            raise ValueError(f"{name}:{n}: header line before any path line")
        body = line.strip()
        if body.startswith("!"):
            current.removes.add(body[1:].strip().lower())
            continue
        key, sep, value = body.partition(":")
        if not sep:
            raise ValueError(f"{name}:{n}: expected 'Name: value', got {body!r}")
        current.headers.append((key.strip().lower(), value.strip()))
    return rules


def _vercel_regex(source):
    """The subset of path-to-regexp that vercel.json sources use in practice."""
    out = []
    i = 0
    while i < len(source):
        c = source[i]
        if c == "(":
            depth, j = 1, i + 1
            while j < len(source) and depth:
                depth += {"(": 1, ")": -1}.get(source[j], 0)
                j += 1
            out.append("(?:" + source[i + 1: j - 1] + ")")
            i = j
            continue
        if c == ":":
            m = re.match(r":[A-Za-z_][A-Za-z0-9_]*(\([^)]*\))?([*+?])?", source[i:])
            group, mod = m.group(1), m.group(2)
            seg = "(?:" + group[1:-1] + ")" if group else "[^/]+"
            if mod in ("*", "+"):
                seg = "(?:" + seg + "(?:/" + seg + ")*)" + ("?" if mod == "*" else "")
            elif mod == "?":
                seg = "(?:" + seg + ")?"
            if mod in ("*", "?") and out and out[-1] == "/":
                out[-1] = "(?:/"
                seg = seg + ")?"
            out.append(seg)
            i += len(m.group(0))
            continue
        out.append(re.escape(c) if c != "/" else "/")
        i += 1
    return re.compile("^" + "".join(out) + "/?$")


def parse_vercel(text, name="vercel.json"):
    data = json.loads(text)
    rules, warnings = [], []
    for k, entry in enumerate(data.get("headers", [])):
        src = entry.get("source", "")
        if entry.get("has") or entry.get("missing"):
            warnings.append(f"{name}: headers[{k}] ({src}) has has/missing conditions; treated as always matching")
        headers = [(h["key"].strip().lower(), h["value"]) for h in entry.get("headers", [])]
        rules.append(HeaderRule(src, _vercel_regex(src), headers, set(), f"{name}: headers[{k}] {src}"))
    return rules, warnings


def csp_headers_for(rules, paths):
    """[(header name, value, origin)] the host sends for a file served at `paths`."""
    found = []
    for rule in rules:
        if not any(rule.matches(p) for p in paths):
            continue
        for gone in rule.removes:
            found = [f for f in found if f[0] != gone]
        for key, value in rule.headers:
            if key in (CSP, CSP_RO):
                found.append((key, value, f"{rule.origin} ({rule.pattern})"))
    return found


def served_paths(rel):
    """URL paths a built file is reachable at, e.g. about/index.html -> /about/, /about/index.html."""
    rel = rel.replace("\\", "/")
    paths = ["/" + rel]
    if rel == "index.html" or rel.endswith("/index.html"):
        d = rel[: -len("index.html")]
        paths.insert(0, "/" + d)
        if d:
            paths.append("/" + d.rstrip("/"))
    elif rel.endswith(".html"):
        paths.append("/" + rel[: -len(".html")])
    return paths
