"""Evaluate every policy that applies to every page in a build directory."""

import os
from pathlib import Path
from urllib.parse import urlsplit, unquote

from . import policy as P
from .headers import CSP, CSP_RO, csp_headers_for, served_paths
from .scan import page_items


class Finding:
    __slots__ = ("file", "item", "policy", "directive", "fix", "report_only")

    def __init__(self, file, item, policy, directive, fix, report_only):
        self.file = file
        self.item = item
        self.policy = policy
        self.directive = directive  # the directive that actually decided (after fallback)
        self.fix = fix
        self.report_only = report_only

    def to_dict(self):
        i = self.item
        return {
            "file": self.file,
            "line": i.line,
            "what": i.label,
            "url": i.url,
            "via": i.via,
            "effective_directive": i.directive,
            "decided_by": self.directive,
            "policy_source": self.policy.source,
            "report_only": self.report_only,
            "fix": self.fix,
        }


def _source_expr(url, origin):
    u = urlsplit(url)
    if f"{u.scheme}://{u.netloc}" == origin:
        return "'self'"
    if u.scheme in ("http", "https", "ws", "wss") and u.netloc:
        return f"{u.scheme}://{u.netloc}"
    return f"{u.scheme}:"


def _fix(item, decided_by, source_list, origin):
    """A concrete change that would allow this item (not necessarily the best one)."""
    eff = item.directive
    if item.kind in ("element",):
        add = P.csp_hash(item.text)
    elif item.kind in ("attribute", "navigation"):
        token = P.csp_hash(item.text)
        unsafe = "" if P._has(source_list, "'unsafe-hashes'") else "'unsafe-hashes' "
        add = unsafe + token
    elif item.kind == "script-url" and P._has(source_list, "'strict-dynamic'"):
        return "give it a nonce, or an integrity hash listed in the policy ('strict-dynamic' ignores URLs)"
    else:
        add = _source_expr(item.url, origin)
    kept = [t for t in source_list if t.lower() != "'none'"]
    if decided_by != "default-src":
        # adding to script-src / style-src / child-src also covers the inheriting directive
        if len(kept) < len(source_list):
            return f"replace 'none' in {decided_by} with {add}"
        return f"add {add} to {decided_by}"
    # don't widen default-src for every resource type: give this type its own list
    return f"set {eff} {' '.join(kept + [add])}  (it inherits default-src now)"


def allowed(item, source_list, origin):
    k = item.kind
    is_script = item.directive.startswith("script-src") or item.directive == "worker-src"
    if k == "element":
        if item.label.startswith("inline <script type=speculationrules") and P._has(source_list, "'inline-speculation-rules'"):
            return True
        return P.inline_allowed(source_list, "element", item.text, item.nonce, is_script)
    if k in ("attribute", "navigation"):
        return P.inline_allowed(source_list, k, item.text, None, is_script)
    if k == "script-url":
        return P.external_script_allowed(source_list, item.url, origin, item.nonce, item.integrity)
    if k == "style-url":
        return P.external_style_allowed(source_list, item.url, origin, item.nonce)
    return P.url_allowed(source_list, item.url, origin)


def evaluate(items, policies, origin, file):
    out = []
    for pol in policies:
        for item in items:
            decided_by, source_list = pol.governing(item.directive)
            if decided_by is None:
                continue
            if not allowed(item, source_list, origin):
                out.append(Finding(file, item, pol, decided_by, _fix(item, decided_by, source_list, origin), pol.report_only))
    return out


class Result:
    def __init__(self):
        self.pages = []  # (rel, [policy sources])
        self.findings = []
        self.warnings = []
        self.unprotected = []


def run(root, rules, extra_policies, origin, enforce_report_only=False):
    root = Path(root)
    res = Result()
    html_files = sorted(
        p for p in root.rglob("*") if p.is_file() and p.suffix.lower() in (".html", ".htm")
    )
    if not html_files:
        res.warnings.append(f"no .html files under {root}")

    def read_css(url):
        u = urlsplit(url)
        if u.scheme + "://" + u.netloc != origin.rstrip("/"):
            return None
        f = root / unquote(u.path).lstrip("/")
        try:
            f.resolve().relative_to(root.resolve())
        except ValueError:
            return None
        if f.is_file():
            return f.read_text(encoding="utf-8", errors="replace")
        return None

    for f in html_files:
        rel = f.relative_to(root).as_posix()
        paths = served_paths(rel)
        page_url = origin.rstrip("/") + paths[0]
        html = f.read_text(encoding="utf-8", errors="replace")
        items, metas = page_items(html, page_url, read_css)
        items.sort(key=lambda i: i.line)

        policies = []
        for text in extra_policies:
            for part in P.split_policies(text):
                policies.append(P.Policy(part, "--policy"))
        for name, value, src in csp_headers_for(rules, paths):
            ro = name == CSP_RO
            for part in P.split_policies(value):
                pol = P.Policy(part, ("Report-Only header " if ro else "header ") + src, report_only=ro and not enforce_report_only)
                policies.append(pol)
        for line, equiv, content in metas:
            if equiv == CSP_RO:
                res.warnings.append(f"{rel}:{line}: Content-Security-Policy-Report-Only in <meta> is ignored by browsers")
                continue
            for part in P.split_policies(content):
                policies.append(P.Policy(part, f"<meta> {rel}:{line}", from_meta=True))
        for pol in policies:
            for w in pol.warnings:
                res.warnings.append(f"{rel}: {pol.source}: {w}")
        if not policies:
            res.unprotected.append(rel)
        res.pages.append((rel, policies))
        res.findings.extend(evaluate(items, policies, origin, rel))
    return res
