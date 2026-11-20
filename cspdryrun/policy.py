"""CSP parsing and the CSP Level 3 matching rules this tool needs.

Only what can be decided from static files is modelled: source-list matching for
URLs, inline elements, inline attributes and javascript: URLs, nonces, hashes,
'unsafe-inline', 'unsafe-hashes', 'strict-dynamic' and directive fallback.
"""

import base64
import hashlib
import re
from urllib.parse import urlsplit, unquote

# CSP3 "directive fallback list" for the effective directives we check.
FALLBACK = {
    "script-src-elem": ["script-src-elem", "script-src", "default-src"],
    "script-src-attr": ["script-src-attr", "script-src", "default-src"],
    "style-src-elem": ["style-src-elem", "style-src", "default-src"],
    "style-src-attr": ["style-src-attr", "style-src", "default-src"],
    "img-src": ["img-src", "default-src"],
    "font-src": ["font-src", "default-src"],
    "media-src": ["media-src", "default-src"],
    "object-src": ["object-src", "default-src"],
    "manifest-src": ["manifest-src", "default-src"],
    "connect-src": ["connect-src", "default-src"],
    "frame-src": ["frame-src", "child-src", "default-src"],
    "worker-src": ["worker-src", "child-src", "script-src", "default-src"],
    # These never fall back to default-src.
    "form-action": ["form-action"],
    "base-uri": ["base-uri"],
}

# Directives a <meta http-equiv> policy is not allowed to carry.
META_IGNORED = {"frame-ancestors", "report-uri", "report-to", "sandbox"}

DEFAULT_PORT = {"http": 80, "https": 443, "ws": 80, "wss": 443, "ftp": 21}

_HASH_RE = re.compile(r"^'(sha256|sha384|sha512)-([A-Za-z0-9+/_-]+={0,2})'$", re.I)
_NONCE_RE = re.compile(r"^'nonce-([A-Za-z0-9+/_-]+={0,2})'$", re.I)
_SCHEME_RE = re.compile(r"^([a-z][a-z0-9+.-]*):$", re.I)
_HOST_RE = re.compile(
    r"^(?:(?P<scheme>[a-z][a-z0-9+.-]*)://)?"
    r"(?P<host>\*|(?:\*\.)?[a-z0-9-]+(?:\.[a-z0-9-]+)*|\[[0-9a-f:.]+\])"
    r"(?::(?P<port>\d+|\*))?"
    r"(?P<path>/[^;,\s]*)?$",
    re.I,
)


class Policy:
    """One parsed policy. `source` says where it came from, for the report."""

    def __init__(self, text, source, report_only=False, from_meta=False):
        self.text = text.strip()
        self.source = source
        self.report_only = report_only
        self.directives = {}
        self.warnings = []
        for part in text.split(";"):
            tokens = part.split()
            if not tokens:
                continue
            name = tokens[0].lower()
            if from_meta and name in META_IGNORED:
                self.warnings.append(f"{name} is ignored in a <meta> policy")
                continue
            if name in self.directives:
                self.warnings.append(f"duplicate {name} is ignored (browsers use the first one)")
                continue
            self.directives[name] = tokens[1:]

    def governing(self, effective):
        """(directive name, source list) that decides `effective`, or (None, None)."""
        for name in FALLBACK.get(effective, [effective]):
            if name in self.directives:
                return name, self.directives[name]
        return None, None


def split_policies(header_value):
    """A header value can hold several comma-separated policies; all are enforced."""
    return [p for p in header_value.split(",") if p.strip()]


def csp_hash(text, alg="sha256"):
    digest = hashlib.new(alg, text.encode("utf-8")).digest()
    return f"'{alg}-{base64.b64encode(digest).decode()}'"


def _norm_b64(value):
    return value.replace("-", "+").replace("_", "/").rstrip("=")


def _hashes(source_list):
    out = []
    for tok in source_list:
        m = _HASH_RE.match(tok)
        if m:
            out.append((m.group(1).lower(), _norm_b64(m.group(2))))
    return out


def _nonces(source_list):
    return [m.group(1) for m in (_NONCE_RE.match(t) for t in source_list) if m]


def _has(source_list, keyword):
    return any(t.lower() == keyword for t in source_list)


def _hash_matches(text, hashes):
    for alg, value in hashes:
        digest = base64.b64encode(hashlib.new(alg, text.encode("utf-8")).digest()).decode()
        if _norm_b64(digest) == value:
            return True
    return False


def inline_allowed(source_list, kind, text, nonce=None, is_script=True):
    """CSP3 "does element match source list for type and source".

    kind is "element" (inline <script>/<style>), "attribute" (on*= / style=)
    or "navigation" (javascript: URL).
    """
    hashes = _hashes(source_list)
    nonces = _nonces(source_list)
    strict_dynamic = is_script and _has(source_list, "'strict-dynamic'")
    if _has(source_list, "'unsafe-inline'") and not hashes and not nonces and not strict_dynamic:
        return True
    if kind == "element":
        if nonce and nonce in nonces:
            return True
        return _hash_matches(text, hashes)
    # attributes and javascript: URLs: hashes only count with 'unsafe-hashes'
    if _has(source_list, "'unsafe-hashes'"):
        return _hash_matches(text, hashes)
    return False


def _scheme_ok(expr_scheme, url_scheme):
    if expr_scheme == url_scheme:
        return True
    return (expr_scheme, url_scheme) in {("http", "https"), ("ws", "wss"), ("ws", "http"), ("ws", "https"), ("wss", "https")}


def _port(parts):
    try:
        return parts.port or DEFAULT_PORT.get(parts.scheme)
    except ValueError:
        return None


def url_allowed(source_list, url, origin):
    """CSP3 "does url match source list in origin". url must be absolute."""
    u = urlsplit(url)
    scheme = u.scheme.lower()
    o = urlsplit(origin)
    for tok in source_list:
        low = tok.lower()
        if low == "*":
            if scheme in ("http", "https", "ws", "wss") or scheme == o.scheme:
                return True
            continue
        if low == "'self'":
            same_host = (u.hostname or "") == (o.hostname or "")
            same = scheme == o.scheme and _port(u) == _port(o)
            upgraded = (o.scheme, scheme) in {("http", "https"), ("http", "wss"), ("https", "wss")}
            if same_host and (same or upgraded):
                return True
            continue
        if low.startswith("'"):
            continue  # keywords, nonces, hashes
        m = _SCHEME_RE.match(tok)
        if m:
            if _scheme_ok(m.group(1).lower(), scheme):
                return True
            continue
        m = _HOST_RE.match(tok)
        if not m or not u.hostname:
            continue
        exp_scheme = (m.group("scheme") or "").lower()
        if exp_scheme:
            if not _scheme_ok(exp_scheme, scheme):
                continue
        elif not _scheme_ok(o.scheme, scheme):
            continue
        host = m.group("host").lower()
        uhost = u.hostname.lower()
        if host == "*":
            pass
        elif host.startswith("*."):
            if not uhost.endswith(host[1:]):
                continue
        elif host.strip("[]") != uhost:
            continue
        port = m.group("port")
        if port != "*":
            uport = _port(u)
            if port:
                if int(port) != uport:
                    continue
            elif uport != DEFAULT_PORT.get(scheme):
                continue
        path = m.group("path")
        if path and path != "/":
            want, have = unquote(path), unquote(u.path or "/")
            if want.endswith("/"):
                if not have.startswith(want):
                    continue
            elif have != want:
                continue
        return True
    return False


def external_script_allowed(source_list, url, origin, nonce=None, integrity=None):
    """Parser-inserted external <script src>: nonce, integrity hashes, or URL."""
    if nonce and nonce in _nonces(source_list):
        return True
    hashes = _hashes(source_list)
    if integrity and hashes:
        listed = set(hashes)
        items = []
        for item in integrity.split():
            alg, _, value = item.partition("-")
            items.append((alg.lower(), _norm_b64(value.split("?")[0])))
        if items and all(i in listed for i in items):
            return True
    if _has(source_list, "'strict-dynamic'"):
        return False  # URL-based sources are ignored
    return url_allowed(source_list, url, origin)


def external_style_allowed(source_list, url, origin, nonce=None):
    if nonce and nonce in _nonces(source_list):
        return True
    return url_allowed(source_list, url, origin)
