"""Pull everything a CSP can block out of built HTML (and the CSS it links)."""

import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

# <script type> values that are executed. Anything else is a data block,
# which the browser never runs, so CSP never checks it.
JS_TYPES = {
    "", "module", "importmap", "speculationrules",
    "text/javascript", "application/javascript", "application/ecmascript",
    "application/x-ecmascript", "application/x-javascript", "text/ecmascript",
    "text/javascript1.0", "text/javascript1.1", "text/javascript1.2",
    "text/javascript1.3", "text/javascript1.4", "text/javascript1.5",
    "text/jscript", "text/livescript", "text/x-ecmascript", "text/x-javascript",
}

_URL_ATTRS = {
    ("img", "src"): "img-src",
    ("input", "src"): "img-src",
    ("video", "poster"): "img-src",
    ("video", "src"): "media-src",
    ("audio", "src"): "media-src",
    ("track", "src"): "media-src",
    ("iframe", "src"): "frame-src",
    ("frame", "src"): "frame-src",
    ("object", "data"): "object-src",
    ("embed", "src"): "object-src",
    ("form", "action"): "form-action",
}

_EVENT_ATTR = re.compile(r"^on[a-z]{3,}$")
_CSS_URL = re.compile(r"""url\(\s*(?:"([^"]*)"|'([^']*)'|([^)\s]*))\s*\)""", re.I)
_CSS_IMPORT = re.compile(r"""@import\s+(?:url\()?\s*["']?([^"')\s;]+)""", re.I)
_FONT_FACE = re.compile(r"@font-face\s*{[^}]*}", re.I | re.S)
_CSS_COMMENT = re.compile(r"/\*.*?\*/", re.S)


class Item:
    """One thing on a page that a policy might block."""

    __slots__ = ("line", "directive", "kind", "label", "url", "text", "nonce", "integrity", "ref", "via")

    def __init__(self, line, directive, kind, label, url=None, text=None, nonce=None, integrity=None, ref=None, via=None):
        self.line = line
        self.directive = directive  # effective directive, e.g. script-src-elem
        self.kind = kind  # "url", "element", "attribute", "navigation", "script-url", "style-url"
        self.label = label
        self.url = url
        self.text = text
        self.nonce = nonce
        self.integrity = integrity
        self.ref = ref  # the URL as written in the file
        self.via = via  # e.g. the CSS file a url() came from


def _short(text, n=40):
    text = " ".join(text.split())
    return text if len(text) <= n else text[: n - 1] + "…"


class _PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.base = None
        self.raw = []  # (line, tag, attrs dict) in document order
        self.inline = []  # (line, tag, attrs, text)
        self.meta_csp = []  # (line, http-equiv lower, content)
        self._open = None
        self._media = []

    def handle_starttag(self, tag, attrs):
        a = {}
        for k, v in attrs:
            a.setdefault(k.lower(), "" if v is None else v)
        line = self.getpos()[0]
        if tag == "base" and "href" in a and self.base is None:
            self.base = a["href"]
        if tag == "meta":
            equiv = a.get("http-equiv", "").strip().lower()
            if equiv in ("content-security-policy", "content-security-policy-report-only"):
                self.meta_csp.append((line, equiv, a.get("content", "")))
        if tag in ("picture", "video", "audio"):
            self._media.append(tag)
        a["__parent_media"] = self._media[-1] if self._media else ""
        self.raw.append((line, tag, a))
        if tag in ("script", "style"):
            self._open = (line, tag, a, [])

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag in ("script", "style"):
            self.handle_endtag(tag)

    def handle_data(self, data):
        if self._open:
            self._open[3].append(data)

    def handle_endtag(self, tag):
        if tag in ("picture", "video", "audio") and tag in self._media:
            while self._media and self._media.pop() != tag:
                pass
        if self._open and tag == self._open[1]:
            line, t, a, parts = self._open
            self.inline.append((line, t, a, "".join(parts)))
            self._open = None


def css_items(css, base_url, line, via, items):
    """url() and @import references in a stylesheet."""
    css = _CSS_COMMENT.sub("", css)
    font_spans = [m.span() for m in _FONT_FACE.finditer(css)]
    import_urls = set()
    for m in _CSS_IMPORT.finditer(css):
        ref = m.group(1)
        import_urls.add(m.start())
        items.append(Item(line, "style-src-elem", "style-url", f"@import {ref}", url=urljoin(base_url, ref), ref=ref, via=via))
    for m in _CSS_URL.finditer(css):
        ref = next(g for g in m.groups() if g is not None).strip()
        if not ref or ref.startswith("#"):
            continue
        before = css[max(0, m.start() - 20): m.start()]
        if "@import" in before:
            continue
        in_font = any(s <= m.start() < e for s, e in font_spans)
        directive = "font-src" if in_font else "img-src"
        items.append(Item(line, directive, "url", f"url({_short(ref, 50)})", url=urljoin(base_url, ref), ref=ref, via=via))


def page_items(html, page_url, read_local_css=None):
    """Return (items, meta_policies) for one HTML document.

    page_url is the absolute URL the page is served at. read_local_css(url)
    returns the text of a same-site stylesheet, or None.
    """
    p = _PageParser()
    p.feed(html)
    p.close()
    base = urljoin(page_url, p.base) if p.base else page_url
    items = []

    if p.base:
        line = next(ln for ln, t, a in p.raw if t == "base")
        items.append(Item(line, "base-uri", "url", f'<base href="{p.base}">', url=base, ref=p.base))

    for line, tag, a in p.raw:
        for name, value in a.items():
            if name.startswith("__"):
                continue
            if _EVENT_ATTR.match(name) and value.strip():
                items.append(Item(line, "script-src-attr", "attribute", f'<{tag} {name}="{_short(value)}">', text=value))
            elif name == "style" and value.strip():
                items.append(Item(line, "style-src-attr", "attribute", f'<{tag} style="{_short(value)}">', text=value))
        for attr in ("href", "src", "action", "formaction", "data"):
            v = a.get(attr, "").strip()
            if v.lower().startswith("javascript:"):
                items.append(Item(line, "script-src-elem", "navigation", f'<{tag} {attr}="{_short(v)}">', text=v))

        def add_url(directive, ref, label=None, kind="url", **kw):
            ref = ref.strip()
            if not ref or ref.lower().startswith("javascript:"):
                return
            items.append(Item(line, directive, kind, label or f'<{tag} {attr_name}="{_short(ref, 60)}">', url=urljoin(base, ref), ref=ref, **kw))

        if tag == "script" and "src" in a:
            if a.get("type", "").strip().lower() in JS_TYPES:
                attr_name = "src"
                add_url("script-src-elem", a["src"], kind="script-url", nonce=a.get("nonce"), integrity=a.get("integrity"))
        elif tag == "link":
            rel = set(a.get("rel", "").lower().split())
            href = a.get("href", "")
            attr_name = "href"
            if not href:
                pass
            elif "stylesheet" in rel:
                add_url("style-src-elem", href, kind="style-url", nonce=a.get("nonce"))
                if read_local_css:
                    css_url = urljoin(base, href)
                    css = read_local_css(css_url)
                    if css is not None:
                        css_items(css, css_url, line, urlsplit(css_url).path, items)
            elif rel & {"icon", "apple-touch-icon", "apple-touch-icon-precomposed", "mask-icon"}:
                add_url("img-src", href)
            elif "manifest" in rel:
                add_url("manifest-src", href)
            elif "modulepreload" in rel:
                add_url("script-src-elem", href, kind="script-url", nonce=a.get("nonce"), integrity=a.get("integrity"))
            elif "preload" in rel:
                as_ = a.get("as", "").lower()
                directive = {"script": "script-src-elem", "style": "style-src-elem", "font": "font-src",
                             "image": "img-src", "fetch": "connect-src", "audio": "media-src",
                             "video": "media-src", "track": "media-src", "worker": "worker-src"}.get(as_)
                if directive:
                    add_url(directive, href)
        else:
            for (t, attr_name), directive in _URL_ATTRS.items():
                if t == tag and a.get(attr_name, "").strip():
                    add_url(directive, a[attr_name])
            if tag == "source":
                parent = a.get("__parent_media")
                if parent in ("video", "audio") and a.get("src"):
                    attr_name = "src"
                    add_url("media-src", a["src"])
            for attr_name in ("srcset",):
                if tag in ("img", "source") and a.get("srcset"):
                    for cand in a["srcset"].split(","):
                        parts = cand.split()
                        if parts:
                            add_url("img-src", parts[0], label=f'<{tag} srcset="…{_short(parts[0], 50)}…">')
            for attr_name in ("formaction",):
                if tag in ("button", "input") and a.get("formaction", "").strip():
                    add_url("form-action", a["formaction"])

    for line, tag, a, text in p.inline:
        if tag == "script":
            if "src" in a:
                continue
            typ = a.get("type", "").strip().lower()
            if typ not in JS_TYPES:
                continue
            what = f"inline <script{' type=' + typ if typ else ''}> {_short(text, 30)!r}"
            items.append(Item(line, "script-src-elem", "element", what, text=text, nonce=a.get("nonce")))
        else:
            items.append(Item(line, "style-src-elem", "element", f"inline <style> {_short(text, 30)!r}", text=text, nonce=a.get("nonce")))
            css_items(text, base, line, None, items)

    return items, p.meta_csp
