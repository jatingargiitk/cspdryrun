"""Load a build directory in headless Chromium with its CSP headers and record
every securitypolicyviolation event, so tests can compare with cspdryrun.

All requests are answered by a Playwright route, so no network is used and the
site is served from whatever origin you name.
"""

import mimetypes
from pathlib import Path
from urllib.parse import urlsplit, unquote

from cspdryrun.headers import CSP, CSP_RO, csp_headers_for, served_paths

LISTEN = """
window.__csp = [];
document.addEventListener('securitypolicyviolation', e => {
  window.__csp.push([e.effectiveDirective, e.blockedURI, e.disposition]);
}, true);
"""

# Make lazy things happen: event handlers compile on first dispatch,
# javascript: URLs and form actions are checked on navigation.
POKE = """
() => {
  for (const el of document.querySelectorAll('*')) {
    for (const a of el.getAttributeNames()) {
      if (/^on[a-z]{3,}$/.test(a)) el.dispatchEvent(new Event(a.slice(2)));
    }
  }
  for (const a of document.querySelectorAll('a[href^="javascript:" i]')) a.click();
  for (const f of document.querySelectorAll('form')) {
    f.addEventListener('submit', ev => {}, {once: true});
    try { f.requestSubmit(); } catch (e) {}
  }
}
"""

DUMMY = {
    ".css": ("text/css", b"body{}"),
    ".js": ("text/javascript", b""),
    ".woff2": ("font/woff2", b""),
}


def browser_violations(site, rules, origin, page_urls):
    """{rel: sorted list of (effectiveDirective, blockedURI, disposition)}"""
    from playwright.sync_api import sync_playwright

    site = Path(site)
    out = {}

    def handle(route):
        url = route.request.url
        u = urlsplit(url)
        if f"{u.scheme}://{u.netloc}" == origin:
            path = unquote(u.path)
            f = site / (path.lstrip("/") + ("index.html" if path.endswith("/") else ""))
            if f.is_dir():
                f = f / "index.html"
            if not f.is_file():
                return route.fulfill(status=404, body="")
            rel = f.relative_to(site).as_posix()
            headers = {}
            ctype = mimetypes.guess_type(f.name)[0] or "application/octet-stream"
            if f.suffix == ".html":
                found = csp_headers_for(rules, served_paths(rel))
                for name in (CSP, CSP_RO):
                    vals = [v for n, v, _ in found if n == name]
                    if vals:
                        headers[name] = ", ".join(vals)
                ctype = "text/html; charset=utf-8"
            headers["content-type"] = ctype
            return route.fulfill(status=200, headers=headers, body=f.read_bytes())
        ctype, body = DUMMY.get(Path(u.path).suffix, ("text/plain", b""))
        if "fonts.googleapis.com" in u.netloc:
            ctype, body = "text/css", b"body{}"
        return route.fulfill(status=200, headers={"content-type": ctype}, body=body)

    with sync_playwright() as p:
        browser = p.chromium.launch()
        try:
            for rel, url in page_urls:
                ctx = browser.new_context()
                ctx.route("**/*", handle)
                ctx.add_init_script(LISTEN)
                page = ctx.new_page()
                page.goto(url, wait_until="load")
                page.wait_for_timeout(300)
                page.evaluate(POKE)
                page.wait_for_timeout(300)
                out[rel] = sorted(tuple(v) for v in page.evaluate("window.__csp"))
                ctx.close()
        finally:
            browser.close()
    return out
