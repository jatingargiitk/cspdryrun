import json

from cspdryrun.headers import csp_headers_for, parse_headers_file, parse_vercel, served_paths
from cspdryrun.scan import page_items

URL = "https://example.com/p/index.html"


def kinds(html):
    items, _ = page_items(html, URL)
    return [(i.directive, i.kind, i.url or i.text) for i in items]


def test_inline_script_text_is_raw_and_data_blocks_skipped():
    items, _ = page_items('<script>a &amp;&lt; b</script><script type="application/json">{}</script>'
                          '<script type="module">m()</script>', URL)
    assert [i.text for i in items] == ["a &amp;&lt; b", "m()"]


def test_attributes_are_decoded_like_the_dom():
    items, _ = page_items('<p style="content: &quot;x&quot;" onclick="f(&quot;a&quot;)">', URL)
    assert sorted(i.text for i in items) == ['content: "x"', 'f("a")']


def test_urls_resolve_against_base():
    got = kinds('<base href="/x/"><img src="a.png" srcset="b.png 2x, https://c.test/c.png 3x">')
    assert ("img-src", "url", "https://example.com/x/a.png") in got
    assert ("img-src", "url", "https://example.com/x/b.png") in got
    assert ("img-src", "url", "https://c.test/c.png") in got
    assert got[0] == ("base-uri", "url", "https://example.com/x/")


def test_media_frames_objects_forms_links():
    got = kinds('<video poster="p.jpg"><source src="v.mp4"></video><picture><source srcset="i.webp"></picture>'
                '<iframe src="https://f.test/"></iframe><embed src="e.swf"><form action="/go"></form>'
                '<link rel="preload" as="font" href="f.woff2"><link rel="manifest" href="m.json">'
                '<link rel="modulepreload" href="m.js"><a href="javascript:void(0)">x</a>')
    directives = [d for d, _, _ in got]
    assert directives == ["img-src", "media-src", "img-src", "frame-src", "object-src", "form-action",
                          "font-src", "manifest-src", "script-src-elem", "script-src-elem"]
    assert got[-1][1] == "navigation"


def test_css_font_face_import_and_images():
    items, _ = page_items('<style>@import "t.css"; @font-face{src:url(f.woff2)} /* url(no.png) */'
                          ' a{background:url("data:image/png;base64,AA")}</style>', URL)
    got = [(i.directive, i.url) for i in items if i.kind != "element"]
    assert got == [("style-src-elem", "https://example.com/p/t.css"),
                   ("font-src", "https://example.com/p/f.woff2"),
                   ("img-src", "data:image/png;base64,AA")]


def test_meta_csp_collected():
    _, metas = page_items('<meta http-equiv="content-security-policy" content="img-src \'self\'">', URL)
    assert metas == [(1, "content-security-policy", "img-src 'self'")]


def test_served_paths():
    assert served_paths("index.html") == ["/", "/index.html"]
    assert served_paths("blog/index.html") == ["/blog/", "/blog/index.html", "/blog"]
    assert served_paths("a/b.html") == ["/a/b.html", "/a/b"]


HEADERS = """
# comment
/*
  Content-Security-Policy: default-src 'self'
  X-Frame-Options: DENY
/blog/:slug
  Content-Security-Policy-Report-Only: img-src 'none'
/legacy/*
  ! Content-Security-Policy
"""


def test_headers_file_matching_and_detach():
    rules = parse_headers_file(HEADERS)
    assert [n for n, _, _ in csp_headers_for(rules, ["/"])] == ["content-security-policy"]
    names = [n for n, _, _ in csp_headers_for(rules, served_paths("blog/post.html"))]
    assert names == ["content-security-policy", "content-security-policy-report-only"]
    assert csp_headers_for(rules, ["/legacy/old.html"]) == []


def test_headers_file_errors():
    import pytest
    with pytest.raises(ValueError, match="before any path"):
        parse_headers_file("  Content-Security-Policy: x")
    with pytest.raises(ValueError, match="expected"):
        parse_headers_file("/*\n  nonsense")


def test_vercel_sources():
    cfg = {"headers": [
        {"source": "/(.*)", "headers": [{"key": "Content-Security-Policy", "value": "default-src 'self'"}]},
        {"source": "/docs/:path*", "headers": [{"key": "content-security-policy", "value": "img-src *"}]},
        {"source": "/blog/:slug", "has": [{"type": "host", "value": "x"}],
         "headers": [{"key": "Content-Security-Policy", "value": "script-src 'none'"}]},
    ]}
    rules, warnings = parse_vercel(json.dumps(cfg))
    assert len(warnings) == 1 and "has/missing" in warnings[0]
    assert len(csp_headers_for(rules, ["/docs"])) == 2
    assert len(csp_headers_for(rules, ["/docs/a/b"])) == 2
    assert len(csp_headers_for(rules, ["/blog/hello"])) == 2
    assert len(csp_headers_for(rules, ["/blog/a/b"])) == 1
