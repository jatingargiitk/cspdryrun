import pytest

from cspdryrun.policy import (
    Policy, csp_hash, external_script_allowed, inline_allowed, split_policies, url_allowed,
)

O = "https://example.com"


def test_parse_first_duplicate_wins_and_lowercases():
    p = Policy("Default-Src 'self'; img-src a.test; img-src b.test", "x")
    assert p.directives == {"default-src": ["'self'"], "img-src": ["a.test"]}
    assert p.warnings == ["duplicate img-src is ignored (browsers use the first one)"]


def test_meta_policy_drops_header_only_directives():
    p = Policy("img-src 'self'; frame-ancestors 'none'; report-uri /r", "m", from_meta=True)
    assert set(p.directives) == {"img-src"}
    assert len(p.warnings) == 2


@pytest.mark.parametrize("effective,expected", [
    ("script-src-elem", "script-src"),
    ("script-src-attr", "script-src"),
    ("img-src", "default-src"),
    ("frame-src", "child-src"),
    ("worker-src", "child-src"),
    ("form-action", None),
    ("base-uri", None),
])
def test_fallback(effective, expected):
    p = Policy("default-src 'none'; script-src 'self'; child-src 'self'", "x")
    assert p.governing(effective)[0] == expected


def test_split_policies():
    assert len(split_policies("default-src 'self', img-src data:")) == 2


def test_hash_format():
    assert csp_hash("console.log(1)") == "'sha256-CihokcEcBW4atb/CW/XWsvWwbTjqwQlE9nj9ii5ww5M='"
    assert csp_hash("a", "sha384").startswith("'sha384-")


@pytest.mark.parametrize("src,url,ok", [
    ("'self'", "https://example.com/a.png", True),
    ("'self'", "https://www.example.com/a.png", False),
    ("'self'", "http://example.com/a.png", False),
    ("*", "https://any.test/x", True),
    ("*", "data:image/png;base64,AA", False),
    ("https:", "https://any.test/x", True),
    ("http:", "https://any.test/x", True),
    ("https:", "http://any.test/x", False),
    ("data:", "data:image/png;base64,AA", True),
    ("*.cdn.test", "https://img.cdn.test/x", True),
    ("*.cdn.test", "https://a.b.cdn.test/x", True),
    ("*.cdn.test", "https://cdn.test/x", False),
    ("cdn.test", "https://cdn.test/x", True),
    ("cdn.test", "http://cdn.test/x", False),
    ("http://cdn.test", "https://cdn.test/x", True),
    ("https://cdn.test", "https://cdn.test:8443/x", False),
    ("https://cdn.test:8443", "https://cdn.test:8443/x", True),
    ("https://cdn.test:*", "https://cdn.test:9/x", True),
    ("https://cdn.test/img/", "https://cdn.test/img/a/b.png", True),
    ("https://cdn.test/img/", "https://cdn.test/other.png", False),
    ("https://cdn.test/img/a.png", "https://cdn.test/img/a.png?v=2", True),
    ("https://cdn.test/img/a.png", "https://cdn.test/img/b.png", False),
    ("'none'", "https://example.com/a", False),
    ("'unsafe-inline'", "https://example.com/a", False),
])
def test_url_matching(src, url, ok):
    assert url_allowed(src.split(), url, O) is ok


def test_unsafe_inline_ignored_when_hash_or_nonce_present():
    assert inline_allowed(["'unsafe-inline'"], "element", "x")
    assert not inline_allowed(["'unsafe-inline'", "'nonce-a'"], "element", "x")
    assert not inline_allowed(["'unsafe-inline'", csp_hash("y")], "element", "x")
    assert not inline_allowed(["'unsafe-inline'", "'strict-dynamic'"], "element", "x")
    # 'strict-dynamic' only means something for scripts
    assert inline_allowed(["'unsafe-inline'", "'strict-dynamic'"], "element", "x", is_script=False)


def test_nonce_and_hash_for_elements():
    assert inline_allowed(["'nonce-abc'"], "element", "x", nonce="abc")
    assert not inline_allowed(["'nonce-abc'"], "element", "x", nonce="abd")
    assert inline_allowed([csp_hash("x")], "element", "x")
    assert inline_allowed([csp_hash("x", "sha512")], "element", "x")
    assert not inline_allowed([csp_hash("x")], "element", "x ")


def test_attributes_need_unsafe_hashes():
    h = csp_hash("go()")
    assert not inline_allowed([h], "attribute", "go()")
    assert inline_allowed(["'unsafe-hashes'", h], "attribute", "go()")
    assert not inline_allowed(["'nonce-a'"], "attribute", "go()")
    assert inline_allowed(["'unsafe-inline'"], "attribute", "go()")


def test_external_scripts():
    assert external_script_allowed(["'self'"], "https://example.com/a.js", O)
    assert not external_script_allowed(["'self'", "'strict-dynamic'"], "https://example.com/a.js", O)
    assert external_script_allowed(["'strict-dynamic'", "'nonce-n'"], "https://x.test/a.js", O, nonce="n")
    h = csp_hash("whatever", "sha384")
    integrity = h.strip("'")
    assert external_script_allowed(["'strict-dynamic'", h], "https://x.test/a.js", O, integrity=integrity)
    assert not external_script_allowed(["'strict-dynamic'", h], "https://x.test/a.js", O, integrity="sha384-other")
