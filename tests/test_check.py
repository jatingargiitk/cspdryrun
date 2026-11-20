import json
from pathlib import Path

from cspdryrun.check import run
from cspdryrun.cli import main
from cspdryrun.headers import parse_headers_file, parse_vercel

EXAMPLES = Path(__file__).resolve().parent.parent / "examples" / "site"
TRICKY = Path(__file__).resolve().parent / "fixtures" / "tricky"
ORIGIN = "https://example.com"


def _run(root, enforce=False, extra=None, vercel=None):
    rules = parse_headers_file((Path(root) / "_headers").read_text(), "_headers") if (Path(root) / "_headers").is_file() else []
    if vercel:
        r, _ = parse_vercel(Path(vercel).read_text())
        rules += r
    return run(root, rules, extra or [], ORIGIN, enforce)


def _blocked(res):
    return [(f.file, f.item.directive, f.item.url or f.item.text, f.report_only) for f in res.findings]


def test_example_site_enforced_and_report_only():
    res = _run(EXAMPLES)
    blocked = [f for f in res.findings if not f.report_only]
    reported = [f for f in res.findings if f.report_only]
    assert {f.file for f in blocked} == {"about/index.html", "blog/post.html", "index.html"}
    what = {(f.file, f.item.label.split()[0], f.item.directive) for f in blocked}
    # inline script, onclick, style=, data: favicon, youtube iframe, cover image, font + css hero
    assert ("index.html", "inline", "script-src-elem") in what
    assert ("index.html", "<button", "script-src-attr") in what
    assert ("index.html", "<p", "style-src-attr") in what
    assert ("index.html", "<link", "img-src") in what  # data: favicon
    assert ("about/index.html", "<iframe", "frame-src") in what
    assert ("blog/post.html", "<img", "img-src") in what
    font = [f for f in blocked if f.item.ref and f.item.ref.endswith("acme-sans.woff2")]
    hero = [f for f in blocked if f.item.ref and "hero.jpg" in f.item.ref]
    assert len(font) == 3 and len(hero) == 3  # the CSS is included from every page
    assert all(f.item.via == "/assets/app.css" for f in font + hero)
    # Report-Only on /blog/* only; GTM is allowed by the enforced policy, reported under 'strict-dynamic'
    assert {f.file for f in reported} == {"blog/post.html"}
    assert any("googletagmanager" in (f.item.url or "") for f in reported)
    # self-hosted script and logo are allowed
    assert not any("/assets/app.js" in (f.item.url or "") and not f.report_only for f in res.findings)
    assert not any("logo.svg" in (f.item.url or "") for f in res.findings)


def test_json_ld_is_not_a_script():
    res = _run(EXAMPLES)
    assert not any("application/ld+json" in f.item.label for f in res.findings)


def test_enforce_report_only_promotes_them():
    res = _run(EXAMPLES, enforce=True)
    assert not any(f.report_only for f in res.findings)
    assert any("googletagmanager" in (f.item.url or "") and f.file == "blog/post.html" for f in res.findings)


def test_tricky_base_hashes_nonces_and_hosts():
    res = _run(TRICKY)
    a = [f for f in res.findings if f.file == "a/index.html" and not f.report_only]
    labels = [f.item.label for f in a]
    assert any("<base" in x for x in labels)
    assert any("console.log(2)" in x for x in labels)
    assert any('console.log("bad nonce")' in x for x in labels)
    assert not any("console.log(1)" in x for x in labels)  # hash matches
    assert not any('console.log("nonce")' in x for x in labels)
    assert not any("text/template" in x for x in labels)
    assert any("color: blue" in x for x in labels)
    assert not any("color: red" in x for x in labels)
    assert any("javascript:alert" in x for x in labels)
    urls = {f.item.url for f in a if f.item.url}
    assert "https://cdn.test/apex.png" in urls
    assert "https://static.test/other/z.png" in urls
    assert "https://cdn.test:8443/q.png" in urls
    assert "https://img.cdn.test/x.png" not in urls
    assert "https://static.test/img/deep/y.png" not in urls
    assert "https://cdn.test:8080/p.png" not in urls
    assert any(f.item.directive == "object-src" for f in a)
    assert any(f.item.directive == "form-action" for f in a)


def test_strict_dynamic_and_comma_separated_policies():
    res = _run(TRICKY)
    b = [f for f in res.findings if f.file == "b/index.html"]
    enforce = [f for f in b if not f.report_only]
    report = [f for f in b if f.report_only]
    # nonce script is allowed; URL-only script and inline without nonce are blocked
    assert any("ignored.test" in (f.item.url or "") for f in enforce)
    assert any("inline without" in f.item.label for f in enforce)
    assert not any("/app.js" in (f.item.url or "") for f in enforce)
    # second policy is `img-src 'self' data:`; both images allowed in enforce, data: reported by report-only
    assert any(f.item.url and f.item.url.startswith("data:") for f in report)
    assert not any(f.item.url and f.item.url.startswith("data:") and not f.report_only for f in b)


def test_meta_policy_and_ignored_directives():
    res = _run(TRICKY)
    c = [f for f in res.findings if f.file == "c/index.html"]
    assert len(c) == 1 and "third.party.test" in c[0].item.url
    assert any("frame-ancestors is ignored" in w for w in res.warnings)
    assert any("Report-Only in <meta> is ignored" in w for w in res.warnings)


def test_proposed_policy_on_clean_page(tmp_path):
    (tmp_path / "index.html").write_text("<img src='https://ok.test/a.png'><img src='https://bad.test/b.png'>")
    res = run(tmp_path, [], ["img-src https://ok.test"], ORIGIN)
    assert len(res.findings) == 1
    assert res.findings[0].item.url == "https://bad.test/b.png"
    assert res.findings[0].fix == "add https://bad.test to img-src"


def test_no_policy_is_unprotected(tmp_path, capsys):
    (tmp_path / "index.html").write_text("<img src='/a.png'>")
    assert main([str(tmp_path)]) == 0
    err = capsys.readouterr().out
    assert "no policy applies" in err and "no policy found" in err


def test_cli_exit_codes_and_json(tmp_path, capsys):
    (tmp_path / "index.html").write_text("<script>alert(1)</script>")
    assert main([str(tmp_path), "--policy", "default-src 'none'", "--format", "json"]) == 1
    data = json.loads(capsys.readouterr().out)
    assert data["findings"][0]["effective_directive"] == "script-src-elem"
    assert data["findings"][0]["decided_by"] == "default-src"
    assert "sha256-" in data["findings"][0]["fix"]
    assert main([str(tmp_path), "--policy", "script-src 'unsafe-inline'"]) == 0
    capsys.readouterr()
    import pytest
    with pytest.raises(SystemExit) as e:
        main([str(tmp_path / "missing")])
    assert e.value.code == 2
    assert "not a directory" in capsys.readouterr().err


def test_cli_headers_file_and_origin(capsys):
    assert main([str(EXAMPLES), "--origin", "https://example.com"]) == 1
    out = capsys.readouterr().out
    assert "3 page(s) checked" in out
    assert "blocked" in out and "Report-Only" in out
    assert "add 'self' to font-src" in out
    assert "add data: to img-src" in out
    assert "add https://images.example-cdn.net to img-src" in out


def test_cli_vercel(tmp_path, capsys):
    (tmp_path / "index.html").write_text('<script src="/app.js"></script>')
    (tmp_path / "vercel.json").write_text(json.dumps({
        "headers": [{"source": "/(.*)", "headers": [{"key": "Content-Security-Policy", "value": "default-src 'none'"}]}]
    }))
    assert main([str(tmp_path), "--vercel", str(tmp_path / "vercel.json")]) == 1
    assert "script-src-elem -> default-src" in capsys.readouterr().out
