"""cspdryrun's verdicts against what headless Chromium actually blocks.

Skipped unless Playwright and its Chromium are installed (CI installs them).
Every violation the browser reports must be predicted. cspdryrun may also
report CSS url()s the page never ends up fetching (no element uses that rule);
that is the only extra it is allowed.
"""

from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

import pytest

pytest.importorskip("playwright.sync_api")

from browser import browser_violations  # noqa: E402
from cspdryrun.check import run  # noqa: E402
from cspdryrun.headers import parse_headers_file, served_paths  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
ORIGIN = "https://example.com"
SITES = [ROOT / "examples" / "site", ROOT / "tests" / "fixtures" / "tricky"]


def _key(f):
    i = f.item
    if i.kind in ("element", "attribute", "navigation"):
        blocked = "inline"
    else:
        u = urlsplit(i.url)
        if u.scheme in ("data", "blob"):
            blocked = u.scheme
        elif i.directive == "frame-src":
            blocked = f"{u.scheme}://{u.netloc}"  # navigations are reported as an origin
        else:
            blocked = i.url
    return (i.directive, blocked, "report" if f.report_only else "enforce")


@pytest.fixture(scope="module", params=SITES, ids=lambda p: p.name)
def site(request):
    root = request.param
    rules = parse_headers_file((root / "_headers").read_text(), "_headers")
    res = run(root, rules, [], ORIGIN)
    pages = [(rel, ORIGIN + served_paths(rel)[0]) for rel, _ in res.pages]
    try:
        seen = browser_violations(root, rules, ORIGIN, pages)
    except Exception as e:  # browser binary missing
        if "Executable doesn't exist" in str(e):
            pytest.skip("playwright chromium not installed")
        raise
    return res, seen


def test_every_browser_violation_is_predicted(site):
    res, seen = site
    for rel, events in seen.items():
        predicted = Counter(_key(f) for f in res.findings if f.file == rel)
        missing = Counter(events) - predicted
        assert not missing, f"{rel}: browser blocked things cspdryrun allowed: {sorted(missing)}"


def test_only_unused_css_urls_are_extra(site):
    res, seen = site
    for rel, events in seen.items():
        extra = Counter(_key(f) for f in res.findings if f.file == rel) - Counter(events)
        for (directive, blocked, _), _n in extra.items():
            src = [f for f in res.findings if f.file == rel and _key(f)[1] == blocked]
            assert src and all(f.item.via for f in src), f"{rel}: cspdryrun blocked {directive} {blocked} but the browser did not"
    assert any(seen.values())


def test_suggested_fixes_are_accepted_by_the_browser():
    """Apply the README's proposed policy (built from cspdryrun's fixes): the
    browser must block exactly the two attributes cspdryrun still reports."""
    import re
    script = (ROOT / "examples" / "readme_examples.sh").read_text()
    proposed = re.search(r'^PROPOSED="(.*)"$', script, re.M).group(1)
    root = ROOT / "examples" / "site"
    rules = parse_headers_file(f"/*\n  Content-Security-Policy: {proposed}\n", "proposed")
    res = run(root, rules, [], ORIGIN)
    pages = [(rel, ORIGIN + served_paths(rel)[0]) for rel, _ in res.pages]
    try:
        seen = browser_violations(root, rules, ORIGIN, pages)
    except Exception as e:
        if "Executable doesn't exist" in str(e):
            pytest.skip("playwright chromium not installed")
        raise
    assert seen == {
        "about/index.html": [],
        "blog/post.html": [],
        "index.html": [("script-src-attr", "inline", "enforce"), ("style-src-attr", "inline", "enforce")],
    }
    assert sorted(_key(f) for f in res.findings) == seen["index.html"]
