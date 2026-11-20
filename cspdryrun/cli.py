"""cspdryrun: what would this Content-Security-Policy block on my built site?"""

import argparse
import json
import sys
from collections import OrderedDict
from pathlib import Path

from . import __version__
from .check import run
from .headers import parse_headers_file, parse_vercel

EPILOG = """examples:
  cspdryrun dist --origin https://example.com
  cspdryrun dist --only --policy "default-src 'self'; img-src 'self' data:"
  cspdryrun dist --headers dist/_headers --enforce-report-only
  cspdryrun build --vercel vercel.json --format json

exit codes: 0 nothing blocked, 1 something would be blocked, 2 usage or input error"""


def _parser():
    ap = argparse.ArgumentParser(
        prog="cspdryrun",
        description="Check what a Content-Security-Policy would block on a built static site, before you deploy it.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("dir", help="build output directory (dist/, build/, out/, public/)")
    ap.add_argument("--policy", action="append", default=[], metavar="CSP",
                    help="a policy to apply to every page, e.g. a proposed one (repeatable)")
    ap.add_argument("--headers", metavar="FILE",
                    help="Netlify / Cloudflare Pages _headers file (default: DIR/_headers if it exists)")
    ap.add_argument("--vercel", metavar="FILE", help="vercel.json with a headers array")
    ap.add_argument("--only", action="store_true",
                    help="check only the --policy policies; ignore _headers, vercel.json and <meta> tags")
    ap.add_argument("--origin", default="https://site.invalid",
                    help="the origin the site is served from, used for 'self' and relative URLs (default: %(default)s)")
    ap.add_argument("--enforce-report-only", action="store_true",
                    help="treat Report-Only policies as enforced: what breaks when you flip the switch")
    ap.add_argument("--format", choices=["text", "json"], default="text")
    ap.add_argument("--version", action="version", version=f"cspdryrun {__version__}")
    return ap


def _text(res, out):
    by_file = OrderedDict()
    for f in res.findings:
        by_file.setdefault(f.file, []).append(f)
    for rel, policies in res.pages:
        found = by_file.get(rel, [])
        if not policies:
            continue
        print(f"{rel}", file=out)
        for i, pol in enumerate(policies, 1):
            print(f"  policy {i}: {pol.source}", file=out)
        if not found:
            print("  ok: nothing blocked", file=out)
        for f in found:
            tag = "REPORT" if f.report_only else "BLOCK "
            via = f" (in {f.item.via})" if f.item.via else ""
            decided = f.item.directive if f.directive == f.item.directive else f"{f.item.directive} -> {f.directive}"
            pol = "" if len(policies) == 1 else f" [policy {[id(p) for p in policies].index(id(f.policy)) + 1}]"
            print(f"  {tag} line {f.item.line}: {f.item.label}{via}", file=out)
            print(f"         {decided}{pol}; fix: {f.fix}", file=out)
        print(file=out)
    if res.unprotected:
        shown = ", ".join(res.unprotected[:5]) + (" …" if len(res.unprotected) > 5 else "")
        print(f"no policy applies to {len(res.unprotected)} page(s): {shown}", file=out)
    for w in res.warnings:
        print(f"warning: {w}", file=out)
    blocked = [f for f in res.findings if not f.report_only]
    reported = [f for f in res.findings if f.report_only]
    pages = len({f.file for f in blocked})
    line = f"{len(res.pages)} page(s) checked: {len(blocked)} blocked on {pages} page(s)"
    if reported:
        line += f", {len(reported)} more only reported (Report-Only)"
    print(line, file=out)


def main(argv=None):
    ap = _parser()
    args = ap.parse_args(argv)
    root = Path(args.dir)
    if not root.is_dir():
        ap.error(f"{root} is not a directory")
    origin = args.origin.rstrip("/")
    if "://" not in origin:
        ap.error("--origin must look like https://example.com")
    rules, warnings = [], []
    if args.only and not args.policy:
        ap.error("--only needs at least one --policy")
    if args.only and (args.headers or args.vercel):
        ap.error("--only ignores headers files, so don't pass --headers or --vercel with it")
    headers = args.headers or (str(root / "_headers") if (root / "_headers").is_file() and not args.only else None)
    try:
        if headers:
            rules += parse_headers_file(Path(headers).read_text(encoding="utf-8"), Path(headers).name)
        if args.vercel:
            r, w = parse_vercel(Path(args.vercel).read_text(encoding="utf-8"), Path(args.vercel).name)
            rules += r
            warnings += w
    except (OSError, ValueError) as e:
        print(f"cspdryrun: error: {e}", file=sys.stderr)
        return 2
    res = run(root, rules, args.policy, origin, args.enforce_report_only, use_meta=not args.only)
    res.warnings = warnings + res.warnings
    if not any(sources for _, sources in res.pages):
        res.warnings.append("no policy found: pass --policy, --headers, --vercel, or add a CSP <meta> tag")
    if args.format == "json":
        json.dump({
            "pages": [{"file": r, "policies": [{"source": p.source, "policy": p.text, "report_only": p.report_only} for p in s]} for r, s in res.pages],
            "findings": [f.to_dict() for f in res.findings],
            "unprotected": res.unprotected,
            "warnings": res.warnings,
        }, sys.stdout, indent=2, ensure_ascii=False)
        print()
    else:
        _text(res, sys.stdout)
    return 1 if any(not f.report_only for f in res.findings) else 0


if __name__ == "__main__":
    sys.exit(main())
