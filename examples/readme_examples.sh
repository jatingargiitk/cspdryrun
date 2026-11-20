#!/usr/bin/env bash
# Re-runs every command shown in README.md and records its output (and exit
# code) under examples/out/. CI runs this and fails if anything changed;
# tests/test_readme.py checks each recorded output appears in README.md.
set -u
cd "$(dirname "$0")/.."
mkdir -p examples/out

record() {  # record NAME -- command...
  local name="$1"; shift; shift
  local out="examples/out/$name.txt"
  "$@" > "$out" 2>&1
  echo "exit $?" >> "$out"
}

PROPOSED="default-src 'self'; script-src 'self' https://www.googletagmanager.com 'sha256-hUizg0THL3POThjSDVwpjWQRCwbqMmpUTVQH8Hce5tI='; style-src 'self' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: https://images.example-cdn.net; frame-src https://www.youtube-nocookie.com"

record headers -- cspdryrun examples/site --origin https://example.com
record proposed -- cspdryrun examples/site --origin https://example.com --only --policy "$PROPOSED"
record flip -- cspdryrun examples/site --origin https://example.com --enforce-report-only
echo "recorded: $(ls examples/out | tr '\n' ' ')"
