"""Every output recorded by examples/readme_examples.sh must appear in README.md."""

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
OUTS = sorted((ROOT / "examples" / "out").glob("*.txt"))
README = (ROOT / "README.md").read_text(encoding="utf-8")


def test_outputs_exist():
    assert {p.stem for p in OUTS} == {"headers", "proposed", "flip"}


@pytest.mark.parametrize("path", OUTS, ids=lambda p: p.stem)
def test_recorded_output_is_in_readme(path):
    body, code_line = path.read_text(encoding="utf-8").rstrip("\n").rsplit("\n", 1)
    assert code_line.startswith("exit ")
    assert body + "\n$ echo $?\n" + code_line.split()[1] in README, (
        f"README is missing the output of {path.name}; re-run examples/readme_examples.sh and update README")


def test_headers_file_is_shown_verbatim():
    assert (ROOT / "examples" / "site" / "_headers").read_text(encoding="utf-8").rstrip() in README
