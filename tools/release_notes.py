"""Release notes for one version: its CHANGELOG.md section and links to the packages. The release workflow makes
the GitHub release page from this. Usage: python tools/release_notes.py 0.4.1"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VERSION = re.compile(r"\d+\.\d+\.\d+")
DATE = re.compile(r"\((\d{4}-\d{2}-\d{2})\)")


def notes(version: str, changelog: str) -> str:
    """The notes for one version. ValueError for a malformed version; LookupError for a missing or empty section."""
    if not VERSION.fullmatch(version):
        raise ValueError(f"not a version number: {version!r}")
    heading, body = None, []
    for line in changelog.splitlines():
        if line.startswith("## "):
            if heading:
                break
            if line.split()[1:2] == [version]:
                heading = line
        elif heading:
            body.append(line)
    text = "\n".join(body).strip("\n")
    if not heading or not text.strip():
        raise LookupError(f"CHANGELOG.md has no notes for {version}")
    date = DATE.search(heading)
    released = f"Released {date.group(1)}.\n\n" if date else ""
    install = (f"Install: [PyPI](https://pypi.org/project/open-action-consent/{version}/) or "
               f"[npm](https://www.npmjs.com/package/open-action-consent/v/{version}).")
    return f"{released}{text}\n\n{install}\n"


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: python tools/release_notes.py VERSION", file=sys.stderr)
        return 2
    try:
        text = notes(argv[0], (ROOT / "CHANGELOG.md").read_text(encoding="utf-8"))
    except (ValueError, LookupError) as e:
        print(f"release_notes: {e}", file=sys.stderr)
        return 1
    sys.stdout.buffer.write(text.encode("utf-8"))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
