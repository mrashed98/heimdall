#!/usr/bin/env python3
"""Fail when a doc links to a file of this repository that does not exist.

Docs on the site and in the README link to repo files as
https://github.com/<owner>/heimdall/(blob|tree|edit)/main/<path>. The site
build checks its own pages, not these, so a link to a file a later change
will add, or one that was moved, used to ship as a 404.
"""

import pathlib
import re
import sys
from urllib.parse import unquote

ROOT = pathlib.Path(__file__).resolve().parent.parent
SKIP = {"node_modules", "dist", "target", ".git", ".astro", "superpowers"}
LINK = re.compile(r"github\.com/[^/\s]+/heimdall/(?:blob|tree|edit)/main/([^)\s\"'#>?]+)", re.I)


def main() -> None:
    bad = []
    for path in sorted(ROOT.rglob("*")):
        if path.suffix not in {".md", ".mdx"} or SKIP & set(path.relative_to(ROOT).parts):
            continue
        for n, line in enumerate(path.read_text().splitlines(), 1):
            for target in LINK.findall(line):
                if not (ROOT / unquote(target).rstrip("/")).exists():
                    bad.append(f"{path.relative_to(ROOT)}:{n}: links to {target}, which is not in the repo")
    for b in bad:
        print(b)
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
