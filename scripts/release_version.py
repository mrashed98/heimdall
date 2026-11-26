#!/usr/bin/env python3
"""Every place outside Cargo.toml that names the current release.

    release_version.py check        fail if any of them differs from Cargo.toml
    release_version.py set          rewrite them to Cargo.toml's version, and
                                    move the docs changelog's Unreleased notes
                                    under that version

The release workflow runs `set` on the release PR after release-please bumps
Cargo.toml; CI runs `check`, so a version string added here can't be missed.
"""

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
V = r"(?P<v>\d+\.\d+\.\d+)"
CHANGELOG = "docs/site/src/content/docs/project/changelog.md"

# (file, pattern); the `v` group is the version. Each pattern must match at
# least once, so a moved or reworded line fails `check` instead of going stale.
# A space in a pattern matches any whitespace, so rewrapping prose is fine.
PLACES = [
    ("deploy/helm/heimdall/Chart.yaml", rf"^version: {V}$"),
    ("deploy/helm/heimdall/Chart.yaml", rf'^appVersion: "{V}"$'),
    (".github/actions/gate/action.yml", rf"a tag such as v{V}"),
    ("README.md", rf"ghcr\.io/mrashed98/heimdall(?:-scanner)?:{V}"),
    ("README.md", rf"the Bifröst · v{V}"),
    ("README.md", rf"actions/gate@v{V}"),
    ("README.md", rf"tag `v{V}` gives"),
    ("README.md", rf"gives `heimdall:{V}`"),
    ("README.md", rf"--version {V}"),
    ("docs/site/src/content/docs/getting-started/kubernetes.mdx", rf"ghcr\.io/mrashed98/heimdall(?:-scanner)?:{V}"),
    ("docs/site/src/content/docs/getting-started/kubernetes.mdx", rf"tag `v{V}`"),
    ("docs/site/src/content/docs/getting-started/kubernetes.mdx", rf"gives `heimdall:{V}`"),
    ("docs/site/src/content/docs/getting-started/kubernetes.mdx", rf"--version {V}"),
    ("docs/site/src/content/docs/guides/ci-gate.mdx", rf"actions/gate@v{V}"),
    ("docs/site/src/content/docs/guides/ci-gate.mdx", rf"such as `v{V}`"),
    ("docs/site/src/content/docs/guides/ci-gate.mdx", rf"\(`@v{V}`\)"),
]
PLACES = [(f, p.replace(" ", r"\s+")) for f, p in PLACES]


def crate_version() -> str:
    text = (ROOT / "Cargo.toml").read_text()
    m = re.search(r'^version = "(\d+\.\d+\.\d+)"$', text, re.M)
    if not m:
        sys.exit("Cargo.toml has no version")
    return m.group(1)


def check(want: str) -> list[str]:
    errors = []
    for file, pattern in PLACES:
        text = (ROOT / file).read_text()
        found = [m.group("v") for m in re.finditer(pattern, text, re.M)]
        if not found:
            errors.append(f"{file}: no match for {pattern}")
        errors += [f"{file}: {v} in {pattern}, want {want}" for v in found if v != want]
    return errors


def set_version(want: str) -> None:
    for file in sorted({f for f, _ in PLACES}):
        path = ROOT / file
        text = path.read_text()
        for f, pattern in PLACES:
            if f == file:
                text = re.sub(
                    pattern,
                    lambda m: m.group(0)[: m.start("v") - m.start()]
                    + want
                    + m.group(0)[m.end("v") - m.start() :],
                    text,
                    flags=re.M,
                )
        path.write_text(text)
    move_unreleased(want)


def move_unreleased(want: str) -> None:
    """Move the notes under `## Unreleased` into `## <want>` (created after
    it when missing), leaving Unreleased empty. Running it again moves only
    notes added since."""
    path = ROOT / CHANGELOG
    text = path.read_text()
    head = "## Unreleased\n"
    if head not in text:
        sys.exit(f"{CHANGELOG}: no '## Unreleased' heading")
    start = text.index(head) + len(head)
    nxt = text.find("\n## ", start)
    end = len(text) if nxt == -1 else nxt + 1
    notes = text[start:end].strip("\n")
    if not notes:
        return
    rest = text[end:]
    section = f"## {want}\n"
    if rest.startswith(section):
        rest = section + "\n" + notes + "\n" + rest[len(section) :]
    else:
        rest = section + "\n" + notes + "\n\n" + rest
    path.write_text(text[:start] + "\n" + rest)


def main() -> None:
    want = crate_version()
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "check":
        errors = check(want)
        for e in errors:
            print(e)
        sys.exit(1 if errors else 0)
    if cmd == "set":
        set_version(want)
        errors = check(want)
        if errors:
            sys.exit("\n".join(errors))
        print(f"every version string is {want}")
        return
    sys.exit(__doc__)


if __name__ == "__main__":
    main()
