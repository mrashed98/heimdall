#!/usr/bin/env python3
"""The repo's guards reject what they claim to reject.

Each case is a mistake a review has found before. scripts/check.sh must
refuse bad arguments with exit 2, and scripts/check_ci_sync.py must fail on
each broken copy of the CI workflows. Run as `scripts/check.sh scripts`.
"""

import copy
import os
import pathlib
import subprocess
import sys
import tempfile

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
WF = ROOT / ".github/workflows"
failures = []


def run(args, env=None):
    return subprocess.run(args, cwd=ROOT, capture_output=True, text=True, env={**os.environ, **(env or {})})


# check.sh: a bad argument is a usage error (exit 2) with a message, never a crash.
for args, says in [(["--skip"], "--skip needs a step"), (["nope"], "no step 'nope'"),
                   (["--skip", "nope"], "no step 'nope'"), (["--bogus"], "unknown option")]:
    r = run(["bash", "scripts/check.sh", *args])
    if r.returncode != 2 or says not in r.stderr:
        failures.append(f"check.sh {' '.join(args)}: exit {r.returncode}, stderr {r.stderr.strip()!r}; want exit 2 saying {says!r}")


def steps_of(doc, job):
    return doc["jobs"][job]["steps"]


def find(steps, pred):
    return next(s for s in steps if pred(s))


def docker_step(doc):
    return find(steps_of(doc, "docker"), lambda s: str(s.get("uses", "")).startswith("docker/build-push-action"))


def check_step(doc, job):
    return find(steps_of(doc, job), lambda s: str(s.get("run", "")).startswith("scripts/check.sh"))


# Each mutation of ci.yml must make check_ci_sync.py fail, saying `says`.
MUTATIONS = [
    ("docker build that cannot fail", lambda d: docker_step(d).update({"continue-on-error": True}), "continue-on-error"),
    ("check.sh step behind if", lambda d: check_step(d, "test").update({"if": "false"}), "must not have `if`"),
    ("job-level continue-on-error", lambda d: d["jobs"]["clippy"].update({"continue-on-error": True}), "continue-on-error"),
    ("check outside check.sh", lambda d: steps_of(d, "clippy").append({"run": "cargo test --doc"}), "outside scripts/check.sh"),
    ("checking action", lambda d: steps_of(d, "audit").append({"uses": "EmbarkStudios/cargo-deny-action@v2"}), "not a known setup action"),
    ("step CI never calls", lambda d: steps_of(d, "clippy").remove(check_step(d, "clippy")), "is not run by CI"),
    ("Dockerfile drift", lambda d: docker_step(d)["with"].update({"file": "deploy/Dockerfile.other"}), "docker builds"),
]

base = run([sys.executable, "scripts/check_ci_sync.py"])
if base.returncode != 0:
    failures.append(f"check_ci_sync.py fails on the real workflows: {base.stdout.strip()}")
ci = yaml.safe_load((WF / "ci.yml").read_text())
for name, mutate, says in MUTATIONS:
    with tempfile.TemporaryDirectory() as tmp:
        doc = copy.deepcopy(ci)
        mutate(doc)
        (pathlib.Path(tmp) / "ci.yml").write_text(yaml.safe_dump(doc))
        (pathlib.Path(tmp) / "docs.yml").write_text((WF / "docs.yml").read_text())
        r = run([sys.executable, "scripts/check_ci_sync.py"], {"CI_SYNC_WORKFLOWS": tmp})
        if r.returncode == 0 or says not in r.stdout:
            failures.append(f"check_ci_sync.py passes a {name} (exit {r.returncode}); want a failure saying {says!r}")

for f in failures:
    print(f)
sys.exit(1 if failures else 0)
