#!/usr/bin/env python3
"""Fail when CI and scripts/check.sh run different checks.

Reads the check workflows as YAML, so every way of writing a step is seen.
Each step is one of:
- `run: scripts/check.sh <steps>`, unconditional (no `if:`, no
  `continue-on-error`), so the check can fail the build;
- a `run:` setup command listed in SETUP_RUNS;
- a `uses:` action listed in SETUP_ACTIONS, or docker/build-push-action,
  whose `file:` Dockerfiles must equal check.sh's `docker` step.
Anything else fails, so a check added to CI outside check.sh is caught, and
every check.sh step must be called from CI.
"""

import pathlib
import re
import subprocess
import sys

try:
    import yaml
except ImportError:
    sys.exit("check_ci_sync.py: PyYAML is missing (pip install pyyaml / apt-get install python3-yaml)")

ROOT = pathlib.Path(__file__).resolve().parent.parent
WORKFLOW_DIR = ROOT / ".github/workflows"
WORKFLOWS = ["ci.yml", "docs.yml"]
# Commands that install or prepare, not check (matched against the whole run).
SETUP_RUNS = [
    re.compile(r"npm ci"),
    re.compile(r'python3 -c "import yaml" \|\| \(sudo apt-get update && sudo apt-get install -y python3-yaml\)'),
    re.compile(r'curl -sSfL "\S*kubeconform\S*" -o kubeconform\.tar\.gz\n'
               r"tar -xzf kubeconform\.tar\.gz kubeconform\n"
               r"sudo install kubeconform /usr/local/bin/kubeconform"),
]
# Actions that fetch, install, cache or publish; none of them checks anything.
SETUP_ACTIONS = {
    "actions/checkout", "actions/setup-node", "dtolnay/rust-toolchain", "Swatinem/rust-cache",
    "azure/setup-helm", "taiki-e/install-action", "docker/setup-buildx-action",
    "actions/upload-pages-artifact", "actions/deploy-pages",
}
CALL = re.compile(r"(?:\./)?scripts/check\.sh((?: [a-z-]+)+)")


def check_sh(*args):
    return subprocess.run(["bash", "scripts/check.sh", *args], cwd=ROOT, check=True,
                          capture_output=True, text=True).stdout.split()


def main() -> None:
    bad, called, ci_docker = [], set(), []
    steps = check_sh("--list")
    for wf in WORKFLOWS:
        jobs = yaml.safe_load((WORKFLOW_DIR / wf).read_text())["jobs"]
        for job_name, job in jobs.items():
            for i, step in enumerate(job.get("steps", [])):
                where = f"{wf}: job {job_name}, step {i + 1}"
                # A step that checks something must be able to fail the build.
                gated = [k for k in ("if", "continue-on-error") if k in step or k in job]
                if "run" in step:
                    cmd = str(step["run"]).strip()
                    m = CALL.fullmatch(cmd)
                    if m:
                        called.update(m.group(1).split())
                        bad += [f"{where}: a check step must not have `{k}`, or it cannot fail the build" for k in gated]
                    elif not any(s.fullmatch(cmd) for s in SETUP_RUNS):
                        bad.append(f"{where}: `{cmd.splitlines()[0]}` is a check outside scripts/check.sh; make it a "
                                   "check.sh step and run `scripts/check.sh <step>` (or add it to SETUP_RUNS if it only installs)")
                elif "uses" in step:
                    action = str(step["uses"]).split("@")[0]
                    if action == "docker/build-push-action":
                        ci_docker.append(str((step.get("with") or {}).get("file", "Dockerfile")))
                        bad += [f"{where}: a check step must not have `{k}`, or it cannot fail the build" for k in gated]
                    elif action not in SETUP_ACTIONS:
                        bad.append(f"{where}: action `{action}` is not a known setup action; if it checks something, "
                                   "run that check as a check.sh step instead (or add it to SETUP_ACTIONS if it only installs)")
                else:
                    bad.append(f"{where}: a step with neither `run` nor `uses`")
    for s in sorted(called - set(steps)):
        bad.append(f"CI calls check.sh step `{s}`, which check.sh does not define")
    if sorted(ci_docker) != sorted(check_sh("--dockerfiles")):
        bad.append(f"CI's docker builds {sorted(ci_docker)} but check.sh docker builds {sorted(check_sh('--dockerfiles'))}")
    for s in steps:
        if s not in called and not (s == "docker" and ci_docker):
            bad.append(f"check.sh step `{s}` is not run by CI; call `scripts/check.sh {s}` from a CI job")
    for b in bad:
        print(b)
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
