#!/usr/bin/env bash
# The checks CI runs (ci.yml, docs.yml; helm is CI-only), in one command whose
# exit status is the truth: it stops at the first failure and exits non-zero.
# Run it as is; piping it through grep or tail hides that status.
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="/opt/homebrew/opt/rustup/bin:/opt/homebrew/bin:$PATH"
export DATABASE_URL="${DATABASE_URL:-postgres://heimdall:heimdall@localhost:5433/heimdall}"

# sqlx test databases are named by test path, so two runs on one server collide.
if pgrep -f "cargo test|target/debug/deps/heimdall-" >/dev/null; then
  echo "check.sh: another cargo test is running against the database; wait for it" >&2
  exit 1
fi

step() { echo "== $*"; "$@"; }
step cargo fmt --check
step python3 scripts/release_version.py check
step python3 scripts/check_repo_links.py
step cargo clippy --all-targets -- -D warnings
step cargo test
(cd web && step npm run check && step npm test && step npm run build)
(cd docs/site && step npm run build)
echo "== all checks passed"
