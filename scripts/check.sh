#!/usr/bin/env bash
# Every CI check, as named steps. CI runs each job as `scripts/check.sh <step>`
# (`scripts/check_ci_sync.py` fails when the two lists differ), so a local run
# and CI run the same commands. The `docker` step builds the Dockerfiles that
# CI's `docker` job builds with docker/build-push-action (for its cache).
#
#   scripts/check.sh              every step; exit 0 only if all passed
#   scripts/check.sh test web     only these steps
#   scripts/check.sh --skip docker
#   scripts/check.sh --list
#
# A missing tool is a failure, never a silent skip. Judge a run by its exit
# status: piping it through grep or tail replaces that status with theirs.
set -euo pipefail
cd "$(dirname "$0")/.."
# rustup first (its cargo, not Homebrew's); Homebrew last, so it never shadows
# the python3 or node already on PATH.
export PATH="/opt/homebrew/opt/rustup/bin:$PATH:/opt/homebrew/bin"
export DATABASE_URL="${DATABASE_URL:-postgres://heimdall:heimdall@localhost:5433/heimdall}"

STEPS=(fmt versions links ci-sync scripts clippy test audit web docs helm docker)

need() {
  command -v "$1" >/dev/null || { echo "check.sh: '$1' is not installed; $2" >&2; exit 1; }
}

step_fmt() { cargo fmt --check; }
step_versions() { python3 scripts/release_version.py check; }
step_links() { python3 scripts/check_repo_links.py; }
step_ci-sync() { python3 scripts/check_ci_sync.py; }
# The guards themselves reject every bypass a review has found (selftest.py).
step_scripts() { python3 scripts/selftest.py; }
step_clippy() { cargo clippy --all-targets -- -D warnings; }
step_test() {
  # sqlx test databases are named by test path, so two runs on one server collide.
  need pgrep "it guards against two test runs on one database"
  if pgrep -f "cargo test|target/debug/deps/heimdall-" >/dev/null; then
    echo "check.sh: another cargo test is running against the database; wait for it" >&2
    exit 1
  fi
  cargo test
}
step_audit() {
  need cargo-deny "install it: brew install cargo-deny (or cargo install cargo-deny)"
  cargo deny check advisories licenses bans sources
}
step_web() { (cd web && npm run check && npm test && npm run build); }
step_docs() { (cd docs/site && npm run build); }
step_helm() {
  need helm "install it: brew install helm"
  need kubeconform "install it: brew install kubeconform"
  local chart=deploy/helm/heimdall out crds
  crds='https://raw.githubusercontent.com/datreeio/CRDs-catalog/main/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json'
  out="$(mktemp -d)"
  helm lint "$chart"
  # No ServiceMonitor CRD.
  helm template h "$chart" | kubeconform -strict -summary
  # Auth configuration and secret wiring.
  helm template h "$chart" --set config.auth.public_url=https://heimdall.example.com --set config.auth.local.enabled=true --set config.auth.oidc.issuer=https://id.example.com --set config.auth.oidc.client_id=heimdall --set config.auth.oidc.client_secret_env=HEIMDALL_OIDC_CLIENT_SECRET > "$out/auth.yaml"
  grep -q 'public_url: https://heimdall.example.com' "$out/auth.yaml"
  grep -q 'client_secret_env: HEIMDALL_OIDC_CLIENT_SECRET' "$out/auth.yaml"
  grep -q 'name: heimdall-secrets' "$out/auth.yaml"
  kubeconform -strict -summary "$out/auth.yaml"
  # Enabled ingress with multiple hosts.
  helm template h "$chart" --set ingress.enabled=true --set 'ingress.hosts[0]=one.example.com' --set 'ingress.hosts[1]=two.example.com' > "$out/ingress.yaml"
  grep -q 'host: "one.example.com"' "$out/ingress.yaml"
  grep -q 'host: "two.example.com"' "$out/ingress.yaml"
  kubeconform -strict -summary "$out/ingress.yaml"
  # With the ServiceMonitor CRD.
  helm template h "$chart" --api-versions monitoring.coreos.com/v1 |
    kubeconform -strict -summary -schema-location default -schema-location "$crds"
  # ServiceMonitor forced, offline render.
  helm template h "$chart" --set serviceMonitor.force=true > "$out/forced.yaml"
  grep -q 'kind: ServiceMonitor' "$out/forced.yaml"
  kubeconform -strict -summary -schema-location default -schema-location "$crds" "$out/forced.yaml"
  # The ClusterRole must not grant secrets (ADR 0003).
  helm template h "$chart" --api-versions monitoring.coreos.com/v1 > "$out/rendered.yaml"
  grep -q 'kind: ClusterRole' "$out/rendered.yaml"
  awk 'BEGIN { RS = "\n---\n" } /kind: ClusterRole\n/ && /secrets/ { print "ClusterRole mentions secrets:"; print; bad = 1 } END { exit bad }' "$out/rendered.yaml"
}
# Keep this list equal to the `file:` entries of CI's docker job (ci-sync checks).
DOCKERFILES=(deploy/Dockerfile deploy/Dockerfile.scanner)
step_docker() {
  need docker "install Docker, or skip this step explicitly: --skip docker"
  local f
  for f in "${DOCKERFILES[@]}"; do docker build --platform linux/amd64 -f "$f" .; done
}

run=() skip=()
while (($#)); do
  case "$1" in
    --list) printf '%s\n' "${STEPS[@]}"; exit 0 ;;
    --dockerfiles) printf '%s\n' "${DOCKERFILES[@]}"; exit 0 ;;
    --skip)
      (($# >= 2)) || { echo "check.sh: --skip needs a step (steps: ${STEPS[*]})" >&2; exit 2; }
      skip+=("$2"); shift 2 ;;
    -*) echo "check.sh: unknown option '$1' (--list, --dockerfiles, --skip <step>)" >&2; exit 2 ;;
    *) run+=("$1"); shift ;;
  esac
done
((${#run[@]})) || run=("${STEPS[@]}")
# `${a[@]+"${a[@]}"}`: an empty array under `set -u` on bash 3.2 (macOS /bin/bash).
for s in "${run[@]}" ${skip[@]+"${skip[@]}"}; do
  [[ " ${STEPS[*]} " == *" $s "* ]] || { echo "check.sh: no step '$s' (steps: ${STEPS[*]})" >&2; exit 2; }
done

for s in "${run[@]}"; do
  if [[ " ${skip[*]-} " == *" $s "* ]]; then echo "== $s: SKIPPED (asked)"; continue; fi
  echo "== $s"
  "step_$s"
done
if ((${#skip[@]})); then
  echo "== passed, except the skipped steps: ${skip[*]}"
else
  echo "== passed: ${run[*]}"
fi
