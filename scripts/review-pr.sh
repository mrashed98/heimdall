#!/usr/bin/env bash
# Run /review-pr on the staged changes, headless and report-only. Called by
# .githooks/pre-commit after the fast checks; `make review` runs it by hand.
#
#   HEIMDALL_SKIP_AI_REVIEW=1 git commit ...   skip it for one commit
#
# Fails the commit on a FAIL verdict, on no verdict (usage limit, crash), or
# if the review changed the working tree or the index.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

if [[ "${HEIMDALL_SKIP_AI_REVIEW:-}" == 1 ]]; then
  echo "review-pr: SKIPPED (HEIMDALL_SKIP_AI_REVIEW=1)"; exit 0
fi
if git diff --cached --quiet; then
  echo "review-pr: nothing staged"; exit 0
fi
if ! command -v claude >/dev/null; then
  echo "review-pr: SKIPPED: the claude CLI is not installed (https://claude.com/claude-code)"; exit 0
fi

log="$(git rev-parse --git-path review-pr.log)"
state() { { git diff; git diff --cached; git ls-files --others --exclude-standard; } | shasum; }
before="$(state)"
echo "review-pr: reviewing the staged changes (log: $log). Skip with HEIMDALL_SKIP_AI_REVIEW=1."
set +e
claude -p "/review-pr --hook" \
  --permission-mode dontAsk \
  --allowedTools "Read" "Grep" "Glob" "Bash" "Skill" "Agent" "TodoWrite" \
  --output-format text > "$log" 2>&1
code=$?
set -e
cat "$log"

if [[ "$(state)" != "$before" ]]; then
  echo "review-pr: the review changed the working tree or the index; check 'git status' before committing" >&2; exit 1
fi
verdict="$(grep -E '^REVIEW-PR VERDICT: (PASS|FAIL)$' "$log" | tail -n 1 || true)"
case "$verdict" in
  "REVIEW-PR VERDICT: PASS") exit 0 ;;
  "REVIEW-PR VERDICT: FAIL") echo "review-pr: findings above; fix them, or HEIMDALL_SKIP_AI_REVIEW=1 to commit anyway" >&2; exit 1 ;;
  *) echo "review-pr: no verdict (claude exit $code; a usage limit or error?). See $log, or HEIMDALL_SKIP_AI_REVIEW=1 to commit anyway" >&2; exit 1 ;;
esac
