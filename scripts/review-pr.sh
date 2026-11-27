#!/usr/bin/env bash
# Run /review-pr on the staged changes, headless and report-only. Called by
# .githooks/pre-commit after the fast checks; `make review` runs it by hand.
#
#   HEIMDALL_SKIP_AI_REVIEW=1 git commit ...   skip it for one commit
#
# Fails the commit on a FAIL verdict, on no verdict (usage limit, crash), on
# a PASS from a claude run that exited non-zero, or if the review changed the
# index or the working tree (untracked files included, by content).
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

if [[ "${HEIMDALL_SKIP_AI_REVIEW:-}" == 1 ]]; then
  echo "review-pr: SKIPPED (HEIMDALL_SKIP_AI_REVIEW=1)"; exit 0
fi
if ! command -v claude >/dev/null; then
  echo "review-pr: SKIPPED: the claude CLI is not installed (https://claude.com/claude-code)"; exit 0
fi

# During `git commit`, git points GIT_INDEX_FILE at the index being committed
# (.git/index, index.lock or a temporary one for `git commit <paths>`). Read
# it from a copy, and keep it out of the review: inherited, it sends the
# review's `git worktree add` to the commit's index, which fails.
index="${GIT_INDEX_FILE:-$(git rev-parse --git-path index)}"
unset GIT_INDEX_FILE
# Two tree ids: the staged snapshot, then the working tree (tracked and
# untracked, not ignored). Built on a copy, so the real index is never locked
# or written.
trees() {
  local copy s
  copy="$(mktemp)"
  cp "$index" "$copy" &&
    GIT_INDEX_FILE="$copy" git write-tree &&
    GIT_INDEX_FILE="$copy" git add -A &&
    GIT_INDEX_FILE="$copy" git write-tree
  s=$?
  rm -f "$copy"
  return "$s"
}

before="$(trees)"
staged="${before%%$'\n'*}"
if [[ "$staged" == "$(git rev-parse -q --verify 'HEAD^{tree}')" ]]; then
  echo "review-pr: nothing staged"; exit 0
fi

log="$(git rev-parse --git-path review-pr.log)"
echo "review-pr: reviewing the staged changes (log: $log). Skip with HEIMDALL_SKIP_AI_REVIEW=1."
set +e
claude -p "/review-pr --hook $staged" \
  --permission-mode dontAsk \
  --allowedTools "Read" "Grep" "Glob" "Bash" "Skill" "Agent" "TodoWrite" \
  --output-format text > "$log" 2>&1
code=$?
set -e
cat "$log"

after="$(trees)"
if [[ "$after" != "$before" ]]; then
  echo "review-pr: the review changed the working tree or the index; check 'git status' before committing" >&2; exit 1
fi
# The skill ends its reply with the verdict; anything after it is no verdict.
last="$(awk 'NF { line = $0 } END { print line }' "$log")"
case "$code:$last" in
  "0:REVIEW-PR VERDICT: PASS") exit 0 ;;
  *":REVIEW-PR VERDICT: FAIL") echo "review-pr: findings above; fix them, or HEIMDALL_SKIP_AI_REVIEW=1 to commit anyway" >&2; exit 1 ;;
  *) echo "review-pr: no verdict as the last line, or claude exited $code. See $log, or HEIMDALL_SKIP_AI_REVIEW=1 to commit anyway" >&2; exit 1 ;;
esac
