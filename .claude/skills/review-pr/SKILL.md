---
name: review-pr
description: "Review a Heimdall change with every pstack verification method (thermos, blast-radius, interrogate, no-comments, deslop, prove-it-works, test-behavior) plus the repo's own checks, before cubic or Amazon Q do. Use for /review-pr, `/review-pr <PR number>`, or `/review-pr --hook` (the pre-commit hook: staged changes, report only)."
---

# Review a PR

Find every real defect in a change before it is pushed, the kinds the bots
on #63 to #75 kept finding: a comment or doc that says more than the code,
a guard with one branch unchecked, a script that fails unclearly, copied
text not adapted, a step missing from a parallel path, a test that passes
when its behavior breaks.

## Scope and mode

Read `$ARGUMENTS`:

- empty: the current branch against `origin/main` (merge base), working tree included. **Fix mode.**
- a PR number: that PR's diff (`gh pr diff <n>`). **Fix mode.** Fixes must
  land on the PR's branch: unless `git rev-parse HEAD` equals the PR's
  `headRefOid` (`gh pr view <n> --json headRefName,headRefOid`), fetch, then
  work in a worktree of that branch (`git worktree add <scratchpad>/pr-<n>
  <headRefName>`), and remove it after pushing.
- `--hook <tree>`: the staged snapshot that `scripts/review-pr.sh` passes as
  a tree id. The change is `git diff HEAD <tree>`; the rest of that tree is
  context. **Report mode.** First check the snapshot out, and run steps 1 and
  7 in it, never in the checkout being committed:

  ```sh
  repo="$PWD" snap="$(mktemp -d)/snap"
  git worktree add --detach "$snap" "$(git commit-tree <tree> -p HEAD -m review-pr)"
  ln -s "$repo/web/node_modules" "$snap/web/node_modules"
  ln -s "$repo/docs/site/node_modules" "$snap/docs/site/node_modules"
  (cd "$snap" && CARGO_TARGET_DIR="$repo/target" make lint)   # reuses the build
  git worktree remove --force "$snap"   # when done
  ```

Steps 2 to 6 never edit: pass "report only, do not edit" to each, and skip
its "fix" or "apply" step, because they run at the same time on one
checkout. In **fix mode**, once they return, apply the accepted fixes one at
a time and rerun the checks after each. In **report mode** nothing edits a
file in the checkout, and the reply ends with the verdict line.

Write the scope (base, files, intent from commits and PR description) once
and give the same scope to every step.

## Steps

Run them in this order. Steps 2 to 6 are independent and report-only: start
them in one message, in the background.

1. **Repo checks.** `make lint` (format, version strings, links, CI sync,
   guard self-test, clippy, web); in report mode, in the snapshot. In fix
   mode on a full branch, `make check` when Postgres and Docker are up. A
   failing check is a finding; judge it by the exit status, never by
   filtered output.
2. **Bugs and code quality.** Run the `pstack:thermos` skill.
3. **What it breaks elsewhere.** Run the `pstack:blast-radius` skill. Prove
   the one fact the change is safe because of by running code.
4. **Adversarial.** Run the `pstack:interrogate` skill. Only findings proven
   by a run survive.
5. **Comments.** Run the `pstack:no-comments` skill (comment-sicko). Every
   comment, doc line, CLAUDE.md row and error message in scope must say what
   the code does, no more.
6. **Slop.** Run the `pstack:deslop` skill on the scope.
7. **Tests.** Apply `pstack:principle-test-behavior-not-implementation`: for
   each test the change adds or edits, mutate the code it names once and
   confirm the test fails, then restore. Report a test that still passes.
   In report mode, mutate only in the snapshot.
8. **Rules.** Check the change against every row of the rule table in
   `CLAUDE.md`. A rule enforced by "review" is checked here by hand.
9. **Proof.** Apply `pstack:principle-prove-it-works`: for each behavior the
   change claims (commit messages, PR description, docs), name the run that
   shows it. A claim with no run is a finding. For a console change, fix
   mode also drives the page (the `run` skill); report mode does not start
   the app, so it names the web test that shows the behavior instead.

## Verdict

Merge findings that share a root cause, drop what no step could back with
evidence, and list each kept finding with `file:line`, the failure, the step
that found it, and severity (bug / doc-claim / nit). Say which steps could
not run and why (a usage limit, a missing tool): a step that did not run is
not a pass.

In report mode the last line of the reply is exactly one of these
(`scripts/review-pr.sh` reads only the last non-empty line):

```
REVIEW-PR VERDICT: PASS
REVIEW-PR VERDICT: FAIL
```

FAIL when any bug or doc-claim finding is kept, or any step could not run.
Nits alone pass.
