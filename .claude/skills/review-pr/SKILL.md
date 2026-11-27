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
- a PR number: that PR's diff (`gh pr diff <n>`). **Fix mode.**
- `--hook`: only the staged changes (`git diff --cached`), with the rest of the tree as context. **Report mode.**

In **report mode** nothing edits a file: every skill below runs report-only
(pass "report only, do not edit" to each subagent, and skip every "fix" or
"apply" step), and the reply ends with the verdict line. In **fix mode**,
apply accepted fixes and rerun the checks after each.

Write the scope (base, files, intent from commits and PR description) once
and give the same scope to every step.

## Steps

Run them in this order. Steps 2 to 6 are independent: start them in one
message, in the background.

1. **Repo checks.** `make lint` (format, version strings, links, CI sync,
   guard self-test, clippy, web). In fix mode on a full branch, `make check`
   when Postgres and Docker are up. A failing check is a finding; judge it by
   the exit status, never by filtered output.
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
   In report mode, mutate only in a throwaway worktree
   (`git worktree add`, then `git diff --cached | git apply` in it), never in
   the checkout being committed; remove the worktree after.
8. **Rules.** Check the change against every row of the rule table in
   `CLAUDE.md`. A rule enforced by "review" is checked here by hand.
9. **Proof.** Apply `pstack:principle-prove-it-works`: for each behavior the
   change claims (commit messages, PR description, docs), name the run that
   shows it. A claim with no run is a finding. For console changes, drive
   the page (the `run` skill) in fix mode.

## Verdict

Merge findings that share a root cause, drop what no step could back with
evidence, and list each kept finding with `file:line`, the failure, the step
that found it, and severity (bug / doc-claim / nit). Say which steps could
not run and why (a usage limit, a missing tool): a step that did not run is
not a pass.

In report mode the last line of the reply is exactly one of:

```
REVIEW-PR VERDICT: PASS
REVIEW-PR VERDICT: FAIL
```

FAIL when any bug or doc-claim finding is kept, or any step could not run.
Nits alone pass.
