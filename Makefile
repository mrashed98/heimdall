# Thin wrappers over scripts/check.sh, which CI runs step by step.
# A bare `make` prints this list; it never starts a check.
.DEFAULT_GOAL := help
.PHONY: help check lint fast review test hooks list

help:           ## list the targets
	@awk -F':.*## ' '/^[a-z]+:.*## / { printf "make %-6s %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

check:          ## every CI check (tools: CONTRIBUTING.md, "Before you open a pull request")
	scripts/check.sh

lint:           ## fmt versions links ci-sync scripts clippy web (no test audit docs helm docker)
	scripts/check.sh fmt versions links ci-sync scripts clippy web

fast:           ## the pre-commit hook's checks without the AI review, on the working tree
	scripts/check.sh fmt versions links ci-sync scripts
	node web/scripts/conventions.mjs

review:         ## /review-pr on the staged changes, report only (needs the claude CLI)
	scripts/review-pr.sh

test:           ## Rust tests against DATABASE_URL
	scripts/check.sh test

hooks:          ## before every commit: make fast on the staged files, then make review
	git config core.hooksPath .githooks

list:           ## the check.sh steps
	scripts/check.sh --list
