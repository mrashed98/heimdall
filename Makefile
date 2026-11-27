# Thin wrappers over scripts/check.sh, which CI runs step by step.
.PHONY: check lint fast test hooks list

check:          ## every CI check (needs Postgres, Docker, helm, cargo-deny)
	scripts/check.sh

lint:           ## no database: format, guards, clippy, web checks
	scripts/check.sh fmt versions links ci-sync scripts clippy web

fast:           ## what the pre-commit hook runs
	.githooks/pre-commit

test:           ## Rust tests against DATABASE_URL
	scripts/check.sh test

hooks:          ## run the fast checks before every commit
	git config core.hooksPath .githooks

list:           ## the check.sh steps
	scripts/check.sh --list
