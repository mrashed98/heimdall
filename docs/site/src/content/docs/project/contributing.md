---
title: Contributing
description: How to set up, what a good change looks like, and how pull requests flow into main.
editUrl: https://github.com/mrashed98/heimdall/edit/main/CONTRIBUTING.md
---

Thanks for helping Heimdall keep watch. This page mirrors
[CONTRIBUTING.md](https://github.com/mrashed98/heimdall/blob/main/CONTRIBUTING.md).

By taking part you agree to follow the
[Code of Conduct](https://github.com/mrashed98/heimdall/blob/main/CODE_OF_CONDUCT.md).
Found a security problem? Read the [security policy](/heimdall/project/security/)
instead of opening an issue.

## How changes flow

`main` is protected. Nothing lands on it except through a pull request that:

1. passes every required CI check (formatting, lints, tests, Helm chart validation, dependency audit, image build);
2. is approved by a code owner;
3. has all review conversations resolved;
4. is up to date with `main` (squash merge keeps history linear).

Direct pushes and force pushes to `main` are blocked for everyone.

## Getting set up

You need Rust (stable), Python 3 with PyYAML, Node 22.23.4 or newer, and
Docker. The full `make check` also needs helm, kubeconform and cargo-deny.

```bash
git clone https://github.com/mrashed98/heimdall.git
cd heimdall
(cd web && npm ci) && (cd docs/site && npm ci)
docker compose -f docker-compose.dev.yml up -d            # Postgres on localhost:5433
export DATABASE_URL=postgres://heimdall:heimdall@localhost:5433/heimdall
cargo test
```

## Before you open a pull request

Run the checks CI runs. Each CI job calls a step of `scripts/check.sh`, so
these are the same commands:

```bash
make check     # every step (needs Postgres, Docker, helm, kubeconform, cargo-deny)
make lint      # fmt, versions, links, ci-sync, scripts, clippy and web; not test, audit, docs, helm or docker
make hooks     # run the fast checks (`make fast`) on the staged files before every commit
```

`scripts/check.sh --list` names the steps; `scripts/check.sh test web` runs
some of them, and `--skip docker` leaves one out. A missing tool fails the
step instead of skipping it.

## What a good change looks like

- **Small and focused.** One problem per pull request. Open an issue first for
  anything large, so you can agree on the approach before writing code.
- **Tested first.** Write the test that fails without your change, then make it
  pass. Database tests use `#[sqlx::test]`; HTTP clients are tested against
  `wiremock`. No real network calls in tests.
- **Readable Rust.** Heimdall is meant to be maintainable by people still
  learning Rust: plain structs and enums, no custom macros, `anyhow::Result` in
  app code, and comments that explain *why* when ownership shapes the code.
- **Fits the budget.** Heimdall must run in 1 GB RAM and 1 CPU. Avoid loading
  whole tables into memory or adding heavy dependencies.
- **Uses the project's words.** Terms such as Realm, Finding, Oath and Release
  are defined in the [glossary](/heimdall/concepts/glossary/). Hard-to-reverse
  decisions are recorded in the [architecture decisions](/heimdall/decisions/);
  if your change revisits one, update or supersede the ADR in the same pull
  request.

## Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/): `feat:`, `fix:`,
`docs:`, `refactor:`, `test:`, `chore:`. The pull request title becomes the squash
commit, so make it one of these.

## Working on these docs

The documentation lives in `docs/site/` (Astro Starlight). See its
[README](https://github.com/mrashed98/heimdall/blob/main/docs/site/README.md) to run it locally.
The build fails on broken internal links.

## Releases

Maintainers tag releases as `vMAJOR.MINOR.PATCH`. A tag builds the release binaries
and the multi-arch container images and publishes them to GitHub Releases and GHCR.

## License

By contributing, you agree that your contributions are licensed under the
[Apache License 2.0](/heimdall/project/license/).
