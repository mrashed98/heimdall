# Contributing to Heimdall

Thanks for helping Heimdall keep watch. This guide covers how to get set up, how changes flow,
and what a pull request needs before it can merge.

By taking part you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md). Found a security
problem? Please read [SECURITY.md](SECURITY.md) instead of opening an issue.

## How changes flow

`main` is protected. Nothing lands on it except through a pull request that:

1. passes every required CI check (formatting, lints, tests, Helm chart validation, dependency audit, image build);
2. is approved by a code owner (see [.github/CODEOWNERS](.github/CODEOWNERS));
3. has all review conversations resolved;
4. is up to date with `main` (squash merge keeps history linear).

Direct pushes and force pushes to `main` are blocked for everyone.

## Getting set up

You need Rust (stable), Docker and, for chart work, Helm.

```bash
git clone https://github.com/mrashed98/heimdall.git
cd heimdall
docker compose -f docker-compose.dev.yml up -d            # Postgres on localhost:5433
export DATABASE_URL=postgres://heimdall:heimdall@localhost:5433/heimdall
cargo test
```

## Before you open a pull request

Run the same checks CI runs:

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
helm lint deploy/helm/heimdall
```

## What a good change looks like

- **Small and focused.** One problem per pull request. Open an issue first for anything large,
  so we can agree on the approach before you write code.
- **Tested first.** Write the test that fails without your change, then make it pass. Database
  tests use `#[sqlx::test]`; HTTP clients are tested against `wiremock`. No real network calls in tests.
- **Readable Rust.** Heimdall is meant to be maintainable by people still learning Rust: plain
  structs and enums, no custom macros, `anyhow::Result` in app code, and comments that explain
  *why* when ownership shapes the code.
- **Fits the budget.** Heimdall must run in 1 GB RAM / 1 CPU. Avoid loading whole tables into
  memory or adding heavy dependencies.
- **Uses the project's words.** Terms such as Realm, Finding, Oath and Release are defined in
  [GLOSSARY.md](GLOSSARY.md). Hard-to-reverse decisions are recorded in [docs/adr/](docs/adr/);
  if your change revisits one, update or supersede the ADR in the same pull request.

## Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/): `feat:`, `fix:`, `docs:`,
`refactor:`, `test:`, `chore:`. The pull request title becomes the squash commit, so make it one
of these.

## Releases

Maintainers tag releases as `vMAJOR.MINOR.PATCH`. A tag builds the release binaries and the
multi-arch container images and publishes them to GitHub Releases and GHCR.

## License

By contributing, you agree that your contributions are licensed under the
[Apache License 2.0](LICENSE), the same license as the rest of the project.
