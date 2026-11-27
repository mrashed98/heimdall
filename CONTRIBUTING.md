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

Releases come from merges to `main` (`.github/workflows/release.yml`, with
[release-please](https://github.com/googleapis/release-please)). It needs
*Settings → Actions → General → Allow GitHub Actions to create and approve pull
requests* turned on (or a `RELEASE_TOKEN` secret, see the workflow) to open its
pull request.

1. Each merge updates one open pull request, `chore(release): vX.Y.Z`. Its version comes from the
   pull request titles since the last release (`feat:` bumps the minor version and `fix:` the
   patch while Heimdall is below 1.0), and it updates `CHANGELOG.md`, `Cargo.toml`,
   `Cargo.lock` and, through `scripts/release_version.py set`, the chart, the docs and the gate
   action. It also moves the notes under **Unreleased** in the docs changelog to that version.
2. Merging that pull request tags `vX.Y.Z` and creates the release as a draft. Every CI check
   runs on the tag; only if all pass are the files published and the release made public:
   static Linux binaries and
   `SHA256SUMS` on GitHub Releases, multi-arch images on GHCR, and the Helm chart at
   `oci://ghcr.io/mrashed98/charts/heimdall`.

Write user-facing notes under **Unreleased** in `docs/site/src/content/docs/project/changelog.md`.
CI runs `scripts/release_version.py check`, so a version string it lists that disagrees with
`Cargo.toml` fails the build. It only knows the places in its `PLACES` list: when you write a
version number somewhere new, add it there. To finish a failed
release or republish one's files, run the release workflow by hand with its tag. That run
skips the CI gate (it trusts the tag), and moves `latest` only if the tag is the highest
release.

## License

By contributing, you agree that your contributions are licensed under the
[Apache License 2.0](LICENSE), the same license as the rest of the project.
