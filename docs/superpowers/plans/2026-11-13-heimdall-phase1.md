# Heimdall Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A single Rust binary (`heimdall`) that inventories SBOMs and the k3s cluster, matches against OSV, watches releases, alerts in Teams, gates CI, and manages oaths. It runs in 1 GB / 1 CPU with external Postgres.

**Architecture:** One crate (lib + bin). `heimdall serve` runs the axum API (Bifröst) plus tokio interval loops (Sight, advisory refresh, watchers, matcher, Gjallarhorn outbox, oath expiry, digest). Every other subcommand (`gate`, `oath`, `keys`, `sight`, `scan-images`) is a thin HTTP client of the same API. All state lives in Postgres. Findings are rows with a stable text key, and notifications go through a DB outbox, so nothing is lost or duplicated across restarts.

**Tech Stack:**
- Runtime and HTTP: Rust stable (edition 2024), tokio, axum, reqwest (rustls).
- Data: sqlx (Postgres, migrations, `#[sqlx::test]`), serde/serde_json/serde_yaml.
- Kubernetes and CLI: kube + k8s-openapi, clap (derive).
- Versions and parsing: semver, packageurl, cvss.
- Observability: tracing + tracing-opentelemetry + opentelemetry-otlp, metrics + metrics-exporter-prometheus.
- Utilities: chrono, chrono-tz, sha2, rand, walkdir, flate2.
- Tests: wiremock, tower (`ServiceExt::oneshot`).

**Spec:** `docs/superpowers/specs/2026-11-12-heimdall-design.md`

## Global Constraints

- Container limit **1 GB RAM / 1 CPU**; steady-state RSS target **≤ 256 MB**.
- Postgres is external (existing VM). No other stateful dependency.
- Teams is the only notifier: Workflows webhook + Adaptive Cards.
- User-facing words: Realm, Bifröst, Sight, Watchers, Gjallarhorn, Hofund, **Oath**. Code modules use plain names: `realm`, `ingest`, `inventory`, `watchers`, `notify`, `gate`, `oath`.
- Readable for a Rust learner: no custom macros; generics only where a library demands them; `anyhow::Result` in app code; clone rather than fight lifetimes; comment *why* when ownership shapes code.
- Alert rules (immediate): new critical/high CVE; major release; fix available for a CVE we're exposed to (including under an oath); oath expired; end of support ≤ 60 days. Everything else goes to the weekly digest (Monday 09:00, timezone from config, default UTC).
- Alerts fire from the first run. They are grouped **per advisory/release** and sent paced at **≥ 2 s** between cards.
- Release alerts only for **direct** libraries and configured or inventory-derived infra targets. Pre-releases are ignored.
- Gate source order: **OSV → GitHub Advisory DB → fail** with exit code `2`. Vulnerabilities found give exit code `1`. Server-side gate timeout **60 s**.
- Oaths are scoped to `(advisory, component name, service, realm)`. A reason is required. `snooze` has `expires_at`; `ignore` has `review_at` (default +90 days). Oaths carry across versions that are still affected.
- Not exposed to the internet: the Helm chart's Ingress is off by default.
- Polling defaults: Sight 15 min, OSV refresh 15 min, Kubernetes CVE feed 30 min, release watchers 1 h, **NVD incremental 2 h**.
- **Grill decisions (spec §12) apply everywhere.** In short:
  - OSV **and** NVD for every component; a CVE in both counts once; the higher severity wins.
  - NVD-only library matches are labelled "NVD match only, verify".
  - Release notes are fetched and classified by pattern matching.
  - `own_registries` images are never release-watched.
  - `0.x` minor bumps count as major.
  - `--all-realms` oaths.
  - `admins:` list.
  - Retention: findings and releases 1 year, outbox 30 days, oaths forever.
- Vocabulary follows `GLOSSARY.md`. Decisions recorded in `docs/adr/0001–0004` must not be "fixed".

**Deviations from spec (recorded in the spec's decisions log by Task 1):**
- API keys are hashed with **SHA-256**, not argon2. The keys are 32 random bytes, so a slow hash adds nothing and costs CPU on a 1-CPU pod.
- Sight reads Helm chart versions from the `helm.sh/chart` label on workloads plus ArgoCD `Application`s, **not from Helm release Secrets**. That avoids cluster-wide Secret read access.

## Review Focus

1. **Image tags with variants and non-semver tags** (`16.4-alpine`, `16.4-bookworm`, `latest`, `sha-abc123`): only compare tags with the same suffix; ignore non-semver tags. Pinned in Task 3 (`parse_tag`) and Task 13 (oci watcher test).
2. **Debian/Ubuntu packages** whose binary name differs from the source package, or that have epochs (`1:2.3-1`): the OSV query uses the `upstream` qualifier's source name, and dpkg ordering respects epochs and `~`. Pinned in Task 2 (`osv_package`) and Task 3.
3. **Teams webhook down, returning 429 or 5xx, or a pod restart mid-send:** cards are retried with backoff, `Retry-After` is honoured, and each card is sent exactly once after a restart. Pinned in Task 14.
4. **Malformed or huge SBOMs** (no purl, nested components, 10k components, 40 MB body): components without a purl are skipped and counted. The body limit is 50 MB. A malformed upload returns 400 and never wipes the existing inventory. Pinned in Tasks 4 and 7.
5. **Oath expiring while the pod is down:** on the next start the expiry is processed, alerting exactly once. Pinned in Task 10.

---

## File Structure

```
heimdall/
├── Cargo.toml
├── docker-compose.dev.yml          # Postgres 17 for dev/tests
├── heimdall.example.yaml
├── migrations/0001_init.sql
├── src/
│   ├── main.rs                     # clap dispatch only
│   ├── lib.rs                      # pub mod list + AppState
│   ├── config.rs                   # HeimdallConfig (serde_yaml)
│   ├── db.rs                       # pool + migrate
│   ├── model.rs                    # Severity, Source, FindingKind, OathKind
│   ├── purl.rs                     # purl helpers, OSV package mapping
│   ├── version.rs                  # semver/go/dpkg ordering, is_major, parse_tag
│   ├── auth.rs                     # API keys + axum extractor
│   ├── client.rs                   # CLI HTTP client (HEIMDALL_URL / HEIMDALL_API_KEY)
│   ├── ingest/{mod,sbom,manifests,api}.rs
│   ├── inventory/{mod,store,sight}.rs
│   ├── vuln/{mod,osv,nvd,ghsa,k8s_feed,severity}.rs
│   ├── watchers/{mod,github,endoflife,oci,helm,tf_registry,go_proxy,npm,notes}.rs
│   ├── retention.rs
│   ├── matcher.rs
│   ├── oath.rs
│   ├── gate.rs
│   ├── notify/{mod,outbox,teams,digest}.rs
│   ├── scan_images.rs
│   ├── server.rs                   # router + scheduler loops
│   └── telemetry.rs                # tracing/OTLP + metrics
├── tests/fixtures/…                # SBOMs, OSV/GHSA/GitHub/etc. JSON, k8s objects
├── deploy/
│   ├── Dockerfile                  # heimdall (distroless)
│   ├── Dockerfile.scanner          # heimdall + syft (alpine)
│   └── helm/heimdall/…
├── .github/actions/gate/action.yml
├── .github/workflows/ci.yml
└── README.md
```

Unit tests live in `#[cfg(test)] mod tests` inside each file. DB tests use `#[sqlx::test(migrations = "./migrations")]` with `DATABASE_URL` pointing at the compose Postgres. HTTP clients are tested against `wiremock`. Every external base URL is a field on the client struct, so tests can redirect it.

---

### Task 1: Scaffold, config, dev database

**Files:**
- Create: `Cargo.toml`, `src/main.rs`, `src/lib.rs`, `src/config.rs`, `src/db.rs`, `docker-compose.dev.yml`, `heimdall.example.yaml`, `.github/workflows/ci.yml`, `.gitignore`
- Modify: `docs/superpowers/specs/2026-11-12-heimdall-design.md` (add the two deviations to §11 and the argon2 line in §7.7)

**Interfaces:**
- Produces:
  - `config::HeimdallConfig::load(path: &Path) -> anyhow::Result<HeimdallConfig>` with fields:
    - `realms: Vec<String>`
    - `digest: DigestConfig { weekday: chrono::Weekday, hour: u32, timezone: chrono_tz::Tz }`
    - `teams: Vec<TeamsRoute { name, webhook_env: String, realms: Vec<String> /*empty=all*/, min_severity: Severity }>`
    - `watchers: WatcherTargets { github: Vec<GithubTarget>, endoflife: Vec<EolTarget>, tf_registry: Vec<TfTarget> }`
    - `declared: Vec<DeclaredComponent { realm, service, purl }>`
    - `registries: Vec<RegistryCred { host, secret_env: String }>`
    - `schedules: Schedules` (minutes, with the defaults from Global Constraints)
  - `GithubTarget { repo: String, inventory_name: String, major_component: u8 /*default 0*/, cpe: Option<String> }`
  - `EolTarget { product: String, inventory_name: String, major_component: u8, cpe: Option<String>, repo: Option<String> /*GitHub repo for release notes*/ }`
  - Additional `HeimdallConfig` fields:
    - `own_registries: Vec<String>` (host or host/org prefixes, e.g. `ghcr.io/yourorg`)
    - `admins: Vec<String>`
    - `nvd: NvdConfig { api_key_env: String /*default NVD_API_KEY*/, minutes: u32 /*120*/ }`
    - `retention: Retention { findings_days: 365, releases_days: 365, outbox_days: 30 }`
  - `digest.timezone` has default `UTC`. The example config sets `cpe:` for postgresql (`cpe:2.3:a:postgresql:postgresql`), clickhouse, valkey and kafka.
  - `TfTarget { registry: String /*registry.terraform.io|registry.opentofu.org*/, kind: TfKind /*provider|module*/, source: String, current: String }`
  - `db::connect(url: &str) -> anyhow::Result<PgPool>` (max 5 connections, runs migrations)
  - The `heimdall` binary with clap subcommands: `serve`, `gate`, `oath`, `keys`, `sight`, `scan-images`, `realms`. Each is stubbed to `todo!()` except `serve --check-config`.

- [ ] **Step 1: Write the failing test** in `src/config.rs`

```rust
#[test]
fn example_config_parses_with_defaults() {
    let cfg = HeimdallConfig::load(Path::new("heimdall.example.yaml")).unwrap();
    assert_eq!(cfg.realms, vec!["dev-k3s"]);
    assert_eq!(cfg.digest.weekday, chrono::Weekday::Mon);
    assert_eq!(cfg.digest.hour, 9);
    assert_eq!(cfg.schedules.sight_minutes, 15);
    assert_eq!(cfg.schedules.watchers_minutes, 60);
    let k8s = cfg.watchers.github.iter().find(|t| t.repo == "kubernetes/kubernetes").unwrap();
    assert_eq!(k8s.major_component, 1);
}
```

- [ ] **Step 2:** Run `cargo test config::` and expect FAIL (`HeimdallConfig` not defined).
- [ ] **Step 3: Implement the config types and write `heimdall.example.yaml`.** The file must contain:
  - realm `dev-k3s`
  - GitHub targets for every repo in spec §7.3. `major_component: 1` for `kubernetes/kubernetes` and `k3s-io/k3s`.
  - endoflife targets: `postgresql`, `clickhouse`, `kubernetes` (major_component 1), `k3s` (1), `ubuntu`, `debian`, `valkey`, `amazon-eks` (1), `amazon-rds-postgresql`
  - one Teams route `default` with `webhook_env: TEAMS_WEBHOOK_DEFAULT` and `min_severity: high`
  - a declared Postgres VM component `pkg:generic/postgresql@17.2` in realm `dev-k3s`, service `postgres-vm`

  Defaults go in `#[serde(default = ...)]` functions.
- [ ] **Step 4:** Run `cargo test config::` and expect PASS.
- [ ] **Step 5: Set up the dev database.** In `docker-compose.dev.yml`, add a `postgres:17` service on port 5433 with db/user/password `heimdall`. In `.github/workflows/ci.yml`, add a Postgres service container and run `cargo test` with `DATABASE_URL`. Verify `docker compose -f docker-compose.dev.yml up -d && cargo run -- serve --check-config heimdall.example.yaml` prints `config ok`.
- [ ] **Step 6:** Update the spec with the two deviations, then `git init` and commit.

```bash
git init && git add -A && git commit -m "chore: scaffold heimdall crate, config, dev db"
```

---

### Task 2: Schema, model types, purl helpers

**Files:**
- Create: `migrations/0001_init.sql`, `src/model.rs`, `src/purl.rs`

**Interfaces:**
- Produces enums, stored as lowercase `text` with a CHECK, via `sqlx::Type` + `#[sqlx(type_name="text", rename_all="lowercase")]`:
  - `model::Severity { Critical, High, Medium, Low, Unknown }`. Implements `Ord` where Critical > High > Medium > Unknown > Low; `Unknown` ranks as medium for alerting.
  - `model::Source { Git, Ci, Cluster, Declared }`
  - `model::FindingKind { Vuln, FixAvailable, MajorRelease, OathExpired, Eol, K8sCve, ReleaseNoteCve }`
  - `model::MatchSource { Osv, Nvd, Both }`
  - `model::OathKind { Snooze, Ignore }`
- Produces purl helpers:
  - `purl::name_key(purl: &str) -> anyhow::Result<String>`: the purl without version and qualifiers, e.g. `pkg:npm/%40scope/lib`. It's the identity used for oaths, direct flags and watcher matching.
  - `purl::osv_package(purl: &str) -> Option<OsvPackage { ecosystem: String, name: String, version: String }>`
- Tables, all with `id bigserial` unless noted:
  - `services(realm, name, unique(realm,name))`
  - `components(purl text unique, name_key, ecosystem, version)`
  - `service_components(service_id, component_id, source, direct bool, via_image_digest text null, uploaded_at)`, PK `(service_id, component_id, source)`
  - `image_sboms(digest text pk, image_ref, scanned_at)`
  - `image_components(digest, component_id)`
  - `advisories(id text pk, aliases text[], severity, summary, fixed jsonb /*{name_key: [versions]}*/, modified timestamptz, source)`
  - `component_advisories(component_id, advisory_id)`
  - `releases(target, version, published_at, is_major, unique(target,version))`
  - `watcher_state(target text pk, etag, last_checked, last_seen)`
  - `findings(key text unique, kind, realm, service_id null, component_id null, ref_id, severity, status /*open|resolved*/, opened_at, resolved_at, notified_at, details jsonb)`
  - `oaths(advisory_id, name_key, service_id, realm, kind, reason not null, version_at_creation, expires_at, review_at, created_by, created_at, status /*active|expired|revoked*/)`
  - `oath_events(oath_id, event, at, by, note)`
  - `outbox(group_key, card jsonb, route, attempts int, next_attempt_at, sent_at null)`
  - `api_keys(name unique, sha256 bytea unique, scope, created_at)`
  - `kv(key text pk, value text)`
  - **Additions from the grill decisions:**
    - `components.cpes text[]`
    - `advisories.scores jsonb` (`{"osv": 7.5, "nvd": 9.8}`) and `advisories.cve_id text null`, indexed: the join key between OSV and NVD
    - `component_advisories.match_source` (`MatchSource`)
    - `oaths.realm` is nullable (null = all realms)
    - `releases.notes_url text`, `releases.notes_class text /*cve_affecting|security|bugfix|plain|none*/`, `releases.mentioned_ids text[]`, `releases.excerpt jsonb /*{fix:[..], breaking:[..]}*/`
    - `nvd_products(vendor_product text pk, backfilled_at)`
    - `declared_since` on `service_components` (set on first insert, kept on replace)

- [ ] **Step 1: Write the failing tests** in `src/purl.rs`

```rust
#[test] fn go_maps_to_osv() {
    let p = osv_package("pkg:golang/github.com/gin-gonic/gin@v1.9.0").unwrap();
    assert_eq!((p.ecosystem.as_str(), p.name.as_str(), p.version.as_str()),
               ("Go", "github.com/gin-gonic/gin", "v1.9.0"));
}
#[test] fn scoped_npm_maps_to_osv() {
    let p = osv_package("pkg:npm/%40vue/core@3.4.0").unwrap();
    assert_eq!((p.ecosystem.as_str(), p.name.as_str()), ("npm", "@vue/core"));
}
#[test] fn debian_uses_upstream_source_name_and_release() {
    let p = osv_package("pkg:deb/debian/libssl3@3.0.11-1~deb12u2?arch=amd64&upstream=openssl&distro=debian-12").unwrap();
    assert_eq!((p.ecosystem.as_str(), p.name.as_str(), p.version.as_str()),
               ("Debian:12", "openssl", "3.0.11-1~deb12u2"));
}
#[test] fn ubuntu_lts_maps() {
    let p = osv_package("pkg:deb/ubuntu/libc6@2.39-0ubuntu8?upstream=glibc&distro=ubuntu-24.04").unwrap();
    assert_eq!((p.ecosystem.as_str(), p.name.as_str()), ("Ubuntu:24.04:LTS", "glibc"));
}
#[test] fn oci_and_generic_are_not_osv() {
    assert!(osv_package("pkg:oci/postgres@sha256:abc?repository_url=docker.io/library/postgres").is_none());
    assert!(osv_package("pkg:generic/kubernetes@1.31.2").is_none());
}
#[test] fn name_key_strips_version_and_qualifiers() {
    assert_eq!(name_key("pkg:npm/%40vue/core@3.4.0?foo=bar").unwrap(), "pkg:npm/%40vue/core");
}
```

- [ ] **Step 2:** Run `cargo test purl::` and expect FAIL.
- [ ] **Step 3: Implement `osv_package` and `name_key`** using the `packageurl` crate. Strip the `upstream` qualifier's ` (version)` suffix if present. Ubuntu LTS releases (`.04` in even years) get the `:LTS` suffix. Before hard-coding ecosystem strings, check them against `https://osv-vulnerabilities.storage.googleapis.com/ecosystems.txt`. If Ubuntu's format differs, update the test to the real string.
- [ ] **Step 4:** Run `cargo test purl::` and expect PASS.
- [ ] **Step 5: Write the migration and model enums,** then add `#[sqlx::test] async fn migrations_apply(pool: PgPool)` in `src/db.rs` asserting `select count(*) from findings` = 0. Run `cargo test db::` and expect PASS.
- [ ] **Step 6:** Commit with message `feat: schema, model enums, purl mapping`.

---

### Task 3: Version ordering

**Files:**
- Create: `src/version.rs`

**Interfaces:**
- Produces:
  - `version::compare(ecosystem: &str, a: &str, b: &str) -> Option<std::cmp::Ordering>`. Rules: `"Go"` strips a leading `v` then uses semver; `"npm"` uses semver; `"Debian:*"`/`"Ubuntu:*"` uses dpkg; anything else tries lenient semver (pads `X.Y` to `X.Y.0`, strips `v`), otherwise `None`.
  - `version::dpkg_cmp(a: &str, b: &str) -> Ordering`
  - `version::is_major(old: &str, new: &str, major_component: u8) -> bool`: true when numeric component `0..=major_component` of `new` is greater than `old`'s.
  - `version::parse_tag(tag: &str) -> Option<Tag { version: semver::Version, suffix: String }>`, where suffix is everything after the first `-` that follows a numeric `X[.Y[.Z]]` prefix.
  - `version::is_prerelease(v: &str) -> bool`
  - `version::recommend_fix(ecosystem: &str, current: &str, fixed: &[&str]) -> Option<FixAdvice { suggest: String, latest: String }>`: `suggest` is the smallest fixed version > current that shares current's major (per the 0.x rule), otherwise the smallest fixed > current; `latest` is the max fixed.
  - The `is_major` 0.x rule: when old's first component is 0, use component index `major_component + 1`.

- [ ] **Step 1: Write the failing tests**

```rust
#[test] fn dpkg_epoch_tilde_and_revision() {
    use std::cmp::Ordering::*;
    assert_eq!(dpkg_cmp("1:0.9", "2.0"), Greater);
    assert_eq!(dpkg_cmp("1.0~rc1", "1.0"), Less);
    assert_eq!(dpkg_cmp("1.0-1", "1.0-2"), Less);
    assert_eq!(dpkg_cmp("3.0.11-1~deb12u2", "3.0.11-1~deb12u3"), Less);
    assert_eq!(dpkg_cmp("2.39-0ubuntu8", "2.39-0ubuntu8.1"), Less);
}
#[test] fn go_versions_with_v_prefix() {
    assert_eq!(compare("Go", "v1.9.0", "v1.10.0"), Some(std::cmp::Ordering::Less));
}
#[test] fn major_rules() {
    assert!(is_major("17.2", "18.0", 0));
    assert!(!is_major("17.2", "17.3", 0));
    assert!(is_major("1.31.2", "1.32.0", 1));   // Kubernetes: minor is major
    assert!(!is_major("1.31.2", "1.31.3", 1));
    assert!(is_major("v1.31.2+k3s1", "v1.32.0+k3s1", 1));
    assert!(is_major("0.3.9", "0.4.0", 0));        // 0.x: second number is major
    assert!(!is_major("0.3.9", "0.3.10", 0));
    assert!(is_major("0.9.1", "1.0.0", 0));
}
#[test] fn smallest_fix_in_same_major() {
    let fixed = ["2.4.1", "2.5.3", "3.0.0"];
    assert_eq!(recommend_fix("npm", "2.4.0", &fixed), Some(FixAdvice { suggest: "2.4.1".into(), latest: "3.0.0".into() }));
    assert_eq!(recommend_fix("npm", "2.6.0", &["3.0.0"]), Some(FixAdvice { suggest: "3.0.0".into(), latest: "3.0.0".into() }));
}
#[test] fn tags_keep_suffix_and_skip_non_semver() {
    let t = parse_tag("16.4-alpine").unwrap();
    assert_eq!((t.version.to_string().as_str(), t.suffix.as_str()), ("16.4.0", "alpine"));
    assert_eq!(parse_tag("16.4").unwrap().suffix, "");
    assert!(parse_tag("latest").is_none());
    assert!(parse_tag("sha-abc123").is_none());
}
#[test] fn prereleases_detected() {
    assert!(is_prerelease("v1.32.0-rc.1"));
    assert!(is_prerelease("2.0.0-beta.2"));
    assert!(!is_prerelease("v1.32.0+k3s1"));
}
```

- [ ] **Step 2:** Run `cargo test version::` and expect FAIL.
- [ ] **Step 3: Implement.** `dpkg_cmp` follows the Debian Policy §5.6.12 algorithm: compare epoch, then upstream version, then revision. Each part alternates non-digit and digit runs. In non-digit runs, `~` sorts before everything (even the empty string) and letters sort before non-letters. Digit runs compare numerically.
- [ ] **Step 4:** Run `cargo test version::` and expect PASS.
- [ ] **Step 5:** Commit with message `feat: version ordering (semver, go, dpkg), tag parsing`.

---

### Task 4: CycloneDX parsing and direct-dependency manifests

**Files:**
- Create: `src/ingest/mod.rs`, `src/ingest/sbom.rs`, `src/ingest/manifests.rs`
- Test fixtures: `tests/fixtures/sbom/go-service.cdx.json` (real syft output for a small Go module), `tests/fixtures/sbom/nested.cdx.json`, `tests/fixtures/manifests/go.mod`, `tests/fixtures/manifests/pnpm-ws/{package.json,apps/web/package.json,node_modules/x/package.json}`

**Interfaces:**
- Produces:
  - `ingest::sbom::parse(bytes: &[u8]) -> anyhow::Result<ParsedSbom { components: Vec<SbomComponent { purl: String, cpes: Vec<String> }>, skipped_without_purl: usize, image_digest: Option<String> }>`. `cpes` combines the CycloneDX `cpe` field with syft's `properties` named `syft:cpe23`. `image_digest` comes from `metadata.component` when it's a container with a `sha256:` version or digest. Components are deduplicated.
  - `ingest::manifests::direct_name_keys(repo_root: &Path) -> anyhow::Result<Vec<String /*name_key*/>>`

- [ ] **Step 1: Write the failing tests**

```rust
// sbom.rs
#[test] fn nested_components_flattened_and_purlless_counted() {
    let s = parse(include_bytes!("../../tests/fixtures/sbom/nested.cdx.json")).unwrap();
    assert_eq!(s.components.len(), 3);          // fixture: 3 purls incl. one nested
    assert_eq!(s.skipped_without_purl, 1);
}
#[test] fn invalid_json_is_error_not_empty() {
    assert!(parse(b"{not json").is_err());
    assert!(parse(br#"{"bomFormat":"SPDX"}"#).is_err());
}
// manifests.rs
#[test] fn go_mod_direct_only() {
    let keys = direct_name_keys(Path::new("tests/fixtures/manifests")).unwrap();
    assert!(keys.contains(&"pkg:golang/github.com/gin-gonic/gin".to_string()));
    assert!(!keys.iter().any(|k| k.contains("golang.org/x/sys")));   // marked // indirect
}
#[test] fn pnpm_workspace_package_jsons_skip_node_modules() {
    let keys = direct_name_keys(Path::new("tests/fixtures/manifests/pnpm-ws")).unwrap();
    assert!(keys.contains(&"pkg:npm/%40vue/core".to_string()));      // apps/web devDependencies
    assert!(!keys.contains(&"pkg:npm/should-not-appear".to_string())); // node_modules/x
}
```

- [ ] **Step 2:** Run `cargo test ingest::` and expect FAIL.
- [ ] **Step 3: Implement.**
  - `sbom.rs`: plain serde structs for just `bomFormat`, `metadata.component`, `components[].{purl,components}`. Recurse into nested components. Reject anything where `bomFormat != "CycloneDX"`.
  - `manifests.rs`: walk the tree with walkdir, skipping `node_modules` and `.git`. For `go.mod`, handle `require` lines and blocks and skip entries commented `// indirect`. For `package.json`, take `dependencies` + `devDependencies` keys. Encode `@` as `%40` so keys match the purl form.
- [ ] **Step 4:** Run `cargo test ingest::` and expect PASS.
- [ ] **Step 5:** Commit with message `feat: cyclonedx parsing and direct-dependency detection`.

---

### Task 5: Inventory store

**Files:**
- Create: `src/inventory/mod.rs`, `src/inventory/store.rs`

**Interfaces:**
- Consumes: `purl::name_key`, `model::Source`.
- Produces:
  - `store::upsert_service(pool, realm: &str, name: &str) -> anyhow::Result<i64>`
  - `store::replace_components(pool, service_id: i64, source: Source, items: &[InventoryItem]) -> anyhow::Result<ReplaceReport { added: usize, removed: usize }>`. Runs in one transaction; deletes this `(service, source)`'s rows that aren't in `items`.
  - `InventoryItem { purl: String, cpes: Vec<String>, direct: bool, via_image_digest: Option<String> }`. CPEs are stored on `components.cpes` as a union.
  - `store::store_image_sbom(pool, digest: &str, image_ref: &str, purls: &[String]) -> anyhow::Result<()>`
  - `store::pending_image_digests(pool) -> anyhow::Result<Vec<(String /*digest*/, String /*image_ref*/)>>`: digests referenced by any `service_components.via_image_digest` without an `image_sboms` row.
  - `store::sync_declared(pool, declared: &[DeclaredComponent]) -> anyhow::Result<()>`: one `replace_components(Source::Declared)` per service.
  - `store::effective_components(pool, realm: &str) -> anyhow::Result<Vec<EffectiveComponent { service_id, service, component_id, purl, name_key, direct: bool }>>`: union of direct rows for sources git/cluster/declared, plus image components reached through `via_image_digest`. **Excludes `ci`.**

- [ ] **Step 1: Write the failing tests** (`#[sqlx::test(migrations = "./migrations")]`)
  - `replace_removes_missing_and_keeps_other_sources`: replace git with {a, b}, cluster with {c}, then git with {a}. Expect `removed == 1`, effective = {a, c}.
  - `ci_source_not_effective`: replace ci with {x}; effective is empty.
  - `image_components_reach_service`: cluster item `pkg:oci/...` with `via_image_digest = "sha256:d1"`, then `store_image_sbom("sha256:d1", ..., [openssl purl])`. Effective contains openssl for that service. `pending_image_digests` is empty after the store and contained `sha256:d1` before.
- [ ] **Step 2:** Run `cargo test inventory::store` and expect FAIL.
- [ ] **Step 3:** Implement with sqlx queries. Upsert components by `purl`.
- [ ] **Step 4:** Run the tests and expect PASS.
- [ ] **Step 5:** Commit with message `feat: inventory store with replace semantics`.

---

### Task 6: API keys and auth

**Files:**
- Create: `src/auth.rs`, `src/client.rs`
- Modify: `src/main.rs` (`keys create|list|revoke`)

**Interfaces:**
- Produces:
  - `auth::Scope { Ingest, Read, Admin }`. Admin ⊇ Read ⊇ nothing; Ingest is separate, but Admin includes Ingest.
  - `auth::create_key(pool, name: &str, scope: Scope) -> anyhow::Result<String>`. Returns plaintext `hd_` + 43-char base64url of 32 random bytes; stores the SHA-256.
  - `auth::ensure_bootstrap(pool, key: &str) -> anyhow::Result<()>`. Inserts it as `admin` named `bootstrap` if no key with that hash exists.
  - axum extractor `auth::Authed { name: String, scope: Scope }` from `Authorization: Bearer <key>`, plus `auth::require(authed: &Authed, needed: Scope) -> Result<(), ApiError>`.
  - `api::ApiError` (in `src/ingest/api.rs`, re-exported): `IntoResponse` with JSON `{error}` and status 400/401/403/404/413/500.
  - `client::Client::from_env() -> anyhow::Result<Client>` (`HEIMDALL_URL`, `HEIMDALL_API_KEY`), with `get_json<T>`, `post_json<B,T>`, `delete`.

- [ ] **Step 1: Write the failing tests**
  - `create_key_roundtrip`: create an ingest key; build a router with one route needing Ingest; `oneshot` with that key returns 200, with no header returns 401, with a read key returns 403.
  - `admin_includes_ingest_and_read`.
  - `bootstrap_idempotent`: calling it twice leaves one row.
  - `admin_key_only_for_listed_admins`: `create_key(.., "eve", Admin)` with `admins: [mahmoud]` gives an error; `"mahmoud"` gives ok.
  - `delisted_admin_key_rejected`: a key created for `mahmoud`, with config `admins: []`, returns 403 on an Admin route. The extractor checks the current `cfg.admins` for Admin-scope keys; `bootstrap` is always allowed.
- [ ] **Step 2:** Run and expect FAIL.
- [ ] **Step 3:** Implement. Compare hashes by DB lookup on `sha256`.
- [ ] **Step 4:** Run and expect PASS.
- [ ] **Step 5:** Commit with message `feat: api keys with scopes`.

---

### Task 7: Bifröst ingest API

**Files:**
- Create: `src/ingest/api.rs`, `src/server.rs` (router only for now)

**Interfaces:**
- Consumes: Tasks 4–6.
- Produces:
  - `server::router(state: AppState) -> axum::Router`. `AppState { pool: PgPool, cfg: Arc<HeimdallConfig>, http: reqwest::Client }` lives in `lib.rs`.
  - `POST /api/v1/ingest/sbom` (Ingest). Query: `service, realm, branch, default_branch`; body JSON `{ sbom: <cyclonedx>, direct: [name_key] }`. When `branch == default_branch` it uses `Source::Git`, otherwise `Source::Ci`. Returns `{source, added, removed, skipped_without_purl}`. An unknown realm gives 400.
  - `POST /api/v1/ingest/cluster` (Ingest). Body `ClusterInventory { realm, services: Vec<ClusterService { name, items: Vec<InventoryItem> }> }`. Replaces Source::Cluster for each listed service, and also for cluster services in that realm that are **not** listed (they get an empty set: workload removed).
  - `POST /api/v1/ingest/image/{digest}` (Ingest). Query `image_ref`; body: raw CycloneDX.
  - `GET /api/v1/images/pending` (Ingest) returns `[{digest, image_ref}]`.
  - Body limit: **50 MB** on ingest routes.

- [ ] **Step 1: Write the failing tests** (`tower::ServiceExt::oneshot`)
  - `default_branch_upload_is_git`: post the fixture with `branch=main&default_branch=main`; response `source == "git"`, `added > 0`.
  - `feature_branch_upload_is_ci`.
  - `malformed_sbom_400_and_inventory_untouched`: upload good, then post `{not json` and expect 400. Effective components are unchanged.
  - `oversized_body_413`: a 51 MB body returns 413.
  - `cluster_ingest_empties_vanished_services`.
- [ ] **Step 2:** Run and expect FAIL.
- [ ] **Step 3:** Implement the handlers. Build the `direct` flag by checking `name_key(purl)` against the `direct` list.
- [ ] **Step 4:** Run and expect PASS.
- [ ] **Step 5:** Commit with message `feat: bifrost ingest api`.

---

### Task 8: OSV client and severity

**Files:**
- Create: `src/vuln/mod.rs`, `src/vuln/osv.rs`, `src/vuln/severity.rs`
- Fixtures: `tests/fixtures/osv/querybatch.json`, `tests/fixtures/osv/GHSA-*.json` (one with a CVSS v3 vector, one with only `database_specific.severity`, one Debian DSA with `urgency`)

**Interfaces:**
- Consumes: `purl::osv_package`, `store::effective_components`.
- Produces:
  - `severity::normalize(osv_vuln: &serde_json::Value) -> Severity`. Order: CVSS v3/v4 score from `severity[]` (v3 via the `cvss` crate; for v4, if the crate can't score it, fall through), then `database_specific.severity` (GHSA words), then Debian `urgency`/Ubuntu `priority`, then `Unknown`. Score bands: ≥9 critical, ≥7 high, ≥4 medium, >0 low.
  - `osv::OsvClient { base: Url /*https://api.osv.dev*/, http }`:
    - `query_batch(&self, pkgs: &[OsvPackage]) -> anyhow::Result<Vec<Vec<OsvHit { id, modified }>>>`, chunked into 1000 per request, handling `next_page_token` per query.
    - `get(&self, id: &str) -> anyhow::Result<serde_json::Value>`
  - `osv::refresh(pool, client, components: &[(i64 /*component_id*/, String /*purl*/)]) -> anyhow::Result<RefreshReport { checked, new_links, fetched }>`.
    - Upserts `advisories`, fetching full records only when `modified` is newer than stored.
    - Fills `fixed` from `affected[].ranges[].events[].fixed`, keyed by the component's `name_key`.
    - Replaces `component_advisories` for the checked components.

- [ ] **Step 1: Write the failing tests**
  - `severity_from_cvss_v3`: fixture vector `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` gives Critical.
  - `severity_from_ghsa_words`: `"MODERATE"` gives Medium.
  - `severity_from_debian_urgency`: `"high"` gives High.
  - `refresh_links_and_skips_unchanged` (wiremock + sqlx). The first refresh fetches 2 advisories and links them. The second refresh, with identical `modified`, does 0 fetches (assert wiremock `expect(1)` on `/v1/vulns/{id}`).
  - `fixed_versions_recorded`: an advisory with a `fixed: "1.9.1"` event gives `fixed[name_key] == ["1.9.1"]`.
  - `cve_alias_recorded`: GHSA with alias `CVE-2026-1111` gives `advisories.cve_id == "CVE-2026-1111"` and `scores.osv` set.
  - `severity::merge(a, b) -> Severity` returns the higher: `merge(High, Critical) == Critical`.
- [ ] **Step 2:** Run and expect FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run and expect PASS.
- [ ] **Step 5:** Commit with message `feat: osv client, severity normalization, advisory refresh`.

---

### Task 8b: NVD incremental feed and CPE matching

**Files:**
- Create: `src/vuln/nvd.rs`
- Fixtures: `tests/fixtures/nvd/changed_page1.json`, `tests/fixtures/nvd/changed_page2.json`, `tests/fixtures/nvd/backfill_postgresql.json`

**Interfaces:**
- Consumes: `components.cpes`, configured target `cpe` fields, the `advisories` upsert from Task 8.
- Produces:
  - `nvd::NvdClient { base: Url /*https://services.nvd.nist.gov/rest/json/cves/2.0*/, api_key: String, http }`
    - `changed(&self, from: DateTime<Utc>, to: DateTime<Utc>) -> anyhow::Result<Vec<NvdCve>>`: paged by `startIndex`/`resultsPerPage=2000`; windows over 120 days are split; ≥ 0.6 s between requests (50 req / 30 s with a key).
    - `backfill(&self, vendor_product: &str) -> anyhow::Result<Vec<NvdCve>>` using `virtualMatchString=cpe:2.3:*:{vendor}:{product}`.
  - `NvdCve { id, cvss: Option<f32>, severity: Severity, summary, configs: Vec<CpeRange { criteria: String, start_incl, start_excl, end_incl, end_excl: Option<String> }> }`
  - `nvd::cpe_matches(range: &CpeRange, component_cpe: &str, version: &str, ecosystem: &str) -> bool`. Compares vendor and product exactly. A non-`*` version in `criteria` means an exact match; otherwise the version ranges are evaluated with `version::compare` (lenient).
  - `nvd::refresh(pool, client, now) -> anyhow::Result<NvdReport { changed, matched }>`:
    - Window from `kv nvd_last` to `now`; on first run, `now - 1 day`.
    - Backfills each unseen `vendor:product` from component CPEs and target `cpe`s, recording it in `nvd_products`.
    - Matches against all components.
    - Upserts advisories keyed by CVE ID: if an OSV advisory with the same `cve_id` exists, merges `scores.nvd` and severity via `severity::merge`, and sets `match_source = Both` on existing links. Otherwise it inserts an advisory with `id = cve_id` and links it with `match_source = Nvd`.
    - Sets `kv nvd_last = now` only on success.

- [ ] **Step 1: Write the failing tests**
  - `cpe_range_match`: `cpe:2.3:a:postgresql:postgresql:*` with `start_incl 16.0` and `end_excl 16.5` matches 16.4 and not 16.5.
  - `vendor_product_must_match`: product `postgres` ≠ `postgresql`, so no match.
  - `paging_and_window`: two-page fixture gives all CVEs; both requests carry the `apiKey` header.
  - `osv_and_nvd_same_cve_one_advisory_higher_severity`: seeded OSV advisory (High, alias CVE-X) plus NVD CVE-X at 9.8 gives one advisory, severity Critical, scores `{osv, nvd}`, link `match_source == Both`.
  - `nvd_only_link_marked`.
  - `backfill_once_per_product`: the second refresh makes no backfill request (`expect(1)`).
  - `failed_refresh_keeps_window`: on a 503, `kv nvd_last` is unchanged.
- [ ] **Step 2:** Run `cargo test vuln::nvd` and expect FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run and expect PASS.
- [ ] **Step 5:** Commit with message `feat: nvd incremental feed with cpe matching`.

---

### Task 9: GitHub Advisory DB fallback

**Files:**
- Create: `src/vuln/ghsa.rs`
- Fixture: `tests/fixtures/ghsa/graphql_response.json`

**Interfaces:**
- Produces:
  - `ghsa::GhsaClient { base: Url /*https://api.github.com/graphql*/, token: String, http }`
  - `ghsa::covers(pkg: &OsvPackage) -> bool`: true for ecosystems `Go`, `npm`, `PyPI`, `Maven`, `crates.io`, `RubyGems`, `NuGet`, `Packagist`.
  - `GhsaClient::check(&self, pkgs: &[OsvPackage]) -> anyhow::Result<Vec<Vec<GhsaHit { id: String /*GHSA id*/, severity: Severity, fixed: Option<String> }>>>`. Uses GraphQL `securityVulnerabilities(ecosystem:, package:)` with aliases, 50 packages per query, and filters by `vulnerableVersionRange` against the version using `version::compare`.

- [ ] **Step 1: Write the failing tests**
  - `debian_not_covered`, `npm_covered`.
  - `check_filters_by_range` (wiremock): fixture has range `< 1.9.1` for gin; v1.9.0 is a hit and v1.9.1 is not.
- [ ] **Step 2:** Run and expect FAIL.
- [ ] **Step 3:** Implement. The range grammar is GitHub's: comma-separated `>= x`, `< y`, `= z`.
- [ ] **Step 4:** Run and expect PASS.
- [ ] **Step 5:** Commit with message `feat: github advisory fallback client`.

---

### Task 10: Oaths

**Files:**
- Create: `src/oath.rs`
- Modify: `src/server.rs` (routes), `src/main.rs` (`oath snooze|ignore|list|revoke|extend`)

**Interfaces:**
- Produces:
  - `oath::create(pool, req: NewOath { advisory_id, purl /*current component purl*/, service, realm, kind: OathKind, reason: String, until: Option<NaiveDate>, by: String }) -> anyhow::Result<i64>`. Validation:
    - reason not blank
    - snooze requires `until` in the future
    - ignore sets `review_at = now + 90d` unless `until` is given
    - stores `name_key(purl)` and `version_at_creation`
  - `oath::active_for(pool, advisory_id: &str, name_key: &str, service_id: i64, realm: &str) -> anyhow::Result<Option<Oath>>`
  - `oath::process_expiries(pool, now: DateTime<Utc>) -> anyhow::Result<Vec<Oath>>`: marks due oaths `expired`, writes an `oath_events` row, and returns the oaths that just expired. Idempotent: an already-expired oath is never returned again.
  - `oath::revoke(pool, id, by)`, `oath::extend(pool, id, until, by)`
  - Routes (Admin for writes, Read for list): `POST /api/v1/oaths`, `GET /api/v1/oaths?status=`, `POST /api/v1/oaths/{id}/revoke`, `POST /api/v1/oaths/{id}/extend`. The `by` field is the API key's name.
  - CLI: `heimdall oath snooze <ADVISORY> --service S --realm R --purl P --until YYYY-MM-DD --reason "..."`; `oath ignore` takes the same arguments without `--until`.

- [ ] **Step 1: Write the failing tests**
  - `blank_reason_rejected`, `snooze_requires_future_until`.
  - `ignore_defaults_review_90_days`.
  - `active_matches_any_version_of_same_name`: oath taken on `gin@v1.9.0`; `active_for` with name_key `pkg:golang/github.com/gin-gonic/gin` returns Some. (Carrying across versions works because the scope is name_key; the "carried" digest note is Task 14.)
  - `expiry_processed_once_after_downtime`: oath until yesterday. Run `process_expiries` at now and it returns 1; run it again and it returns 0.
  - `all_realms_oath_applies_everywhere`: `NewOath.all_realms = true` stores `realm = NULL`; `active_for(.., realm="prod")` returns it. A per-realm oath for `dev-k3s` is not returned for `prod`.
  - `NewOath` gains `all_realms: bool`; the CLI gains `--all-realms`, which conflicts with `--realm`.
- [ ] **Step 2:** Run and expect FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run and expect PASS.
- [ ] **Step 5:** Commit with message `feat: oaths (snooze/ignore) with expiry processing`.

---

### Task 11: Matcher (findings)

**Files:**
- Create: `src/matcher.rs`

**Interfaces:**
- Consumes: `store::effective_components`, `advisories`/`component_advisories`, `oath::active_for`, `oath::process_expiries`, `version::compare`.
- Produces:
  - `matcher::run(pool, realm: &str, now: DateTime<Utc>) -> anyhow::Result<MatchReport { opened: Vec<i64 /*finding ids*/>, resolved: usize }>`.
  - Finding keys (text, built only by `matcher::key(kind, parts: &[&str]) -> String` joined with `|`):
    - Vuln: `vuln|realm|service|name_key|advisory`. Severity from the advisory. `details` = `{purl, version, fixed: [..], advice: Option<FixAdvice>, oath: Option<id>, direct: bool, match_source, scores}`.
    - FixAvailable: `fix|realm|service|name_key|advisory`. Opened when an affected component's advisory has a fixed version greater than the current one. Fires even under an oath.
    - OathExpired: `oath_expired|oath_id`, for each oath returned by `process_expiries`.
  - Findings that are open but not produced this run are set to `resolved` (except MajorRelease/Eol/K8sCve, which are owned by watchers in Task 13).
  - `notified_at` stays null for new findings. Vuln findings under an active oath are inserted with `details.oath` set and are **not** alertable (Task 14 reads this).

- [ ] **Step 1: Write the failing tests** (seed tables directly)
  - `vuln_opened_once_and_stable`: two runs give one row; the second run's `opened` is empty.
  - `vuln_resolves_when_component_removed`: replace inventory without the component, run, and status is `resolved`.
  - `fix_available_when_fixed_version_greater`: current v1.9.0, fixed ["1.9.1"] gives a FixAvailable finding. Current v1.9.2 gives no vuln (OSV wouldn't link it) and no FixAvailable.
  - `fix_available_even_under_oath`.
  - `oath_expired_finding_from_expiry`.
  - `ci_inventory_produces_no_findings`.
  - `fix_available_for_indirect_has_direct_false`.
  - `advice_uses_recommend_fix`: details `advice.suggest == "2.4.1"`, `latest == "3.0.0"`.
  - `nvd_link_produces_vuln_with_match_source_nvd`.
- [ ] **Step 2:** Run and expect FAIL.
- [ ] **Step 3:** Implement as a few SQL queries plus Rust joins. Clarity beats cleverness.
- [ ] **Step 4:** Run and expect PASS.
- [ ] **Step 5:** Commit with message `feat: matcher producing deduplicated findings`.

---

### Task 12: Hofund (CI gate)

**Files:**
- Create: `src/gate.rs`
- Modify: `src/server.rs`, `src/main.rs`

**Interfaces:**
- Consumes: Tasks 4, 5, 7, 8, 9, 10.
- Produces:
  - `POST /api/v1/gate` (Ingest). Query and body are the same as `/ingest/sbom` plus `fail_on: Severity`. The server:
    1. ingests (same code path)
    2. queries OSV live for the uploaded components (timeout 60 s total)
    3. on OSV error or timeout, queries GHSA for covered ecosystems; components in uncovered ecosystems become `unverified`
    4. applies oaths
  - Response: `GateResponse { verdict: "pass"|"fail"|"unverified", source: "osv"|"ghsa", findings: Vec<GateFinding { advisory, severity, purl, fixed: Option<String>, oath: Option<i64> }>, unverified: Vec<String> }`.
  - Verdict rules: `fail` if any finding ≥ fail_on without an oath; else `unverified` if `unverified` is non-empty; else `pass`.
  - CLI `heimdall gate --service S --realm R --sbom FILE --fail-on high [--repo-root .] [--branch B] [--default-branch D]`:
    - `branch` defaults to `$GITHUB_REF_NAME`.
    - `default_branch` defaults to the `repository.default_branch` read from the JSON file at `$GITHUB_EVENT_PATH`.
    - `direct` is computed with `direct_name_keys(repo_root)`.
    - Prints a table: severity, advisory, package, version → fixed, oath.
    - Exit code `0` pass, `1` fail, `2` unverified or the server is unreachable.

- [ ] **Step 1: Write the failing tests**
  - `gate_fails_on_high` (wiremock OSV gives a high advisory): verdict fail.
  - `gate_passes_when_oathed`.
  - `osv_down_falls_back_to_ghsa_pass` (OSV mock returns 503, GHSA mock returns no hits, npm-only SBOM): verdict pass, source ghsa.
  - `osv_down_with_debian_components_unverified`: verdict unverified, and `unverified` lists the deb purls.
  - CLI unit test `exit_code_mapping`: pass→0, fail→1, unverified→2.
  - `default_branch_from_event_file`: temp file `{"repository":{"default_branch":"main"}}` gives "main".
- [ ] **Step 2:** Run and expect FAIL.
- [ ] **Step 3:** Implement. The gate's live OSV query reuses `OsvClient` and doesn't wait for the 15-min refresh.
- [ ] **Step 4:** Run and expect PASS.
- [ ] **Step 5:** Commit with message `feat: hofund ci gate with osv->ghsa fallback`.

---

### Task 13: Watchers and the Kubernetes CVE feed

**Files:**
- Create: `src/watchers/{mod,github,endoflife,oci,helm,tf_registry,go_proxy,npm}.rs`, `src/vuln/k8s_feed.rs`
- Fixtures: one recorded response per source under `tests/fixtures/watchers/`

**Interfaces:**
- Produces:
  - `watchers::ReleaseInfo { version: String, published_at: Option<DateTime<Utc>> }`
  - One free function per source, each taking `(http, base: &Url, …, etag: Option<&str>) -> anyhow::Result<Fetched { releases: Vec<ReleaseInfo>, etag: Option<String>, not_modified: bool }>`:
    - `github::fetch(repo)`: `GET /repos/{repo}/releases?per_page=30`, drops `prerelease` and `draft`; Bearer token from `GITHUB_TOKEN`.
    - `endoflife::fetch(product) -> Vec<Cycle { cycle, latest, eol: Option<NaiveDate> }>` from `GET https://endoflife.date/api/{product}.json`. Before relying on that path, check whether endoflife.date's v1 path (`/api/v1/products/{product}`) is current.
    - `oci::tags(registry_host, repository, creds: Option<&RegistryCred>)`: OCI distribution `GET /v2/{repo}/tags/list` with the bearer-token handshake (Docker Hub uses `auth.docker.io`).
    - `helm::fetch_index(repo_url)` → chart versions; OCI charts use `oci::tags`.
    - `tf_registry::fetch(registry, kind, source)`: `GET /v1/providers/{ns}/{name}/versions` or `/v1/modules/{ns}/{name}/{provider}/versions`.
    - `go_proxy::fetch(module)`: `GET https://proxy.golang.org/{escaped}/@v/list`, where escaping uppercases with `!`.
    - `npm::fetch(name)`: `GET https://registry.npmjs.org/{name}` → `versions` + `time`.
  - `k8s_feed::fetch(http, base) -> Vec<K8sCve { id, summary, url, published }>` from `https://kubernetes.io/docs/reference/issues-security/official-cve-feed/index.json`.
  - `watchers::run_all(state: &AppState, now) -> anyhow::Result<WatchReport>`. For each target:
    - Inventory-derived targets: images (`pkg:oci` name_key → registry/repo, current tag from the purl `tag` qualifier); charts (`pkg:helm` from Sight); and direct `golang`/`npm` libraries only.
    - Configured targets come from `cfg.watchers`.
    - Stores new `releases`. Uses and updates `watcher_state.etag`.
    - Opens findings:
      - MajorRelease, key `major|target|version`, when `is_major(current, new, major_component)` and the release is not a prerelease. For images, compare only tags with the **same suffix**.
      - Eol, key `eol|realm|target|cycle`, when the running cycle's `eol` is within 60 days.
    - Minor/patch releases are recorded only, for the digest.
  - `k8s_feed::run(pool, realm)`: for each feed CVE not seen before, opens a K8sCve finding, key `k8scve|realm|id`, severity `High`. It only does this if the realm has a `pkg:generic/kubernetes` or `pkg:generic/k3s` component.
  - Each target is checked independently; one failing target logs, increments `heimdall_watcher_failures_total{watcher}`, and doesn't stop the others.

- [ ] **Step 1: Write the failing tests** (wiremock + sqlx)
  - `github_skips_prereleases_and_drafts`.
  - `github_304_not_modified_uses_etag`: the second call sends `If-None-Match`; the mock returns 304, giving `not_modified`.
  - `oci_major_only_same_suffix`: current tag `16.4-alpine`; tags `[16.5-alpine, 17.0-alpine, 17.0-bookworm, latest]` give exactly one MajorRelease finding, for `17.0-alpine`.
  - `k8s_minor_is_major`: target kubernetes, current 1.31.2, release v1.32.0 gives a MajorRelease finding.
  - `eol_within_60_days`: cycle `16` with eol today+30 while running 16.4 gives an Eol finding; eol today+90 gives none.
  - `transitive_libraries_not_watched`: an npm component with `direct=false` makes no request to the npm mock (`expect(0)`).
  - `one_target_failure_does_not_stop_others`.
  - `go_module_path_escaping`: `github.com/BurntSushi/toml` becomes `github.com/!burnt!sushi/toml`.
  - `k8s_cve_once_per_realm`.
  - `own_registry_images_not_watched`: with `own_registries: [ghcr.io/acme]`, no tag request is made for `ghcr.io/acme/api`, but one is made for `docker.io/library/postgres`.
  - `zero_x_minor_is_major`: a direct npm lib at 0.3.9 with release 0.4.0 gives a MajorRelease finding.
- [ ] **Step 2:** Run and expect FAIL.
- [ ] **Step 3:** Implement the source functions first, then `run_all`. Keep each source file under ~150 lines.
- [ ] **Step 4:** Run and expect PASS.
- [ ] **Step 5:** Commit with message `feat: release watchers, eol, kubernetes cve feed`.

---

### Task 13b: Release notes

**Files:**
- Create: `src/watchers/notes.rs`
- Modify: `src/watchers/mod.rs` (call it for every newly stored release)
- Fixtures: `tests/fixtures/notes/{gh_release_security.json,gh_release_bugfix.json,gh_release_breaking.json,npm_pkg_repo.json,artifacthub_chart.json}`

**Interfaces:**
- Consumes: releases stored by Task 13; open Vuln findings (to know which IDs currently affect us).
- Produces:
  - `notes::locate(target: &WatchTarget, http) -> anyhow::Result<Option<NotesSource>>`, where `NotesSource { GithubRepo(String), ArtifactHub { repo: String, chart: String } }`. Lookup order:
    1. configured `repo`/GitHub target
    2. npm `repository.url` → github.com owner/repo
    3. Go module path starting `github.com/` (first two path segments)
    4. OCI config label `org.opencontainers.image.source`, read from the image config blob via `oci`
    5. charts via Artifact Hub `GET /api/v1/packages/helm/{repo}/{chart}/{version}` → `changes`
  - `notes::fetch(source, version, http) -> anyhow::Result<Option<Notes { url: String, body: String }>>`. GitHub `GET /repos/{r}/releases/tags/{tag}` tries `v{version}` then `{version}`.
  - `notes::classify(body: &str, affecting_ids: &HashSet<String>) -> Classified { class: NotesClass, mentioned_ids: Vec<String>, fix_lines: Vec<String> /*≤5*/, breaking_lines: Vec<String> /*≤5*/ }`
    - IDs: regex `CVE-\d{4}-\d{4,}` and `GHSA(-[23456789cfghjmpqrvwx]{4}){3}`, case-insensitive, uppercased.
    - Class precedence: `CveAffecting` (any mentioned ID in `affecting_ids`, also matching via advisory aliases), then `Security` (any ID, or the words security/vulnerability/exploit), then `Bugfix` (lines starting with `fix`/`fixed`/`bug`, or under a "Bug Fixes"/"Fixes" heading), then `Plain`. `None` when there are no notes.
    - Breaking lines: lines containing `breaking` or under a "Breaking" heading.
  - Stores into the `releases` columns. `CveAffecting` opens finding `ReleaseNoteCve`, key `relnote|target|version|id` per affecting ID, severity = that advisory's severity, `details {notes_url, id, services}`.

- [ ] **Step 1: Write the failing tests**
  - `classify_cve_affecting`: body "Fixes CVE-2026-1234" with affecting `{CVE-2026-1234}` gives CveAffecting.
  - `classify_ghsa_lowercase_normalised`.
  - `classify_security_not_affecting`: body mentions CVE-2026-9999, not in the set, gives Security.
  - `classify_bugfix_lines_capped_at_5`.
  - `breaking_lines_extracted`.
  - `locate_npm_repository_url`: `git+https://github.com/vuejs/core.git` gives `vuejs/core`.
  - `fetch_tries_v_prefix_then_plain` (wiremock: 404 on `v1.2.3`, 200 on `1.2.3`).
  - `no_notes_class_none`.
  - `release_note_cve_finding_opened_once`.
- [ ] **Step 2:** Run `cargo test watchers::notes` and expect FAIL.
- [ ] **Step 3:** Implement with the `regex` crate.
- [ ] **Step 4:** Run and expect PASS.
- [ ] **Step 5:** Commit with message `feat: release notes lookup and classification`.

---

### Task 14: Gjallarhorn (Teams outbox, grouping, digest)

**Files:**
- Create: `src/notify/{mod,outbox,teams,digest}.rs`

**Interfaces:**
- Consumes: the findings table (Tasks 11 and 13), `cfg.teams`, `cfg.digest`.
- Produces:
  - `notify::enqueue_alerts(pool, cfg) -> anyhow::Result<usize>`:
    - Selects open findings with `notified_at IS NULL` that are alertable:
      - Vuln: severity ≥ High and no `details.oath`
      - FixAvailable, MajorRelease, OathExpired, Eol, K8sCve: always
    - Groups them by `(kind, ref_id)` into one card each, listing every affected realm/service/purl/version→fixed.
    - Routes to every `TeamsRoute` whose `realms` is empty or contains the realm and whose `min_severity` ≤ the card's severity. MajorRelease and Eol count as High for routing.
    - Inserts one `outbox` row per route and sets `notified_at`, in **one transaction**.
    - Non-alertable findings get `notified_at` set when the digest that contains them is sent.
  - `notify::enqueue_first_run_summary(pool, cfg, realm)`: once per realm, guarded by `kv` key `first_run|realm`. It's queued **before** the first `enqueue_alerts`. The card is titled "Heimdall has opened his eyes" and shows open findings counted by severity.
  - `teams::card(group: &AlertGroup) -> serde_json::Value`: the Workflows payload `{"type":"message","attachments":[{"contentType":"application/vnd.microsoft.card.adaptive","content":{AdaptiveCard 1.4}}]}`.
    - Titles:
      - Vuln: "⚠ {advisory} ({severity}) affects {n} service(s)"
      - FixAvailable: "Fix available: upgrade {pkg} {from} → {to} fixes {advisory}"
      - MajorRelease: "{target} {version} released (major)"
      - OathExpired: "Oath expired: {advisory} on {service}"
      - Eol: "{target} {cycle} reaches end of support on {date}"
      - K8sCve: "Kubernetes security advisory {id}"
    - The body has a FactSet per affected service, plus a link to the advisory (`https://osv.dev/vulnerability/{id}`).
  - `outbox::drain_once(pool, http, cfg, now) -> anyhow::Result<DrainResult { sent: usize, retry: usize }>`:
    - Sends **at most one** due row; the caller loops every 2 s.
    - On 2xx it sets `sent_at`.
    - On 429 or 5xx it sets `attempts += 1` and `next_attempt_at = now + max(Retry-After, 30s × 2^attempts capped at 1h)`.
    - On other 4xx it logs an error, sets `sent_at` with `card.failed = true`, and increments `heimdall_teams_failures_total`.
    - Webhook URL comes from env var `route.webhook_env`.
  - `digest::maybe_send(pool, cfg, now) -> anyhow::Result<bool>`:
    - Runs when `now` in `cfg.digest.timezone` is on the configured weekday and hour, and `kv` key `digest_last` is not today.
    - Card content:
      - medium/low/unknown vuln findings opened since the last digest
      - minor/patch releases recorded since the last digest
      - active oaths with expires/review dates, flagging "carried to new version X" when the current component version ≠ `version_at_creation`
    - Enqueues one outbox row per route.

- [ ] **Step 1: Write the failing tests**
  - `one_card_per_advisory_across_services`: the same advisory in 3 services gives 1 outbox row for 1 route.
  - `oathed_vuln_not_alerted_but_fix_available_is`.
  - `medium_not_immediate`.
  - `enqueue_is_idempotent`: the second call gives 0.
  - `first_run_summary_once_and_first`: the summary's outbox id < the first alert's outbox id; a second call enqueues nothing.
  - `drain_429_honours_retry_after` (wiremock returns 429 with `Retry-After: 120`): `next_attempt_at == now + 120s` and `sent_at` is null.
  - `drain_sends_exactly_once_after_restart`: a sent row isn't sent again by a fresh `drain_once`.
  - `digest_monday_9_once`: Monday 09:10 in the configured timezone gives true; the same day again gives false; Tuesday gives false.
  - `digest_flags_carried_oath`.
  - `card_snapshot`: `teams::card` for a fixture group matches `tests/fixtures/teams/vuln_card.json`.
  - Card additions from the grill decisions, each with a test asserting the text is present:
    - `card_labels_indirect`: "indirect dependency" when `details.direct == false`.
    - `card_labels_nvd_only`: "NVD match only, verify" when `match_source == Nvd` and the component is a library (purl type not `generic`/`oci`).
    - `card_shows_both_scores`: "OSV 7.5 · NVD 9.8" when both are present.
    - `fix_card_shows_advice`: "upgrade to 2.4.1 (latest 3.0.0)".
    - `major_card_quotes_breaking_lines` (≤ 5) plus a notes link.
    - `release_note_cve_card`: title "{target} {version} release notes mention {id} (affects {services})". `ReleaseNoteCve` is always alertable.
  - Digest additions:
    - `digest_lists_release_notes_by_class`: sections for security, then bug fixes (first fix lines), then other, then "no release notes found".
    - `digest_lists_declared_since`: "postgres-vm: postgresql 17.2, declared since 2026-11-13".
- [ ] **Step 2:** Run and expect FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run and expect PASS.
- [ ] **Step 5:** Commit with message `feat: gjallarhorn teams alerts, outbox, weekly digest`.

---

### Task 15: Sight (cluster scanner)

**Files:**
- Create: `src/inventory/sight.rs`
- Modify: `src/main.rs` (`heimdall sight --realm R [--push URL]`)
- Fixtures: `tests/fixtures/k8s/{pods,deployments,nodes,argo_apps}.json`, `version.json`

**Interfaces:**
- Consumes: `ClusterInventory`/`ClusterService`/`InventoryItem` (Task 7).
- Produces:
  - Pure builder `sight::build_inventory(realm: &str, objs: &ClusterObjects { pods, workloads /*Deployments, StatefulSets, DaemonSets as DynamicObject*/, nodes, argo_apps, server_version }) -> ClusterInventory`:
    - **Service name:** pod annotation `heimdall.io/service`, then label `app.kubernetes.io/name`, then the owner workload's name (ReplicaSet → Deployment via the pod-template-hash convention: strip the last `-hash`), then the pod name.
    - **Images:** each container status `imageID` digest becomes item `pkg:oci/{repo_last}@{digest}?repository_url={registry/repo}&tag={tag}` with `via_image_digest = digest`. A missing tag means no tag qualifier.
    - **Charts:** the workload label `helm.sh/chart = name-1.2.3` becomes `pkg:helm/{name}@1.2.3` on that service. Each ArgoCD Application with `spec.source.chart` becomes `pkg:helm/{chart}@{targetRevision}` on a service named after the app.
    - **Cluster versions:** go on the synthetic service `cluster`. `server_version.gitVersion` containing `+k3s` gives `pkg:generic/k3s@{gitVersion}` plus `pkg:generic/kubernetes@{semver part}`. Node `osImage` "Ubuntu 24.04.1 LTS" gives `pkg:generic/ubuntu@24.04.1`, and the same for Debian.
  - `sight::collect(client: kube::Client) -> anyhow::Result<ClusterObjects>`: list only, all namespaces. ArgoCD CRD absence is OK (empty list).
  - `sight::run(state, realm)`: in-process `collect` → `build_inventory` → the same handler logic as `/ingest/cluster`. `--push` POSTs to a remote Bifröst instead (scout mode).
  - RBAC needed (used by Task 18): `get,list` on `pods, nodes`, `deployments, statefulsets, daemonsets, replicasets`, `applications.argoproj.io`. **No secrets.**

- [ ] **Step 1: Write the failing tests** (pure, fixtures)
  - `service_name_precedence`: annotation > label > deployment name.
  - `image_digest_and_tag_extracted`: `docker.io/library/postgres:16.4-alpine@sha256:…` gives repository_url `docker.io/library/postgres`, tag `16.4-alpine`.
  - `helm_chart_label_parsed`: `kube-prometheus-stack-65.1.0` gives name `kube-prometheus-stack`, version `65.1.0` (split at the last `-` followed by a digit).
  - `k3s_version_yields_both`.
  - `ubuntu_node_os`.
  - `same_image_in_two_pods_one_item_per_service`.
- [ ] **Step 2:** Run and expect FAIL.
- [ ] **Step 3:** Implement. `collect` is thin and not unit-tested. It's verified in Task 18 against k3s.
- [ ] **Step 4:** Run and expect PASS.
- [ ] **Step 5:** Commit with message `feat: sight cluster inventory`.

---

### Task 16: Image SBOM scanner job

**Files:**
- Create: `src/scan_images.rs`, `deploy/Dockerfile.scanner`
- Modify: `src/main.rs` (`heimdall scan-images [--max N] [--syft PATH]`)

**Interfaces:**
- Consumes: `GET /api/v1/images/pending`, `POST /api/v1/ingest/image/{digest}`, `client::Client`.
- Produces: `scan_images::run(client, syft: &Path, max: usize) -> anyhow::Result<ScanReport { scanned, failed }>`.
  - For each pending item, up to `max` (default 20), it runs `syft registry:{image_ref}@{digest} -o cyclonedx-json` with the env `DOCKER_CONFIG` passed through, then uploads.
  - A failing image is logged and counted; the job continues. The exit code is non-zero only if all images failed.

- [ ] **Step 1: Write the failing test.** `scans_pending_and_continues_on_failure` uses wiremock for the API and a fake `syft` shell script in a tempdir that prints a fixture SBOM, or exits 1 for a digest containing `bad`. Expect `scanned == 1`, `failed == 1`, and one upload received.
- [ ] **Step 2:** Run and expect FAIL.
- [ ] **Step 3:** Implement with `tokio::process::Command`. `Dockerfile.scanner` is alpine plus a pinned syft release binary plus the static `heimdall` binary.
- [ ] **Step 4:** Run and expect PASS.
- [ ] **Step 5:** Commit with message `feat: image sbom scanner job`.

---

### Task 17: `serve` wiring, read API, telemetry, metrics

**Files:**
- Create: `src/telemetry.rs`
- Modify: `src/server.rs`, `src/main.rs`

**Interfaces:**
- Consumes: everything above.
- Produces:
  - `telemetry::init(service_name: &str) -> anyhow::Result<Guard>`. The OTLP exporter is enabled only when `OTEL_EXPORTER_OTLP_ENDPOINT` is set; otherwise JSON logs go to stdout. `RUST_LOG` filter, default `info`.
  - `GET /metrics` (no auth, cluster-internal) with these metrics:
    - `heimdall_findings_open{realm,service,kind,severity}`
    - `heimdall_versions_behind{realm,target}`: count of newer non-prerelease releases than the running one
    - `heimdall_watcher_failures_total{watcher}`
    - `heimdall_watcher_duration_seconds{watcher}`
    - `heimdall_teams_failures_total`
    - `heimdall_outbox_pending`
    - `heimdall_oaths_active{kind}`
    - `heimdall_oath_next_expiry_timestamp_seconds`

    Gauges are recomputed after each matcher run.
  - Read API (Read scope): `GET /api/v1/findings?realm=&status=open&kind=&min_severity=`, `GET /api/v1/services?realm=`, `GET /api/v1/services/{id}/components`, `GET /api/v1/releases?target=&since=`. CLI: `heimdall findings`, `heimdall realms`.
  - `GET /healthz` checks the DB ping.
  - `server::serve(cfg_path) -> anyhow::Result<()>`. Startup sequence:
    1. config
    2. telemetry
    3. pool + migrations
    4. bootstrap key (`HEIMDALL_BOOTSTRAP_ADMIN_KEY`)
    5. `sync_declared`
    6. HTTP on `0.0.0.0:8080`
    7. spawn loops

    Loops (each `tokio::time::interval` with `MissedTickBehavior::Skip`; errors are logged and never kill the loop; first tick immediate):
    - Sight, every 15 min per realm with a cluster (dev-k3s in-process)
    - OSV refresh + matcher + `enqueue_alerts`, every 15 min
    - k8s feed, every 30 min
    - watchers + `enqueue_alerts`, every 60 min
    - oath expiry + matcher, every 15 min
    - outbox drain, every 2 s
    - digest check, every 1 min
    - NVD refresh + matcher + `enqueue_alerts`, every 120 min
    - retention cleanup, daily. `retention::cleanup(pool, cfg, now)` deletes resolved findings older than 365 days, releases older than 365 days and sent outbox rows older than 30 days, and **never touches oaths or oath_events**. Test `retention_keeps_oaths`.

    **First-run order per realm:** Sight, then OSV refresh, then matcher, then `enqueue_first_run_summary`, then `enqueue_alerts`.

- [ ] **Step 1: Write the failing tests**
  - `metrics_endpoint_exposes_findings_gauge`: seed one open high finding, recompute, and `/metrics` contains `heimdall_findings_open{` with `severity="high"} 1`.
  - `findings_filter_min_severity`.
  - `healthz_ok`.
- [ ] **Step 2:** Run and expect FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run `cargo test` (whole suite) and expect PASS.
- [ ] **Step 5: Smoke test locally.** Run `docker compose -f docker-compose.dev.yml up -d`, then `HEIMDALL_BOOTSTRAP_ADMIN_KEY=hd_test cargo run --release -- serve heimdall.example.yaml`, then `curl localhost:8080/healthz`. Expect `ok` and log lines from each loop.
- [ ] **Step 6:** Commit with message `feat: serve scheduler, read api, telemetry, metrics`.

---

### Task 18: Packaging, Helm chart, GitHub Action, README, k3s verification

**Files:**
- Create:
  - `deploy/Dockerfile` (multi-stage: `cargo build --release` with musl, or the `gcr.io/distroless/static`-compatible target)
  - `deploy/helm/heimdall/{Chart.yaml,values.yaml,templates/{deployment,service,configmap,clusterrole,clusterrolebinding,serviceaccount,cronjob-scan-images,servicemonitor,ingress}.yaml}`
  - `.github/actions/gate/action.yml`
  - `README.md`
- Modify: `.github/workflows/ci.yml` (build multi-arch images on tag)

**Interfaces:**
- Helm values:
  - `image`, `scannerImage`, `config` (rendered into the ConfigMap as `heimdall.yaml`), `existingSecret` (keys: `DATABASE_URL`, `GITHUB_TOKEN`, `TEAMS_WEBHOOK_*`, `HEIMDALL_BOOTSTRAP_ADMIN_KEY`; SOPS-managed outside the chart)
  - `resources` (default limits `memory: 1Gi, cpu: 1`; requests `256Mi, 100m`)
  - `scanImages.schedule` (default `"0 */6 * * *"`), `scanImages.resources`, `scanImages.dockerConfigSecret`
  - `serviceMonitor.enabled` (true), `ingress.enabled` (**false**)
- GitHub Action inputs: `service`, `realm`, `path` (default `.`; monorepos call the action once per service), `fail-on` (default `high`), `heimdall-url`, `api-key`, `version`. syft scans `dir:${path}`, and the gate uses `--repo-root ${path}`.
- Secrets add `NVD_API_KEY`. Steps:
  1. download the `heimdall` release binary
  2. install syft
  3. `syft dir:. -o cyclonedx-json > sbom.json`
  4. `heimdall gate ...`
- README: what Heimdall is; the theme vocabulary table (spec §3); quick start; config reference; "how to add a watcher target" (config only) and "how to add a watcher type" (new file in `src/watchers/` + a line in `run_all`); oath CLI examples; GitHub Action example for self-hosted runners.

- [ ] **Step 1:** Run `helm lint deploy/helm/heimdall && helm template deploy/helm/heimdall | kubectl apply --dry-run=client -f -`. Expect no errors. Confirm the ClusterRole has no `secrets` rule: `helm template … | grep -c secrets` prints `0` for the ClusterRole document.
- [ ] **Step 2:** Run `docker build -f deploy/Dockerfile -t heimdall:dev . && docker build -f deploy/Dockerfile.scanner -t heimdall-scanner:dev .`. Expect both to succeed. Check the final heimdall image size is < 50 MB.
- [ ] **Step 3: Deploy to k3s.** Import the images into k3s and install the chart pointing at the Postgres VM. Then:
  - `kubectl top pod` after 1 h shows memory **≤ 256 Mi**.
  - Logs show Sight found services, the OSV refresh ran, and the watchers ran.
  - The Teams channel got the "Heimdall has opened his eyes" card, then grouped alerts.
- [ ] **Step 4:** Run the gate action from a test repo on a self-hosted runner, with a dependency that has a known high CVE. Expect the job to fail with exit code 1 and the table to show the advisory. Run `heimdall oath snooze …`, re-run, and expect the job to pass.
- [ ] **Step 5:** Commit with message `feat: docker images, helm chart, github action, readme`.
