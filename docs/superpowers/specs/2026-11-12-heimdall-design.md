# Heimdall — Design

*Date: 2026-11-12 · Status: draft for review*

> Heimdall guards the Bifröst, sees across all the realms, hears the grass grow,
> and sounds the Gjallarhorn when danger comes. This tool does the same for a
> software stack: it watches every dependency in every environment and warns
> early, once, and only when it matters.

## 1. Intent

A lightweight replacement for OWASP Dependency-Track, written in Rust, that fits
in **1 GB RAM / 1 CPU** inside a Kubernetes cluster. Dependency-Track's Java
server needs ~4 GB, its UI is unfriendly, and it treats *new versions* as an
afterthought. Heimdall makes two things first-class:

1. **Vulnerabilities**: know about critical/high CVEs affecting anything we run,
   as soon as public databases publish them.
2. **Releases**: know when anything we depend on (libraries, images, charts,
   infra software, OSes, Kubernetes itself) ships a major version, or a version
   that fixes a CVE we are exposed to.

It is a clean-room implementation. Dependency-Track (Apache 2.0) is a reference
for concepts only; no code is ported.

The owner is new to Rust and is relying on Claude to write the code for now.
**The code must stay readable for a Rust learner** (see §9).

## 2. Phases

| Phase | Scope |
|---|---|
| **1 (this design)** | Rust backend + CLI: inventory, vulnerability matching, release watchers, Teams alerts, CI gate, suppressions, metrics. No web UI. |
| 2 | Friendly web UI over the same API; Grafana dashboards from Heimdall's metrics. |
| 3 | New features: production realm (EKS/RDS checks), drift reports, AWS "What's New" feed, CHANGELOG.md fallback, AI release-note summaries, others TBD. (NVD and release notes moved into phase 1; see §12.) |

## 3. Vocabulary (the Heimdall theme)

User-facing names (CLI, docs, Teams messages, metrics) use the theme. **Code
modules use plain descriptive names** so a Rust learner can navigate; the
mapping lives here and in the README.

| Theme name | Meaning | Code module |
|---|---|---|
| **Realm** | An environment/cluster (`dev-k3s` now; `prod` later) | `realm` |
| **Bifröst** | The ingest API: everything entering Heimdall crosses it (SBOM uploads, cluster inventory) | `ingest` |
| **Sight** | Inventory scanning: what is actually running (cluster scanner + image SBOM job) | `inventory` |
| **Watchers** ("Heimdall hears the grass grow") | Pollers for new releases and new advisories | `watchers` |
| **Gjallarhorn** | The notifier: Teams alerts and the weekly digest | `notify` |
| **Hofund** (Heimdall's sword) | The CI gate that blocks a build at the bridge | `gate` |
| **Oath** | A suppression: ignore or snooze a CVE, with a reason | `suppression` |

CLI: `heimdall serve`, `heimdall gate`, `heimdall oath snooze ...`, `heimdall realms`, etc.

## 4. Goals

- One container, steady-state RSS **≤ 256 MB**, hard limit 1 GB / 1 CPU. Postgres external.
- Detect a new critical/high advisory affecting inventory within **≤ 30 min** of its appearance in OSV.
- Every alert fires **once per (component, service, realm, reason)**; re-fires only on state change (fix released, oath expired, severity raised).
- Adding a new thing to track is a **config entry**, not new Rust code, for any source type already supported.
- CI gate returns a verdict **synchronously** (no client-side polling as in Dependency-Track).
- Observable like any other service: OTLP traces/logs to the OTel collector, Prometheus `/metrics`.

## 5. Non-goals (phase 1)

- Web UI (phase 2).
- Production realm, EKS/RDS API checks, AWS "What's New" feed, NVD mirror, drift reports (phase 3). The data model must not block them (§7).
- Running image scanning inside the main pod.
- License compliance and policy engine beyond the severity gate.
- Multi-tenant / SSO / LDAP.

## 6. Anti-goals (would be failure even if it "works")

- **Alert fatigue**: if the Teams channel gets muted, Heimdall has failed.
- **Exceeding the budget**: if it needs more than 1 GB, it has failed its reason to exist.
- **Silent ignores**: a suppressed CVE must never become invisible or permanent without review.
- **Clever Rust**: code the owner cannot read and maintain.

## 7. Architecture

```
          CI pipelines                        k3s cluster (realm: dev-k3s)
   (syft SBOM -> heimdall gate)        ┌──────────────────────────────────────┐
              │                        │  Heimdall pod (1 binary, 1 GB/1 CPU)  │
              ▼                        │   ├─ Bifröst  (axum HTTP API)          │
        ┌───────────┐   HTTPS          │   ├─ Sight    (kube-rs cluster scan)   │
        │  Bifröst  │◄─────────────────┤   ├─ Watchers (tokio scheduled tasks)  │
        └───────────┘                  │   ├─ Matcher  (inventory × advisories) │
                                       │   ├─ Gjallarhorn (Teams)               │
  Image SBOM CronJob (syft) ──POST────►│   └─ /metrics, OTLP ──► OTel collector │
  (own limits, per unique digest)      └──────────────────────────────────────┘
                                                       │ sqlx
                                                       ▼
                                             Postgres VM (existing)
```

Single Rust binary, single Deployment, one replica. All background work runs as
tokio tasks in the same process. Postgres on the existing VM is the only
external state.

### 7.1 Inventory ("what do we run") — three sources, one model

Every component is stored as a **PURL** (package URL) + version, attached to a
**service** in a **realm**, tagged with the **source** it came from:

| Source | How it arrives |
|---|---|
| `git` | SBOMs committed in repos, uploaded by CI on the default branch |
| `ci` | SBOM generated and uploaded on each CI build (via `heimdall gate`) |
| `cluster` | Sight: running images, Helm releases, Kubernetes/k3s version, node OS |

Recording the source per realm makes drift detection (phase 3) a query, not a redesign.

- `git` = uploads from the repo's **default branch** (the intended state).
  `ci` = uploads from any other branch (evaluated by the gate, kept for 30
  days, never treated as inventory for alerting).
- **Upload semantics:** an upload *replaces* the component set for
  `(service, realm, source)`. Components that disappear close their findings
  automatically ("resolved: no longer present").
- **Service identity:** one name shared by all sources. In the cluster, Sight
  uses the pod label `app.kubernetes.io/name`, falls back to the owning
  Deployment/StatefulSet/DaemonSet name, and can be overridden with the
  annotation `heimdall.io/service`. CI passes the same name to `--service`.
  Third-party workloads (Postgres, Valkey…) become services named the same way.
- **Images as components:** an image is a component of the service that runs
  it. The OS and library packages inside an image are attached to the
  **image digest** and reach services through it, so one image SBOM serves
  every service that uses that image.
- **Direct vs transitive:** `heimdall gate` reads the repo's manifests
  (`go.mod` direct `require` entries, and every `package.json` in a pnpm
  workspace: `dependencies` + `devDependencies`) and marks those components
  `direct=true` in the upload. Only direct libraries get release tracking
  (§7.3); every component, direct or transitive, gets CVE matching.

**SBOM format:** CycloneDX JSON (generated by syft in CI). Go modules, pnpm
packages, OS packages inside images, and anything else syft catalogs all
arrive this way, so Heimdall does not parse lockfiles itself.

**Sight (cluster scanner)**, every 15 min via the Kubernetes API (read-only ClusterRole):
- Pods → unique image references + digests → components (`pkg:oci/...`).
- Helm chart versions from the `helm.sh/chart` workload label (not Helm release Secrets; see ADR 0003) and ArgoCD `Application` resources → chart name + version.
- Server version → Kubernetes / k3s version.
- Nodes → OS image (Ubuntu/Debian version) and kubelet version.

**Image SBOM CronJob:** a separate Kubernetes CronJob (syft image, its own
resource limits) asks Heimdall for "image digests without an SBOM", generates
SBOMs for them, and POSTs them through Bifröst. Each digest is scanned once.

**Declared components:** things outside any cluster or SBOM (e.g. the Postgres
VM's version) are declared in config (`heimdall.yaml` → `declared:`) with a realm.

**Remote realms (future):** Sight talks to Bifröst through the same ingest
API it would use over the network, so a later production cluster can run
`heimdall sight --push https://heimdall...` in scout mode without redesign.

### 7.2 Vulnerability sources

| Source | Covers | Use |
|---|---|---|
| **OSV.dev** (primary) | GitHub Advisories, Go vulndb, npm, Debian, Ubuntu, PyPI, crates, and more; carries CVE aliases | `POST /v1/querybatch` with all unique PURLs every 15 min; fetch full records for new IDs via `/v1/vulns/{id}` |
| **Kubernetes official CVE feed** | Kubernetes / k3s issues | Poll JSON feed every 30 min |
| NVD | Phase 3 | — |

Only advisories that match the inventory are stored. No full mirror.

**Severity:** use the CVSS v3/v4 score from OSV `severity` when present;
otherwise GHSA `database_specific.severity`; otherwise distro priority (Debian
urgency / Ubuntu priority). Normalize to `critical | high | medium | low | unknown`.
`unknown` is treated as medium for alerting but shown explicitly.

**Version matching:** OSV `querybatch` does the range matching server-side, so
Heimdall does not need its own semver/dpkg range logic for detection. It does
need version *ordering* for "which release fixes this" (§7.4): semver for
Go/npm, dpkg ordering for Debian/Ubuntu, "best effort" for others.

### 7.3 Release watchers

Each watcher is a **type** with config-driven **targets**:

| Watcher type | Targets (initial) |
|---|---|
| `github-releases` | Kubernetes, k3s, Kyverno, ArgoCD, ClickHouse, Kafka, Valkey, OTel collector, SOPS controller, kube-prometheus-stack, Grafana, Loki, Tempo, OpenTofu, Terraform |
| `endoflife` (endoflife.date API) | Postgres, ClickHouse, Kubernetes, k3s, Ubuntu, Debian, Valkey, EKS, RDS (versions + end-of-support dates) |
| `oci-registry` | Tags for every image in inventory (Docker Hub, GHCR, ECR public) |
| `helm-repo` | Chart repos (`index.yaml`) and OCI charts for every chart in inventory |
| `tf-registry` | Terraform and OpenTofu providers/modules declared in config |
| `go-proxy` / `npm-registry` | Latest versions for **direct** libraries only (§7.1). Major releases alert; minor/patch go to the digest unless they fix a CVE we're exposed to. Transitive libraries get no release tracking. |

Inventory-derived targets (images, charts, libraries) are tracked
automatically; infra software is listed in `heimdall.yaml`.

Polling: every 1 h per target, with ETag/If-Modified-Since to stay cheap.
GitHub uses a token (5,000 req/h). New releases are stored as
`release(target, version, published_at, is_major, is_prerelease)`.
Pre-releases are ignored by default.

### 7.4 Matcher and alert rules (Gjallarhorn)

The matcher joins inventory × advisories × releases × oaths and produces
**findings**. Each finding has a stable key
`(realm, service, component, advisory_or_release_id, reason)`; its
notification state is stored so it alerts once.

**Grouping:** alerts are grouped **per advisory** (or per release): one Teams
card per CVE listing every affected service/component/realm, not one card per
service. A later newly-affected service adds an update to the next card,
not a separate flood.

**First run (owner's decision):** alerts fire from the very first sync, with
no silent baseline. Grouping per advisory keeps the volume down. Gjallarhorn
sends through a paced queue (about one card every 2 s) so a large first run
doesn't hit Teams webhook throttling, and it sends a short "Heimdall has
opened his eyes" summary card first (counts by severity).

**Immediate Teams alert:**
1. New **critical or high** CVE affecting an inventory component (not under an active oath).
2. **Major version** release of something in inventory/config.
3. A **release that fixes a CVE we are currently exposed to**, including CVEs under an oath ("Fix available: upgrade `foo` 2.4.0 → 2.4.1 fixes CVE-…").
4. **Oath expired**: the snoozed CVE is back.
5. **End of support** within 60 days for a version we run (endoflife data).

**Weekly digest (Monday 09:00, Teams):** medium/low CVEs, minor/patch releases
that don't fix anything we are exposed to, and the list of active oaths with
their expiry dates. Everything is also visible via API/CLI and metrics.

**Teams delivery:** Teams Workflows incoming webhook (the old Office 365
connectors are retired) with Adaptive Card payloads. Multiple webhooks are
configurable with routing by realm and severity. Failed sends retry with
backoff and are stored, so nothing is lost on restart.

### 7.5 Oaths (suppressions)

An oath is scoped to **(CVE/advisory ID, component, service, realm)**. It is never global.

| Field | Notes |
|---|---|
| kind | `snooze` (has `expires_at`) or `ignore` (has `review_at`, default +90 days) |
| reason | Required, free text (e.g. "no alternative; not reachable from user input") |
| created_by, created_at | Who and when |

Behaviour:
- While active: no immediate alert, no CI gate failure; listed in the weekly digest.
- On `expires_at` / `review_at`: alert (rule 4); the CVE counts again for the gate.
- **Fix released while under an oath**: alert immediately (rule 3); the oath stays until a human acts.
- Full history kept (created, extended, revoked, expired).
- **Across versions:** an oath records the version it was taken on and stays
  in force if the component moves to another version *still affected* by the
  same CVE; the weekly digest flags "oath carried to new version X". If the new
  version is not affected, the finding resolves and the oath closes.
- CLI: `heimdall oath snooze <CVE> --service x --until 2026-12-31 --reason "..."`, `oath ignore`, `oath list`, `oath revoke`.
- Exportable as OpenVEX later (phase 3); the model aligns with VEX statuses.

### 7.6 Hofund (CI gate)

```
syft . -o cyclonedx-json > sbom.json
heimdall gate --service api --realm dev-k3s --sbom sbom.json --fail-on high
```

- Uploads the SBOM through Bifröst with `?wait=true`; the server matches it against OSV
  **synchronously** (bounded by a 60 s timeout) and returns findings.
- Exit code `1` if any finding is ≥ `--fail-on` and not under an active oath; prints a readable table.
- On the default branch the upload also updates the `git` inventory; on other branches it is evaluated but not stored as inventory.
- **CI system: GitHub Actions.** Ship a composite action
  (`uses: <org>/heimdall/gate@v1`) that downloads the binary, runs syft, and
  calls the gate. The branch and default branch are auto-detected from
  `GITHUB_REF_NAME` and `github.event.repository.default_branch`
  (overridable with `--branch` / `--default-branch`).
- **Source fallback (owner's decision):** if OSV is unreachable or times out,
  the gate checks the **GitHub Advisory Database** (GraphQL API, same
  GitHub token) for the ecosystems it covers (Go, npm, and others). If neither
  source can answer for some components, the gate **fails** with exit code `2`
  ("could not verify"), distinct from exit code `1` ("vulnerabilities found").
  No silent pass.
- Static binary for linux/amd64 and arm64 so any CI image can download it.

### 7.7 API and auth

- REST/JSON over axum; the CLI (`clap`) is a thin client of the same API.
- Endpoints (phase 1): ingest SBOM, ingest cluster inventory, list services/components/findings/releases, oath CRUD, image-SBOM work queue, health, metrics.
- **API keys** stored hashed (SHA-256; see ADR 0004) in Postgres, with scopes: `ingest` (CI, CronJob), `read`, `admin` (oaths). Bootstrap admin key from a Kubernetes secret (SOPS-managed).
- The API is designed for the phase-2 UI to consume as-is.
- **Reachability from CI (owner's decision):** self-hosted GitHub Actions
  runners that can reach the cluster network. Heimdall is **not exposed to the
  internet**; CI calls the in-cluster Service (or an internal-only Ingress).
  The Helm chart keeps an optional Ingress, off by default.

### 7.10 Private registries

Some images and charts live in private registries. Heimdall supports
per-registry credentials:
- `registries:` in `heimdall.yaml` maps a registry host to a Kubernetes secret
  (docker-config JSON for GHCR/Docker Hub/generic OCI, basic auth for Helm repos).
- The `oci-registry` and `helm-repo` watchers use them for tag and index lookups.
- The image-SBOM CronJob mounts the same docker-config secret so syft can pull
  private images.
- Private ECR (token-based) is supported via an IAM role or access key that
  refreshes the ECR token every 6 h; it is needed only once AWS is in use (phase 3),
  but the credential abstraction must allow it.

### 7.8 Observability

- `tracing` + OTLP exporter → existing OTel collector → Tempo/Loki.
- Prometheus `/metrics`: open findings by severity/service/realm, versions-behind per component, watcher success/failure/latency, Teams send failures, oath counts and nearest expiry. ServiceMonitor for kube-prometheus-stack.

### 7.9 Configuration

- `heimdall.yaml` (ConfigMap): realms, watcher targets, declared components, Teams webhooks + routing, schedules, thresholds.
- Secrets (SOPS): Postgres URL, GitHub token, Teams webhook URLs, bootstrap key.
- Deployed via a Helm chart in the repo (fits ArgoCD).

## 8. Tech stack (Claude's call)

| Concern | Choice |
|---|---|
| Async runtime | `tokio` |
| HTTP server | `axum` |
| HTTP client | `reqwest` (rustls, no OpenSSL) |
| Database | Postgres via `sqlx` (compile-checked queries, migrations) |
| Kubernetes | `kube` + `k8s-openapi` |
| CLI | `clap` (derive) |
| Serialization | `serde`, `serde_json`, `serde-saphyr` (pure-Rust YAML) |
| SBOM | Parse CycloneDX JSON with plain serde structs for the fields we need (avoid a heavy dependency) |
| Versions | `semver`; small dpkg-version comparator (well-specified algorithm, tested) |
| Observability | `tracing`, `opentelemetry-otlp`, `metrics` + Prometheus exporter |
| Image | Distroless/static, multi-arch |

## 9. Code style constraints (owner is learning Rust)

- Plain structs and enums; no custom macros; generics only where a library requires them.
- `anyhow` for errors in the app, `thiserror` only at module boundaries if needed.
- Clone freely where it avoids lifetime puzzles; performance budget allows it.
- Comments explain *why* when ownership/borrowing shapes the code.
- One module per theme area (§3), small files, README with the theme mapping and a "how to add a watcher" guide.
- Tests: unit tests for version ordering, severity normalization, alert dedupe and oath logic; integration tests against a real Postgres (testcontainers or docker compose) and recorded HTTP fixtures for external sources.

## 10. Constraints recap

- 1 GB RAM / 1 CPU limit; target ≤ 256 MB steady.
- Runs in the k3s dev cluster first; production does not exist yet.
- Postgres on the existing VM.
- Notifications: Microsoft Teams only.
- Ecosystems now: Go, pnpm/npm, Docker/OCI images, Helm, Terraform/OpenTofu, Ubuntu, Debian, Kubernetes/k3s, plus infra software in §7.3.

## 11. Decisions log

**Owner's decisions:** Rust; 1 GB / 1 CPU in-cluster; external Postgres VM;
k3s dev realm first; Teams only; alert rules §7.4; oaths with snooze/ignore
and fix-wake-up; release alerts on direct libraries only; gate falls back
OSV → GitHub Advisory DB → fail; private registries supported; GitHub Actions
on self-hosted runners (no internet exposure); alerts fire from the first run;
alerts grouped per advisory; service name from `app.kubernetes.io/name` label;
uploads replace, and findings close when fixed or removed; EKS/RDS checks moved
to phase 3.

**Deviations (phase 1 plan):** API keys use SHA-256, not argon2 (32 random bytes; a slow hash only costs CPU on a 1-CPU pod; ADR 0004). Sight reads chart versions from `helm.sh/chart` labels and ArgoCD Applications, not Helm release Secrets, to avoid cluster-wide Secret read access (ADR 0003).

**Claude's calls (owner to check):** oaths carry across still-affected
versions; paced Teams queue; theme names user-facing only; tech stack §8.

## 12. Grill session decisions (2026-11-13)

These override earlier sections where they conflict. Terms are defined in
`GLOSSARY.md`; hard-to-reverse choices are recorded in `docs/adr/`.

1. **Own images:** `own_registries:` in config. Images from those registries
   are CVE-scanned but never release-watched.
2. **Oaths across realms:** per realm by default; `--all-realms` makes one oath
   apply in every realm (current and future).
3. **0.x versions:** for `0.x`, the second number is the major
   (`0.3 → 0.4` is a major release).
4. **Indirect dependencies:** "fix available" alerts also fire for indirect
   (transitive) components; the card labels them "indirect dependency".
5. **Monorepos:** the gate action takes a `path` input; run once per service.
6. **Admins:** `admins: [names]` in config. Only listed names can hold admin
   keys; one key per person; removing a name disables their admin keys on the
   next restart. Oaths record the admin's name.
7. **Retention:** oaths and oath history forever; resolved findings and release
   records 1 year; sent outbox rows 30 days.
8. **Declared components:** the weekly digest lists each one as
   "declared since {date}" so stale versions are visible.
9. **Release notes (moved into phase 1):** for each new release, Heimdall
   fetches release notes:
   - **Sources:** GitHub Releases, located via npm `repository`, Go module
     path (github.com), the OCI label `org.opencontainers.image.source`, or the
     configured repo; Helm charts via Artifact Hub change notes.
     `CHANGELOG.md` fallback is phase 3.
   - **Classification (pattern matching; AI summary is phase 3):**
     - mentions a CVE/GHSA ID **currently affecting us** → immediate alert
     - other security mentions → digest, marked security
     - bug-fix lines → digest, first few "fix" lines
     - nothing notable → digest, version and link only
     - no notes found → digest says "no release notes found"
   - Major release cards quote up to 5 "breaking" lines plus a link.
10. **NVD in phase 1, for every component:** NVD is checked alongside OSV.
    - **How:** pull CVEs changed since the last check every 2 h (NVD API 2.0,
      `lastModStartDate`/`lastModEndDate`) and match them locally against the
      CPEs syft puts on components plus `cpe:` fields on infra targets. A one-off
      backfill per unique vendor:product runs on first sight. Only matches are
      stored. Needs an NVD API key.
    - A CVE in both OSV and NVD is one advisory (joined on CVE ID/aliases).
      **Higher severity wins**; cards show both scores.
    - NVD-only matches on library components alert normally but are labelled
      "NVD match only, verify"; infra targets carry no label.
11. **Fix recommendation:** suggest the smallest fixed version in the current
    major line, and show the latest version alongside.
12. **Digest timezone:** configurable (`digest.timezone`), default UTC.

## 13. Left to the builder

- Exact Postgres schema and migration layout.
- Exact polling intervals within the goals above.
- Adaptive Card layout for Teams messages.
- Module/file breakdown within §3's areas.
- Retry/backoff parameters.
- Which syft version and flags for the CronJob and CI examples.
