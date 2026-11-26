# Heimdall

[![CI](https://github.com/mrashed98/heimdall/actions/workflows/ci.yml/badge.svg)](https://github.com/mrashed98/heimdall/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Latest release](https://img.shields.io/github/v/release/mrashed98/heimdall)](https://github.com/mrashed98/heimdall/releases)
[![Docs](https://img.shields.io/badge/docs-mrashed98.github.io%2Fheimdall-informational)](https://mrashed98.github.io/heimdall/)

A lightweight dependency, vulnerability and release tracker for small
Kubernetes clusters, written in Rust.

Heimdall watches every dependency your team runs, in every environment, and
warns early about vulnerabilities, new releases and end of support. It is a
small Rust replacement for Dependency-Track: one binary, one Deployment, an
external Postgres, and about 256 MB of memory (hard limit 1 GB / 1 CPU).

It does four things:

1. **Knows what you run.** It reads your cluster (pods, nodes, Helm chart
   labels, ArgoCD Applications), image SBOMs, SBOMs uploaded from CI, and
   components you declare by hand.
2. **Matches vulnerabilities.** Every component is checked against OSV and NVD,
   plus the Kubernetes official CVE feed.
3. **Watches releases.** It polls GitHub, endoflife.date, OCI registries, Helm
   repos, Terraform registries, the Go proxy and npm, and tells you about
   major releases, fixes for CVEs you are exposed to, and end of support.
4. **Blocks bad builds.** `heimdall gate` (Hofund) fails a CI build when it
   finds vulnerabilities, using the same data.

Alerts go to Microsoft Teams, Slack, Discord, Mattermost, Telegram, PagerDuty,
Prometheus Alertmanager, Jira, a generic webhook or email, routed per realm and severity,
grouped per advisory or release so one CVE is one alert, and sent once. Heimdall is **not
exposed to the internet**: CI runs on self-hosted runners that reach the
in-cluster Service.

### Web UI

Open your Heimdall URL and sign in with your configured OIDC provider, a local
account, or an API key. Choose your realms in the top bar, then explore
findings, services, releases and oaths. Administrators can configure access as
described in the [sign-in guide](https://mrashed98.github.io/heimdall/guides/sign-in-access-control/).

### Alert rules in short

- Immediate: critical and high vulnerabilities (not under an oath), major
  releases, end of support within 60 days, expired oaths, Kubernetes CVEs,
  release notes naming a CVE that affects you, and a **fix available** when
  its CVE is critical or high, or when the fix came out after Heimdall first
  saw the CVE.
- Weekly digest: medium, low and unknown vulnerabilities (with their fix when
  one existed from the start), minor and patch releases, active oaths,
  declared components.
- One vulnerability is one advisory, even when OSV has several records for it
  (`GO-`/`GHSA-`, `PYSEC-`/`GHSA-`, `DSA-`/`DEBIAN-CVE-`, ...) or NVD has it too.
- A finding that disappears and comes back within 30 days (an image not
  scanned yet, a scale to zero) is not announced again.

Details: [alert rules](https://mrashed98.github.io/heimdall/concepts/alerts/).

### Alert channels

Route alerts per realm and severity to any mix of channels. The `teams:` list
keeps working; `channels:` adds the other types. Secrets are only ever named
(`*_env`), never written in the config:

```yaml
teams:
  - { name: default, webhook_env: TEAMS_WEBHOOK_DEFAULT, min_severity: high }
channels:
  - { type: slack, name: dev, webhook_env: SLACK_WEBHOOK_DEV, realms: [dev], min_severity: high }
  - { type: pagerduty, name: oncall, routing_key_env: PAGERDUTY_KEY, realms: [prod], min_severity: critical }
  - { type: alertmanager, name: am, url: "http://alertmanager:9093", min_severity: high }
  - { type: webhook, name: siem, url_env: SIEM_URL, secret_env: SIEM_HMAC, min_severity: low }
  - type: email
    name: security
    host: smtp.example.com
    username_env: SMTP_USERNAME
    password_env: SMTP_PASSWORD
    from: Heimdall <heimdall@example.com>
    to: [security@example.com]
    min_severity: high
```

Also `discord` and `mattermost` (`webhook_env`), `telegram` (`bot_token_env`,
`chat_id`) and `jira` (`url`, `project`, `token_env`, plus `username_env` for
Jira Cloud; one issue per alert).
Each channel gets its own queued copy with the same pacing, retries and
exactly-once delivery; the weekly digest goes to every channel covering the
realm (paging channels, PagerDuty and Alertmanager, only with `digest: true`).
Alertmanager alerts are sent once with `endsAt` = delivery +
`expire_after_hours` (default 24). Details:
[alert channels](https://mrashed98.github.io/heimdall/guides/alert-channels/).

## Why Heimdall

[OWASP Dependency-Track](https://dependencytrack.org) is the inspiration for
this project and a great fit for large organisations. Heimdall is a lightweight
Rust alternative for small clusters: one binary that fits in 1 GB RAM and
1 CPU, with an external Postgres as its only state. It borrows Dependency-Track's
core idea (keep an inventory of components and match it against advisories)
and adds release and end-of-support watching.

## Documentation

Full documentation: <https://mrashed98.github.io/heimdall/>. Also see
[GLOSSARY.md](GLOSSARY.md) and the design decisions in [docs/adr/](docs/adr/).

## Vocabulary

User-facing names (CLI, docs, Teams messages, metrics) use the Heimdall theme.
Code modules use plain names so the source is easy to navigate. See also
[GLOSSARY.md](GLOSSARY.md).

| Theme name | Meaning | Code module |
|---|---|---|
| **Realm** | An environment/cluster (`dev-k3s` now; `prod` later) | `realm` |
| **Bifröst** | The ingest API: everything entering Heimdall (SBOM uploads, cluster inventory) crosses it | `ingest` |
| **Sight** | Inventory scanning: what is actually running (cluster scanner + image SBOM job) | `inventory` |
| **Watchers** | Pollers for new releases and new advisories ("Heimdall hears the grass grow") | `watchers` |
| **Gjallarhorn** | The notifier: alerts on Teams, Slack, Discord, Mattermost, Telegram, PagerDuty, Alertmanager, Jira, webhooks or email, and the weekly digest | `notify` |
| **Hofund** | The CI gate that blocks a build at the bridge | `gate` |
| **Oath** | A suppression: ignore or snooze a CVE, with a reason | `oath` |

## Architecture

```
          CI pipelines                        k3s cluster (realm: dev-k3s)
   (syft SBOM -> heimdall gate)        ┌──────────────────────────────────────┐
              │                        │  Heimdall pod (1 binary, 1 GB/1 CPU)  │
              ▼                        │   ├─ Bifröst  (axum HTTP API)          │
        ┌───────────┐   HTTPS          │   ├─ Sight    (kube-rs cluster scan)   │
        │  Bifröst  │◄─────────────────┤   ├─ Watchers (tokio scheduled tasks)  │
        └───────────┘                  │   ├─ Matcher  (inventory × advisories) │
                                       │   ├─ Gjallarhorn (alert channels)      │
  Image SBOM CronJob (syft) ──POST────►│   └─ /metrics, OTLP ──► OTel collector │
  (own limits, per unique digest)      └──────────────────────────────────────┘
                                                       │ sqlx
                                                       ▼
                                             Postgres VM (existing)
```

One replica; all background work is tokio tasks in the same process. Postgres
is the only state ([ADR 0001](docs/adr/0001-external-postgres.md)). Heimdall
never reads Kubernetes Secrets ([ADR 0003](docs/adr/0003-no-secret-access.md)).
The full design is in
[docs/superpowers/specs/2026-11-12-heimdall-design.md](docs/superpowers/specs/2026-11-12-heimdall-design.md).

## Quick start (local)

You need Rust (stable), Docker and, optionally, an alert channel (a Teams or Slack webhook URL, for example).

1. **Start Postgres.** The repo ships a dev database on port 5433:

   ```bash
   docker compose -f docker-compose.dev.yml up -d
   export DATABASE_URL=postgres://heimdall:heimdall@localhost:5433/heimdall
   ```

   Migrations run automatically when the server starts.

2. **Create a bootstrap key.** A key is `hd_` plus 43 URL-safe base64
   characters (32 random bytes). This command prints exactly that:

   ```bash
   export HEIMDALL_BOOTSTRAP_ADMIN_KEY="hd_$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=')"
   echo -n "$HEIMDALL_BOOTSTRAP_ADMIN_KEY" | wc -c   # prints 46 (3 for "hd_" + 43)
   ```

   (32 bytes encode to 44 base64 characters; `tr -d '='` strips the one `=`
   of padding, leaving 43.) Heimdall refuses to start with a bootstrap key
   that does not match this format. Keep the key in your secret store; only its
   SHA-256 is stored in the database.

3. **Write a config.** Copy `heimdall.example.yaml` to `heimdall.yaml` and
   edit at least `realms`, `own_registries` and `teams` (or `channels`). Check it:

   ```bash
   cargo run -- serve --check-config heimdall.yaml     # prints "config ok"
   ```

4. **Run the server.** Optional environment: `GITHUB_TOKEN` (5000 req/h
   instead of 60 for GitHub), `NVD_API_KEY`, and one variable per alert
   channel secret named in `teams[].webhook_env` or a `channels[]` `*_env` key.

   ```bash
   cargo run -- serve heimdall.yaml     # listens on 0.0.0.0:8080
   curl localhost:8080/healthz          # ok
   ```

5. **Talk to it with the CLI.**

   ```bash
   export HEIMDALL_URL=http://localhost:8080
   export HEIMDALL_API_KEY=$HEIMDALL_BOOTSTRAP_ADMIN_KEY
   heimdall realms
   heimdall findings --min-severity high
   ```

## Deploy without Kubernetes

Docker Compose (Heimdall and Postgres on one host) and a hardened systemd unit
for the static release binary are in `deploy/compose/` and `deploy/systemd/`.
See [Install without Kubernetes](https://mrashed98.github.io/heimdall/getting-started/without-kubernetes/);
outside a cluster, the inventory comes from SBOM uploads, declared components,
`heimdall sight --push` from any cluster you also run, and Sight for Docker,
which reads a Docker host's running containers.

## Deploy on Kubernetes (Helm)

Images are built from `deploy/Dockerfile` (server, distroless, static musl
binary) and `deploy/Dockerfile.scanner` (syft + `heimdall scan-images`).

```bash
docker build -f deploy/Dockerfile -t ghcr.io/mrashed98/heimdall:0.3.2 .
docker build -f deploy/Dockerfile.scanner -t ghcr.io/mrashed98/heimdall-scanner:0.3.2 .
```

Create a Secret (SOPS-managed in a real setup) with these keys, then install:

| Secret key | Used for |
|---|---|
| `DATABASE_URL` | Postgres connection string (required) |
| `HEIMDALL_BOOTSTRAP_ADMIN_KEY` | The admin key named `bootstrap` (optional, but you need some admin key to start) |
| `GITHUB_TOKEN` | GitHub releases, release notes, and the gate's GitHub Advisory DB fallback |
| `NVD_API_KEY` | NVD (name set by `nvd.api_key_env`) |
| `TEAMS_WEBHOOK_*` | One per `teams[].webhook_env` |
| Channel secrets | One per `*_env` key of a `channels[]` entry (webhook URLs, bot token, routing key, HMAC secret, SMTP or Alertmanager credentials) |
| `HEIMDALL_API_KEY` | An **ingest-scope** key, used by the scanner CronJob |

The chart is published to GHCR with each release from 0.4.0 on (for earlier
ones, or a branch, use `deploy/helm/heimdall` from a checkout, without
`--version`):

```bash
helm install heimdall oci://ghcr.io/mrashed98/charts/heimdall --version 0.3.2 \
  -n heimdall --create-namespace \
  --set image.repository=ghcr.io/mrashed98/heimdall \
  --set scannerImage.repository=ghcr.io/mrashed98/heimdall-scanner \
  --set existingSecret=heimdall-secrets \
  -f my-values.yaml
```

What the chart creates:

- Deployment (1 replica, non-root, read-only root filesystem, `/tmp` emptyDir,
  limits 1Gi/1 CPU, requests 256Mi/100m, readiness on `/healthz`, liveness a TCP check so a database outage does not restart the pod), Service on
  port 8080 (named `http`), ConfigMap holding `config:` as `heimdall.yaml`.
- ClusterRole: read-only `get`/`list` on pods, nodes, deployments,
  statefulsets, daemonsets, replicasets, ArgoCD Applications, and `get` on
  `/version`. No Secrets.
- CronJob `scan-images` (default `0 */6 * * *`, `concurrencyPolicy: Forbid`,
  its own resources). For private registries set
  `scanImages.dockerConfigSecret` to a `kubernetes.io/dockerconfigjson` Secret.
- ServiceMonitor scraping `/metrics` (`serviceMonitor.enabled`, default true; only rendered when the Prometheus Operator CRD `monitoring.coreos.com/v1` exists in the cluster, or when `serviceMonitor.force=true`, which offline renderers such as ArgoCD need).
- Ingress, only when `ingress.enabled=true` (default false).

Set `otlpEndpoint` to export traces to an OTel collector. The scanner reaches
Heimdall at `http://<release>.<namespace>.svc:8080`.

## Configuration reference

`heimdall serve <path>` reads one YAML file. Only `realms` is required;
everything else has the default shown. [heimdall.example.yaml](heimdall.example.yaml)
is a complete example.

| Key | Default | Meaning |
|---|---|---|
| `realms` | required | List of realm names Heimdall tracks. |
| `digest.weekday` | `Mon` | Day of the weekly digest. |
| `digest.hour` | `9` | Hour (0-23) in `digest.timezone`. |
| `digest.timezone` | `UTC` | IANA name, e.g. `Africa/Cairo`. |
| `admins` | `[]` | Key names allowed to hold an `admin` key (besides `bootstrap`). One key per person. Removing a name disables their admin keys on the next request. Oaths record the admin's name. |
| `own_registries` | `[]` | Registry hosts or `host/org` prefixes (e.g. `ghcr.io/mrashed98`). Those images are CVE-scanned but never release-watched. |
| `teams[]` | `[]` | Teams routes. Each: `name`, `webhook_env` (name of the env var holding the webhook URL), `realms` (empty = all), `min_severity` (`critical`, `high`, `medium`, `low`). |
| `channels[]` | `[]` | Alert channels of any `type`: `teams`, `slack`, `discord`, `mattermost`, `telegram`, `pagerduty`, `alertmanager`, `jira`, `webhook`, `email`. Each: `name` (unique across `teams` and `channels`), `realms`, `min_severity`, plus its type's keys. Secrets only via `*_env` keys. See [Alert channels](#alert-channels). |
| `watchers.github[]` | `[]` | `repo`, `inventory_name`, optional `major_component` (see below), optional `cpe`. |
| `watchers.endoflife[]` | `[]` | `product`, `inventory_name`, optional `major_component`, `cpe`, and `repo` (GitHub repo for release notes). |
| `watchers.tf_registry[]` | `[]` | `registry` (`registry.terraform.io` or `registry.opentofu.org`), `kind` (`provider` or `module`), `source`, `current` (version you run). |
| `declared[]` | `[]` | Components outside any cluster or SBOM: `realm`, `service`, `purl` (e.g. `pkg:generic/postgresql@17.2`). The weekly digest lists each as "declared since {date}". |
| `registries[]` | `[]` | Private registry credentials: `host`, `secret_env` (env var holding `user:password`). Used by the OCI watcher for tag lookups. |
| `sight.realm` | first of `realms` | The realm of the cluster Heimdall itself runs in. In-process Sight scans it; skipped when no cluster is reachable. |
| `schedules.sight_minutes` | `15` | Cluster scan interval. |
| `schedules.osv_minutes` | `15` | OSV match interval, at most 15 (larger values count as 15): the matcher after each OSV refresh also expires oaths. |
| `schedules.k8s_cve_minutes` | `30` | Kubernetes CVE feed interval. |
| `schedules.watchers_minutes` | `60` | Release watcher interval. |
| `nvd.api_key_env` | `NVD_API_KEY` | Name of the env var holding the NVD API key. |
| `nvd.minutes` | `120` | NVD poll interval. |
| `retention.findings_days` | `365` | Resolved findings are deleted after this long. |
| `retention.releases_days` | `365` | Release records. |
| `retention.outbox_days` | `30` | Sent notification rows. Oaths and their history are kept forever. |

`major_component` says which version number counts as the major. `0` (default)
means the first number; `1` means the second, which is how Kubernetes and k3s
work (`1.30 -> 1.31`). Independently of this, for `0.x` software the second
number is always the major (`0.3 -> 0.4`).

`cpe` ties a configured target to NVD: Heimdall matches NVD CVEs for that
vendor:product against the inventory item named `inventory_name`.

## Adding things to watch

### A watcher target (config only)

Add an entry under `watchers:` for any type that already exists. To watch a
new GitHub project:

```yaml
watchers:
  github:
    - { repo: cert-manager/cert-manager, inventory_name: cert-manager }
```

`inventory_name` is the name the project has in your inventory (a
`pkg:generic/<inventory_name>` component, usually declared under `declared:` or
derived from a cluster image or chart). Restart the server (or roll the
ConfigMap) and the next watcher run picks it up. Images, Helm charts and direct
Go/npm libraries in the inventory are tracked automatically; you only list
infrastructure software.

### A watcher type (code)

Existing types are `github`, `endoflife`, `oci`, `helm`, `tf_registry`,
`go_proxy` and `npm` (one file each in `src/watchers/`). To add one:

1. Create `src/watchers/<name>.rs` with a `fetch` function that returns the
   releases (copy `github.rs` or `npm.rs`), and add `pub mod <name>;` in
   `src/watchers/mod.rs`.
2. Add a variant to `WatchKind` (with its `label()`) and to `Origin` in
   `src/watchers/mod.rs`.
3. Add a match arm for it in `fetch_target`, which is called for every target
   by `run_all`.
4. If targets come from config, add a struct to `src/config.rs` and push a
   `Planned` for each in `src/watchers/plan.rs`.
5. Add a test next to the others (recorded HTTP fixtures live in `tests/fixtures`).

## CLI

`heimdall` with no command (or `--help`) shows the Bifröst banner, a rainbow
gradient over the letters (shown below in plain text):

```text
█   █  █████  █████  █   █  ████    ███   █      █
█   █  █        █    ██ ██  █   █  █   █  █      █
█████  ████     █    █ █ █  █   █  █████  █      █
█   █  █        █    █   █  █   █  █   █  █      █
█   █  █████  █████  █   █  ████   █   █  █████  █████
the watcher at the Bifröst · v0.3.2
```

Output is coloured when stdout is a terminal, and in CI where there is no
terminal but `CI` or `GITHUB_ACTIONS` is set. Severities use the same colours
everywhere: critical bold white on red, high red, medium yellow, low blue,
unknown dim. Turn colour off with `--no-color`, `NO_COLOR` or `TERM=dumb`.
`COLORTERM=truecolor` gives the full gradient; other terminals get the six
basic ANSI colours. `serve` prints the banner only on a terminal, so JSON logs
stay clean, and `gate` prints only its compact header. Exit codes are
unchanged.

A `heimdall gate` report (plain text; the terminal version has rounded
borders and colour):

```text
>> Hofund - CI gate
+----------+---------------------+--------------------------------+--------------------+------+
| SEVERITY | ADVISORY            | PACKAGE                        | VERSION -> FIXED   | OATH |
+===============================================================================================+
| CRITICAL | GHSA-jf85-cpcp-j695 | pkg:npm/lodash                 | 4.17.11 -> 4.17.21 | -    |
| HIGH     | CVE-2024-45337      | pkg:golang/golang.org/x/crypto | 0.21.0 -> 0.31.0   | #7   |
| MEDIUM   | GHSA-3xgq-45jj-v275 | pkg:npm/cross-spawn            | 7.0.3 -> 7.0.5     | -    |
+----------+---------------------+--------------------------------+--------------------+------+
findings: 1 critical, 1 high, 1 medium
verdict: FAIL (checked against osv)
```

## The oath CLI

Set `HEIMDALL_URL` and `HEIMDALL_API_KEY` (an admin key) first. An oath is
always scoped to one advisory, one component, one service and one realm (or
`--all-realms`), and always needs a `--reason`.

```bash
# Snooze until a date (the date is the first day it no longer holds)
heimdall oath snooze GHSA-xxxx-yyyy-zzzz --service api --realm dev-k3s \
  --purl pkg:golang/example.com/lib@1.2.3 \
  --until 2026-12-31 --reason "not reachable from user input; upgrade planned"

# Ignore, with a review date (default: 90 days from today)
heimdall oath ignore CVE-2026-0001 --service api --all-realms \
  --purl pkg:npm/left-pad@1.3.0 --reason "dev-only dependency"

heimdall oath list --status active     # active, expired or revoked
heimdall oath extend 12 --until 2027-03-31
heimdall oath revoke 12
```

While an oath is active there is no immediate alert and the gate ignores that
advisory; it appears in the weekly digest. When it expires (noticed within 15
minutes) the CVE alerts and counts again. If a fix is released while the oath
is active you are still alerted. An oath stays in force when the component
moves to another version that is still affected by the same CVE.

The advisory may be given by any of its names (`GHSA-...`, its CVE, a `GO-...`
id); the oath is stored under the id findings carry. A name that matches no
known advisory is stored as typed, with a warning printed.

Other read commands: `heimdall findings [--realm R] [--status open|resolved]
[--kind vuln|fixavailable|majorrelease|oathexpired|eol|k8scve|releasenotecve]
[--min-severity high]`, `heimdall realms`, and `heimdall sight --realm R
[--push URL]` (scan a cluster and ingest in-process, or push to a Heimdall
over the network).

## API keys

Keys have a name and a scope: `ingest` (CI and the scanner CronJob), `read`
and `admin` (oaths, key management).

```bash
heimdall keys create --name ci-runner --scope ingest   # prints the key once
heimdall keys create --name alice --scope admin        # only if alice is in `admins`
heimdall keys list
heimdall keys revoke ci-runner
```

Key creation needs an admin key. An `admin` key can only be created for a name
listed under `admins:` in the config; `bootstrap` is reserved: it can only
exist through `HEIMDALL_BOOTSTRAP_ADMIN_KEY` (changing that variable rotates
it; removing it or setting it empty deletes the key at the next start), and
`keys create --name bootstrap` is rejected. Create a named admin key for
yourself, then remove the variable. Keys are stored as
SHA-256 hashes ([ADR 0004](docs/adr/0004-sha256-api-keys.md)).

## GitHub Action (Hofund gate)

`.github/actions/gate` is a composite action for **self-hosted runners** that
can reach Heimdall. It downloads the `heimdall` release binary for the
runner's OS/architecture, installs a pinned syft (checksum verified), runs
`syft dir:<path> -o cyclonedx-json`, then `heimdall gate`. The branch and the
repository's default branch are detected automatically from `GITHUB_REF_NAME`
and `GITHUB_EVENT_PATH`. Linux runners only.

| Input | Default | Meaning |
|---|---|---|
| `service` | required | Service name, the same one Sight shows in the cluster. |
| `realm` | required | Realm. |
| `path` | `.` | Directory to scan; also where `go.mod`/`package.json` are read to mark direct dependencies. |
| `fail-on` | `high` | Lowest severity that fails the build. |
| `heimdall-url` | required | e.g. `http://heimdall.heimdall.svc:8080`. |
| `api-key` | required | An ingest-scope key (store it as a GitHub secret). |
| `repository` | the action's own repo | `owner/name` that publishes the release binaries. Set it when the action is used locally (`uses: ./...`) and the default is empty. |
| `version` | `latest` | Release tag of the binary to download. |

```yaml
jobs:
  gate:
    runs-on: [self-hosted, linux]
    steps:
      - uses: actions/checkout@v4
      - uses: mrashed98/heimdall/.github/actions/gate@v0.3.2
        with:
          service: api
          realm: dev-k3s
          heimdall-url: http://heimdall.heimdall.svc:8080
          api-key: ${{ secrets.HEIMDALL_API_KEY }}
```

**Monorepos:** call the action once per service, each with its own `path`:

```yaml
      - uses: mrashed98/heimdall/.github/actions/gate@v0.3.2
        with: { service: api, realm: dev-k3s, path: services/api,
                heimdall-url: "${{ vars.HEIMDALL_URL }}", api-key: "${{ secrets.HEIMDALL_API_KEY }}" }
      - uses: mrashed98/heimdall/.github/actions/gate@v0.3.2
        with: { service: web, realm: dev-k3s, path: services/web,
                heimdall-url: "${{ vars.HEIMDALL_URL }}", api-key: "${{ secrets.HEIMDALL_API_KEY }}" }
```

On the default branch the upload also updates the service's inventory; on
other branches the SBOM is only evaluated. Without the action, the same thing
by hand:

```bash
syft dir:. -o cyclonedx-json > sbom.json
heimdall gate --service api --realm dev-k3s --sbom sbom.json --fail-on high
```

An SBOM with no components is refused with `400 empty SBOM` (the gate exits
`2`), so a broken SBOM step cannot empty a service's inventory. Pass
`--allow-empty` (API: `allow_empty=true`) for a service with no dependencies.
Ingest and gate bodies are limited to 20 MB, and at most two uploads are
handled at once (the rest wait).

### Exit codes (`heimdall gate`)

| Code | Meaning |
|---|---|
| `0` | Pass: nothing at or above `--fail-on` outside an active oath. |
| `1` | Vulnerabilities found; a table of advisories is printed, ending in `verdict: FAIL`. |
| `2` | Could not verify: Heimdall unreachable, a bad response or input, or neither OSV nor the GitHub Advisory Database could answer for some components. There is no silent pass. |

The server answers within a 60 s bound. If OSV is unreachable the gate falls
back to the GitHub Advisory Database (needs `GITHUB_TOKEN` on the server).

## Metrics

`GET /metrics` (Prometheus text format, no auth, cluster-internal):

| Metric | Labels | Meaning |
|---|---|---|
| `heimdall_findings_open` | `realm`, `service`, `kind`, `severity` | Open findings. |
| `heimdall_versions_behind` | `realm`, `target` | How many releases newer than the running version. |
| `heimdall_watcher_failures_total` | `watcher` | Failed fetches per watcher type. |
| `heimdall_watcher_duration_seconds` | `watcher` | Time spent per watcher type per run (a Prometheus summary: quantiles plus `_sum` and `_count`). |
| `heimdall_teams_failures_total` | | Cards Teams rejected (Teams channels only). |
| `heimdall_notify_failures_total` | `channel_type` | Alerts any channel rejected, by type. |
| `heimdall_outbox_pending` | | Notifications waiting to be sent. |
| `heimdall_oaths_active` | `kind` | Active oaths (`snooze`, `ignore`). |
| `heimdall_oath_next_expiry_timestamp_seconds` | | Unix time of the nearest oath date; `0` when none. |

Logs are JSON on stdout (filter with `RUST_LOG`). Set
`OTEL_EXPORTER_OTLP_ENDPOINT` to also export traces.

## Troubleshooting

- **Server exits at startup with "DATABASE_URL is not set"**: set it, or check
  the Secret named by `existingSecret` has that key.
- **"bootstrap key must be `hd_` followed by 43 base64url characters"**:
  regenerate with the command in the quick start.
- **`config error` from `--check-config`**: the message names the file and the
  field. Unknown keys, `digest.hour` over 23, zero `*_minutes`, and realms not
  listed in `realms` are all errors; `realms` is required and `min_severity`
  must be a known severity.
- **Pod not ready**: `/healthz` returns 503 when Postgres does not answer
  within 5 s. Check network access to the database VM.
- **`heimdall: HEIMDALL_URL is not set`**: the CLI needs `HEIMDALL_URL` and
  `HEIMDALL_API_KEY` in the environment.
- **401 / 403 from the CLI**: wrong key (401), or the key's scope is too low or
  an admin key's name is not in `admins` (403).
- **Gate exits 2 in CI**: the runner cannot reach Heimdall, or the server
  could not verify some components. The final line reads `verdict: UNVERIFIED (checked against …)`, and the
  `unverified:` lines above it list the components that could not be checked.
- **No alerts arrive**: check that the variables named in `teams[].webhook_env`
  and the `channels[]` `*_env` keys exist in the Secret, and watch `heimdall_outbox_pending` and
  `heimdall_notify_failures_total` (the logs name the failing channel).
- **GitHub rate limit errors in logs**: set `GITHUB_TOKEN`.
- **Scanner CronJob fails with a missing key**: add `HEIMDALL_API_KEY`
  (ingest scope) to the Secret.
- **An image is never scanned**: the scanner reports each failure to
  `POST /api/v1/images/{digest}/failed`; failing images go to the back of the
  queue, and after five failures are retried once a day. The last error is in
  the `image_scan_attempts` table.
- **Gate or ingest returns `empty SBOM`**: the SBOM has no components with a
  purl. Fix the SBOM step, or pass `--allow-empty` / `allow_empty=true`.
- **Sight finds nothing**: it is skipped when no cluster is reachable (running
  locally). In-cluster, confirm the ClusterRoleBinding exists.

## Development

```bash
docker compose -f docker-compose.dev.yml up -d
export DATABASE_URL=postgres://heimdall:heimdall@localhost:5433/heimdall
cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test
```

Releases come from merging the release pull request that release-please keeps
open on `main` (see [CONTRIBUTING](CONTRIBUTING.md#releases)). Each release
attaches static linux binaries (`heimdall-linux-amd64`, `heimdall-linux-arm64`),
the chart and `SHA256SUMS` to the GitHub release, pushes multi-arch images to
ghcr tagged with the version without the `v` (tag `v0.3.2`
gives `heimdall:0.3.2`, the tag the chart pulls by default) and `latest`, and pushes
the chart to `oci://ghcr.io/mrashed98/charts/heimdall`.

## Contributing, security and license

- [CONTRIBUTING.md](CONTRIBUTING.md): how to propose changes.
- [SECURITY.md](SECURITY.md): how to report a vulnerability.
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md): community standards.
- [GLOSSARY.md](GLOSSARY.md) and [docs/adr/](docs/adr/): vocabulary and decisions.
- [LICENSE](LICENSE): Apache-2.0.

## Acknowledgements and data sources

Heimdall stands on the work of these projects and data providers:

- [OWASP Dependency-Track](https://dependencytrack.org): the inspiration.
- [OSV.dev](https://osv.dev): primary vulnerability data.
- [NVD](https://nvd.nist.gov): National Vulnerability Database.
- [GitHub Advisory Database](https://github.com/advisories): gate fallback.
- Kubernetes official CVE feed: <https://kubernetes.io/docs/reference/issues-security/official-cve-feed/>.
- [endoflife.date](https://endoflife.date): end-of-support dates.
- [Anchore syft](https://github.com/anchore/syft): SBOM generation.
- [CycloneDX](https://cyclonedx.org): SBOM format.
- [Package URL spec](https://github.com/package-url/purl-spec): component identity.

This product uses data from the NVD API but is not endorsed or certified by the NVD.
