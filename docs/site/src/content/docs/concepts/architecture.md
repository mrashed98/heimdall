---
title: Architecture
description: How Heimdall is put together, from the Bifröst API to Postgres.
---

```text
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

Heimdall is one Rust binary, one Deployment and one replica. All background work
runs as tokio tasks in the same process. Postgres is the only state
([ADR 0001](/heimdall/decisions/0001-external-postgres/)). Heimdall never reads
Kubernetes Secrets ([ADR 0003](/heimdall/decisions/0003-no-secret-access/)).

## The parts

- **Bifröst** is the HTTP API (axum). SBOM uploads, cluster inventory, image
  SBOMs, the CI gate, oaths, keys and the read API all live here. See the
  [HTTP API reference](/heimdall/reference/http-api/).
- **Sight** is the inventory. It reads the cluster through the Kubernetes API
  with a read-only ClusterRole, and takes SBOMs from CI and from the image
  scanner CronJob.
- **Watchers** poll outside sources on a schedule and record new releases.
- **Matcher** joins inventory, advisories, releases and oaths into findings.
- **Gjallarhorn** turns findings into Teams cards, through a paced queue stored
  in the database.
- **Image scanner CronJob** is a separate Kubernetes job (syft, its own limits)
  that asks Heimdall for image digests without an SBOM, generates them and posts
  them back.

## Where inventory comes from

Every component is stored as a purl plus a version, attached to a service in a
realm, and tagged with the source it came from:

| Source | How it arrives |
|---|---|
| `git` | An SBOM uploaded by CI on the repository's default branch. |
| `ci` | An SBOM uploaded from any other branch. It is evaluated by the gate, but is not treated as inventory. |
| `cluster` | Sight: running images, Helm chart labels, ArgoCD Applications, the Kubernetes or k3s version, node OS. |
| `declared` | Components you list under `declared:` in the config. |

An upload **replaces** the component set for that service, realm and source.
Components that disappear close their findings automatically.

**Service identity.** One name is shared by every source. In the cluster, Sight
uses the annotation `heimdall.io/service` if present, then the pod label
`app.kubernetes.io/name`, then the name of the owning Deployment, StatefulSet or
DaemonSet. CI passes the same name with `--service`.

**Images as components.** An image is a component of the service that runs it.
The OS and library packages inside an image are attached to the image digest and
reach services through it, so one image SBOM serves every service that uses that
image.

**Direct and indirect.** `heimdall gate` reads `go.mod` and `package.json` files
and marks those components as direct. Only direct libraries get release tracking.
Every component, direct or not, gets vulnerability matching.

## The scheduled loops

`heimdall serve` runs these loops. Intervals are configurable under
[`schedules`](/heimdall/reference/configuration/#schedules) and `nvd`:

| Loop | Default interval |
|---|---|
| Sight (cluster scan) | 15 minutes |
| OSV match (and oath expiry) | 15 minutes (at most) |
| Kubernetes CVE feed | 30 minutes |
| Watchers (releases) | 60 minutes |
| NVD | 120 minutes |

The matcher runs after every OSV refresh (and after NVD and the watchers). It
also expires lapsed oaths, so there is no separate oath loop; the OSV loop runs
at least every 15 minutes, which bounds how late an expiry is noticed.

On start, each realm gets a first run in order (Sight, OSV, matcher, a summary
card, then alerts), so no alert can arrive before the realm's summary. Old rows
are removed once a day (see [retention](/heimdall/reference/configuration/#retention)).

## Observability

Logs are JSON on stdout (filter with `RUST_LOG`). Prometheus metrics are served
on `/metrics`, and traces can be exported over OTLP. See
[Monitoring Heimdall](/heimdall/guides/monitoring/).
