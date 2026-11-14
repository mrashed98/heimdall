---
title: What is Heimdall?
description: The problem Heimdall solves, how it compares with Dependency-Track, and its resource budget.
---

Every team runs more software than it can keep in its head: container images,
Helm charts, Go and npm libraries, Kubernetes itself, the operating system on
the nodes, a database on a VM somewhere. Each of those gets vulnerabilities,
new versions and, one day, an end-of-support date. Most teams hear about them
late, or by accident.

Heimdall keeps a list of what you run and watches the outside world for news
about it. It does four things:

1. **Knows what you run.** It reads your cluster (pods, nodes, Helm chart
   labels, ArgoCD Applications), image SBOMs, SBOMs uploaded from CI, and
   components you declare by hand.
2. **Matches vulnerabilities.** Every component is checked against OSV and NVD,
   plus the Kubernetes official CVE feed.
3. **Watches releases.** It polls GitHub, endoflife.date, OCI registries, Helm
   repos, Terraform registries, the Go proxy and npm, and tells you about major
   releases, fixes for CVEs you are exposed to, and end of support.
4. **Blocks bad builds.** `heimdall gate` (Hofund) fails a CI build when it
   finds vulnerabilities, using the same data.

Alerts go to Microsoft Teams, grouped per advisory or release so one CVE is one
card, and sent once. Heimdall is **not exposed to the internet**: CI runs on
self-hosted runners that reach the in-cluster Service.

## Heimdall and Dependency-Track

[OWASP Dependency-Track](https://dependencytrack.org) is the inspiration for
this project and a great fit for large organisations. Heimdall borrows its core
idea (keep an inventory of components and match it against advisories) and
makes different trade-offs for small clusters:

| | Dependency-Track | Heimdall |
|---|---|---|
| Aim | Component analysis for large organisations | A watcher for small clusters |
| Releases and end of support | Not the focus | First-class: major releases, fixes for CVEs you have, end-of-support dates |
| Footprint | A Java server and a web UI | One Rust binary, one Deployment, external Postgres |
| Interface | Web UI | CLI and HTTP API (a web UI is planned for a later phase) |
| CI gate | Upload, then poll for the result | One synchronous call, answered within 60 seconds |

Heimdall is a clean-room implementation: Dependency-Track is a reference for
concepts only, and no code is ported.

## The resource budget

Heimdall is built to fit a small, shared cluster:

- Container limit: **1 GB of memory and 1 CPU**.
- Steady-state memory target: **256 MB or less**.
- Postgres is external and is the only state. See
  [ADR 0001](/heimdall/decisions/0001-external-postgres/).
- Heimdall mirrors neither OSV nor NVD: it asks for what it needs and keeps
  only advisories that match your inventory. See
  [ADR 0002](/heimdall/decisions/0002-advisories-without-mirrors/).
- Heavy work (generating SBOMs for images) runs in a separate CronJob with its
  own limits, never inside the main pod.

## What Heimdall does not do (yet)

Phase 1 is a backend and a CLI. There is no web UI, no multi-tenant or SSO
support, no license compliance and no policy engine beyond the severity gate.
Teams is the only notifier.

## Next steps

- [Quick start](/heimdall/getting-started/quick-start/): run it on your laptop.
- [Install on Kubernetes](/heimdall/getting-started/kubernetes/): the Helm chart.
- [Glossary](/heimdall/concepts/glossary/): what Realm, Oath and the other names mean.
