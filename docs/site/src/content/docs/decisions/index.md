---
title: Architecture decisions
description: The hard-to-reverse choices behind Heimdall, one short record each.
sidebar:
  order: 0
  label: Overview
---

An architecture decision record (ADR) explains one choice that would be costly
to undo, and why it was made. Heimdall keeps them in
[`docs/adr/`](https://github.com/mrashed98/heimdall/tree/main/docs/adr) in the
repository; these pages are generated from those files when the site is built.

| Decision | In one line |
|---|---|
| [0001: Postgres on an external VM](/heimdall/decisions/0001-external-postgres/) | All state lives in Postgres outside the pod, so the pod stays stateless. |
| [0002: OSV and NVD without local mirrors](/heimdall/decisions/0002-advisories-without-mirrors/) | Query OSV in batches, pull NVD incrementally, store only what matches. |
| [0003: Sight never reads Kubernetes Secrets](/heimdall/decisions/0003-no-secret-access/) | Chart versions come from workload labels and ArgoCD, not Helm Secrets. |
| [0004: API keys hashed with SHA-256](/heimdall/decisions/0004-sha256-api-keys/) | Keys are random, so a fast hash is safe and cheap on one CPU. |
| [0005: Console channel secrets encrypted in Postgres](/heimdall/decisions/0005-encrypted-channel-secrets/) | AES-256-GCM under `HEIMDALL_SECRET_KEY`; no restart per channel and no RBAC to write Secrets. |

If you change something an ADR covers, update or supersede the ADR in the same
pull request. See [Contributing](/heimdall/project/contributing/).
