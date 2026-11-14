---
title: HTTP API
description: Every HTTP route, with its required scope, parameters and response shape.
---

The CLI is a thin client of this API, and the API is designed for a future web UI
to use as it is. All bodies are JSON. The server listens on port `8080`.

## Authentication

Send an API key in the `Authorization` header:

```bash
curl -H "Authorization: Bearer $HEIMDALL_API_KEY" "$HEIMDALL_URL/api/v1/realms"
```

Keys have one of three scopes: `ingest`, `read` and `admin`. **`admin` satisfies
every scope**; `read` and `ingest` satisfy only themselves. An admin key whose
name is not in `admins` (and is not `bootstrap`) is refused with `403`.

`/healthz` and `/metrics` need no key.

## Errors

Errors come back as a status code and a JSON body, `{"error": "message"}`:

| Status | Meaning |
|---|---|
| `400` | Bad input: unknown realm, malformed body or parameter, rule violation. |
| `401` | Missing or unknown key. |
| `403` | The key's scope is too low, or its admin name is not allowed. |
| `404` | No such oath, key or service. |
| `413` | Body too large (limit 50 MB on ingest and gate). |
| `500` | Internal error. The detail is logged, never returned. |

## Summary

| Method and path | Scope | Purpose |
|---|---|---|
| `GET /healthz` | none | Health check. |
| `GET /metrics` | none | Prometheus metrics. |
| `GET /api/v1/realms` | read | Realms with counts. |
| `GET /api/v1/findings` | read | List findings. |
| `GET /api/v1/services` | read | List services. |
| `GET /api/v1/services/{id}/components` | read | A service's components. |
| `GET /api/v1/releases` | read | Recorded releases. |
| `POST /api/v1/ingest/sbom` | ingest | Upload an SBOM. |
| `POST /api/v1/ingest/cluster` | ingest | Upload a cluster inventory. |
| `POST /api/v1/ingest/image/{digest}` | ingest | Upload an image SBOM. |
| `GET /api/v1/images/pending` | ingest | Images that need an SBOM. |
| `POST /api/v1/gate` | ingest | Run the CI gate. |
| `GET /api/v1/oaths` | read | List oaths. |
| `POST /api/v1/oaths` | admin | Create an oath. |
| `POST /api/v1/oaths/{id}/revoke` | admin | Revoke an oath. |
| `POST /api/v1/oaths/{id}/extend` | admin | Move an oath's date. |
| `GET /api/v1/keys` | admin | List keys. |
| `POST /api/v1/keys` | admin | Create a key. |
| `DELETE /api/v1/keys/{name}` | admin | Revoke a key. |

## Health and metrics

### `GET /healthz`

`200` with body `ok` when the database answers. `503` with
`database unavailable` or `database timeout` (after 5 seconds) otherwise.

### `GET /metrics`

Prometheus text format. See [Metrics](/heimdall/reference/metrics/).

## Read API

Empty query values count as absent (`?realm=`). An unknown `realm` is a `400`.

### `GET /api/v1/realms`

Scope `read`. Returns an array of `{"name", "services", "open_findings"}`.

### `GET /api/v1/findings`

Scope `read`. Newest first.

| Parameter | Default | Meaning |
|---|---|---|
| `realm` | all | Only this realm. |
| `status` | `open` | `open` or `resolved`. |
| `kind` | all | `vuln`, `fixavailable`, `majorrelease`, `oathexpired`, `eol`, `k8scve`, `releasenotecve`. |
| `min_severity` | `low` | Lowest severity: `critical`, `high`, `medium`, `low`, `unknown`. |
| `limit` | `500` | 1 to 5000. |

Each row:

```json
{
  "id": 42,
  "key": "…",
  "kind": "vuln",
  "realm": "dev-k3s",
  "service": "api",
  "purl": "pkg:npm/lodash@4.17.11",
  "ref_id": "GHSA-jf85-cpcp-j695",
  "severity": "critical",
  "status": "open",
  "opened_at": "2026-11-14T09:00:00Z",
  "resolved_at": null,
  "details": {}
}
```

`service`, `purl`, `ref_id` and `resolved_at` can be `null`. `details` is a JSON
object whose contents depend on `kind`.

### `GET /api/v1/services`

Scope `read`. Optional `realm`. Returns `{"id", "realm", "name", "components"}`
rows ordered by realm and name.

### `GET /api/v1/services/{id}/components`

Scope `read`. `404` if the service does not exist. Rows:

```json
{
  "id": 7, "purl": "pkg:npm/lodash@4.17.11", "name_key": "pkg:npm/lodash",
  "ecosystem": "npm", "version": "4.17.11", "source": "git",
  "direct": true, "via_image_digest": null
}
```

### `GET /api/v1/releases`

Scope `read`. Newest first.

| Parameter | Default | Meaning |
|---|---|---|
| `target` | all | Only this watcher target. |
| `since` | none | A date (`2026-01-31`, midnight UTC) or an RFC 3339 time. |
| `limit` | `500` | 1 to 5000. |

Rows: `id`, `target`, `version`, `published_at` (nullable), `is_major`,
`notes_url` (nullable), `notes_class` (nullable).

## Bifröst: ingest

These routes accept bodies up to 50 MB.

### `POST /api/v1/ingest/sbom`

Scope `ingest`. Upload a CycloneDX SBOM for one service.

| Query parameter | Meaning |
|---|---|
| `service` | Service name. |
| `realm` | Realm (must be in `realms`). |
| `branch` | Branch the SBOM was built from. |
| `default_branch` | The repository's default branch. |

Body:

```json
{ "sbom": { "bomFormat": "CycloneDX", "components": [] }, "direct": ["pkg:npm/lodash"] }
```

`direct` is optional: the name keys (purl without version) to mark as direct
dependencies. When `branch` equals `default_branch` the upload replaces the
service's `git` components; otherwise it replaces its `ci` components.

Response:

```json
{ "source": "git", "added": 12, "removed": 3, "skipped_without_purl": 0 }
```

### `POST /api/v1/ingest/cluster`

Scope `ingest`. Upload what Sight saw in a realm. Services in the realm that have
cluster components but are not listed are emptied.

```json
{
  "realm": "dev-k3s",
  "services": [
    { "name": "api",
      "items": [ { "purl": "pkg:oci/api?repository_url=ghcr.io/my-org/api&tag=1.2.3",
                   "cpes": [], "direct": false, "via_image_digest": null } ] }
  ]
}
```

`cpes`, `direct` and `via_image_digest` are optional. Response:
`{ "services": 1, "added": 4, "removed": 0 }`.

### `POST /api/v1/ingest/image/{digest}`

Scope `ingest`. Upload the SBOM of one image. `digest` must be
`sha256:` followed by 64 hex characters. Query parameter `image_ref` is required.
The body is a CycloneDX SBOM (not wrapped). Response:
`{ "digest": "sha256:…", "components": 214, "skipped_without_purl": 2 }`.

### `GET /api/v1/images/pending`

Scope `ingest`. Image digests that have no SBOM yet:
`[ { "digest": "sha256:…", "image_ref": "ghcr.io/my-org/api:1.2.3" } ]`.

## Hofund: the gate

### `POST /api/v1/gate`

Scope `ingest`. Ingests the SBOM exactly like `/api/v1/ingest/sbom`, checks every
component and returns a verdict. Query parameters are the same four as ingest, plus:

| Parameter | Meaning |
|---|---|
| `fail_on` | `critical`, `high`, `medium`, `low` or `unknown`. |

The body is the same as for `ingest/sbom`. The call answers within 60 seconds and
always returns `200` when it can give a verdict:

```json
{
  "verdict": "fail",
  "source": "osv",
  "findings": [
    { "advisory": "GHSA-jf85-cpcp-j695", "severity": "critical",
      "purl": "pkg:npm/lodash@4.17.11", "fixed": "4.17.21", "oath": null }
  ],
  "unverified": []
}
```

- `verdict`: `pass`, `fail` or `unverified`.
- `source`: `osv` or `ghsa` (the GitHub Advisory Database fallback).
- `fixed` and `oath` are `null` when there is no fix or no covering oath.
- Findings are sorted worst first.

## Oaths

### `GET /api/v1/oaths`

Scope `read`. Optional `status`: `active`, `expired` or `revoked`. Newest first.
Each oath:

```json
{
  "id": 12, "advisory_id": "CVE-2026-0001", "name_key": "pkg:npm/left-pad",
  "service_name": "api", "realm": null, "kind": "ignore",
  "reason": "dev-only dependency", "version_at_creation": "1.3.0",
  "expires_at": null, "review_at": "2027-02-12T00:00:00Z",
  "created_by": "alice", "created_at": "2026-11-14T09:00:00Z", "status": "active"
}
```

`realm` is `null` for all-realms oaths. A snooze has `expires_at`; an ignore has
`review_at`.

### `POST /api/v1/oaths`

Scope `admin`.

```json
{
  "advisory_id": "GHSA-xxxx-yyyy-zzzz",
  "purl": "pkg:golang/example.com/lib@1.2.3",
  "service": "api",
  "realm": "dev-k3s",
  "all_realms": false,
  "kind": "snooze",
  "reason": "not reachable; upgrade planned",
  "until": "2026-12-31"
}
```

`realm` or `all_realms: true`, not both. `until` is required for `snooze` and
optional for `ignore` (default 90 days). It must be after today (UTC). `by` is
taken from the key's name. Returns `{ "id": 12 }`. Rule violations are `400`.

### `POST /api/v1/oaths/{id}/revoke`

Scope `admin`. Returns the oath. `404` if there is no such id. Revoking an already
revoked oath changes nothing.

### `POST /api/v1/oaths/{id}/extend`

Scope `admin`. Body `{ "until": "2027-03-31" }`. Returns the oath, active again.
`400` if the oath is revoked or the date is not after today.

## Keys

### `GET /api/v1/keys`

Scope `admin`. `[ { "name", "scope", "created_at" } ]`. Never includes the key or
its hash.

### `POST /api/v1/keys`

Scope `admin`. Body `{ "name": "ci-runner", "scope": "ingest" }`. Returns
`{ "name", "scope", "key" }`. **The key is shown once.** `400` if the name is
invalid, reserved (`bootstrap`), already used, or an `admin` name not listed in
`admins`.

### `DELETE /api/v1/keys/{name}`

Scope `admin`. Returns `{ "revoked": "<name>" }`, or `404`.
