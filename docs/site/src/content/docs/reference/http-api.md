---
title: HTTP API
description: Every HTTP route, with its required scope, parameters and response shape.
---

The CLI and web UI use this API. All bodies are JSON. The server listens on port `8080`.

## Authentication

Send an API key in the `Authorization` header:

```bash
curl -H "Authorization: Bearer $HEIMDALL_API_KEY" "$HEIMDALL_URL/api/v1/realms"
```

Keys have one of three scopes: `ingest`, `read` and `admin`. **`admin` satisfies
every scope**; `read` and `ingest` satisfy only themselves. An admin key whose
name is not in `admins` (and is not `bootstrap`) is refused with `403`.

`/healthz` and `/metrics` need no key. Browser sessions use the `heimdall_session` cookie; mutations require the `X-CSRF-Token` returned by `GET /auth/me`. Bearer keys do not need CSRF tokens.

## Errors

Errors come back as a status code and a JSON body, `{"error": "message"}`:

| Status | Meaning |
|---|---|
| `400` | Bad input: unknown realm, malformed body or parameter, rule violation. |
| `401` | Missing or unknown key. |
| `403` | The key's scope is too low, or its admin name is not allowed. |
| `404` | No such oath, key or service. |
| `413` | Body too large (limit 20 MB on ingest and gate). |
| `500` | Internal error. The detail is logged, never returned. |

## Summary

| Method and path | Scope | Purpose |
|---|---|---|
| `GET /healthz` | none | Health check. |
| `GET /metrics` | none | Prometheus metrics. |
| `GET /api/v1/status` | read | Realm-scoped overview and feed status. |
| `GET /api/v1/realms` | read | Realms with counts. |
| `GET /api/v1/findings` | read | List findings. |
| `GET /api/v1/findings/{id}` | read | Finding details. |
| `GET /api/v1/services` | read | List services. |
| `GET /api/v1/services/{id}/components` | read | A service's components. |
| `GET /api/v1/releases` | read | Recorded releases. |
| `POST /api/v1/ingest/sbom` | ingest | Upload an SBOM. |
| `POST /api/v1/ingest/cluster` | ingest | Upload a cluster inventory. |
| `POST /api/v1/ingest/image/{digest}` | ingest | Upload an image SBOM. |
| `GET /api/v1/images/pending` | ingest | Images that need an SBOM. |
| `POST /api/v1/images/{digest}/failed` | ingest | Report an image that could not be scanned. |
| `POST /api/v1/gate` | ingest | Run the CI gate. |
| `GET /api/v1/oaths` | read | List oaths. |
| `POST /api/v1/oaths` | admin | Create an oath. |
| `POST /api/v1/oaths/{id}/revoke` | admin | Revoke an oath. |
| `POST /api/v1/oaths/{id}/extend` | admin | Move an oath's date. |
| `GET /api/v1/users` | admin | List users. |
| `PATCH /api/v1/users/{id}` | admin | Enable or disable a user. |
| `GET /api/v1/users/{id}/grants` | admin | List stored grants. |
| `PUT /api/v1/users/{id}/grants` | admin | Replace stored grants. |
| `GET /api/v1/audit` | admin | Query audit events. |
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
| `offset` | `0` | Pagination offset. |
| `realms` | permitted realms | Comma-separated realm selection. |
| `view_status` | unset | `open`, `snoozed`, `ignored`, or `resolved`. |
| `severity` | all | Exact severity. |
| `service`, `search` | unset | Service name, or advisory/alias/package search. |
| `has_fix` | unset | Boolean fix-availability filter. |
| `sort`, `order` | `opened_at`, `desc` | Sort by `opened_at`, `severity`, `kind`, `realm`, `service`, or `advisory`; order `asc` or `desc`. |

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

Scope `read`. Optional `realm`, `limit`, and `offset`. Returns `{"id", "realm", "name", "components"}`
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
| `offset` | `0` | Pagination offset. |
| `since` | none | A date (`2026-01-31`, midnight UTC) or an RFC 3339 time. |
| `limit` | `500` | 1 to 5000. |

Rows: `id`, `target`, `version`, `published_at` (nullable), `is_major`,
`notes_url` (nullable), `notes_class` (nullable).

## Bifröst: ingest

These routes accept bodies up to 20 MB. At most two uploads (`ingest/sbom`,
`ingest/image` and the gate together) are handled at once; more wait their
turn before their body is read, so a burst of CI jobs cannot exhaust the
1 GB container.

### `POST /api/v1/ingest/sbom`

Scope `ingest`. Upload a CycloneDX SBOM for one service.

| Query parameter | Meaning |
|---|---|
| `service` | Service name. |
| `realm` | Realm (must be in `realms`). |
| `branch` | Branch the SBOM was built from. |
| `default_branch` | The repository's default branch. |
| `allow_empty` | Optional, `true` to accept an SBOM with no components. |

Body:

```json
{ "sbom": { "bomFormat": "CycloneDX", "components": [] }, "direct": ["pkg:npm/lodash"] }
```

`direct` is optional: the name keys (purl without version) to mark as direct
dependencies. When `branch` equals `default_branch` the upload replaces the
service's `git` components; otherwise it replaces its `ci` components.

An SBOM with no components (none with a purl) is refused with `400` and
`empty SBOM` in the message, and the inventory is left alone: such an SBOM is
almost always a broken generator, and taking it would empty the service and
resolve its findings. Pass `allow_empty=true` when the service really has no
dependencies.

Response:

```json
{ "source": "git", "added": 12, "removed": 3, "skipped_without_purl": 0 }
```

### `POST /api/v1/ingest/cluster`

Scope `ingest`. Upload what Sight saw in a realm. Services in the realm that have
cluster components but are not listed are emptied. The whole upload is one
transaction: if anything fails, nothing of it is applied.

An inventory with no services is refused with `400` and `empty cluster
inventory` in the message, and the inventory is left alone: a failed scan
(missing RBAC, wrong context) would otherwise empty every cluster service of the
realm and resolve its findings. Pass the query parameter `allow_empty=true` when
the cluster really runs nothing. Sight never sends an empty inventory on
purpose, so an empty scan shows up as an error in its log.

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
`[ { "digest": "sha256:…", "image_ref": "ghcr.io/my-org/api@sha256:…" } ]`.
Never-tried digests come first, then the least recently tried, so one image
that keeps failing cannot hold up the rest. A digest that failed five times is
listed again only a day after its last try.

### `POST /api/v1/images/{digest}/failed`

Scope `ingest`. Report that an image could not be scanned. Body
`{ "error": "syft exited with 1: …" }`; the error is kept (first 1000
characters) next to an attempt count. `heimdall scan-images` calls this for
every image that fails. `digest` must be `sha256:` followed by 64 hex
characters. Returns `{ "digest": "sha256:…" }`.

## Hofund: the gate

### `POST /api/v1/gate`

Scope `ingest`. Ingests the SBOM exactly like `/api/v1/ingest/sbom`, checks every
component and returns a verdict. Query parameters are the same four as ingest, plus:

| Parameter | Meaning |
|---|---|
| `fail_on` | `critical`, `high`, `medium`, `low` or `unknown`. |

The body is the same as for `ingest/sbom`, and so is the `400` for an empty
SBOM (and `allow_empty=true`). The call answers within 60 seconds and
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
- OSV often has several records for one vulnerability (a `GO-` and a `GHSA-`
  record for the same CVE). They give one finding, under the `GHSA-` record
  (else the alphabetically smallest id), with the highest severity of them and
  a fix any of them knows. An oath filed under any of the names
  covers it.

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

API keys require `admin`; sessions require editor access to the oath realm.

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
taken from the key's name. Rule violations are `400`.

`advisory_id` may be any name of the advisory: its id, a CVE id, or an alias
such as a `GO-` id. The oath is stored under the advisory id that findings
carry, and the name you gave is kept in its history (`filed as CVE-…`). When
no known advisory has that name, the oath is stored as given and a warning
comes back:

```json
{ "id": 12, "warning": null }
```

`warning` is a message when the name matched nothing (the CLI prints it);
such an oath applies only once an advisory with exactly that id is linked.

### `POST /api/v1/oaths/{id}/revoke`

API keys require `admin`; sessions require editor access to the oath realm. Returns the oath. `404` if there is no such id. Revoking an already
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

## Browser authentication and access

| Method and path | Purpose |
|---|---|
| `GET /auth/login` | Discover enabled local and OIDC methods. |
| `POST /auth/local` | Sign in with JSON `username` and `password`; sets the session cookie. |
| `GET /auth/oidc/start` | Begin OIDC authorization. |
| `GET /auth/oidc/callback` | Finish OIDC authorization. |
| `GET /auth/me` | Current `kind`, `name`, `grants`, and `csrf_token`. |
| `POST /auth/logout` | Delete the session (requires CSRF token). |

Users, stored grants, and audit endpoints require global admin. PATCH a user with `{"disabled": true}` or `false`; PUT grants with an array such as `[{"role":"viewer","realm":"payments"}]`. List users supports `limit`, `offset`, `sort`, and `order`. Audit supports `actor`, `action`, `since`, `until`, `limit`, `offset`, `sort`, and `order`. Local users are created with the CLI.

`GET /api/v1/status` accepts comma-separated `realms`. UI projections `/api/v1/ui/services`, `/api/v1/ui/services/{id}/{section}`, `/api/v1/ui/releases`, and `/api/v1/ui/oaths` support `realms`, `limit`, `offset`, `sort`, and `order`; release projections also accept `kind`, and oath projections accept `tab`. These are separate from the existing services and releases response shapes. Lists are filtered to the session's permitted realms.
