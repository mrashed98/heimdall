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
| `404` | No such oath, key, service or channel. |
| `409` | Conflict: an alert channel name already used, or `HEIMDALL_SECRET_KEY` not set. |
| `413` | Body too large (limit 20 MB on ingest and gate). |
| `429` | Too many requests, such as a second channel test within 10 seconds. |
| `502` | A channel test failed at the destination. |
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
| `GET /api/v1/trends` | read | Open findings per day, per realm. |
| `GET /api/v1/services/{id}/trend` | read | Open findings per day for one service. |
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
| `GET /api/v1/channels` | admin | List alert channels, from the config and the console. |
| `POST /api/v1/channels` | admin | Create a console alert channel. |
| `PATCH /api/v1/channels/{id}` | admin | Edit a console alert channel. |
| `GET /api/v1/channels/{id}/queued` | admin | Count the alerts deleting a channel would discard. |
| `DELETE /api/v1/channels/{id}` | admin | Delete a console alert channel. |
| `POST /api/v1/channels/{name}/test` | admin | Send a test alert to a channel. |

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
| `severity` | all | Exact severity, or a comma list such as `critical,high`. |
| `service`, `search` | unset | Service name, or advisory/alias/package search. |
| `has_fix` | unset | Boolean fix-availability filter. |
| `sort`, `order` | `opened_at`, `desc` | Sort by `opened_at`, `severity`, `epss`, `kind`, `realm`, `service`, or `advisory`; order `asc` or `desc`. |

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

With `ui=true` (or `sort=epss`), rows also carry `epss` and `epss_percentile`
(0 to 1) when the finding's CVE has an [EPSS score](/heimdall/concepts/matching/#epss).
The fields are left out otherwise, so API-key responses keep the shape above.
`GET /api/v1/findings/{id}` returns both fields, `null` when unscored.

With `ui=true`, rows also carry `summary` (the advisory's) and `fix` (the
version that fixes it, from the finding's own advice or its `fixavailable`
sibling), each left out when unknown. Unless `kind` is given, a `fixavailable`
finding whose `vuln` sibling (same advisory, component, service and realm) is
in the same status is folded into that row, so the list shows one row per
vulnerability, and `has_fix` counts the folded sibling's fix. `GET /api/v1/findings/{id}` also returns `kind`, `details`, `severity`,
`ref_id`, `status`, `opened_at`, `realm`, `service`, and `affected_services`: the number of distinct services in the realm that have this package at the same version in their inventory (any branch, image or cluster source).

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

### `GET /api/v1/trends`

Scope `read`. Open findings per severity at the end of each day (UTC), per
realm, oldest first. Heimdall records today's counts after every matcher run,
so a day holds the last counts taken that day. A day with no row is one the
server did not run; it is not a day with zero findings.

| Parameter | Default | Meaning |
|---|---|---|
| `days` | `90` | Days ending today, 1 to 366. |
| `realms` | the caller's realms | Comma-separated realms. A realm not in the config is a `400`; realms the caller cannot read are ignored. |

```json
{"realm": "prod", "day": "2026-11-26", "critical": 2, "high": 14, "medium": 30, "low": 8, "unknown": 1}
```

Rows older than `retention.trends_days` are deleted.

### `GET /api/v1/services/{id}/trend`

Scope `read`. The same counts for one service, without `realm`. `days` as
above. `404` if the service is not in a realm the caller can read.

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

## Alert channels

Scope `admin`: an admin API key, or a browser session of a global admin. These
routes back **Settings → Alert channels**; see [Managing channels in the
console](/heimdall/guides/alert-channels/#managing-channels-in-the-console). No
response ever contains a secret value or the value of an environment variable.

### `GET /api/v1/channels`

```json
{
  "management_enabled": true,
  "channels": [
    {
      "id": 3,
      "source": "ui",
      "type": "slack",
      "name": "sec-slack",
      "realms": ["prod"],
      "min_severity": "critical",
      "digest": true,
      "settings": {},
      "secrets": { "webhook": { "set": true } },
      "missing_env": [],
      "state": "ok",
      "health": { "queued": 0, "last_sent_at": "2026-11-23T09:00:02Z", "failing": null }
    }
  ]
}
```

- `management_enabled`: whether `HEIMDALL_SECRET_KEY` is set and valid.
- `channels`: the config channels in config order, then the console channels by
  name.
- `id`: `null` for a config channel. `source`: `config` or `ui`.
- `digest`: the effective value, after the type's default.
- `settings`: the type's non-secret fields (for example `chat_id`, `host`,
  `to`), without `type`, `name`, `realms`, `min_severity`, `digest` or any
  `*_env` key.
- `secrets`: each secret field of the type, as `{ "set": true | false }`. For
  `teams`, `slack`, `discord`, `mattermost` and `webhook` the URL is a secret;
  for `jira` the secrets are `username` (optional) and `token`.
- `missing_env`: for a config channel, the names of its variables that are not
  set. Always empty for a console channel.
- `state`: `ok`; `key_missing` (the channel holds secrets and there is no key);
  `unreadable` (its secrets were sealed under another key); `invalid` (its
  stored settings no longer validate; alerts raised meanwhile are not queued
  for it); `name_clash` (a config channel has its name and is used instead).
  Always `ok` for a config channel.
- `realms`: for a console channel, as saved, including a realm since removed
  from the config (which delivery ignores).
- `health`: `queued` unsent alerts, `last_sent_at` of the last delivery (or
  `null`), and `failing`, the redacted error of the oldest queued alert when it
  has one.

### `POST /api/v1/channels`

```json
{
  "type": "telegram",
  "name": "ops-chat",
  "realms": ["prod"],
  "min_severity": "high",
  "digest": null,
  "settings": { "chat_id": -1001234567890 },
  "secrets": { "bot_token": "123456:ABC..." }
}
```

`realms` (default `[]`, all realms), `digest` (default `null`, the type's
default), `settings` and `secrets` are optional. `settings` takes the type's
non-secret keys from the [configuration
reference](/heimdall/reference/configuration/#channels); `secrets` maps each
secret field (the `*_env` key without `_env`: `webhook`, `bot_token`,
`routing_key`, `url` and `secret` for `webhook`, `username`, `password`,
`bearer_token`) to its value. Validation is the same as for the config.

Returns `201` with `{ "id": 3 }`. `400` for an invalid body: unknown type or
realm, a name that is empty, contains `:` or control characters, or starts or
ends with whitespace, a reserved or `*_env` key in `settings`, an unknown or
empty secret, a missing required secret, or a setting that fails validation.
`409` if the name is used by a config or console channel, or if
`HEIMDALL_SECRET_KEY` is not set.

### `PATCH /api/v1/channels/{id}`

Every field is optional; an absent field keeps the saved value. `name` and
`type` cannot be changed.

| Field | Effect |
|---|---|
| `realms`, `min_severity` | Replace the saved value. |
| `digest` | `true` or `false`; `null` resets to the type's default. |
| `settings` | Replaces every non-secret setting. |
| `secrets` | Per field: omitted keeps the stored secret, a string replaces it, `null` clears it (optional secrets only). |

Validation runs on the merged result, so rules such as "username and password
together" still hold; on any error nothing changes. If the stored secrets were
sealed under another key, the request must re-enter or clear every stored
secret. Returns `204`. `400` for an invalid result, `404` for an unknown id,
`409` if `HEIMDALL_SECRET_KEY` is not set.

### `GET /api/v1/channels/{id}/queued`

`{ "queued": 2 }`: how many alerts deleting the channel would discard. `0` when
a config channel with the same name and type owns them. `404` for an unknown id.

### `DELETE /api/v1/channels/{id}`

Deletes a console channel and, in the same transaction, discards its queued
alerts (marked failed, "channel deleted"), except those owned by a config
channel with the same name and type. Works without `HEIMDALL_SECRET_KEY`.
Returns `{ "discarded": 2 }`, or `404`. Config channels have no id and cannot be
deleted here.

### `POST /api/v1/channels/{name}/test`

Sends a fixed test alert to the channel named `name`, from the config or the
console (the config one when both have the name), directly rather than through
the outbox. Returns `204` when the destination accepted it, or `502` with
`{ "error": "..." }`, secrets redacted. `404` if no channel has the name, `409`
if it is a console channel whose state is not `ok` (`{"error": "channel state is
key_missing"}`), `429` if the channel was tested less than 10 seconds ago. Each
test is audited as `channel_tested` with `ok: true` or `false`.

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
