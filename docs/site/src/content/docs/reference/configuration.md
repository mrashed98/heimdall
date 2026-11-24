---
title: Configuration
description: Every key of heimdall.yaml with its type, default and an example.
---

`heimdall serve <path>` reads one YAML file. With the Helm chart, the same keys
go under `config:` in your values. Only **`realms`** is required; everything else
has the default shown. A complete example is
[`heimdall.example.yaml`](https://github.com/mrashed98/heimdall/blob/main/heimdall.example.yaml).

Check a file without starting the server:

```bash
heimdall serve --check-config heimdall.yaml     # prints "config ok"
```

A problem prints `config error: ...` naming the file and the field, and exits
with a failure code. The check is strict: an unknown key anywhere (a typo such
as `major_componant`, or a key under the wrong parent) is an error, and so are
`digest.hour` outside 0 to 23, any `*_minutes` (and `nvd.minutes`) of `0`, a
realm in `teams[].realms`, `channels[].realms`, `declared[].realm` or
`sight.realm` that is not listed in `realms`, a channel name used twice (across
`teams` and `channels`), and a channel setting that cannot work (an empty
`*_env`, a URL with credentials in it, an invalid email address).

## Summary

| Key | Type | Default |
|---|---|---|
| [`realms`](#realms) | list of strings | required |
| [`digest`](#digest) | object | Monday, 9, UTC |
| [`admins`](#admins) | list of strings | `[]` |
| [`own_registries`](#own_registries) | list of strings | `[]` |
| [`teams`](#teams) | list of routes | `[]` |
| [`channels`](#channels) | list of channels | `[]` |
| [`watchers`](#watchers) | object | empty |
| [`declared`](#declared) | list | `[]` |
| [`registries`](#registries) | list | `[]` |
| [`sight`](#sight) | object | first realm |
| [`schedules`](#schedules) | object | see below |
| [`nvd`](#nvd) | object | see below |
| [`retention`](#retention) | object | see below |

## `realms`

List of realm names Heimdall tracks. **Required.** Uploads and API calls that name
an unknown realm are rejected with `400`.

```yaml
realms:
  - dev-k3s
```

## `digest`

When the weekly digest is sent.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `digest.weekday` | weekday | `Mon` | Day of the week (`Mon`, `Tue`, ...). |
| `digest.hour` | integer | `9` | Hour of the day (0 to 23) in `digest.timezone`. |
| `digest.timezone` | IANA name | `UTC` | For example `Africa/Cairo`. |

```yaml
digest:
  weekday: Mon
  hour: 9
  timezone: Africa/Cairo
```

## `admins`

Type: list of strings. Default: `[]`.

Key names allowed to hold an `admin` key, besides `bootstrap`. Use one key per
person. Removing a name disables that person's admin keys on the next request.
Oaths record the admin's name.

```yaml
admins: [alice, bob]
```

## `own_registries`

Type: list of strings. Default: `[]`.

Registry hosts or `host/org` prefixes. Images from them are scanned for
vulnerabilities but never release-watched.

```yaml
own_registries:
  - ghcr.io/mrashed98
```

## `teams`

Type: list of routes. Default: `[]`. See [Microsoft Teams alerts](/heimdall/guides/teams/).

| Key | Type | Meaning |
|---|---|---|
| `name` | string | Route name. |
| `webhook_env` | string | Name of the environment variable holding the webhook URL. |
| `realms` | list of strings | Realms this route covers. Empty means all. Default `[]`. |
| `min_severity` | `critical`, `high`, `medium`, `low`, `unknown` | Lowest severity the route receives. **Required.** |

```yaml
teams:
  - name: default
    webhook_env: TEAMS_WEBHOOK_DEFAULT
    realms: []
    min_severity: high
```

`teams` routes are Teams channels; the same route can be written under
`channels` with `type: teams`.

## `channels`

Type: list of channels. Default: `[]`. See [Alert channels](/heimdall/guides/alert-channels/).
Admins can also add channels in the web console; those are stored in Postgres,
not in this file, and need `HEIMDALL_SECRET_KEY` (see [Managing channels in the
console](/heimdall/guides/alert-channels/#managing-channels-in-the-console) and
[Environment variables](/heimdall/reference/environment-variables/)). A config
channel wins over a console channel of the same name.
Every channel has:

| Key | Type | Meaning |
|---|---|---|
| `type` | `teams`, `slack`, `discord`, `telegram`, `pagerduty`, `alertmanager`, `webhook`, `email` | The kind of channel. **Required.** |
| `name` | string | Channel name, unique across `teams` and `channels`. **Required.** |
| `realms` | list of strings | Realms this channel covers. Empty means all. Default `[]`. |
| `min_severity` | `critical`, `high`, `medium`, `low`, `unknown` | Lowest severity the channel receives. **Required.** |
| `digest` | boolean | Receive the weekly digest and the first-run summary. Default `true`, except `false` for `pagerduty` and `alertmanager`. Also accepted on `teams` routes. |

And, by type (keys of other types are rejected):

| Type | Key | Type | Meaning |
|---|---|---|---|
| `teams`, `slack`, `discord` | `webhook_env` | string | Variable holding the webhook URL. **Required.** |
| `telegram` | `bot_token_env` | string | Variable holding the bot token. **Required.** |
| `telegram` | `chat_id` | integer or string | Chat id (`-1001234567890`) or `@channelname`. **Required.** |
| `telegram` | `api_url` | URL | Bot API base. Default `https://api.telegram.org`. |
| `pagerduty` | `routing_key_env` | string | Variable holding the Events API v2 routing key. **Required.** |
| `pagerduty` | `url` | URL | Events endpoint. Default `https://events.pagerduty.com/v2/enqueue`. |
| `alertmanager` | `url` | URL | Base URL; alerts go to `{url}/api/v2/alerts`. No credentials in it. **Required.** |
| `alertmanager` | `username_env`, `password_env` | string | Variables holding basic auth credentials (both or neither). |
| `alertmanager` | `bearer_token_env` | string | Variable holding a bearer token (not with basic auth). |
| `alertmanager` | `expire_after_hours` | integer | `endsAt` = delivery time + this. Default `24`. |
| `webhook` | `url_env` | string | Variable holding the URL to POST to. **Required.** |
| `webhook` | `secret_env` | string | Variable holding the HMAC-SHA256 secret for `X-Heimdall-Signature`. |
| `email` | `host` | string | SMTP server. **Required.** |
| `email` | `port` | integer | Default 587 (`starttls`), 465 (`tls`) or 25 (`none`). |
| `email` | `security` | `starttls`, `tls`, `none` | Default `starttls`. |
| `email` | `username_env`, `password_env` | string | Variables holding the SMTP login (both or neither; not with `security: none`). |
| `email` | `from` | string | Sender address. **Required.** |
| `email` | `to` | list of strings | Recipients, at least one. **Required.** |

```yaml
channels:
  - type: slack
    name: dev-chat
    webhook_env: SLACK_WEBHOOK_DEV
    realms: [dev]
    min_severity: high
  - type: alertmanager
    name: am
    url: http://alertmanager.monitoring:9093
    min_severity: high
```

## `watchers`

Config-driven release targets. See [Watching infrastructure](/heimdall/guides/watching-infrastructure/).
All three lists default to `[]`.

### `watchers.github[]`

| Key | Type | Meaning |
|---|---|---|
| `repo` | string | GitHub repository, `owner/name`. **Required.** |
| `inventory_name` | string | Name in your inventory (`pkg:generic/<name>`). **Required.** |
| `major_component` | integer | Which version number is the major: `0` (default) first, `1` second. |
| `cpe` | string | Optional CPE 2.3 prefix tying the target to NVD. |

### `watchers.endoflife[]`

| Key | Type | Meaning |
|---|---|---|
| `product` | string | endoflife.date product name. **Required.** |
| `inventory_name` | string | Name in your inventory. **Required.** |
| `major_component` | integer | As above. Default `0`. |
| `cpe` | string | Optional CPE 2.3 prefix. |
| `repo` | string | Optional GitHub repository used for release notes. |

### `watchers.tf_registry[]`

| Key | Type | Meaning |
|---|---|---|
| `registry` | string | `registry.terraform.io` or `registry.opentofu.org`. **Required.** |
| `kind` | `provider` or `module` | **Required.** |
| `source` | string | For example `hashicorp/aws`. **Required.** |
| `current` | string | The version you run. **Required.** |

```yaml
watchers:
  github:
    - { repo: kubernetes/kubernetes, inventory_name: kubernetes, major_component: 1 }
    - { repo: apache/kafka, inventory_name: kafka, cpe: "cpe:2.3:a:apache:kafka" }
  endoflife:
    - { product: postgresql, inventory_name: postgresql, repo: postgres/postgres }
  tf_registry:
    - { registry: registry.terraform.io, kind: provider, source: hashicorp/aws, current: "5.40.0" }
```

## `declared`

Components outside any cluster or SBOM, such as a database on a VM. The weekly
digest lists each as "declared since {date}".

| Key | Type | Meaning |
|---|---|---|
| `realm` | string | Realm the component belongs to. |
| `service` | string | Service name. |
| `purl` | string | Package URL, for example `pkg:generic/postgresql@17.2`. |

```yaml
declared:
  - { realm: dev-k3s, service: postgres-vm, purl: "pkg:generic/postgresql@17.2" }
```

## `registries`

Private registry credentials, used by the OCI watcher for tag lookups. See
[Private registries](/heimdall/guides/private-registries/).

| Key | Type | Meaning |
|---|---|---|
| `host` | string | Registry host. |
| `secret_env` | string | Name of the environment variable holding `user:password`. |

```yaml
registries:
  - host: registry.example.com
    secret_env: REGISTRY_EXAMPLE_CREDENTIALS
```

## `sight`

| Key | Type | Default | Meaning |
|---|---|---|---|
| `sight.realm` | string | first of `realms` | The realm of the cluster Heimdall itself runs in. In-process Sight scans it, and is skipped when no cluster is reachable. |

## `schedules`

Polling intervals in minutes.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `schedules.sight_minutes` | integer | `15` | Cluster scan. |
| `schedules.osv_minutes` | integer | `15` | OSV match. At most 15: larger values count as 15, because the matcher run after each OSV refresh is also what expires oaths. |
| `schedules.k8s_cve_minutes` | integer | `30` | Kubernetes CVE feed. |
| `schedules.watchers_minutes` | integer | `60` | Release watchers. |

## `nvd`

| Key | Type | Default | Meaning |
|---|---|---|---|
| `nvd.api_key_env` | string | `NVD_API_KEY` | Name of the environment variable holding the NVD API key. |
| `nvd.minutes` | integer | `120` | NVD poll interval. |

## `retention`

How long old rows are kept, in days. Cleanup runs once a day. Oaths and their
history are kept forever. The same job also deletes the scan-failure history of
images that were scanned or no longer run in any cluster.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `retention.findings_days` | integer | `365` | Resolved findings. |
| `retention.releases_days` | integer | `365` | Release records. |
| `retention.outbox_days` | integer | `30` | Sent notification rows. |

## Fixed values

Not configurable: the server listens on `0.0.0.0:8080`, ingest bodies are
limited to 20 MB, at most two uploads are handled at once, and the database
pool holds 10 connections.

## Web authentication (`auth`)

`auth` is optional. When absent the UI offers API-key sign-in. See [Sign-in and access control](/heimdall/guides/sign-in-access-control/) for complete examples.

| Key | Default | Meaning |
|---|---|---|
| `auth.public_url` | required when auth is present | External HTTPS URL, or HTTP localhost. |
| `auth.trusted_proxies` | `[]` | CIDRs allowed to supply X-Forwarded-For; configure the ingress controller pod CIDR when using ingress. |
| `auth.session.idle_hours` | `12` | Idle session timeout; positive integer. |
| `auth.session.absolute_days` | `7` | Maximum session lifetime; positive integer. |
| `auth.local.enabled` | `false` | Enable local password sign-in. |
| `auth.oidc.issuer` | required for OIDC | Provider issuer URL. |
| `auth.oidc.client_id` | required for OIDC | Client identifier. |
| `auth.oidc.client_secret_env` | required for OIDC | Name of the environment variable containing the secret. |
| `auth.oidc.scopes` | `[openid, profile, email]` | Requested scopes; `groups` is also included by default when `groups_claim` is set. An explicit list overrides the defaults. |
| `auth.oidc.groups_claim` | unset | Name of the ID-token groups claim. |
| `auth.oidc.groups_max_age_minutes` | `60` | OIDC sessions require reauthentication after this many minutes; minimum 5. |
| `auth.oidc.admin_match_username` | `false` | Allow preferred_username to match admins. Email must be verified to match. |
| `auth.oidc.role_mappings` | `[]` | List of `group`, `role`, `realms` mappings. |
| `auth.oidc.default_role` | unset | Optional `role` and `realms` grant. |
| `retention.audit_days` | `365` | Audit log retention in days. |

Roles are `viewer`, `editor`, or `admin`; realms must be configured names or `*`. Admin grants must use only `realms: ["*"]` and users must also be listed in top-level `admins`. Unknown configuration fields are rejected.
