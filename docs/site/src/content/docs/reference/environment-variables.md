---
title: Environment variables
description: Every environment variable Heimdall reads, and which command or component uses it.
---

## Server (`heimdall serve`)

| Variable | Required | Meaning |
|---|---|---|
| `DATABASE_URL` | yes | Postgres connection string, for example `postgres://heimdall:heimdall@localhost:5433/heimdall`. Also used by `heimdall sight` in in-process mode. |
| `HEIMDALL_BOOTSTRAP_ADMIN_KEY` | no | The admin key named `bootstrap`. Must be `hd_` plus 43 base64url characters, or the server refuses to start. Changing it rotates the key. If unset or empty, the `bootstrap` key is deleted at startup (so removing the variable revokes it). |
| `HEIMDALL_SECRET_KEY` | no | Key that encrypts the secrets of alert channels added in the web console: 32 random bytes in standard base64 (`openssl rand -base64 32`). Read at startup. If unset or malformed (the error is logged, never the value), Heimdall starts and config channels deliver, but channels cannot be managed in the console and console channels that hold a secret keep their alerts queued. Back it up: without it the stored secrets must be re-entered. See [Managing channels in the console](/heimdall/guides/alert-channels/#managing-channels-in-the-console). |
| `HEIMDALL_OIDC_CLIENT_SECRET` | when configured | OIDC client secret when named by `auth.oidc.client_secret_env`; the name is configurable. |
| `GITHUB_TOKEN` | no | Raises the GitHub rate limit (5000 requests an hour instead of 60), fetches release notes, and enables the gate's GitHub Advisory Database fallback. |
| `NVD_API_KEY` | no | NVD API key. The variable name is configurable with `nvd.api_key_env`. |
| `TEAMS_WEBHOOK_*` | no | One variable per `teams[].webhook_env`, holding the webhook URL. The names are yours to choose. |
| Channel secrets | no | One variable per `*_env` key of a `channels[]` entry: webhook URLs, the Telegram bot token, the PagerDuty routing key, the webhook HMAC secret, SMTP and Alertmanager credentials. The names are yours to choose. See [Alert channels](/heimdall/guides/alert-channels/). |
| Registry credentials | no | One variable per `registries[].secret_env`, holding `user:password`. |
| `RUST_LOG` | no | Log filter. Default `info`. |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | no | When set, traces are exported over OTLP/HTTP. Other standard `OTEL_*` variables are read by the exporter. |

## CLI client

| Variable | Meaning |
|---|---|
| `HEIMDALL_URL` | Base URL of the server. Required by every client command. |
| `HEIMDALL_API_KEY` | API key. Required by every client command, and by `sight --push`. |
| `GITHUB_REF_NAME` | `heimdall gate` uses it as the branch when `--branch` is not given. Set by GitHub Actions. |
| `GITHUB_EVENT_PATH` | `heimdall gate` reads `repository.default_branch` from this file when `--default-branch` is not given. Set by GitHub Actions. |

## Terminal output

| Variable | Effect |
|---|---|
| `NO_COLOR` | Turns colour off. |
| `TERM=dumb` | Turns colour off. |
| `CI`, `GITHUB_ACTIONS`, `CLICOLOR_FORCE` | Keep colour on when stdout is not a terminal. |
| `COLORTERM=truecolor` or `24bit` | Full-colour gradient in the banner. |

`--no-color` also turns colour off.

## Image scanner CronJob

Set by the Helm chart:

| Variable | Meaning |
|---|---|
| `HEIMDALL_URL` | The in-cluster Service URL. |
| `HEIMDALL_API_KEY` | From the Secret (ingest scope). |
| `SYFT_CHECK_FOR_APP_UPDATE` | `false`, so syft does not check for updates. |
| `XDG_CACHE_HOME` | `/cache`, an emptyDir. |
| `DOCKER_CONFIG` | `/docker`, only when `scanImages.dockerConfigSecret` is set. |
