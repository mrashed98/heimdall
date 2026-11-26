---
title: CLI
description: Every heimdall subcommand and flag, the banner and styled output, colour control and exit codes.
---

`heimdall` is one binary: the server and the command-line client. Most commands
are thin clients of the [HTTP API](/heimdall/reference/http-api/) and need two
environment variables:

| Variable | Meaning |
|---|---|
| `HEIMDALL_URL` | Base URL, for example `http://heimdall.internal:8080`. |
| `HEIMDALL_API_KEY` | An API key with the scope the command needs. |

Run `heimdall --help` or `heimdall <command> --help` any time. `heimdall --version`
prints the version.

## Commands at a glance

| Command | What it does | Needs |
|---|---|---|
| [`serve`](#heimdall-serve) | Run the server, or validate the config. | `DATABASE_URL` |
| [`gate`](#heimdall-gate) | Hofund, the CI gate. | ingest key |
| [`oath`](#heimdall-oath) | Snooze, ignore, list, extend, revoke oaths. | admin key (`list`: read) |
| [`user`](#heimdall-user) | Manage local users directly. | `DATABASE_URL`, config |
| [`keys`](#heimdall-keys) | Create, list, revoke API keys. | admin key |
| [`sight`](#heimdall-sight) | Scan the cluster and ingest its inventory. | cluster access |
| [`scan-images`](#heimdall-scan-images) | Generate SBOMs for images that have none. | ingest key, syft |
| [`findings`](#heimdall-findings) | List findings. | read key |
| [`realms`](#heimdall-realms) | List realms with counts. | read key |
| [`baseline`](#heimdall-baseline) | Mark a realm's backlog announced without alerting. | `DATABASE_URL`, config |

## Global flag

| Flag | Meaning |
|---|---|
| `--no-color` | Turn off colour. Works with every command. |

## `heimdall serve`

Run the server, or just check the config.

```bash
heimdall serve [--check-config] [CONFIG]
```

| Argument | Default | Meaning |
|---|---|---|
| `CONFIG` | `heimdall.yaml` | Path to the config file. |
| `--check-config` | off | Parse the config, print `config ok` and exit. On error prints `config error: ...` and exits `1`. |

The server listens on `0.0.0.0:8080`. It needs `DATABASE_URL`, and reads
`HEIMDALL_BOOTSTRAP_ADMIN_KEY` if set. See
[Environment variables](/heimdall/reference/environment-variables/).

## `heimdall gate`

Hofund: the CI gate. Uploads an SBOM, prints a report, exits `0`, `1` or `2`.

```bash
heimdall gate --service api --realm dev-k3s --sbom sbom.json --fail-on high
```

| Flag | Default | Meaning |
|---|---|---|
| `--service NAME` | required | Service name. |
| `--realm NAME` | required | Realm. |
| `--sbom FILE` | required | CycloneDX JSON SBOM. |
| `--fail-on SEVERITY` | required | Lowest severity that fails the build: `critical`, `high`, `medium`, `low` or `unknown`. |
| `--repo-root DIR` | `.` | Where `go.mod` and `package.json` files are read for direct dependencies. |
| `--branch NAME` | `$GITHUB_REF_NAME` | Branch being built. Required if the variable is not set. |
| `--default-branch NAME` | from `$GITHUB_EVENT_PATH` | The repository's default branch. Required if the event file has no `repository.default_branch`. |
| `--allow-empty` | off | Accept an SBOM with no components. Without it the server refuses one (exit `2`), so a broken SBOM step cannot empty the service's inventory. |

**Exit codes**

| Code | Meaning |
|---|---|
| `0` | Pass. |
| `1` | Vulnerabilities at or above `--fail-on`, outside an active oath. |
| `2` | Unverified, or any error (server unreachable, bad response, bad input). Errors print `hofund: ...` and never pass silently. |

The client waits up to 120 seconds; the server answers within 60. See the
[CI gate guide](/heimdall/guides/ci-gate/).

## `heimdall oath`

Oaths (suppressions). Needs an admin key, except `list` which needs read. See
[Managing oaths](/heimdall/guides/oaths/).

### `heimdall oath snooze` and `ignore`

```bash
heimdall oath snooze <ADVISORY> --service S (--realm R | --all-realms) --purl PURL --reason TEXT --until DATE
heimdall oath ignore <ADVISORY> --service S (--realm R | --all-realms) --purl PURL --reason TEXT [--until DATE]
```

| Argument | Meaning |
|---|---|
| `ADVISORY` | Advisory id, for example `GHSA-...`, or any other name of it (`CVE-...`, `GO-...`). It is stored under the id findings carry. |
| `--service` | Service name. |
| `--realm` / `--all-realms` | One realm, or every realm. Give exactly one. |
| `--purl` | The component's current package URL. |
| `--reason` | Why this is acceptable. Required, not blank. |
| `--until YYYY-MM-DD` | Snooze: **required**, the first day the oath no longer holds. Ignore: the review date, default 90 days from today. Must be after today (UTC). |

Prints `oath <id>`. When no known advisory has the given name, the oath is still
stored, and a warning is printed on stderr: it applies only once an advisory
with exactly that id turns up.

### `heimdall oath list`

`--status active|expired|revoked` (optional). Prints a table.

### `heimdall oath revoke <ID>`

Revokes an oath.

### `heimdall oath extend <ID> --until DATE`

Moves the oath's date. An expired oath becomes active again.

## `heimdall keys`

API keys. Needs an admin key. Scopes: `ingest`, `read`, `admin`.

```bash
heimdall keys create --name ci-runner --scope ingest   # prints the key once
heimdall keys create --name alice --scope admin        # only if alice is in `admins`
heimdall keys list                                     # name, scope, created_at
heimdall keys revoke ci-runner
```

Names match `[A-Za-z0-9._-]{1,64}`. An `admin` key can only be created for a name
listed under `admins:` in the config. `bootstrap` is reserved: it exists only
through `HEIMDALL_BOOTSTRAP_ADMIN_KEY` (changing that variable rotates it;
removing it, or setting it empty, deletes the key at the next start), and
`keys create --name bootstrap` is rejected. Create a named admin key for yourself,
then remove the variable. Keys are stored as SHA-256 hashes
([ADR 0004](/heimdall/decisions/0004-sha256-api-keys/)); the plaintext is shown
only once.

## `heimdall sight`

Scan a cluster, or with `--docker` a Docker host, and ingest its inventory.

| Flag | Default | Meaning |
|---|---|---|
| `--realm NAME` | required | Realm the cluster or host belongs to. |
| `--push URL` | off | POST to this Heimdall instead of ingesting in-process (scout mode). Needs `HEIMDALL_API_KEY`. |
| `--config FILE` | `heimdall.yaml` | Config path, for in-process mode (also needs `DATABASE_URL`). |
| `--docker` | off | Read a Docker host's running containers instead of a cluster. |
| `--docker-host URL` | `unix:///var/run/docker.sock` | The Docker Engine API, `unix://` or `tcp://`. |
| `--docker-name NAME` | the name Docker reports | The host's name in service names. |

A Docker scan replaces only that host's services, so it never empties a
cluster's or another host's, and a host running nothing is a valid scan.

Prints `sight: N services, N components added, N removed`.

## `heimdall scan-images`

Generate SBOMs for images that have none. This is what the Helm CronJob runs.

| Flag | Default | Meaning |
|---|---|---|
| `--max N` | `20` | Most images to scan in one run. |
| `--syft PATH` | `syft` | Path to the syft binary. |

Each image that fails is reported to the server
(`POST /api/v1/images/{digest}/failed`), which then offers the other images
first; an image that failed five times is offered again only a day after its
last try. Exits with failure only if every attempted image failed.

## `heimdall findings`

| Flag | Default | Meaning |
|---|---|---|
| `--realm NAME` | all | Only this realm. |
| `--status` | `open` | `open` or `resolved`. |
| `--kind` | all | `vuln`, `fixavailable`, `majorrelease`, `oathexpired`, `eol`, `k8scve` or `releasenotecve`. |
| `--min-severity` | `low` | Lowest severity to list. |

## `heimdall realms`

Lists realms with their service and open-finding counts.

## `heimdall baseline`

`heimdall baseline --realm NAME [--config heimdall.yaml]` marks every open finding of the realm that was not announced yet as announced, without sending anything. Run it once before you add an alert channel to a realm with a large backlog, so the channel is not flooded. The findings stay open in the web UI, the API and the counts; one-shot kinds (`k8scve`, `releasenotecve`, `oathexpired`) resolve as if they had been sent. Afterwards new findings and state changes (a fix appears, an oath expires, a severity rises) alert as usual. The run is recorded in the audit log. Like `user`, it connects directly using `DATABASE_URL`.

## Banner and styled output

`heimdall` with no command (or `--help`) shows the Bifröst banner, a rainbow
gradient over the letters, shown here in plain text:

```text
█   █  █████  █████  █   █  ████    ███   █      █
█   █  █        █    ██ ██  █   █  █   █  █      █
█████  ████     █    █ █ █  █   █  █████  █      █
█   █  █        █    █   █  █   █  █   █  █      █
█   █  █████  █████  █   █  ████   █   █  █████  █████
the watcher at the Bifröst · v0.1.0
```

- Output is coloured when stdout is a terminal, and in CI where there is no
  terminal but `CI`, `GITHUB_ACTIONS` or `CLICOLOR_FORCE` is set.
- Severities use the same colours everywhere: critical bold white on red, high
  red, medium yellow, low blue, unknown dim.
- Turn colour off with `--no-color`, `NO_COLOR` or `TERM=dumb`.
- `COLORTERM=truecolor` (or `24bit`) gives the full gradient; other terminals get
  the six basic ANSI colours.
- `serve` prints the banner only on a terminal, so JSON logs stay clean, and
  `gate` prints only its compact header. Exit codes are unchanged.

## Exit codes

| Command | Codes |
|---|---|
| `gate` | `0` pass, `1` vulnerabilities, `2` unverified or error. |
| `scan-images` | `0` unless every attempted image failed, then `1`. |
| everything else | `0` success, `1` error (message on stderr as `error: ...`). |

## `heimdall user`

`heimdall user [--config heimdall.yaml] create NAME [--role viewer|editor|admin]` creates a local user and prompts for a password. A role grants access to all realms; admin requires the name in `admins`. `heimdall user passwd NAME` changes a password, `heimdall user disable NAME` disables the user and revokes sessions, and `heimdall user list` lists users. These commands connect directly using `DATABASE_URL` and load the configuration; they do not use the HTTP API.
