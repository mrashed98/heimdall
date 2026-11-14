---
title: Managing oaths
description: Snooze or ignore an advisory on purpose, with a reason, a date and a review. Create, list, extend and revoke oaths.
---

Sometimes you cannot fix a vulnerability right away: the code path is not
reachable, the upgrade is planned for next quarter, or it is a dev-only
dependency. An **oath** records that decision so the advisory stops alerting,
without becoming invisible or permanent.

## What an oath covers

An oath is always scoped to **one advisory, one component, one service and one
realm** (or all realms). It is never global. It always needs a `--reason`.

Two kinds:

| Kind | Date | Behaviour |
|---|---|---|
| **snooze** | `--until` is required. It is the first day the oath no longer holds. | The advisory comes back when the date passes. |
| **ignore** | `--until` is a review date. The default is 90 days from today. | The oath comes up for review on that date. |

Dates must be after today (UTC) and are taken as midnight UTC.

## Create one

You need an admin key (set `HEIMDALL_URL` and `HEIMDALL_API_KEY` first). Your key's
name is recorded as the author.

```bash
# Snooze until a date
heimdall oath snooze GHSA-xxxx-yyyy-zzzz --service api --realm dev-k3s \
  --purl pkg:golang/example.com/lib@1.2.3 \
  --until 2026-12-31 --reason "not reachable from user input; upgrade planned"

# Ignore, with a review date (default: 90 days from today)
heimdall oath ignore CVE-2026-0001 --service api --all-realms \
  --purl pkg:npm/left-pad@1.3.0 --reason "dev-only dependency"
```

Both print `oath <id>`. Use `--realm` for one realm or `--all-realms` for every
realm, current and future (give one or the other).

The advisory can be given under any of its names: the id Heimdall shows
(`GHSA-…`), its CVE id, or another database's id for it (`GO-…`, `PYSEC-…`).
The oath is stored under the id findings carry, and the name you typed is kept
in its history. If no known advisory has that name, the oath is still stored as
typed, and the CLI prints a warning: it only applies once an advisory with
exactly that id turns up, so check for a typo.

## Manage them

```bash
heimdall oath list --status active     # active, expired or revoked
heimdall oath extend 12 --until 2027-03-31
heimdall oath revoke 12
```

`extend` moves the date. An expired oath becomes active again when extended. A
revoked oath cannot be extended.

## What changes while an oath is active

- No immediate alert, and the gate ignores that advisory for that component.
- The oath is listed in the weekly digest.
- If a **fix is released** while the oath is active, you are still alerted, and
  the oath stays until a human acts. (For a medium or low advisory this holds
  when the fix came out after Heimdall first saw the advisory; see
  [alert rules](/heimdall/concepts/alerts/).)
- When the date passes the oath becomes `expired`, an "oath expired" alert fires,
  and the advisory counts again, in alerts and in the gate. Expiry is noticed
  by the matcher run that follows each OSV refresh, so it lands at most 15
  minutes after the date.

## Across versions

An oath records the version it was taken on. If the component moves to another
version that is **still affected** by the same CVE, the oath stays in force, and
the digest flags "oath carried to new version". If the new version is not
affected, the finding resolves.

## Audit trail

Every oath keeps its history (created, extended, revoked, expired) forever. Oaths
are never removed by [retention](/heimdall/reference/configuration/#retention).

