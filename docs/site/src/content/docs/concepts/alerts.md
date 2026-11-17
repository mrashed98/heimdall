---
title: Alert rules and the digest
description: Which findings alert immediately, how alerts are grouped, and what goes in the weekly digest.
---

Heimdall tries hard not to cry wolf. If its channel gets muted, it has failed.
So alerts follow strict rules, the same for every [alert
channel](/heimdall/guides/alert-channels/) (Teams, Slack, Discord, Telegram,
PagerDuty, Alertmanager, webhooks, email). "Card" below means one alert message
on any channel.

## Immediate alerts

A card is sent right away for:

1. A new **critical or high** vulnerability affecting a component, not under an
   active oath.
2. A **major release** of something in your inventory or watcher config.
3. A **release that fixes a CVE you are exposed to**, including CVEs under an
   oath ("Fix available: upgrade `foo` 2.4.0 to 2.4.1 fixes CVE-…"), when the
   CVE is critical or high, or when the fix came out after Heimdall first saw
   the CVE (a later matcher run). A medium or low CVE that had a fix from the
   start goes to the weekly digest instead, with its fix shown. This also
   fires for indirect dependencies, and the card says "indirect dependency".
4. An **oath expired**: the CVE is back.
5. **End of support** within 60 days for a version you run.
6. Release notes that mention a CVE currently affecting you.

Kubernetes CVE feed entries alert too.

Release alerts apply only to direct libraries and to configured or
inventory-derived infrastructure targets. Pre-releases are ignored, images from
`own_registries` are never release-watched, and for `0.x` software the second
number counts as the major version.

## Grouping and pacing

- Cards are grouped **per advisory** (or per release). One CVE is one card,
  listing every affected service, component and realm. When OSV has several
  records for one CVE (Go's and GitHub's, Debian's DSA and DEBIAN-CVE), they
  count as one advisory: see [matching](/heimdall/concepts/matching/).
- A finding is announced **once**. It re-fires only on a state change: a fix is
  released, an oath expires, or the severity rises.
- A finding that goes away and comes back within 30 days (a new image not
  scanned yet, a scale to zero, a finished Job) is not announced again. After
  30 days away, it counts as new.
- Alerts fire from the very first run, with no silent baseline. Heimdall first
  sends a short "Heimdall has opened his eyes" card per realm with counts by
  severity. To start quietly instead, run
  [`heimdall baseline`](/heimdall/reference/cli/#heimdall-baseline) for the
  realm before adding the channel: the backlog stays visible in the UI, and
  only new findings and state changes alert.
- Cards go through a queue stored in the database, sent about one every 2
  seconds, so a big first run does not hit throttling. Failed sends retry
  with growing delays, and queued cards survive a restart.

## Routing

Each channel (or Teams route) has a `min_severity` and an optional realm list. Releases, end
of support and Kubernetes CVEs count as `high` for routing. See
[Alert channels](/heimdall/guides/alert-channels/).

## The weekly digest

Everything that did not deserve an immediate alert goes into one card per channel
each week (default Monday 09:00 UTC, see `digest` in the
[configuration reference](/heimdall/reference/configuration/#digest)):

- medium, low and unknown vulnerabilities opened since the last digest, with
  the fixed version when one existed from the start,
- minor and patch releases, by what their release notes say,
- active oaths, flagging those carried to a new version,
- declared components, each as "declared since {date}" so stale versions show.

## Release notes

For each new release Heimdall fetches release notes (GitHub Releases, found via
the configured repo, the npm repository field, the Go module path or the image
label `org.opencontainers.image.source`; Helm charts through Artifact Hub). It
classifies them by pattern matching:

- mentions a CVE or GHSA id that affects you: immediate alert;
- other security mentions: digest, marked as security;
- bug-fix lines: digest, with the first few lines;
- nothing notable: digest with the version and a link;
- no notes found: the digest says so.

Major release cards quote up to five "breaking" lines plus a link.
