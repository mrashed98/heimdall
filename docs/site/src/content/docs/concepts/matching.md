---
title: How matching works
description: How Heimdall matches your components against OSV and NVD, merges duplicates, and chooses a severity.
---

Heimdall checks **every component** against two advisory databases, and does not
mirror either of them
([ADR 0002](/heimdall/decisions/0002-advisories-without-mirrors/)).

## OSV

[OSV.dev](https://osv.dev) is the primary source. Heimdall sends all unique
package URLs in batches and lets OSV do the version-range matching, then fetches
full records for new advisory ids. OSV carries GitHub Advisories, the Go
vulnerability database, npm, Debian, Ubuntu and more, with CVE aliases.

## NVD

The [National Vulnerability Database](https://nvd.nist.gov) is checked alongside
OSV. Each run asks NVD for the CVEs that changed since the last successful run
(NVD API 2.0), and matches them locally against:

- the CPEs that syft puts on components, and
- the `cpe:` field of infrastructure targets you configure under `watchers:`.

A one-off backfill runs per unique vendor and product the first time it is seen.
Only matches are stored. An NVD API key is needed (see
[environment variables](/heimdall/reference/environment-variables/)).

## Kubernetes

The Kubernetes official CVE feed is polled separately. Every realm running
Kubernetes or k3s gets one `k8scve` finding per feed entry.

## Same CVE, counted once

A CVE found in both OSV and NVD is **one advisory**. Heimdall joins them on the
CVE id and its aliases. The **higher severity wins**, and cards show both scores.

NVD-only matches on **library** components still alert, but the card labels them
**"NVD match only, verify"**, because CPE matching produces false positives.
Matches on infrastructure targets carry no such label.

## Severity

Heimdall normalises severity to `critical`, `high`, `medium`, `low` or `unknown`.
It uses the CVSS score from the source when present, then the GitHub advisory
severity, then distro priority. For ordering, `unknown` sits between `medium` and
`low`: it is not hidden, and it is shown explicitly.

## Fix advice

For a vulnerable component Heimdall suggests the smallest fixed version in the
current major line, and shows the latest version alongside.

## Findings

The matcher turns all of this into **findings**. Each has a stable key, so it is
opened once, kept up to date while it applies, and resolved when it no longer
does (for example when the component is upgraded or disappears from the
inventory). Oaths are applied here: see [Managing oaths](/heimdall/guides/oaths/).
