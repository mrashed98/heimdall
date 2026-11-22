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

Each window starts 15 minutes before the previous one ended, so a CVE NVD
indexes late is not skipped (seeing a CVE twice is harmless). An answer without
a list of CVEs is an error, and the window does not move. A one-off backfill
runs per unique vendor and product the first time it is seen. Only matches are
stored. An NVD API key is needed (see
[environment variables](/heimdall/reference/environment-variables/)).

## Kubernetes

The Kubernetes official CVE feed is polled separately. Every realm running
Kubernetes or k3s gets one `k8scve` finding per feed entry. A feed with no
entries is treated as broken: it is logged as a warning and nothing is
recorded, so the next good feed is not mistaken for all-new entries.

## EPSS

Once a day Heimdall downloads [FIRST's EPSS scores](https://www.first.org/epss/):
for each CVE, the chance (0 to 100%) that it is exploited in the wild in the
next 30 days, and its percentile among all CVEs. Only the CVEs your advisories
name are stored, and the table is replaced whole only by a complete file. A CVE
first seen during the day gets its score on the next run.

EPSS does not change severities or alerts. It is shown next to each finding in
the web UI and the API, so among many critical and high findings you can fix
the ones most likely to be exploited first: sort the Findings table by **EPSS**.

## Same CVE, counted once

A CVE found in both OSV and NVD is **one advisory**. Heimdall joins them on the
CVE id and its aliases. The **higher severity wins**, and cards show both scores.

OSV itself often has several records for one vulnerability: Go's database and
GitHub's (`GO-…` and `GHSA-…`), PyPI's and GitHub's, RustSec's and GitHub's,
Debian's `DSA-`/`DLA-` and `DEBIAN-CVE-…`, Ubuntu's `USN-` and
`UBUNTU-CVE-…`. Records that share a CVE, or where one lists the other as an
alias (followed through chains of aliases), are collapsed for each component
into one link and one finding. The record standing for the group is one the
component is already linked to; failing that, one already linked to any
component; so a finding never moves to another id: not when a record joins the
group or gains an alias, not when databases disagree on affected ranges (one
component hits both records, another only one), not for a new version, not for
another service. Otherwise (and among several linked ones) it is the `GHSA-`
record, then the alphabetically smallest id. It takes over the
others' aliases, the group's CVE, the highest severity among them, and a fixed
version only another record knew. An oath applies to the advisory under any
of its ids, so it survives such a change. An NVD match for the
same CVE joins the same advisory. The gate collapses its results the same way,
and an oath filed under any of the names applies.

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
