---
title: Glossary
description: The words Heimdall uses, in plain language. Realm, Service, Component, Finding, Oath, Release and the rest.
---

Heimdall uses a small theme from Norse myth for its user-facing names. The
source code uses plain names so it is easy to read. This page covers both.

## Theme names and code modules

| Theme name | Meaning | Code module |
|---|---|---|
| **Realm** | An environment or cluster (`dev-k3s` now; `prod` later) | `realm` |
| **Bifröst** | The ingest API: everything entering Heimdall (SBOM uploads, cluster inventory) crosses it | `ingest` |
| **Sight** | Inventory scanning: what is actually running (cluster scanner and image SBOM job) | `inventory` |
| **Watchers** | Pollers for new releases and advisories ("Heimdall hears the grass grow") | `watchers` |
| **Gjallarhorn** | The notifier: Teams alerts and the weekly digest | `notify` |
| **Hofund** | The CI gate that blocks a build at the bridge | `gate` |
| **Oath** | A suppression: ignore or snooze a CVE, with a reason | `oath` |

## Places and things

- **Realm**: An environment Heimdall watches, usually one cluster (for example `dev-k3s`).

- **Service**: A logical piece of software the team runs or depends on in a realm, identified by name. A service owns components.

- **Component**: One specific package or artifact at one version, identified by a package URL (purl).

- **Direct component**: A component the service declares itself, as opposed to one pulled in by another component.

## Seeing

- **Bifröst**: The single entrance through which all inventory enters Heimdall.

- **Sight**: Heimdall's view of what is actually running in a realm.

- **Watcher**: Something that listens to an outside source for new releases, advisories or end-of-support dates.

- **Release**: A newly published version of something a service uses, with its release notes when they can be found.

- **Major release**: A release that changes the leading version number, or the second number for `0.x` software and for software whose majors move on the minor number (Kubernetes, k3s).

- **Own image**: A container image built by the team, from a registry listed under `own_registries`. It is scanned for advisories but never watched for releases.

## Warning

- **Advisory**: A published statement that certain component versions are vulnerable. It may carry several CVE aliases.

- **Finding**: A fact Heimdall holds about a service right now that someone should know: an advisory affecting it, a fix available, a major release, an expired oath, approaching end of support. An alert is how a finding is announced.

- **Gjallarhorn**: How Heimdall announces findings: immediate alerts and the weekly digest, in Teams.

- **Digest**: The weekly Teams summary of everything that did not deserve an immediate alert.

- **Admin**: A named person allowed to swear and revoke oaths. Only names on the configured `admins` list qualify.

- **Hofund**: The CI gate that blocks a build whose components carry unacceptable findings.

- **Oath**: A recorded human decision to accept an advisory for a component in a service, with a reason. It is either snoozed until a date or ignored with periodic review.

## Finding kinds

These are the values of `kind` in the API and the `--kind` flag of `heimdall findings`:

| Kind | Meaning |
|---|---|
| `vuln` | An advisory affects a component. |
| `fixavailable` | A release fixes an advisory you are exposed to. |
| `majorrelease` | A major release of something you run. |
| `oathexpired` | An oath lapsed, so the advisory counts again. |
| `eol` | A version you run reaches end of support within 60 days. |
| `k8scve` | An entry from the Kubernetes official CVE feed. |
| `releasenotecve` | Release notes mention a CVE that affects you. |
