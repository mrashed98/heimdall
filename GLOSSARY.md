# Heimdall

Heimdall watches every dependency a team runs, across every environment, and warns early about vulnerabilities, new releases and end of support.

## Places and things

**Realm**:
An environment Heimdall watches, usually one cluster (e.g. `dev-k3s`).
_Avoid_: Environment, cluster, stage

**Service**:
A logical piece of software the team runs or depends on in a realm, identified by name; owns components.
_Avoid_: App, workload, deployment, project

**Component**:
One specific package or artifact at one version, identified by a package URL.
_Avoid_: Dependency, library, package (when meaning the versioned thing)

**Direct component**:
A component the service declares itself, as opposed to one pulled in by another component.
_Avoid_: Top-level dependency

## Seeing

**Bifröst**:
The single entrance through which all inventory enters Heimdall.
_Avoid_: Upload endpoint, ingest

**Sight**:
Heimdall's view of what is actually running in a realm.
_Avoid_: Cluster scan, discovery

**Watcher**:
Something that listens to an outside source for new releases, advisories or end-of-support dates.
_Avoid_: Poller, crawler, feed

**Release**:
A newly published version of something a service uses, with its release notes when they can be found.
_Avoid_: Update, new version, tag (when meaning the release)

**Major release**:
A release that changes the leading version number, or the second number for `0.x` software and for software whose majors move on the minor number (Kubernetes, k3s).
_Avoid_: Breaking release, big update

**Own image**:
A container image built by the team, from a registry listed as their own; scanned for advisories but never watched for releases.
_Avoid_: Internal image, first-party image

## Warning

**Advisory**:
A published statement that certain component versions are vulnerable; may carry several CVE aliases.
_Avoid_: CVE (when meaning the advisory record), vulnerability

**Finding**:
A fact Heimdall holds about a service right now that someone should know: an advisory affecting it, a fix available, a major release, an expired oath, approaching end of support.
_Avoid_: Issue, alert (an alert is how a finding is announced)

**Gjallarhorn**:
How Heimdall announces findings: immediate alerts and the weekly digest, in Teams.
_Avoid_: Notifier, alerting

**Digest**:
The weekly Teams summary of everything that did not deserve an immediate alert.
_Avoid_: Report, newsletter, summary

**Admin**:
A named person allowed to swear and revoke oaths; only names on the configured admin list qualify.
_Avoid_: Owner, maintainer, user

**Hofund**:
The CI gate that blocks a build whose components carry unacceptable findings.
_Avoid_: Quality gate, policy check

**Oath**:
A recorded human decision to accept an advisory for a component in a service, with a reason; either snoozed until a date or ignored with periodic review.
_Avoid_: Suppression, exception, waiver, mute
