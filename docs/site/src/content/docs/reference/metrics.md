---
title: Metrics
description: Every Prometheus metric Heimdall exposes on /metrics, with labels and meaning.
---

`GET /metrics` serves the Prometheus text format. It needs no authentication and
is meant to be scraped from inside the cluster. See
[Monitoring Heimdall](/heimdall/guides/monitoring/) for the ServiceMonitor and
alert ideas.

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `heimdall_findings_open` | gauge | `realm`, `service`, `kind`, `severity` | Open findings. A finding without a service has `service=""`. |
| `heimdall_versions_behind` | gauge | `realm`, `target` | How many releases are newer than the running version. |
| `heimdall_watcher_failures_total` | counter | `watcher` | Failed fetches per watcher type. |
| `heimdall_watcher_duration_seconds` | summary | `watcher` | Time spent per watcher type per run. |
| `heimdall_teams_failures_total` | counter | none | Cards Teams rejected (Teams channels only). |
| `heimdall_notify_failures_total` | counter | `channel_type` | Alerts a channel rejected (a 4xx other than 429, a permanent SMTP error), by channel type: `teams`, `slack`, `discord`, `telegram`, `pagerduty`, `alertmanager`, `webhook`, `email`. |
| `heimdall_outbox_pending` | gauge | none | Notifications waiting to be sent. |
| `heimdall_oaths_active` | gauge | `kind` (`snooze`, `ignore`) | Active oaths. |
| `heimdall_oath_next_expiry_timestamp_seconds` | gauge | none | Unix time of the nearest oath date (snooze expiry or ignore review). `0` when there is none. |

## Notes

- The gauges are recomputed after each matcher run. A series that disappears
  (for example a resolved finding) is set to `0` once, so it does not stay
  counted.
- `heimdall_watcher_duration_seconds` is recorded with the default Prometheus
  exporter, which renders it as a **summary** (quantiles with `_sum` and
  `_count`) rather than bucketed histogram series. Query it with
  `rate(heimdall_watcher_duration_seconds_sum[5m]) / rate(heimdall_watcher_duration_seconds_count[5m])`.
- `kind` values are the [finding kinds](/heimdall/concepts/glossary/#finding-kinds).
  `severity` is one of `critical`, `high`, `medium`, `low`, `unknown`.
- Watcher types in the `watcher` label are `github`, `endoflife`, `oci`, `helm`,
  `tf_registry`, `go_proxy` and `npm`.

## Example queries

```text
sum by (severity) (heimdall_findings_open)
sum by (realm, service) (heimdall_findings_open{severity=~"critical|high"})
topk(10, heimdall_versions_behind)
increase(heimdall_watcher_failures_total[1h])
```
