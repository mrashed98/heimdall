---
title: Monitoring Heimdall
description: Prometheus metrics, the ServiceMonitor, dashboard ideas, JSON logs and OpenTelemetry traces.
---

Heimdall is observable like any other service.

## Metrics

`GET /metrics` serves the Prometheus text format. It needs no authentication,
because it is meant for the cluster network. The full list is in the
[metrics reference](/heimdall/reference/metrics/).

With the Prometheus Operator, the Helm chart creates a **ServiceMonitor**
(`serviceMonitor.enabled`, on by default; it is only rendered when the
`monitoring.coreos.com/v1` API exists in the cluster, or when
`serviceMonitor.force` is true, which offline renderers such as ArgoCD need).
Add labels so kube-prometheus-stack selects it:

```yaml
serviceMonitor:
  enabled: true
  force: true        # ArgoCD or another offline render
  interval: 60s
  labels:
    release: kube-prometheus-stack
```

## What to alert on

Some starting points (adjust names and thresholds to your setup):

```yaml
- alert: HeimdallTeamsFailing
  expr: increase(heimdall_teams_failures_total[1h]) > 0
- alert: HeimdallOutboxBacklog
  expr: heimdall_outbox_pending > 20
  for: 30m
- alert: HeimdallWatcherFailing
  expr: increase(heimdall_watcher_failures_total[1h]) > 3
- alert: HeimdallOathExpiresSoon
  expr: (heimdall_oath_next_expiry_timestamp_seconds > 0)
        and (heimdall_oath_next_expiry_timestamp_seconds - time() < 7 * 86400)
```

## Grafana ideas

- **Open findings by severity**: `sum by (severity) (heimdall_findings_open)`.
- **Per realm and service**: a table of `heimdall_findings_open` grouped by
  `realm` and `service`.
- **Falling behind**: top ten of `heimdall_versions_behind` per target.
- **Watcher health**: failures and duration per `watcher`.
- **Oaths**: `heimdall_oaths_active` by `kind`, and the nearest expiry as a
  countdown from `heimdall_oath_next_expiry_timestamp_seconds`.

## Logs

Logs are JSON lines on stdout. Filter with `RUST_LOG` (default `info`), for
example `RUST_LOG=heimdall=debug`.

## Traces (OTLP)

Set `OTEL_EXPORTER_OTLP_ENDPOINT` to export traces to an OpenTelemetry collector
over OTLP/HTTP. The exporter also reads the other standard `OTEL_*` variables.
With the Helm chart, set `otlpEndpoint` in the values. The service name is
`heimdall`.

## Health checks

`GET /healthz` returns `200 ok` when Postgres answers, and `503` when it does not
answer within 5 seconds. The chart uses it for readiness only. Liveness is a TCP
check, so a database outage does not restart the pod.
