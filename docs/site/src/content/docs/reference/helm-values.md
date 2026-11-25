---
title: Helm values
description: Every value of the Heimdall Helm chart, with its default.
---

The chart is in `deploy/helm/heimdall`. These are the defaults from its
`values.yaml`. See [Install on Kubernetes](/heimdall/getting-started/kubernetes/)
for a walkthrough.

| Value | Default | Meaning |
|---|---|---|
| `image.repository` | `ghcr.io/mrashed98/heimdall` | Server image. |
| `image.tag` | `""` | Image tag. Empty means the chart `appVersion` (release images are tagged without the `v`, e.g. `0.1.0`). |
| `image.pullPolicy` | `IfNotPresent` | Pull policy. |
| `scannerImage.repository` | `ghcr.io/mrashed98/heimdall-scanner` | Image-SBOM scanner image (syft plus `heimdall scan-images`). |
| `scannerImage.tag` | `""` | Empty means the chart `appVersion`. |
| `scannerImage.pullPolicy` | `IfNotPresent` | Pull policy. |
| `imagePullSecrets` | `[]` | Secrets for pulling the images. |
| `config` | see below | Rendered into the ConfigMap as `heimdall.yaml`. Takes any key of the [configuration reference](/heimdall/reference/configuration/). |
| `existingSecret` | `heimdall-secrets` | Name of an existing Secret. Every key becomes an environment variable of the server. |
| `otlpEndpoint` | `""` | When set, becomes `OTEL_EXPORTER_OTLP_ENDPOINT` to export traces. |
| `resources.limits.memory` | `1Gi` | Server memory limit. |
| `resources.limits.cpu` | `"1"` | Server CPU limit. |
| `resources.requests.memory` | `256Mi` | Server memory request. |
| `resources.requests.cpu` | `100m` | Server CPU request. |
| `terminationGracePeriodSeconds` | `30` | Time to finish in-flight requests on shutdown. |
| `service.port` | `8080` | Service port. |
| `scanImages.enabled` | `true` | Create the image-scanner CronJob. |
| `scanImages.schedule` | `"0 */6 * * *"` | CronJob schedule. |
| `scanImages.max` | `20` | Most images scanned per run. |
| `scanImages.dockerConfigSecret` | `""` | A `kubernetes.io/dockerconfigjson` Secret so syft can pull private images. |
| `scanImages.resources.limits.memory` | `1Gi` | Scanner memory limit. |
| `scanImages.resources.limits.cpu` | `"1"` | Scanner CPU limit. |
| `scanImages.resources.requests.memory` | `256Mi` | Scanner memory request. |
| `scanImages.resources.requests.cpu` | `100m` | Scanner CPU request. |
| `serviceMonitor.enabled` | `true` | Create a ServiceMonitor, when the `monitoring.coreos.com/v1` API exists or `serviceMonitor.force` is set. |
| `serviceMonitor.force` | `false` | Render the ServiceMonitor without checking for the API. For renders that cannot see the cluster (ArgoCD, `helm template`); set it only when the Prometheus Operator CRDs are installed. |
| `serviceMonitor.interval` | `60s` | Scrape interval. |
| `serviceMonitor.labels` | `{}` | Extra labels, so kube-prometheus-stack selects it. |
| `ingress.enabled` | `false` | Create an Ingress. Heimdall is not meant to be internet-exposed. |
| `ingress.className` | `""` | Ingress class. |
| `ingress.annotations` | `{}` | Ingress annotations. |
| `ingress.hosts` | `[]` | Host names; when non-empty overrides `ingress.host`. |
| `ingress.host` | `heimdall.internal.example` | Host name. |
| `ingress.tls` | `[]` | TLS blocks. |

## Default `config`

```yaml
config:
  realms:
    - dev-k3s
  own_registries: []
  admins: []
  teams:
    - name: default
      webhook_env: TEAMS_WEBHOOK_DEFAULT
      realms: []
      min_severity: high
  sight:
    realm: dev-k3s
```

## Keys of the Secret

| Key | Used for |
|---|---|
| `DATABASE_URL` | Postgres connection string (required). |
| `GITHUB_TOKEN` | GitHub releases, release notes and the gate's fallback. |
| `NVD_API_KEY` | NVD. |
| `HEIMDALL_BOOTSTRAP_ADMIN_KEY` | The `bootstrap` admin key. |
| `HEIMDALL_SECRET_KEY` | Encrypts the secrets of alert channels added in the console (`openssl rand -base64 32`). Optional; back it up. See [Managing channels in the console](/heimdall/guides/alert-channels/#managing-channels-in-the-console). |
| `HEIMDALL_OIDC_CLIENT_SECRET` | OIDC client secret when selected by `config.auth.oidc.client_secret_env`. |
| `TEAMS_WEBHOOK_*` | One per `teams[].webhook_env`. |
| Channel secrets | One per `*_env` key of a `channels[]` entry (`webhook_env`, `bot_token_env`, `routing_key_env`, `url_env`, `secret_env`, `username_env`, `password_env`, `bearer_token_env`). See [Alert channels](/heimdall/guides/alert-channels/). |
| `HEIMDALL_API_KEY` | An ingest-scope key, used by the scanner CronJob. |

## Template notes

- The Deployment has one replica and uses the `Recreate` strategy, because the
  scheduled loops are not leader-elected.
- The pod config checksum is an annotation, so changing `config` restarts the pod.
- The scanner reads `HEIMDALL_API_KEY` from the Secret, and reaches Heimdall at
  `http://<release>.<namespace>.svc:<service.port>`.

Set `config.auth` to the authentication block described in the [configuration reference](/heimdall/reference/configuration/). Its secret is read from `existingSecret`, not stored in values. Configure `ingress.hosts`, `ingress.className`, annotations, and TLS when enabling ingress.
