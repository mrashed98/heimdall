---
title: Watching infrastructure
description: Watch GitHub projects, endoflife.date products, Terraform registries and more, and tie them to NVD with cpe.
---

Images, Helm charts and direct Go and npm libraries in your inventory are tracked
automatically. **Infrastructure software** (Kubernetes, Postgres, a Kafka
cluster, Terraform itself) is not in any SBOM, so you list it under `watchers:` in
the config. Adding a target is a config change, not code, and the next watcher run
picks it up after a restart (or a ConfigMap roll).

## The inventory name

Most targets have an `inventory_name`. It is the name the software has in your
inventory: a `pkg:generic/<inventory_name>` component. You usually create that
component by declaring it:

```yaml
declared:
  - { realm: dev-k3s, service: postgres-vm, purl: "pkg:generic/postgresql@17.2" }
```

The watcher compares the version you declared with the newest release. If no
component with that name exists, the target is still polled but has no current
version to compare against.

## GitHub releases

```yaml
watchers:
  github:
    - { repo: cert-manager/cert-manager, inventory_name: cert-manager }
    - { repo: kubernetes/kubernetes, inventory_name: kubernetes, major_component: 1 }
    - { repo: apache/kafka, inventory_name: kafka, cpe: "cpe:2.3:a:apache:kafka" }
```

Set `GITHUB_TOKEN` to get 5000 requests an hour instead of 60.

## endoflife.date

Use this for products with support cycles. It gives both new versions and
**end-of-support dates**: a version you run that reaches end of support within 60
days raises a high-severity `eol` finding.

```yaml
watchers:
  endoflife:
    - { product: postgresql, inventory_name: postgresql, cpe: "cpe:2.3:a:postgresql:postgresql", repo: postgres/postgres }
    - { product: ubuntu, inventory_name: ubuntu }
```

The optional `repo` is the GitHub repository used to find release notes. If a
`github` target has the same `inventory_name`, the `endoflife` entry is used for
end-of-support dates only and the GitHub target tracks releases.

## Terraform and OpenTofu

```yaml
watchers:
  tf_registry:
    - registry: registry.terraform.io   # or registry.opentofu.org
      kind: provider                    # or module
      source: hashicorp/aws
      current: "5.40.0"                 # the version you run
```

Here you state the version yourself with `current`. These targets are filed under
the first realm.

## Registry, Helm, Go and npm (automatic)

These watchers need no config:

- **OCI registries**: every image in your inventory whose tag reads as a version,
  except images from `own_registries`.
- **Helm repositories**: every chart in your inventory.
- **Go proxy and npm**: **direct** libraries only. Transitive libraries get no
  release tracking.

## Major versions: `major_component`

`major_component` says which version number counts as the major. `0` (the default)
means the first number. `1` means the second, which is how Kubernetes and k3s work
(`1.30` to `1.31`). Independently of this, for `0.x` software the second number is
always the major (`0.3` to `0.4`).

## `cpe`: tie a target to NVD

`cpe` ties a configured target to NVD: Heimdall matches NVD CVEs for that
vendor and product against the inventory item named `inventory_name`. Use the
CPE 2.3 prefix, for example `cpe:2.3:a:apache:kafka`. Infrastructure matches carry
no "verify" label on cards.

## `own_registries`

Images from your own registries are scanned for vulnerabilities but never
release-watched, since you build them:

```yaml
own_registries:
  - ghcr.io/my-org        # a host/org prefix
  - registry.example.com  # or a whole host
```

## Adding a new watcher type

Existing types are `github`, `endoflife`, `oci`, `helm`, `tf_registry`, `go_proxy`
and `npm`, one file each in `src/watchers/`. Adding a type is a code change; see
the "A watcher type (code)" section of the
[README](https://github.com/mrashed98/heimdall#adding-things-to-watch) and the
[contributing guide](/heimdall/project/contributing/).
