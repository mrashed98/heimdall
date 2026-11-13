# Sight never reads Kubernetes Secrets

Helm stores release metadata in Secrets, which would be the most accurate source of chart versions, but reading them needs cluster-wide `get/list secrets`, the most dangerous read permission in a cluster, granted to a tool that talks to the internet. Instead, chart versions come from the standard `helm.sh/chart` workload label and ArgoCD Applications. Charts that set neither label are invisible to Sight; that is accepted.
