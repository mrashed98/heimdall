-- What reported a service's cluster components: '' for the Kubernetes
-- cluster (as before), 'docker:<host>' for a Docker host. A cluster ingest
-- only empties services of its own origin.
ALTER TABLE services ADD COLUMN origin TEXT NOT NULL DEFAULT '';
