# Postgres on an external VM, not inside the pod

Heimdall must fit in 1 GB RAM / 1 CPU, and an embedded store (SQLite on a PVC) would compete with the service for that budget and tie data durability to a single pod volume. A Postgres VM already exists with backups and operations in place, so all state lives there and the pod stays stateless and freely restartable. The cost is a network dependency: Heimdall is down when that VM is.
