-- EPSS scores (FIRST), replaced daily; only CVEs some advisory names.
CREATE TABLE epss (
    cve_id text PRIMARY KEY,
    score real NOT NULL,
    percentile real NOT NULL,
    scored_on date NOT NULL
);
