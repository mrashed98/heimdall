-- Open findings per severity at the end of each UTC day, for trend charts.
-- The matcher upserts today's row after every run; retention drops old days.
CREATE TABLE realm_daily (
    realm text NOT NULL,
    day date NOT NULL,
    critical integer NOT NULL,
    high integer NOT NULL,
    medium integer NOT NULL,
    low integer NOT NULL,
    unknown integer NOT NULL,
    PRIMARY KEY (realm, day)
);

CREATE TABLE service_daily (
    service_id bigint NOT NULL REFERENCES services (id) ON DELETE CASCADE,
    day date NOT NULL,
    critical integer NOT NULL,
    high integer NOT NULL,
    medium integer NOT NULL,
    low integer NOT NULL,
    unknown integer NOT NULL,
    PRIMARY KEY (service_id, day)
);
-- Retention deletes by day alone.
CREATE INDEX service_daily_day_idx ON service_daily (day);
