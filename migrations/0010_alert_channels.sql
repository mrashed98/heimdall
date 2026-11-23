CREATE TABLE alert_channels (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    type TEXT NOT NULL,
    realms TEXT[] NOT NULL DEFAULT '{}',
    min_severity TEXT NOT NULL,
    digest BOOLEAN,
    settings JSONB NOT NULL DEFAULT '{}',
    secrets BYTEA,
    -- Names of the stored secret fields, readable without the key.
    secret_names TEXT[] NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by TEXT NOT NULL
);
ALTER TABLE outbox ADD COLUMN last_error_at TIMESTAMPTZ, ADD COLUMN last_error TEXT;
