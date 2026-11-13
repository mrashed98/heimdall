-- Heimdall schema. Enums are lowercase text guarded by CHECK constraints.

CREATE TABLE services (
    id bigserial PRIMARY KEY,
    realm text NOT NULL,
    name text NOT NULL,
    UNIQUE (realm, name)
);

CREATE TABLE components (
    id bigserial PRIMARY KEY,
    purl text NOT NULL UNIQUE,
    name_key text NOT NULL,
    ecosystem text NOT NULL,
    version text NOT NULL,
    cpes text[] NOT NULL DEFAULT '{}'
);
CREATE INDEX components_name_key_idx ON components (name_key);

CREATE TABLE service_components (
    service_id bigint NOT NULL REFERENCES services (id) ON DELETE CASCADE,
    component_id bigint NOT NULL REFERENCES components (id) ON DELETE CASCADE,
    source text NOT NULL CHECK (source IN ('git', 'ci', 'cluster', 'declared')),
    direct boolean NOT NULL DEFAULT false,
    via_image_digest text,
    uploaded_at timestamptz NOT NULL DEFAULT now(),
    -- Set on first insert and kept when the row is replaced.
    declared_since timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (service_id, component_id, source)
);
CREATE INDEX service_components_component_id_idx ON service_components (component_id);

CREATE TABLE image_sboms (
    digest text PRIMARY KEY,
    image_ref text NOT NULL,
    scanned_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE image_components (
    digest text NOT NULL REFERENCES image_sboms (digest) ON DELETE CASCADE,
    component_id bigint NOT NULL REFERENCES components (id) ON DELETE CASCADE,
    PRIMARY KEY (digest, component_id)
);

CREATE TABLE advisories (
    id text PRIMARY KEY,
    aliases text[] NOT NULL DEFAULT '{}',
    severity text NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'unknown')),
    summary text NOT NULL DEFAULT '',
    -- {name_key: [fixed versions]}
    fixed jsonb NOT NULL DEFAULT '{}',
    modified timestamptz NOT NULL DEFAULT now(),
    source text NOT NULL,
    -- {"osv": 7.5, "nvd": 9.8}
    scores jsonb NOT NULL DEFAULT '{}',
    -- Join key between OSV and NVD records.
    cve_id text
);
CREATE INDEX advisories_cve_id_idx ON advisories (cve_id);

CREATE TABLE component_advisories (
    component_id bigint NOT NULL REFERENCES components (id) ON DELETE CASCADE,
    advisory_id text NOT NULL REFERENCES advisories (id) ON DELETE CASCADE,
    match_source text NOT NULL CHECK (match_source IN ('osv', 'nvd', 'both')),
    PRIMARY KEY (component_id, advisory_id)
);
CREATE INDEX component_advisories_advisory_id_idx ON component_advisories (advisory_id);

CREATE TABLE releases (
    id bigserial PRIMARY KEY,
    target text NOT NULL,
    version text NOT NULL,
    published_at timestamptz,
    is_major boolean NOT NULL DEFAULT false,
    notes_url text,
    notes_class text CHECK (notes_class IN ('cve_affecting', 'security', 'bugfix', 'plain', 'none')),
    mentioned_ids text[] NOT NULL DEFAULT '{}',
    -- {fix: [..], breaking: [..]}
    excerpt jsonb,
    UNIQUE (target, version)
);

CREATE TABLE watcher_state (
    target text PRIMARY KEY,
    etag text,
    last_checked timestamptz,
    last_seen text
);

CREATE TABLE findings (
    id bigserial PRIMARY KEY,
    key text NOT NULL UNIQUE,
    kind text NOT NULL CHECK (kind IN
        ('vuln', 'fixavailable', 'majorrelease', 'oathexpired', 'eol', 'k8scve', 'releasenotecve')),
    realm text NOT NULL,
    service_id bigint REFERENCES services (id) ON DELETE CASCADE,
    component_id bigint REFERENCES components (id) ON DELETE CASCADE,
    ref_id text,
    severity text NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'unknown')),
    status text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'resolved')),
    opened_at timestamptz NOT NULL DEFAULT now(),
    resolved_at timestamptz,
    notified_at timestamptz,
    details jsonb NOT NULL DEFAULT '{}'
);
CREATE INDEX findings_status_kind_idx ON findings (status, kind);

CREATE TABLE oaths (
    id bigserial PRIMARY KEY,
    advisory_id text NOT NULL,
    name_key text NOT NULL,
    service_id bigint NOT NULL REFERENCES services (id) ON DELETE CASCADE,
    -- NULL means all realms.
    realm text,
    kind text NOT NULL CHECK (kind IN ('snooze', 'ignore')),
    reason text NOT NULL CHECK (length(reason) > 0),
    version_at_creation text NOT NULL,
    expires_at timestamptz,
    review_at timestamptz,
    created_by text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'expired', 'revoked'))
);

CREATE TABLE oath_events (
    id bigserial PRIMARY KEY,
    oath_id bigint NOT NULL REFERENCES oaths (id) ON DELETE CASCADE,
    event text NOT NULL,
    at timestamptz NOT NULL DEFAULT now(),
    by text NOT NULL,
    note text
);

CREATE TABLE outbox (
    id bigserial PRIMARY KEY,
    group_key text NOT NULL,
    card jsonb NOT NULL,
    route text NOT NULL,
    attempts int NOT NULL DEFAULT 0,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    sent_at timestamptz
);

CREATE TABLE api_keys (
    id bigserial PRIMARY KEY,
    name text NOT NULL UNIQUE,
    sha256 bytea NOT NULL UNIQUE,
    scope text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE kv (
    key text PRIMARY KEY,
    value text NOT NULL
);

CREATE TABLE nvd_products (
    vendor_product text PRIMARY KEY,
    backfilled_at timestamptz
);
