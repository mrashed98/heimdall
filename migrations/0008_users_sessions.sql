CREATE TABLE users (
    id BIGSERIAL PRIMARY KEY,
    username TEXT NOT NULL,
    kind TEXT NOT NULL DEFAULT 'local' CHECK (kind IN ('local', 'oidc')),
    oidc_issuer TEXT,
    oidc_subject TEXT,
    email TEXT,
    display_name TEXT,
    preferred_username TEXT,
    password_hash TEXT,
    disabled BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at TIMESTAMPTZ,
    CHECK ((kind = 'local' AND password_hash IS NOT NULL AND oidc_issuer IS NULL AND oidc_subject IS NULL) OR (kind = 'oidc' AND password_hash IS NULL AND oidc_issuer IS NOT NULL AND oidc_subject IS NOT NULL))
);
CREATE UNIQUE INDEX users_local_username_idx ON users (username) WHERE kind = 'local';
CREATE UNIQUE INDEX users_oidc_identity_idx ON users (oidc_issuer, oidc_subject) WHERE kind = 'oidc';
CREATE TABLE user_grants (
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role TEXT NOT NULL CHECK (role IN ('viewer', 'editor', 'admin')),
    realm TEXT NOT NULL,
    PRIMARY KEY (user_id, role, realm)
);
CREATE TABLE sessions (
    id_hash BYTEA PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf_token TEXT NOT NULL,
    groups TEXT[] NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX sessions_expiry_idx ON sessions (expires_at);
CREATE TABLE audit_log (
    id BIGSERIAL PRIMARY KEY,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    action TEXT NOT NULL,
    method TEXT,
    username TEXT,
    ip TEXT,
    detail JSONB
);
CREATE TABLE login_failures (
    id BIGSERIAL PRIMARY KEY,
    username TEXT NOT NULL,
    ip TEXT NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX login_failures_username_idx ON login_failures (username, occurred_at);
CREATE INDEX login_failures_ip_idx ON login_failures (ip, occurred_at);

CREATE TABLE oidc_pending (state_hash BYTEA PRIMARY KEY, nonce TEXT NOT NULL, verifier TEXT NOT NULL, expires_at TIMESTAMPTZ NOT NULL DEFAULT now() + interval '10 minutes');
