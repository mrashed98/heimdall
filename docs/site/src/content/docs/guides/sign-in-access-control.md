---
title: Sign-in and access control
description: Configure OIDC, break-glass access, roles and sessions.
---

Add `auth` to the server configuration to enable OIDC or local sign-in. Without it, sign in with an API key. Set `auth.public_url` to the externally visible HTTPS URL (HTTP is accepted for `localhost`); register the redirect URI `{public_url}/auth/oidc/callback` with your provider. Configure TLS at your ingress.

## Keycloak

Create a confidential OpenID Connect client with authorization-code flow enabled. Add the exact redirect URI and configure a groups mapper so the ID token contains a `groups` claim. Supply its client secret in the environment, then configure for example:

```yaml
realms: [payments, platform]
admins: [alice@example.com]
auth:
  public_url: https://heimdall.example.com
  local: { enabled: true }
  oidc:
    issuer: https://keycloak.example.com/realms/engineering
    client_id: heimdall
    client_secret_env: HEIMDALL_OIDC_CLIENT_SECRET
    scopes: [openid, profile, email, groups]
    groups_claim: groups
    role_mappings:
      - { group: /platform, role: editor, realms: ['*'] }
      - { group: /payments, role: viewer, realms: [payments] }
```

Group values must match the claim emitted by your provider exactly. Choose a default grant with `default_role: { role: viewer, realms: ['*'] }` if every signed-in user should have access. Otherwise, users without grants see a no-access page.

## Microsoft Entra ID

Register a confidential web application, add `{public_url}/auth/oidc/callback` as its web redirect URI, create a client secret, and configure group claims in the ID token. The claim commonly contains group object IDs; use those exact IDs in `role_mappings`.

```yaml
auth:
  public_url: https://heimdall.example.com
  oidc:
    issuer: https://login.microsoftonline.com/TENANT_ID/v2.0
    client_id: APPLICATION_CLIENT_ID
    client_secret_env: HEIMDALL_OIDC_CLIENT_SECRET
    scopes: [openid, profile, email]
    groups_claim: groups
    role_mappings:
      - { group: GROUP_OBJECT_ID, role: viewer, realms: [payments] }
```

Include the top-level `realms` and `admins` appropriate to your installation. Group mappings and grants stored in Postgres are combined. Provider group overage responses must be addressed in the identity provider configuration so the needed groups are present in the token.

## Break-glass local user

Enable `auth.local.enabled` and create a local account on a host with database access:

```bash
export DATABASE_URL='postgres://heimdall:password@localhost:5432/heimdall'
heimdall user --config heimdall.yaml create emergency-admin --role admin
```

The command prompts for a password; add `emergency-admin` to `admins` first. Use `heimdall user passwd NAME`, `disable NAME`, or `list` to manage accounts. The `--config` option can be supplied to any `user` subcommand.

## Roles and realms

| Role | Access |
|---|---|
| viewer | Read findings, services, releases and oaths in granted realms. |
| editor | Viewer access plus create, extend and revoke oaths in granted realms. |
| admin | Global administration, including users, grants, keys and audit. |

Grants apply to named realms or `*`. Admin access is global and also requires the user's local username or OIDC preferred username or email to appear in the top-level `admins` list. API-key admin rules remain in force.

## Sessions, CSRF and audit

Sessions are stored in Postgres. Defaults are 12 hours idle and seven days absolute; configure `auth.session.idle_hours` and `absolute_days`. The session cookie is HttpOnly and SameSite=Lax, and Secure except for HTTP localhost. Logout removes the session; disabling a user takes effect on the next request. Browser session mutations require the `X-CSRF-Token` returned by `GET /auth/me`; bearer-key requests are exempt. Local login failures are throttled per username and IP.

Administrators can inspect the audit log in Access or via `/api/v1/audit`. It records sign-ins, sign-outs, user and grant changes, key changes and oath actions. `retention.audit_days` controls audit retention (default 365 days).
