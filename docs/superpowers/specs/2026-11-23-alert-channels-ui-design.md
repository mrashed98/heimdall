# Alert channels in the UI: design

Date: 2026-11-23. Status: draft, waiting for approval.

## Intent

Heimdall can already send alerts to Teams, Slack, Discord, Telegram,
PagerDuty, Alertmanager, email and a signed generic webhook. Today those
channels can only be declared in `heimdall.yaml`, with their secrets held in
environment variables. The owner wants both ways to work: channels in the
config file stay supported, admins can also add and manage channels from
Settings in the web console, and the console shows every channel, including
the ones from the config, so it is the single place to see where alerts go.

This is the first of two integration projects. The second is Jira and
DefectDojo (issue #58). It will reuse the encrypted secret storage built
here, but it is out of scope for this design.

## Goals

- Settings → Alert channels lists every channel: the ones from the config
  file and the ones created in the UI. For each it shows the source,
  type, realms, minimum severity, digest on/off, and delivery health (the
  last sent and the last failed delivery, and how many alerts are queued).
- Admins can create, edit and delete UI channels of every existing type,
  with the same fields and validation rules as the config.
- A UI channel takes part in alerting, the digest and the first-run summary
  as soon as it is saved, without a restart.
- Secrets entered in the UI are stored encrypted in Postgres with
  AES-256-GCM, keyed by `HEIMDALL_SECRET_KEY`.
- "Send test" works on any channel, from the config or the UI.
- Every create, edit, delete and test is written to the existing
  `audit_log`.

## Non-goals

- Editing config channels from the UI. They stay read-only there; the file is
  their source of truth.
- Writing UI channels back to `heimdall.yaml`, or exporting them to it.
- New channel types and new event types (issue #57).
- Jira and DefectDojo (issue #58).
- Rotating `HEIMDALL_SECRET_KEY`. A later change can add a key id per row.

## Anti-goals (it fails even if it works when...)

- A saved secret can be read back: shown in the UI, returned by the API, or
  written to logs, errors or the audit log.
- A missing or wrong `HEIMDALL_SECRET_KEY` stops Heimdall from starting or
  stops the config channels from delivering.
- Alerts are lost or sent twice because a channel was edited, renamed or
  deleted while alerts were queued for it.
- A non-admin can see or change channels.

## Constraints

- Postgres is the only state. The pod has 1 GB of memory and 1 CPU.
- Existing API-key response shapes stay backwards compatible. The new
  endpoints are UI-only (`/api/ui/...`, session and admin role).
- No new crypto dependency: use `ring::aead` (already in the tree via
  rustls) for AES-256-GCM.
- Secrets follow the existing rule: never inline in config, never in URLs
  that get logged.
- WCAG AA, and the console design system and components from #61.

## Approaches considered (secret storage)

1. **Encrypted in Postgres, keyed by `HEIMDALL_SECRET_KEY` (chosen).** A
   channel added in the UI works immediately and Postgres stays the only
   state. Cost: one more secret to back up. Losing the key makes the stored
   secrets unreadable, and they then have to be re-entered.
2. **The UI only references environment variable names.** No secrets in the
   database, but every new channel still needs a Secret change and a
   restart, which defeats the point of the UI.
3. **Heimdall writes Kubernetes Secrets.** No new key, but Heimdall needs
   RBAC to write Secrets and can no longer run outside Kubernetes.

The owner picked 1.

## Design

### Key

- `HEIMDALL_SECRET_KEY`: 32 random bytes, base64-encoded. It is read at
  startup.
- **Missing:** UI channel management is turned off. The page lists the
  config channels and shows a notice explaining how to set the key. The
  create, edit and test endpoints for UI channels return 409.
  - UI channels that already exist still take part in alerting. They are
    still loaded, but their secrets cannot be resolved, so their rows stay
    queued, exactly like a missing env var today.
  - Leaving them out would let `enqueue_alerts` mark findings as notified
    without queueing anything for them, so those alerts would be lost.
  - They are listed with "Key missing".
  - Delete still works without the key, because it needs no decryption.
- **Malformed** (not base64, or not 32 bytes): log an error and behave as
  if it were missing. Do not crash.
- **Wrong** (decryption fails for a row): that channel shows "Secret
  unreadable: re-enter it". Its queued alerts stay queued, as with a
  missing env var today. Other channels are unaffected.
- The Helm chart gets an optional `secretKey.existingSecret` value, mounted
  as the env var. The docs say how to generate the key
  (`openssl rand -base64 32`) and that it must be backed up.

### Storage

Migration `0010_alert_channels.sql`:

- `alert_channels`:
  - `id`
  - `name` (unique)
  - `type`
  - `settings` (JSONB: the non-secret fields of the type, the same shape
    as the config minus the `*_env` keys)
  - `secrets` (BYTEA: AES-GCM ciphertext of a JSON map from field to
    value, with a random 96-bit nonce prepended)
  - `created_at`, `created_by`, `updated_at`, `updated_by`
- The AAD is `alert_channels:<id>`, so a ciphertext cannot be moved to
  another row.
- `outbox` gains `last_error_at TIMESTAMPTZ` and `last_error TEXT`
  (redacted).
  - Today a transient failure (network error, 5xx, 429, an SMTP login
    failure held) only bumps `attempts` and records nothing. A channel
    whose host is down would look healthy with a growing queue.
  - The drain loop sets both columns on every Retry, Hold or Reject.
  - Health shows:
    - "failing" when the oldest queued row has a `last_error`;
    - otherwise the last sent time;
    - in both cases, the queued count.

### One channel list

- Replace every `cfg.channels()` call in the alert pipeline (`notify/mod.rs`,
  `outbox.rs`, `digest.rs`) with one loader that returns the config channels
  followed by the UI channels, read from Postgres on each call.
- The loader is called once per alert run or drain tick, not per row, so the
  cost is one small query.
- Secret lookup, today `env(var)` in `notify/channels/mod.rs`, goes through
  a resolver:
  - A config channel resolves its env var as now.
  - A UI channel resolves the decrypted value from its row.
  - `missing_env` and `request` keep their behaviour: a missing secret
    keeps the rows queued.
- Each loaded channel carries its source (`config` or `ui`) for the API.

### Names

- Names are unique across both sources. Creating a UI channel with a name
  already used by the config is rejected.
- If the config later gains a name that a UI channel already uses, the
  config wins. The UI channel is skipped from delivery and listed with a
  "Name clash with config" warning. Startup logs a warning; it does not
  fail.
- The outbox keys rows by channel name and type, so **name and type cannot
  be changed after creation**. To rename, the admin creates a new channel
  and deletes the old one.
- **Deleting a channel discards its queued rows in the same transaction.**
  They are marked sent with `card.failed = true` and the reason "channel
  deleted".
  - The delete confirmation shows how many queued alerts will be discarded.
  - Without this, the existing `orphaned` handling only logs. A later
    channel with the same name and type would then inherit those rows and
    send them to a different destination.
  - This is a design call, not something the owner decided. The
    alternative, moving the queued rows to another channel, needs a target
    picker and is left out.
- **Clash with the config, same name and type:** the config channel
  delivers rows already queued under that name. This is accepted and
  documented. The clash warning tells the admin to delete the UI channel.

### API (admin role, session auth)

- `GET /api/ui/channels`: every channel with its source, type, name,
  settings, realms, `min_severity`, `digest`, and health.
  - Secret fields come back only as `{"set": true|false}`.
  - Config channels show which env var names are missing, never their
    values.
  - The response includes `management_enabled` (whether the key is
    present).
- `POST /api/ui/channels`: create. Validated with the same rules as the
  config (`validate` reused per type), including the realms check.
- `PATCH /api/ui/channels/{id}`: edit the settings. For each secret field:
  - omitted: keep the stored value;
  - a string: replace it;
  - `null`: clear it (optional secrets only).

  Validation runs on the merged result of the stored and new secrets, so
  rules like "username and password together" and "no bearer token
  alongside basic auth" still hold. This lets an admin switch
  authentication modes or turn webhook signing off without recreating the
  channel.
- `DELETE /api/ui/channels/{id}`.
- `POST /api/ui/channels/{name}/test`: sends a fixed test alert directly,
  not through the outbox, and returns success, or the error with secrets
  redacted. It is rate-limited per channel, to 1 every 10 seconds.
  - The limit is kept in memory. The chart runs a single replica.
- Audit actions: `channel_created`, `channel_updated`, `channel_deleted`,
  `channel_tested`. The detail holds the name, type and changed field
  names, never values.

### UI

Settings (`/access`, `Access.svelte`) already has the tabs Members &
access, API keys and Audit log. Add **Alert channels** as a tab after API
keys, which is the order in the mockup. No routing change. Alert channels:

```
Alert channels                                     [ Add channel ▾ ]
Findings go out as grouped alerts to every channel that covers their realm.

 Name          Type        Realms     Min severity  Digest  Last delivery     Source
 ops-teams     Teams       all        high          yes     sent 2h ago       config   [Test]
 sec-slack     Slack       prod       critical      yes     failed 10m ago ⚠  UI       [Test] [Edit] [⋯]
```

- **Add channel:** the admin picks a type (Teams, Slack, Discord, Telegram,
  PagerDuty, Alertmanager, Email, Webhook), then fills in one form per type.
  The form has the common fields (name, realms multi-select, minimum
  severity, digest) plus the type's fields.
- **Secret inputs** are password fields. When editing, they show "Saved ·
  Replace" instead of a value.
- **Config rows** have no Edit or Delete. A tooltip says "Defined in
  heimdall.yaml", and missing env vars are listed by name.
- **Key not set:** the list shows the config channels and a notice in
  place of the Add button.
- **Empty state:** keeps the mockup's wording ("None yet. Findings stay
  pending and go out as grouped alerts once a channel exists.") and offers
  the type buttons.

## Left to the builder

- Exact component breakdown, form layout per type, and the copy of
  validation messages.
- The struct shape for the resolver and the loaded channel. Keep
  `ChannelConfig` as the single description of a channel's fields if
  possible.
- How health is computed from the `outbox` table: one grouped query per
  list call.
- Test alert payload content (it must say it is a test).
