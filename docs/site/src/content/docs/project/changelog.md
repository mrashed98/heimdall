---
title: Changelog
description: Where to find release notes for each Heimdall version.
---

Heimdall does not keep a separate changelog file yet. See
[GitHub Releases](https://github.com/mrashed98/heimdall/releases) for the notes of
each version, with the binaries and container image tags.

## Unreleased

- **Mattermost and Jira channels.** `type: mattermost` posts to an incoming
  webhook; `type: jira` opens one issue per alert (Jira Cloud or Data Center),
  in `heimdall.yaml` or the console. See
  [Mattermost](/heimdall/guides/alert-channels/#mattermost) and
  [Jira](/heimdall/guides/alert-channels/#jira).
- **A broken channel no longer discards alerts.** A 401, 403, 404 or 410 (and
  Jira's 400) means the channel's credentials, permissions or settings are
  wrong, or its webhook or chat is gone. The channel's queue now waits and
  retries until it is fixed, as a failed SMTP login already did.
- **Alert channels in the console.** Settings → Alert channels lists every
  channel, from `heimdall.yaml` and from the console, with its delivery health.
  Admins can add, edit, delete and test channels of every type there, with no
  restart. Secrets entered in the console are encrypted in Postgres under the
  new `HEIMDALL_SECRET_KEY` (32 random bytes, base64; add it to the Secret named
  by `existingSecret` and back it up). Without the key Heimdall runs as before
  and adding or editing console channels is off; existing ones can still be
  deleted. The same operations are available as
  `/api/v1/channels` for admin keys. See [Managing channels in the
  console](/heimdall/guides/alert-channels/#managing-channels-in-the-console)
  and [ADR 0005](/heimdall/decisions/0005-encrypted-channel-secrets/).
- **Telegram `chat_id` changes reach queued alerts.** The chat is read from the
  channel when an alert is sent, not when it is queued. This applies to
  channels in `heimdall.yaml` as well as console channels: alerts waiting in the
  queue go to the new chat after you change `chat_id`.
- **Channel destinations are checked.** No channel sends to link-local or
  cloud metadata addresses, redirects are no longer followed (a channel whose
  server redirects keeps its alerts queued and says why), and each send
  connects only to the addresses it checked. Behind an `HTTP_PROXY` or
  `HTTPS_PROXY`, the proxy connects instead, so block those addresses there
  too ([Behind a proxy](/heimdall/guides/alert-channels/#behind-a-proxy)). The new
  `console_channels.allowed_hosts` limits where console channels may send. See
  [Where channels may send](/heimdall/guides/alert-channels/#where-channels-may-send)
  and [ADR 0006](/heimdall/decisions/0006-channel-destinations/).
