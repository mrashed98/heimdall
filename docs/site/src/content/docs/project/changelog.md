---
title: Changelog
description: Where to find release notes for each Heimdall version.
---

Heimdall does not keep a separate changelog file yet. See
[GitHub Releases](https://github.com/mrashed98/heimdall/releases) for the notes of
each version, with the binaries and container image tags.

## Unreleased

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
