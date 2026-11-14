---
title: Security policy
description: How to report a vulnerability in Heimdall, and which versions are supported.
editUrl: https://github.com/mrashed98/heimdall/edit/main/SECURITY.md
---

Heimdall is a security tool, so reports about Heimdall itself are taken seriously.

## Reporting a vulnerability

Please **do not open a public issue**. Report privately through
[GitHub security advisories](https://github.com/mrashed98/heimdall/security/advisories/new).

Include what you found, how to reproduce it, and the version affected. You will get
an acknowledgement within 7 days. Once a fix is released, the advisory is published
with credit to you unless you prefer otherwise.

## Supported versions

Only the latest release receives security fixes while Heimdall is pre-1.0.

## Security design notes

- Heimdall is **not internet-exposed**. CI reaches it from self-hosted runners.
- It **never reads Kubernetes Secrets**
  ([ADR 0003](/heimdall/decisions/0003-no-secret-access/)).
- API keys are stored as SHA-256 hashes
  ([ADR 0004](/heimdall/decisions/0004-sha256-api-keys/)) and shown once.
- Teams webhook URLs and registry credentials are read from environment
  variables, never from the config file.
