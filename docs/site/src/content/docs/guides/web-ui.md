---
title: Using the web UI
description: Explore findings and take oaths in Heimdall.
---

Open Heimdall's public URL and sign in with an enabled identity provider, local account, or API key. If you can sign in but have no grants, ask an administrator for access. See [Sign-in and access control](/heimdall/guides/sign-in-access-control/).

Use the navigation to open **Overview** (risk and feed status), **Findings**, **Services**, **Releases**, and **Oaths** (snoozed or ignored findings). Administrators also have **Access** for users, API keys, and audit events. Findings can be searched, filtered and sorted; select one to see its details. Services show their components, images and findings.

The top-bar realm switcher selects the realms shown on the pages. The selection is included in the URL so you can share a link; recipients still need access to those realms.

To take an oath, open a finding and choose **Take an oath**. Select snooze or ignore, supply a reason and the requested date, then submit. Editors can also extend or revoke an oath from the Oaths page. An all-realms oath requires editor access to `*`.

The interface follows your system's light or dark preference. Use the top-bar theme control to choose a mode; the choice is stored in your browser.
