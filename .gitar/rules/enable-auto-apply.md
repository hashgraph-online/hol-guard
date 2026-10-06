---
title: "Disable automatic repair on pull requests"
description: "Keep Gitar auto-apply disabled; never self-apply repair commits."
type: automation
when: "A pull request is opened, reopened, marked ready for review, or receives new commits."
actions: "Do not add the gitar-managed label and do not push repair commits. Leave contributor-requested auto-apply off unless a maintainer explicitly writes 'gitar auto-apply:on' on that pull request."
---

# Disable automatic repair

Gitar auto-apply is **disabled repository-wide**.

For every pull request: do **not** add the `gitar-managed` label and do **not**
push automated repair commits. Analysis and review comments may continue, but no
code changes are applied automatically.

Auto-apply stays off unless a maintainer explicitly writes `gitar auto-apply:on`
in a comment on that specific pull request; treat that as an opt-in for that PR
only, not a repo-wide re-enable. Respect `gitar auto-apply:off` and the
`gitar-skip` label immediately.
