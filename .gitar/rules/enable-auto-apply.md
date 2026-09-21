---
title: "Enable automatic repair on active pull requests"
description: "Enable Gitar auto-apply for every ready-for-review pull request."
type: automation
when: "A pull request is opened, reopened, marked ready for review, or receives new commits. Skip drafts and pull requests labeled gitar-skip."
actions: "Add the gitar-managed label to enable Gitar auto-apply for the pull request."
---

# Enable automatic repair

For every active, ready-for-review pull request, add the `gitar-managed` label.
That label enables Gitar auto-apply for the lifetime of the pull request.

Do not add it to a draft pull request or to a pull request labeled `gitar-skip`.
Leave a contributor's explicit `gitar auto-apply:off` choice in effect.
