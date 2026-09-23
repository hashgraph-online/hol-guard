---
title: "Handle denied fork auto-apply"
description: "Keep analysis useful when GitHub rejects a Gitar repair push to a fork."
type: automation
when: "Gitar cannot push an automatic repair to a ready-for-review fork pull request. Skip drafts and pull requests labeled gitar-skip."
actions: "Do not retry a write or change the contributor's auto-apply setting. Keep the precise repair in analysis; the trusted repository workflow posts one contributor notice."
---

# Fork auto-apply access

When GitHub prevents Gitar from pushing to a managed fork pull request:

1. Say that review and CI analysis can continue, but no repair commit was applied.
2. Do not retry the push or change an explicit `gitar auto-apply:off` choice.
3. The trusted GitHub Action may post one notice explaining **Allow edits from maintainers**. If GitHub presents **Allow edits and access to secrets by maintainers**, do not ask the contributor to enable it.
4. Do not request tokens, secrets, repository membership, or a workaround that bypasses GitHub's fork permission boundary.
5. Once the contributor grants ordinary maintainer-edit permission and explicitly requests another auto-apply pass, perform only the bounded repairs allowed by the repository instructions.
