---
title: "Explain fork auto-apply access"
description: "Give fork contributors the GitHub setting required for Gitar to commit deterministic repairs."
type: automation
when: "A ready-for-review pull request comes from a personal fork, has the gitar-managed label, and GitHub reports that maintainers cannot modify the head branch. Skip drafts and pull requests labeled gitar-skip."
actions: "Post one concise comment explaining the required GitHub setting and continue automatic repair after the fork owner grants ordinary maintainer-edit permission."
---

# Fork auto-apply access

When GitHub prevents Gitar from pushing to a managed fork pull request:

1. Say that review and CI analysis can continue, but no repair commit was applied.
2. Tell the fork owner to enable **Allow edits from maintainers** on the pull request if they want Gitar to commit a deterministic repair.
3. If GitHub presents **Allow edits and access to secrets by maintainers**, do not ask the contributor to enable it. Provide analysis or a suggestion instead.
4. Post at most one notice per pull request. Start it with `<!-- gitar-fork-access:v1 -->` and do not duplicate it when that marker is already present.
5. Do not request tokens, secrets, repository membership, or a workaround that bypasses GitHub's fork permission boundary.
6. After ordinary maintainer-edit permission is available, resume only the bounded automatic repairs allowed by the repository instructions.
