---
title: "Enable automatic repair on extension contribution pull requests"
description: "Enable Gitar auto-apply only for pull requests confined to the declarative extension contribution surface."
type: automation
when: "A pull request is opened, reopened, marked ready for review, or receives new commits, and every file it changed lives under the extension contribution surface: contributions/, tests/fixtures/command-source-*.v1.json, contracts/extensions/, docs/guard/extensions/catalog.v*.json, or src/codex_plugin_scanner/guard/contracts/data/extensions/. Skip drafts, pull requests labeled gitar-skip, and every pull request with a file outside that surface."
actions: "Add the gitar-managed label to enable Gitar auto-apply for the pull request. When an active pull request changes any file outside the contribution surface, do not add gitar-managed and remove it if present."
---

# Enable automatic repair for extension contributions only

Gitar auto-apply is **scoped to the declarative extension contribution
surface**. For every other pull request it stays disabled.

For an active, ready-for-review pull request whose changes stay entirely
inside the extension contribution surface — authored inputs under
`contributions/`, command-source fixtures under
`tests/fixtures/command-source-*.v1.json`, extension contracts and
per-extension trust bindings under `contracts/extensions/`, the extension
catalog under `docs/guard/extensions/catalog.v*.json`, or packaged contract
data under `src/codex_plugin_scanner/guard/contracts/data/extensions/` — add
the `gitar-managed` label. That label enables Gitar auto-apply for the
lifetime of the pull request.

Do not add it to a draft pull request, a pull request labeled `gitar-skip`,
or any pull request that changes a file outside the surface listed above. If
an active pull request carries `gitar-managed` but a file outside the surface
appears in its diff, remove the label.

An explicit `gitar auto-apply:on` directive from the pull request author or a
maintainer enables auto-apply for that pull request even outside the
contribution surface. Respect `gitar auto-apply:off` and the `gitar-skip`
label immediately.
