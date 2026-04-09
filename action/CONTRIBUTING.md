# Contributing to AI Plugin Scanner Action

Thanks for helping maintain the canonical GitHub Action bundle for `plugin-scanner` (legacy package alias: `codex-plugin-scanner`).

## What lives here

This repository is the preferred public GitHub Action slug for the scanner. The implementation source of truth for scanner behavior lives in:

- [`hashgraph-online/ai-plugin-scanner`](https://github.com/hashgraph-online/ai-plugin-scanner)

The legacy compatibility slug remains available at:

- [`hashgraph-online/hol-codex-plugin-scanner-action`](https://github.com/hashgraph-online/hol-codex-plugin-scanner-action)

Most functional changes should start in the source repository and then be published into this canonical repository and the legacy compatibility repository through the release sync workflow.

## What changes belong here

Changes that are appropriate in this repository:

- README, Marketplace copy, and examples for the canonical action slug
- action metadata in [`action.yml`](./action.yml)
- release-only docs like this contributing guide
- canonical action release wiring

Changes that should usually happen in the source repository first:

- scanner behavior
- CLI flags and output contracts
- action runner logic
- release automation that produces this bundle

## Local review checklist

Before opening a PR:

1. Keep the diff focused on the action repository surface.
2. Make sure README examples use the canonical slug: `hashgraph-online/ai-plugin-scanner-action@v1`.
3. If `action.yml` changes, confirm the inputs and outputs documented in [`README.md`](./README.md) still match.
4. If release/version copy changes, keep it aligned with the latest published scanner release and the compatibility repository mirror.

## Pull requests

- Use a focused title and description.
- Include screenshots when the change is mainly Marketplace or README presentation.
- Link the related source-repo PR when the update was generated from `ai-plugin-scanner`.

## Security

For vulnerability reports, follow [`SECURITY.md`](./SECURITY.md) and do not open public issues for undisclosed security bugs.
