# GitHub Action Marketplace Publishing

## Why The Marketplace Action Needs A Separate Repository

GitHub Marketplace action publication has repository-level constraints:

- the action must be in a public repository
- the repository must contain a single root `action.yml`
- the repository must not contain any workflow files
- the action `name` must be unique in GitHub Marketplace

The scanner package repository intentionally contains CI, release, and scorecard workflows, so it should remain the source repository for the Python package and the action bundle, not the Marketplace listing itself.

## Source Of Truth In This Repository

These files are the canonical source for the Marketplace action:

- `action/action.yml`
- `action/README.md`
- `LICENSE`
- `SECURITY.md`

Tagged releases from this repository also publish a root-ready bundle zip named like:

- `hol-codex-plugin-scanner-action-v1.2.0.zip`

That zip contains the exact file layout expected by the dedicated Marketplace repository root.

## Recommended Publication Model

Use two repositories:

1. `hashgraph-online/codex-plugin-scanner`
   - source of truth for the Python package
   - source of truth for the action bundle
   - owns CI, tests, docs, and package publishing
2. a dedicated public action repository
   - example slug: `hashgraph-online/hol-codex-plugin-scanner-action`
   - contains only the Marketplace action files at the repository root
   - publishes Marketplace releases and floating major tags like `v1`

## Files To Place In The Dedicated Action Repository Root

- `action.yml`
- `README.md`
- `LICENSE`
- `SECURITY.md`

Do not copy `.github/workflows` into that repository.

## Action Metadata Choices

The Marketplace-ready action metadata is configured as:

- `name`: `HOL Codex Plugin Scanner`
- `branding.icon`: `check-circle`
- `branding.color`: `blue`

Those values are chosen to reduce name-collision risk and give the listing a clear trust-and-validation visual treatment.

## Release Strategy

For the dedicated Marketplace repository:

- publish immutable releases such as `v1.2.0`
- move the floating major tag `v1` to the latest compatible release
- keep the action README aligned with the scanner package release it wraps

For the scanner package repository:

- continue publishing PyPI releases from `publish.yml`
- continue generating the Marketplace action zip asset on tagged releases

## Validation Checklist Before Publishing

- confirm the dedicated action repository is public
- confirm `action.yml` is at the repository root
- confirm the repository has no workflow files
- confirm the release is tagged with a semantic version like `v1.2.0`
- confirm the floating `v1` tag points to the current compatible release
- confirm the publishing account has accepted the GitHub Marketplace developer agreement
- confirm the Marketplace category selection is set during release publication

## Runtime Behavior

The action supports both source-repo and Marketplace-repo installs:

- when the package source exists adjacent to the action, it installs the local checkout
- otherwise, it installs `codex-plugin-scanner` from PyPI

That lets the source repository test the action in CI while keeping the same `action.yml` portable to the dedicated Marketplace repository.

## Plugin Author Submission Workflow

The Marketplace action also supports a plugin-author submission flow:

- the plugin repository runs the scanner action in CI
- the action enforces a score threshold such as `80`
- if the plugin clears the threshold, passes the configured severity gate, and provides an explicit `submission_token`, the action opens or reuses a submission issue in `hashgraph-online/awesome-codex-plugins`
- the issue body includes a machine-readable registry payload so registry automation can ingest the same submission signal

This keeps the plugin-author path compact: scan, qualify, and submit from one workflow.
