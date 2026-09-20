# Changelog

All notable changes to HOL Guard will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.2.0](https://github.com/hashgraph-online/hol-guard/compare/v3.1.0...v3.2.0) (2026-09-21)


### Features

* **extensions:** migrate authoring to native declarative sources ([01d73fd](https://github.com/hashgraph-online/hol-guard/commit/01d73fd3461741eb47a62c33d259f6c0c6e3bb7d))


### Bug Fixes

* **audit:** allow dashboard workspace selection ([#3015](https://github.com/hashgraph-online/hol-guard/issues/3015)) ([42f303d](https://github.com/hashgraph-online/hol-guard/commit/42f303dd5e413e0255de41749d0ae0f28778df96))
* **authority:** stabilize trusted root construction ([47e3961](https://github.com/hashgraph-online/hol-guard/commit/47e39612d307e56849e2e1b7ed242bc4fb0a8b7f))
* bind configuration reads and stabilize native CI ([c14cf1f](https://github.com/hashgraph-online/hol-guard/commit/c14cf1f37faacafc0856debefa3995e479365d36))
* **ci:** restore native command model ownership and sudo test parity ([488a8fd](https://github.com/hashgraph-online/hol-guard/commit/488a8fdd33185133eda16a9f8dc467ebd573cee0))
* guard background config read against trust errors in attention loop ([c7933ab](https://github.com/hashgraph-online/hol-guard/commit/c7933ab4387e81d9f56cbd0abc2b9a9a38897430))
* preserve command floors and validate cross-platform config files ([af5c563](https://github.com/hashgraph-online/hol-guard/commit/af5c563009302950b45810466079995e3271a70c))
* **runtime:** satisfy native evaluation contracts ([a3284be](https://github.com/hashgraph-online/hol-guard/commit/a3284be40333f0afad0e9884783b58e7e3b4bf4b))
* **security:** document config path containment ([88469f9](https://github.com/hashgraph-online/hol-guard/commit/88469f9b74a4a9fbf7cb7e90f9f5f7e7567b5b32))

## [3.1.0](https://github.com/hashgraph-online/hol-guard/compare/v3.0.193...v3.1.0) (2026-09-20)


### Features

* **extensions:** add Errand command-safety extension ([e42e8a4](https://github.com/hashgraph-online/hol-guard/commit/e42e8a4f746e66882d62c34a944392fae91380fe))


### Bug Fixes

* **ci:** open Release Please pull requests with a repo token ([#3011](https://github.com/hashgraph-online/hol-guard/issues/3011)) ([f674f69](https://github.com/hashgraph-online/hol-guard/commit/f674f69665cfbcb79ab9e82d671e99f7674905ae))
* **codex:** omit PreToolUse permissionDecision allow ([#3013](https://github.com/hashgraph-online/hol-guard/issues/3013)) ([1653932](https://github.com/hashgraph-online/hol-guard/commit/1653932ab8625198b38f44bfca0485287e2f7ead))
* **hooks:** fan frozen bounded hooks into the daemon worker pool ([#3009](https://github.com/hashgraph-online/hol-guard/issues/3009)) ([79afae8](https://github.com/hashgraph-online/hol-guard/commit/79afae8c2c5fc02acffb4ed13b34d0c7375364e4))


### Performance Improvements

* **ci:** cut test and native build delays and fix release handoffs ([#3008](https://github.com/hashgraph-online/hol-guard/issues/3008)) ([fba6f74](https://github.com/hashgraph-online/hol-guard/commit/fba6f7428536ee545dabcdd8c1fbedfa861f3ae0))

## [Unreleased]

### Fixed

- Claude marketplace scans treat `strict` as an optional boolean on each
  `plugins[]` entry (default `true`) instead of requiring a root-level field
  that Claude Code rejects.
- `HARDCODED_SECRET` no longer treats pure `${VAR}` or `{{var}}` expansions as
  embedded credentials outside docs and tests. Non-empty defaults and suffixes
  still fail.
- Native DeepSeek Harness packages can set `dsh.bundle.mode` to `"patch"` so
  patch-only bundles are not required to export Cordis `apply(ctx)`. Packages
  that declare `main` or `exports` still need that runtime.

### Changed

- Added the HOL Guard 3.0 Managed Controls user, operator, migration, recovery,
  incident, rollback, support, and release documentation set.
- Persistent menu-bar and system-tray ownership moved to the separate
  `hashgraph-online/hol-guard-desktop` application.
- HOL Guard Core remains headless and continues to own policy enforcement,
  approvals, receipts, the local daemon, browser dashboard, fallback
  notifications, updates, repair, and diagnostics.
- The canonical dashboard launcher remains available to trusted local callers.
- User-facing credential redaction moved to the platform-neutral
  `guard.secret_redaction` module.

### Removed

- Python/pystray tray runtime, platform startup adapters, tray CLI commands,
  dashboard tray controls, tray update handoff, tray assets, and tray-only
  dependencies.
