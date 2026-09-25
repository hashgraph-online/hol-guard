# Changelog

All notable changes to HOL Guard will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.5.1](https://github.com/hashgraph-online/hol-guard/compare/v3.5.0...v3.5.1) (2026-09-25)


### Bug Fixes

* **dashboard:** replace window.confirm with an in-app confirmation dialog ([#3108](https://github.com/hashgraph-online/hol-guard/issues/3108)) ([2e62aab](https://github.com/hashgraph-online/hol-guard/commit/2e62aab4b914cbd3df8f83708edcacdfb04dbcc3))
* **guard:** keep Windows command paths and daemon startup ([#3101](https://github.com/hashgraph-online/hol-guard/issues/3101)) ([3415ade](https://github.com/hashgraph-online/hol-guard/commit/3415adeb2dc171b81a0a7185a573f5a4ee313c86))
* **runtime:** keep native policy prep working when old resident scopes pile up ([#3106](https://github.com/hashgraph-online/hol-guard/issues/3106)) ([0986515](https://github.com/hashgraph-online/hol-guard/commit/0986515e7969d9dd5b14bb3554b58fc1523309da))

## [3.5.0](https://github.com/hashgraph-online/hol-guard/compare/v3.4.5...v3.5.0) (2026-09-24)


### Features

* **devin:** add Devin CLI harness adapter with managed native hooks ([#3099](https://github.com/hashgraph-online/hol-guard/issues/3099)) ([b992f68](https://github.com/hashgraph-online/hol-guard/commit/b992f680a263c264f5936b09bc91190351c72378))
* **guard:** add bounded command event parser ([#3097](https://github.com/hashgraph-online/hol-guard/issues/3097)) ([6a46a6e](https://github.com/hashgraph-online/hol-guard/commit/6a46a6ec3802524aa882f0d3582788f6959ac9fe))


### Bug Fixes

* **guard:** recover Linux enrollment without discarding native authority ([#3096](https://github.com/hashgraph-online/hol-guard/issues/3096)) ([856de33](https://github.com/hashgraph-online/hol-guard/commit/856de33862f1382012713a6a2a2d34a8e756ddac))
* **tests:** suppress real browser launches during pytest runs ([#3103](https://github.com/hashgraph-online/hol-guard/issues/3103)) ([694fc6c](https://github.com/hashgraph-online/hol-guard/commit/694fc6c5b3ad5d8dc2e99696202e4245092ca63b))

## [3.4.5](https://github.com/hashgraph-online/hol-guard/compare/v3.4.4...v3.4.5) (2026-09-24)


### Bug Fixes

* **dashboard:** clarify command activity run results ([#3090](https://github.com/hashgraph-online/hol-guard/issues/3090)) ([6d802ab](https://github.com/hashgraph-online/hol-guard/commit/6d802ab5f2c2edd7aa8e6dd3a5e645b8d91ba3ce))

## [3.4.4](https://github.com/hashgraph-online/hol-guard/compare/v3.4.3...v3.4.4) (2026-09-24)


### Bug Fixes

* **evidence:** preserve command context in action rows ([#3088](https://github.com/hashgraph-online/hol-guard/issues/3088)) ([2b250d9](https://github.com/hashgraph-online/hol-guard/commit/2b250d9a392880d69f46519e4ea88caab52a077d))

## [3.4.3](https://github.com/hashgraph-online/hol-guard/compare/v3.4.2...v3.4.3) (2026-09-24)

### Features

* Add an evidence-gated harness capability report ([#3081](https://github.com/hashgraph-online/hol-guard/pull/3081)) ([f5d568f](https://github.com/hashgraph-online/hol-guard/commit/f5d568f9c60d03cf26ec8ace7ed9aa8686af7ca7))
* Add bounded local evaluation contracts and witnesses ([#3083](https://github.com/hashgraph-online/hol-guard/pull/3083)) ([ddbe315](https://github.com/hashgraph-online/hol-guard/commit/ddbe315f62eb09dcca9ee2ef962061c172b76d9a))

### Bug Fixes

* Fail closed when Cline post-tool review is unavailable ([#3082](https://github.com/hashgraph-online/hol-guard/pull/3082)) ([e1472f7](https://github.com/hashgraph-online/hol-guard/commit/e1472f7d470d66bc6a2acf63ba8a55888ab4288f))
* **audit:** choose a project folder before running a workspace audit ([#3086](https://github.com/hashgraph-online/hol-guard/issues/3086)) ([c1afee9](https://github.com/hashgraph-online/hol-guard/commit/c1afee972e0cd77c70f67ad0bd6609c8b410805a))
* **contributors:** make extension PRs self-healing ([#3087](https://github.com/hashgraph-online/hol-guard/issues/3087)) ([b22841a](https://github.com/hashgraph-online/hol-guard/commit/b22841ac004b9d8a6deccdeee1a1be3600fddfb9))
* **dashboard:** show the Cloud Review authenticator field ([#3085](https://github.com/hashgraph-online/hol-guard/issues/3085)) ([7166570](https://github.com/hashgraph-online/hol-guard/commit/7166570f1465bfe970d4cc94250cb7b737f10875))
* **release:** follow the newest Release Please stable tag ([#3075](https://github.com/hashgraph-online/hol-guard/issues/3075)) ([13d2486](https://github.com/hashgraph-online/hol-guard/commit/13d24860d620b45ec3f542d5eec363ce7e121e00))
* **release:** verify Release Please wheels against their tag ([#3078](https://github.com/hashgraph-online/hol-guard/issues/3078)) ([56faea4](https://github.com/hashgraph-online/hol-guard/commit/56faea4878649668b84f83c351d112cc279954ac))

## [3.4.2](https://github.com/hashgraph-online/hol-guard/compare/v3.4.1...v3.4.2) (2026-09-23)


### Bug Fixes

* bind uivoid portable fixtures to canonical build sources ([77adeca](https://github.com/hashgraph-online/hol-guard/commit/77adeca00df50e6df670ae285cf8aa0cf3a19fea))
* **ci:** isolate Pi fallback probes and relax permission call count ([#3070](https://github.com/hashgraph-online/hol-guard/issues/3070)) ([035623b](https://github.com/hashgraph-online/hol-guard/commit/035623b74bcc26150806b5ea895a65af441b1433))
* **guard:** preserve native authority across Linux keyring sessions ([#3071](https://github.com/hashgraph-online/hol-guard/issues/3071)) ([9ac28e8](https://github.com/hashgraph-online/hol-guard/commit/9ac28e8f6a6ae9596c6a074585f10ecc1341f331))
* preserve option terminators in versioned package matching ([694d992](https://github.com/hashgraph-online/hol-guard/commit/694d9920c7b96fbbf63a5b5f861b1f83d3239eea))
* refresh decision report bindings after native matcher update ([e81eba1](https://github.com/hashgraph-online/hol-guard/commit/e81eba13ce9f9932d56213004c127d72cc12ea7d))
* **release-notes:** dedupe identities, credit nonconventional squashes, verify published predecessors ([830eef5](https://github.com/hashgraph-online/hol-guard/commit/830eef55a6f2b1d2c82dea8fb92fd1459ad934a6))


### Documentation

* **readme:** link the annotated release archive and contributor wall ([0655c56](https://github.com/hashgraph-online/hol-guard/commit/0655c5608f959f1e81d1ed7d6dfb6b18f5cec506))
* **readme:** link the release archive and contributor wall ([7e29453](https://github.com/hashgraph-online/hol-guard/commit/7e294534387b8dc87ade39f23ac0249e324ff9f7))

## [3.4.1](https://github.com/hashgraph-online/hol-guard/compare/v3.4.0...v3.4.1) (2026-09-22)


### Bug Fixes

* **supply-chain:** keep local repair responsive across workspaces ([#3063](https://github.com/hashgraph-online/hol-guard/issues/3063)) ([e9139a7](https://github.com/hashgraph-online/hol-guard/commit/e9139a7407430947b6e9e573a2f0d2d238cfbc27))

## [3.4.0](https://github.com/hashgraph-online/hol-guard/compare/v3.3.0...v3.4.0) (2026-09-22)


### Features

* **contributors:** support Gitar notice backfills ([#3053](https://github.com/hashgraph-online/hol-guard/issues/3053)) ([7a3932a](https://github.com/hashgraph-online/hol-guard/commit/7a3932ad277fb5f9bf12aff29ddb8e187e512cc5))
* **extensions:** streamline contributor handoffs ([#3048](https://github.com/hashgraph-online/hol-guard/issues/3048)) ([f3d829c](https://github.com/hashgraph-online/hol-guard/commit/f3d829ce117a161c9ab6418f9b450177b799edb8))


### Bug Fixes

* **ci:** stabilize native wheel validation ([#3046](https://github.com/hashgraph-online/hol-guard/issues/3046)) ([ff4de55](https://github.com/hashgraph-online/hol-guard/commit/ff4de55fc4071c57f31f7521a32a33ce65e93911))
* **codex:** deny tool use when the launcher cannot be authenticated ([#3061](https://github.com/hashgraph-online/hol-guard/issues/3061)) ([939517e](https://github.com/hashgraph-online/hol-guard/commit/939517e80890db5afe869bfbb79e4829b7502d83))
* **contributors:** explain Gitar fork access ([#3050](https://github.com/hashgraph-online/hol-guard/issues/3050)) ([3a791c1](https://github.com/hashgraph-online/hol-guard/commit/3a791c1a7a5f8a88d83bc16a8e80ff009c127840))
* **contributors:** notify blocked Gitar forks ([#3052](https://github.com/hashgraph-online/hol-guard/issues/3052)) ([ae36b89](https://github.com/hashgraph-online/hol-guard/commit/ae36b898e6515b347dcb42bd25cca3ff2fa5f05c))
* **dashboard:** reuse quick-apply bulk controls on extension detail and explain locked search ([#3043](https://github.com/hashgraph-online/hol-guard/issues/3043)) ([7f3ee58](https://github.com/hashgraph-online/hol-guard/commit/7f3ee58bf246342f8c3438f9f9b54430b53dd2af))
* **supply-chain:** review new hol-guard releases ([#3060](https://github.com/hashgraph-online/hol-guard/issues/3060)) ([d9ee378](https://github.com/hashgraph-online/hol-guard/commit/d9ee378da6c3643cba30b22c5e36fb35ea1b4981))

## [3.3.0](https://github.com/hashgraph-online/hol-guard/compare/v3.2.0...v3.3.0) (2026-09-21)


### Features

* **extensions:** simplify declarative contribution preparation ([b3371c6](https://github.com/hashgraph-online/hol-guard/commit/b3371c6557f6ab23ccf14861d62408fa8aaaace6))
* **extensions:** simplify declarative contribution preparation ([ca4e5c2](https://github.com/hashgraph-online/hol-guard/commit/ca4e5c2b45688e398ffea54de587ecbefc883971))


### Bug Fixes

* **extensions:** harden contributor preparation ([f078269](https://github.com/hashgraph-online/hol-guard/commit/f0782698b76fd5cb3469bab4d6d57662888b8893))
* **extensions:** preserve v2 catalog bytes on Windows ([b7fdf8e](https://github.com/hashgraph-online/hol-guard/commit/b7fdf8e2929dc3ab7965ca41f6b8f8ec99fee391))
* **extensions:** satisfy listing type check ([f96cc6b](https://github.com/hashgraph-online/hol-guard/commit/f96cc6b45421fa86d6a7e39f2861277951d6fc1f))
* **extensions:** snapshot directory exports ([a5d87e3](https://github.com/hashgraph-online/hol-guard/commit/a5d87e3cdff224d81271376d76b7b771184681db))
* **extensions:** stabilize source digests on Windows ([e147312](https://github.com/hashgraph-online/hol-guard/commit/e147312119f01c56155bb762bb6926e083397b32))
* **extensions:** validate listing schema types ([1db22ed](https://github.com/hashgraph-online/hol-guard/commit/1db22edf3215cf5e99a964b5f2b46dfd90f78bf9))
* **security:** resolve Scorecard dependency findings ([#3017](https://github.com/hashgraph-online/hol-guard/issues/3017)) ([ccd22e0](https://github.com/hashgraph-online/hol-guard/commit/ccd22e0386309e5dc5b64b9b0d378128dcf974bb))


### Dependencies

* **actions:** bump actions/attest-build-provenance from 4.1.0 to 4.2.2 ([#3036](https://github.com/hashgraph-online/hol-guard/issues/3036)) ([45a3849](https://github.com/hashgraph-online/hol-guard/commit/45a38493ad5a9532a12a78213029411d9f5d8ffd))
* **actions:** bump actions/setup-go from 6.4.0 to 7.0.0 ([#1597](https://github.com/hashgraph-online/hol-guard/issues/1597)) ([b709c12](https://github.com/hashgraph-online/hol-guard/commit/b709c120a1913e3af37f9151885c48752ed87288))
* **actions:** bump actions/upload-artifact from 4.6.2 to 7.0.1 ([#3023](https://github.com/hashgraph-online/hol-guard/issues/3023)) ([f663f92](https://github.com/hashgraph-online/hol-guard/commit/f663f92bbf775832ee36f81b3f4ce3654b5c2fa0))
* **actions:** bump docker/setup-buildx-action from 4.1.0 to 4.4.1 ([#3038](https://github.com/hashgraph-online/hol-guard/issues/3038)) ([d1bbb8b](https://github.com/hashgraph-online/hol-guard/commit/d1bbb8b8b2773ea3fb565a31604465de1206d8c2))
* **actions:** bump github/codeql-action/upload-sarif ([#3037](https://github.com/hashgraph-online/hol-guard/issues/3037)) ([d72d418](https://github.com/hashgraph-online/hol-guard/commit/d72d4185dc8a2d9633e3f17428703cb7e3c0fcb1))
* **actions:** bump ossf/scorecard-action from 2.4.3 to 2.4.4 ([#1957](https://github.com/hashgraph-online/hol-guard/issues/1957)) ([f9d29e1](https://github.com/hashgraph-online/hol-guard/commit/f9d29e1c66d04f40e380992ff73249a37c2da9f7))
* **bun:** bump @types/node from 24.13.3 to 26.6.1 in /dashboard ([#3026](https://github.com/hashgraph-online/hol-guard/issues/3026)) ([a37878b](https://github.com/hashgraph-online/hol-guard/commit/a37878ba67fe25ea670452e82386b01c679e8560))
* **bun:** bump typescript from 5.9.3 to 7.0.2 in /dashboard ([#3027](https://github.com/hashgraph-online/hol-guard/issues/3027)) ([1b146d4](https://github.com/hashgraph-online/hol-guard/commit/1b146d41c5c6641b2fe37593452a43fdf3d4489a))
* **docker:** bump astral-sh/uv ([#3025](https://github.com/hashgraph-online/hol-guard/issues/3025)) ([ca33e5d](https://github.com/hashgraph-online/hol-guard/commit/ca33e5d4bb734985a0254401abea18d8ab902d82))
* **pip:** bump the codex-lab-patch-minor group across 1 directory with 3 updates ([#3022](https://github.com/hashgraph-online/hol-guard/issues/3022)) ([8be6b27](https://github.com/hashgraph-online/hol-guard/commit/8be6b27c5d42894e4e79adf8f2317047e5b7e8b2))


### Documentation

* update Rust extension contribution workflow ([#3019](https://github.com/hashgraph-online/hol-guard/issues/3019)) ([5e6a619](https://github.com/hashgraph-online/hol-guard/commit/5e6a619ba026f512a09e87c0fbf254a6c464fbf5))

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
