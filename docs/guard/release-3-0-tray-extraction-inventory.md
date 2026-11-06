# HOL Guard 3.0 persistent-tray extraction inventory

- Source pull request: #1901
- Tray feature commit: `e06355167ae03916c4e7251e08260bbde1506bd9`
- Follow-up updater commit: `9741f5c668e070973c14287d2c4a1f9a6777fc3f`
- Feature parent: `d3f6efe9c568b064492cc380be6fe7fb4dbe0ba8`
- Inventory date: 2026-08-05
- Destination release line: `release/3.0`

This inventory is the deletion and retention checklist for moving persistent native presence out of `hol-guard` and into `hashgraph-online/hol-guard-desktop`.

## Remove from the core

### Tray package and platform adapters

Delete the complete persistent tray package:

- `src/codex_plugin_scanner/guard/tray/__init__.py`
- `src/codex_plugin_scanner/guard/tray/contracts.py`
- `src/codex_plugin_scanner/guard/tray/lifecycle.py`
- `src/codex_plugin_scanner/guard/tray/runtime.py`
- `src/codex_plugin_scanner/guard/tray/security.py`
- `src/codex_plugin_scanner/guard/tray/state.py`
- `src/codex_plugin_scanner/guard/tray/platforms/__init__.py`
- `src/codex_plugin_scanner/guard/tray/platforms/linux.py`
- `src/codex_plugin_scanner/guard/tray/platforms/macos.py`
- `src/codex_plugin_scanner/guard/tray/platforms/windows.py`

### Tray assets

Delete `src/codex_plugin_scanner/guard/tray/assets/` and all generated light/dark PNG variants at 16, 22, 32, 48, and 64 pixels, including `@2x` variants.

The official source brand assets under the daemon dashboard remain available for the separate Desktop repository. They are not tray runtime code.

### Python dependencies and packaging

Remove tray-only dependencies from `pyproject.toml` and `uv.lock`:

- `pystray`
- `pillow`, when no other core feature requires it
- `pyobjc-framework-Quartz`, when no other core feature requires it
- `python-xlib`, when no other core feature requires it
- tray-only transitive entries such as `six`, PyObjC Cocoa/Core, and Xlib when no longer required

Remove `src/codex_plugin_scanner/guard/tray/assets/**` from Hatch build artifacts.

Remove any tray executable, package entry point, standalone artifact, or release manifest field.

### CLI and first-run setup

Remove from `commands_parser_local.py`:

- `--skip-tray` from `hol-guard init`;
- the `tray` command group;
- `status`, `start`, `stop`, `restart`, `repair`, `install`, `uninstall`, and internal `run` subcommands.

Remove from `commands_dispatch_local.py`:

- `_run_guard_tray_command`;
- `_guard_package_version` when no other caller remains;
- all imports and dispatch paths into `guard.tray`.

Remove the tray dispatch registration from `commands_router.py`.

Remove from `commands_support_workspace.py`:

- the tray init-plan step;
- platform adapter detection;
- tray installation and startup behavior;
- tray-specific progress, skip, and failure events.

The first-run flow should continue to cover dashboard, apps, Cloud, and fallback notification setup without starting a persistent GUI process.

### Daemon and dashboard control surface

Remove from the daemon:

- `GET /v1/tray/status`;
- `POST /v1/tray/start`;
- `POST /v1/tray/stop`;
- `POST /v1/tray/restart`;
- `POST /v1/tray/repair`;
- `POST /v1/tray/install`;
- `POST /v1/tray/uninstall`;
- tray-specific imports, response payloads, and authorization tests.

Remove from the React dashboard:

- `dashboard/src/settings/tray-settings-panel.tsx`;
- the Tray settings tab and icon from `dashboard/src/settings/settings-ia.tsx`;
- Tray rendering from `dashboard/src/settings-workspace.tsx`;
- tray API methods from `dashboard/src/guard-api.ts`;
- tray types and action enums from `dashboard/src/guard-types.ts`;
- tray-specific settings information-architecture assertions.

Rebuild the committed daemon dashboard assets after source removal so generated files contain no Tray settings UI or `/v1/tray/*` calls.

### Update and lifecycle handoff

Remove tray stop/restart handoff from `src/codex_plugin_scanner/guard/cli/update_commands.py` and any dashboard update runner integration.

The headless daemon and core update lifecycle remain. Desktop will coordinate its own native tray and bundled core update.

### Documentation and notices

Delete:

- `docs/guard/tray-icon.md`;
- `THIRD_PARTY_NOTICES.md` if it remains exclusively a tray dependency notice.

Remove tray feature claims and commands from:

- `CHANGELOG.md`;
- `README.md`;
- `docs/guard/get-started.md`;
- release notes, troubleshooting, generated help, and support material.

Replace them with a clear boundary statement: persistent native tray behavior belongs to HOL Guard Desktop; the core remains CLI, daemon, and browser-dashboard capable.

### Tray-only tests

Delete the tray-specific suites after equivalent Desktop coverage is planned:

- `tests/test_guard_tray_cli.py`
- `tests/test_guard_tray_contracts.py`
- `tests/test_guard_tray_daemon.py`
- `tests/test_guard_tray_init.py`
- `tests/test_guard_tray_lifecycle.py`
- `tests/test_guard_tray_linux.py`
- `tests/test_guard_tray_macos.py`
- `tests/test_guard_tray_platforms.py`
- `tests/test_guard_tray_runtime.py`
- `tests/test_guard_tray_security.py`
- `tests/test_guard_tray_state.py`
- `tests/test_guard_tray_update.py`
- `tests/test_guard_tray_windows.py`

Remove tray-specific modifications from broader suites such as `tests/test_guard_cli.py` and `tests/test_guard_init.py` while preserving unrelated 3.0 assertions.

## Retain in the headless core

The following were introduced or touched during tray work but may be independently useful and must be reviewed rather than blindly reverted:

### Canonical dashboard launcher

- `src/codex_plugin_scanner/guard/dashboard_launcher.py`
- dashboard CLI refactoring in `commands_dispatch_local.py`
- `tests/test_guard_dashboard_launcher.py`

Retain when it provides one secure, token-redacted path for browser dashboard launch and Desktop bootstrap. Remove only tray-specific call sites.

### Shared redaction and notification behavior

Retain reusable secret-redaction changes and best-effort desktop notification helpers when they serve CLI or browser-only users without a persistent tray process.

### Headless process and event contracts

Retain:

- daemon singleton and process identity protections;
- runtime status and health;
- approval queue and receipts;
- browser dashboard authentication;
- platform-neutral attention events;
- a notification-owner lease or equivalent deduplication contract for Desktop;
- repair, diagnostics, and core update behavior.

## Reimplement in `hol-guard-desktop`

The separate Tauri application owns:

- persistent tray creation;
- native tray icon and menu;
- platform launch at login;
- native application single-instance behavior;
- show, hide, focus, close-to-tray, and quit behavior;
- native notifications and approval deep links;
- Desktop-specific status mapping;
- application update, signing, notarization, and recovery UI;
- official Desktop and tray assets.

Do not port the deleted Python/pystray implementation. Consume the headless 3.0 status and event contracts from a native Tauri implementation.

## Required negative checks for HOL Guard 3.0

Add release-blocking checks that prove:

1. `hol-guard --help` and nested help expose no tray command;
2. installed package metadata contains no tray-only dependency;
3. wheel and standalone core artifact contain no `guard/tray` module or tray PNG assets;
4. a clean core install registers no LaunchAgent, Windows task/run entry, or XDG autostart item for a tray;
5. launching core and the browser dashboard creates no persistent tray or native GUI process;
6. source and generated dashboard assets contain no `/v1/tray/` route or Tray settings tab;
7. CLI/browser fallback notifications still work when configured;
8. Desktop session ownership suppresses duplicate fallback notifications without making Desktop required.

## Completion evidence

Before this inventory is marked complete, PR #1901 must record:

- every deleted path;
- every modified mixed-purpose file;
- every retained reusable contract and its rationale;
- lockfile regeneration evidence;
- dashboard rebuild evidence;
- focused and full regression results;
- built wheel/core artifact content inspection;
- confirmation that no persistent tray process remains in HOL Guard 3.0.
