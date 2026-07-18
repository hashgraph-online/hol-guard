# Changelog

All notable changes to HOL Guard will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added — Tray icon

- **Persistent menu-bar tray icon**: A cross-platform system tray icon
  (macOS menu bar, Windows system tray, Linux appindicator) that opens the
  HOL Guard dashboard without a terminal. Built on pystray with native
  backends per platform.
- **`hol-guard guard tray` CLI subcommands**: `status`, `start`, `stop`,
  `restart`, `repair`, `install`, `uninstall`, and `run` with JSON output
  for scripting and dashboard integration.
- **Dashboard settings integration**: New "Tray icon" tab in Settings
  (`#/settings/tray`) with status display and Start/Stop/Restart/Repair/
  Install/Remove action buttons. Exposed via `/v1/tray/status` (GET) and
  `/v1/tray/{start,stop,restart,repair,install,uninstall}` (POST) daemon
  endpoints.
- **Start at login**: Platform-specific registration (macOS LaunchAgent,
  Windows Run key, Linux XDG autostart) with foreign-registration collision
  detection — refuses to overwrite same-named entries it didn't create.
- **Crash recovery**: Crash-loop detection with `MAX_CRASH_RETRIES=3` and
  a 10-minute window. `tray repair` resets crash state.
- **PID-reuse safety**: `stop_tray` verifies the process start fingerprint
  before terminating — refuses to signal a PID that was recycled to an
  unrelated process.
- **Canonical dashboard launcher**: Single `open_dashboard()` in
  `dashboard_launcher.py` shared by the CLI and tray. Tokens never leave
  the launcher; browser URLs are redacted in all results.
- **Update handoff**: `hol-guard update` stops the tray before the package
  upgrade and restarts it after, so the tray uses the new code.
- **`--skip-tray` flag**: `hol-guard init` offers the tray icon step with
  a `--skip-tray` flag for headless/CI environments.
- **Documentation**: `docs/guard/tray-icon.md` with quick start, architecture,
  security model, and troubleshooting.

### Security

- Auth tokens never appear in locator files, startup registrations, process
  arguments, logs, status JSON, or notifications.
- Locator files use `0o600` permissions on POSIX.
- `sanitize_secret()` redacts token, key, secret, password, bearer, and
  credential patterns from all error messages and payloads.
- Symlink swap attacks on the locator are detected — writes replace symlinks
  rather than following them.
- Partial/corrupted locator writes raise `ValueError` instead of being
  silently parsed.
- The tray is fully event-driven — no polling, no network imports, no
  daemon/cloud polling. Zero `time.sleep` calls in the runtime.

### Dependencies

- `pystray>=0.19.5,<0.20` (LGPLv3, dynamically imported)
- `pillow>=11.0,<13` (MIT-CMU)
- `pyobjc-framework-Quartz>=10.0` (macOS only, MIT)
- `python-xlib>=0.33` (Linux x86_64 only, LGPLv2.1+)

See `THIRD_PARTY_NOTICES.md` for license obligations.

### Tests

- 371 Python tests pass (138 baseline + 233 new across 8 test files)
- All tests pass on Python 3.10, 3.11, 3.12, 3.13, 3.14
- Dashboard TypeScript builds clean, all TS tests pass
- macOS end-to-end smoke test verified (start → status → restart → stop)
