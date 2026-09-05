## Summary

- A CLI self-update could fail with `update_daemon_refresh_failed` / `retirement_failed` when the Guard Desktop app owns the live daemon: the Desktop supervisor respawns every daemon the refresh retires, so retirement never completes, the refresh burns all three attempts, and the update reports failure even though a healthy, authenticated daemon served the home the entire time.
- The refresh path now recognizes a verified Desktop-owned daemon and keeps it serving instead of fighting it. The Desktop app converges its daemon to newer bytes on its own schedule; nothing about the CLI update itself failed.

## Changes

- `daemon_source_is_desktop_core` now recognizes all three Desktop source shapes — the managed Core versions tree, an executable bundled inside a macOS `.app` bundle, and the Windows install directory — and fixes an off-by-one that skipped the last possible marker position in a path. Checkouts and pipx venvs named after the package still do not match.
- New `live_desktop_owned_daemon` returns a fully verified identity (signed state plus authenticated loopback health) only when the daemon's source is a Desktop runtime that still exists on disk.
- The post-update refresh script checks for a Desktop owner before fighting and also surrenders mid-fight (retirement deadline reached, or the just-started daemon replaced) by emitting a `retained_desktop_owner` result with exit code 0 instead of failing after three attempts.
- `refresh_guard_daemon_after_update` prefers a verified Desktop-owned daemon before launching the script, accepts `retained_desktop_owner` from the script, and treats a vanished daemon-state file (`not_running`) as "nothing to restart" rather than a failure. The update summary accepts both as success while still repairing package shims and harness hooks, because the CLI remains the newest runtime in the retained-desktop case.
- The desktop-apply refresh path gets the same fallback, gated by a new `minimum_version` argument so it only retains a daemon already serving the applied version; an older respawned daemon still fails loudly.
- The dashboard update runner accepts `retained_desktop_owner` as a refreshed outcome, while `not_running` still counts as failure there so the legacy in-process restart restores a live daemon — the dashboard flow must end with one running.

## Testing

- New `tests/test_guard_update_daemon_external_owner.py`: the script keeps a Desktop daemon when retirement never completes, surrenders mid-fight after the first retirement attempt, the caller pre-check keeps the daemon without ever launching the refresh script, and parametrized source-shape detection covers the app bundle, managed tree, and Windows path plus checkout/pipx/empty/`None` negatives.
- Existing handoff, runtime-repair, desktop-apply, dashboard, shim-refresh, and harness-launcher suites pass unchanged except for the intentional gate updates; the combined update/daemon slice (1511 tests) passes.
