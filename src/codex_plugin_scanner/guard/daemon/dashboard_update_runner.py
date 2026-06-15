"""Detached worker that upgrades Guard, restarts the daemon, and serves the new dashboard."""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from codex_plugin_scanner.guard.cli.update_commands import run_guard_update
from codex_plugin_scanner.guard.daemon.dashboard_update import clear_dashboard_update_lock
from codex_plugin_scanner.guard.daemon.manager import (
    _retire_guard_daemon_pid,
    clear_guard_daemon_state,
    ensure_guard_daemon_after_update,
    repair_approval_center_locator,
    retire_all_guard_daemons_for_home,
)

_DASHBOARD_UPDATE_DAEMON_SETTLE_SECONDS = 1.5


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    guard_home = Path(args.guard_home).expanduser().resolve()
    try:
        time.sleep(_DASHBOARD_UPDATE_DAEMON_SETTLE_SECONDS)
        retire_all_guard_daemons_for_home(guard_home)
        _retire_guard_daemon_pid(args.daemon_pid, expected_guard_home=guard_home)
        clear_guard_daemon_state(guard_home)
        repair_approval_center_locator(guard_home)

        update_payload, exit_code = run_guard_update(
            dry_run=False,
            force_pypi_reinstall=args.force_pypi_reinstall,
        )
        if exit_code != 0:
            message = update_payload.get("message") or update_payload.get("error") or "Guard update failed."
            print(str(message), file=sys.stderr)
            ensure_guard_daemon_after_update(guard_home, preferred_port=args.daemon_port)
            return 1

        retire_all_guard_daemons_for_home(guard_home)
        _retire_guard_daemon_pid(args.daemon_pid, expected_guard_home=guard_home)
        clear_guard_daemon_state(guard_home)
        ensure_guard_daemon_after_update(guard_home, preferred_port=args.daemon_port)
        return 0
    finally:
        clear_dashboard_update_lock(guard_home)


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Upgrade Guard and restart the local daemon.")
    parser.add_argument("--guard-home", required=True)
    parser.add_argument("--daemon-pid", type=int, required=True)
    parser.add_argument("--daemon-port", type=int, required=True)
    parser.add_argument(
        "--force-pypi-reinstall",
        action="store_true",
        help="Reinstall hol-guard from PyPI to repair a local folder install.",
    )
    return parser.parse_args(argv)


if __name__ == "__main__":
    raise SystemExit(main())
