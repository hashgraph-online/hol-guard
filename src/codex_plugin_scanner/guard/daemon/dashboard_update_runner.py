"""Detached worker that upgrades Guard, restarts the daemon, and serves the new dashboard."""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from ..cli.update_commands import run_guard_update
from .dashboard_update import clear_dashboard_update_lock
from .manager import _retire_guard_daemon_pid, clear_guard_daemon_state, ensure_guard_daemon


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    guard_home = Path(args.guard_home).expanduser().resolve()
    try:
        time.sleep(1.5)
        update_payload, exit_code = run_guard_update(dry_run=False)
        if exit_code != 0:
            message = update_payload.get("message") or update_payload.get("error") or "Guard update failed."
            print(str(message), file=sys.stderr)
            return 1
        _retire_guard_daemon_pid(args.daemon_pid, expected_guard_home=guard_home)
        clear_guard_daemon_state(guard_home)
        ensure_guard_daemon(guard_home)
        return 0
    finally:
        clear_dashboard_update_lock(guard_home)


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Upgrade Guard and restart the local daemon.")
    parser.add_argument("--guard-home", required=True)
    parser.add_argument("--daemon-pid", type=int, required=True)
    parser.add_argument("--daemon-port", type=int, required=True)
    return parser.parse_args(argv)


if __name__ == "__main__":
    raise SystemExit(main())
