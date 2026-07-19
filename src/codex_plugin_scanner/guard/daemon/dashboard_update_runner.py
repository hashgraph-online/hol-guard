"""Detached worker that upgrades Guard, restarts the daemon, and serves the new dashboard."""

from __future__ import annotations

import argparse
import sqlite3
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.cli import update_commands
from codex_plugin_scanner.guard.daemon.dashboard_update import (
    claim_dashboard_update_lock,
    clear_dashboard_update_lock,
    write_dashboard_update_outcome,
)
from codex_plugin_scanner.guard.daemon.manager import (
    _retire_guard_daemon_pid,
    ensure_guard_daemon_after_update,
    guard_daemon_retirement_is_complete,
    retire_all_guard_daemons_for_home,
)
from codex_plugin_scanner.guard.store import GuardStore

_DASHBOARD_UPDATE_DAEMON_SETTLE_SECONDS = 1.5


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    guard_home = Path(args.guard_home).expanduser().resolve()
    if not claim_dashboard_update_lock(guard_home, token=args.update_token):
        print("Guard dashboard update reservation is missing or belongs to another runner.", file=sys.stderr)
        return 1
    try:
        home_dir = Path.home().resolve()
        context = HarnessContext(home_dir=home_dir, workspace_dir=None, guard_home=guard_home)
        try:
            store = GuardStore(guard_home)
        except (OSError, RuntimeError, sqlite3.Error):
            store = None
        time.sleep(_DASHBOARD_UPDATE_DAEMON_SETTLE_SECONDS)
        retire_all_guard_daemons_for_home(guard_home)
        requested_daemon_retired = _retire_guard_daemon_pid(args.daemon_pid, expected_guard_home=guard_home)
        if not requested_daemon_retired or not guard_daemon_retirement_is_complete(guard_home):
            failed_payload: dict[str, object] = {
                "status": "failed",
                "message": "Guard update was not started because its running daemon could not be retired safely.",
            }
            try:
                write_dashboard_update_outcome(guard_home, failed_payload)
            finally:
                _restore_daemon_after_failed_update(
                    context,
                    preferred_port=args.daemon_port,
                )
            print(str(failed_payload["message"]), file=sys.stderr)
            return 1

        update_payload: dict[str, object]
        exit_code: int
        try:
            update_payload, exit_code = update_commands.run_guard_update(
                dry_run=False,
                force_pypi_reinstall=args.force_pypi_reinstall,
                guard_home=guard_home,
                context=context,
                store=store,
                now=datetime.now(timezone.utc).isoformat(),
            )
        except Exception as error:  # pragma: no cover - defensive detached-runner boundary.
            update_payload = {
                "status": "failed",
                "error": type(error).__name__,
                "message": "Guard update failed unexpectedly.",
            }
            exit_code = 1
        if exit_code != 0:
            message = update_payload.get("message") or update_payload.get("error") or "Guard update failed."
            print(str(message), file=sys.stderr)
            try:
                write_dashboard_update_outcome(guard_home, update_payload)
            finally:
                _restore_daemon_after_failed_update(
                    context,
                    preferred_port=args.daemon_port,
                )
            return 1

        # run_guard_update performs its successful restart through a fresh,
        # trusted interpreter. Never restart here with manager functions that
        # were imported from the package version being replaced.
        if not _daemon_refresh_restarted(update_payload.get("daemon_refresh")):
            failed_payload = {
                **update_payload,
                "status": "failed",
                "message": "Guard updated, but its daemon could not be restarted in a fresh interpreter.",
            }
            try:
                write_dashboard_update_outcome(guard_home, failed_payload)
            finally:
                _restore_daemon_after_failed_update(
                    context,
                    preferred_port=args.daemon_port,
                )
            return 1
        write_dashboard_update_outcome(guard_home, update_payload)
        return 0
    finally:
        clear_dashboard_update_lock(guard_home, token=args.update_token)


def _restore_daemon_after_failed_update(context: HarnessContext, *, preferred_port: int) -> None:
    """Restore dashboard availability, preferring the isolated fresh interpreter."""

    refresh_payload, refresh_note = _isolated_daemon_refresh(context)
    if _daemon_refresh_restarted(refresh_payload):
        return
    if refresh_note:
        print(refresh_note, file=sys.stderr)
    ensure_guard_daemon_after_update(
        context.guard_home,
        home_dir=context.home_dir,
        preferred_port=preferred_port,
    )


def _isolated_daemon_refresh(
    context: HarnessContext,
) -> tuple[dict[str, object] | None, str | None]:
    try:
        return update_commands.refresh_guard_daemon_after_update(context)
    except Exception as error:  # pragma: no cover - defensive detached-runner boundary.
        return None, f"Could not restart the Guard daemon in an isolated interpreter: {error}"


def _daemon_refresh_restarted(payload: object) -> bool:
    return isinstance(payload, dict) and payload.get("status") == "restarted"


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Upgrade Guard and restart the local daemon.")
    parser.add_argument("--guard-home", required=True)
    parser.add_argument("--daemon-pid", type=int, required=True)
    parser.add_argument("--daemon-port", type=int, required=True)
    parser.add_argument("--update-token", required=True)
    parser.add_argument(
        "--force-pypi-reinstall",
        action="store_true",
        help="Reinstall hol-guard from PyPI to repair a local folder install.",
    )
    return parser.parse_args(argv)


if __name__ == "__main__":
    raise SystemExit(main())
