"""Dependency-light daemon refresh program loaded by the installed runtime."""

DAEMON_REFRESH_SCRIPT = """
from __future__ import annotations

import inspect
import json
import sys
import time
from pathlib import Path

from codex_plugin_scanner.guard.daemon.manager import (
    clear_guard_daemon_state,
    ensure_guard_daemon_after_update,
    guard_daemon_retirement_is_complete,
    load_guard_daemon_url,
    publish_approval_center_locator,
    repair_approval_center_locator,
    retire_all_guard_daemons_for_home,
)
from codex_plugin_scanner.guard.daemon.runtime_peer import live_desktop_owned_daemon

payload = json.loads(sys.stdin.read())
guard_home = Path(payload["guard_home"]).expanduser().resolve()
home_dir_value = payload.get("home_dir")
home_dir = (
    Path(home_dir_value).expanduser().resolve()
    if isinstance(home_dir_value, str) and home_dir_value.strip()
    else Path.home().resolve()
)


def desktop_owner_result(attempts, retired_pids):
    # Guard Desktop supervises its daemon and respawns anything this program
    # retires, so retirement can never win. When a verified Desktop-owned
    # daemon is serving the home, keeping it is the safe outcome; it loads
    # newer bytes when the Desktop app itself updates.
    identity = live_desktop_owned_daemon(guard_home)
    if identity is None:
        return None
    return {
        "status": "retained_desktop_owner",
        "retired": retired_pids,
        "daemon_url": identity.get("daemon_url"),
        "daemon_version": identity.get("package_version"),
        "attempts": attempts,
        "runtime_verified": True,
    }


state_path = guard_home / "daemon-state.json"
if not state_path.is_file():
    print(json.dumps({"status": "not_running"}))
    raise SystemExit(0)
kept_owner = desktop_owner_result(0, [])
if kept_owner is not None:
    print(json.dumps(kept_owner))
    raise SystemExit(0)
try:
    state = json.loads(state_path.read_text(encoding="utf-8"))
except (OSError, json.JSONDecodeError):
    state = {}
preferred_port = state.get("port") if isinstance(state.get("port"), int) else None
refresh_parameters = inspect.signature(ensure_guard_daemon_after_update).parameters
refresh_kwargs = {"preferred_port": preferred_port}
if "home_dir" in refresh_parameters:
    refresh_kwargs["home_dir"] = home_dir
if "allow_windows_job_breakaway" in refresh_parameters:
    refresh_kwargs["allow_windows_job_breakaway"] = True
retired = []
last_failure_status = "runtime_replaced"
for attempt in range(1, 4):
    retirement_complete = False
    retirement_deadline = time.monotonic() + 5.0
    while True:
        for pid in retire_all_guard_daemons_for_home(guard_home):
            if pid not in retired:
                retired.append(pid)
        if guard_daemon_retirement_is_complete(guard_home):
            retirement_complete = True
            break
        if time.monotonic() >= retirement_deadline:
            last_failure_status = "retirement_failed"
            break
        time.sleep(0.1)
    if not retirement_complete:
        kept_owner = desktop_owner_result(attempt, retired)
        if kept_owner is not None:
            print(json.dumps(kept_owner))
            raise SystemExit(0)
        continue
    clear_guard_daemon_state(guard_home)
    repair_approval_center_locator(guard_home)
    daemon_url = ensure_guard_daemon_after_update(guard_home, **refresh_kwargs)
    # A separately installed desktop app can race the refresh and replace the
    # just-started daemon with older bytes. Require the updated fingerprint to
    # remain bound across a short stability window before reporting success.
    verified_url = None
    for _stability_check in range(3):
        time.sleep(1.0)
        verified_url = load_guard_daemon_url(guard_home)
        if verified_url is None:
            break
    if verified_url is not None:
        locator_published = True
        try:
            publish_approval_center_locator(guard_home, verified_url)
        except (OSError, RuntimeError):
            locator_published = False
        result = {
            "status": "restarted",
            "retired": retired,
            "daemon_url": verified_url,
            "attempts": attempt,
            "runtime_verified": True,
        }
        if not locator_published:
            result["locator_published"] = False
        print(json.dumps(result))
        raise SystemExit(0)
    kept_owner = desktop_owner_result(attempt, retired)
    if kept_owner is not None:
        print(json.dumps(kept_owner))
        raise SystemExit(0)
    last_failure_status = "runtime_replaced"
print(json.dumps({"status": last_failure_status, "retired": retired, "attempts": 3}))
raise SystemExit(1)
""".strip()
