#!/usr/bin/env python3
"""Serve a seeded HOL Guard daemon for the dashboard integration suite.

The suite drives the real daemon, its HTTP API and the dashboard bundle it
serves. Nothing between the browser and Guard's store is mocked. Each run starts
from an empty, private Guard home that the seed modules in
``dashboard_integration_seeds`` fill through Guard's own store APIs.

The browser session and approval password reach Playwright through one
mode-0600 state file, never stdout, so CI logs cannot leak them.
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
import signal
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

# Guard discovers apps and connectors under the user's home. Point HOME at an
# empty directory inside the run root before Guard is imported, so a local run
# never reads the developer's real configuration and CI sees the same machine.
if "DASHBOARD_E2E_ROOT" in os.environ:
    _isolated_home = Path(os.environ["DASHBOARD_E2E_ROOT"]).resolve() / "home"
    shutil.rmtree(_isolated_home, ignore_errors=True)
    _isolated_home.mkdir(parents=True, mode=0o700)
    os.environ["HOME"] = str(_isolated_home)
    for _variable in ("XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME", "CODEX_HOME"):
        os.environ.pop(_variable, None)

from dashboard_integration_seeds import SeedContext, run_seeds
from installed_extension_authority_fixture import describe_authority, read_authority

from codex_plugin_scanner.guard.approval_gate import public_config, update_settings
from codex_plugin_scanner.guard.daemon import server as daemon_server
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.local_dashboard_session import build_local_dashboard_session_token
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_authority import AuthorityHealth
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_base import EncryptedFileSecretStore


def _write_private(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_CLOEXEC | os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    os.fchmod(descriptor, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(text)


def _fresh_directory(path: Path) -> Path:
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True, mode=0o700)
    path.chmod(0o700)
    return path.resolve()


def _use_file_secret_store(store: GuardStore, guard_home: Path) -> None:
    # Hosted Linux runners have no desktop keyring. Keep the authority key in
    # Guard's encrypted file store so this isolated home works the same on CI
    # and on a developer machine.
    store._extension_control_authority_secret_store = EncryptedFileSecretStore(guard_home)  # pyright: ignore[reportPrivateUsage]


def _prepare_authority(store: GuardStore, guard_home: Path, password: str) -> None:
    if not public_config(guard_home).configured:
        update_settings(
            guard_home,
            {"enabled": True, "new_password": password, "confirm_password": password, "cooldown_seconds": 0},
        )
    view = read_authority(store)
    if view.health is AuthorityHealth.UNENROLLED:
        # Enrollment needs a person at an interactive terminal. This disposable
        # CI home bootstraps an empty authority directly instead; every policy
        # change the browser makes still goes through the daemon's preview,
        # approval proof and apply routes.
        view = store._bootstrap_extension_control_authority(  # pyright: ignore[reportPrivateUsage]
            BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
            key=None,
        )
    if view.health is not AuthorityHealth.PROTECTED:
        raise RuntimeError(f"integration authority is not protected: {view.health.value} ({describe_authority(store)})")


def _error_code(error: urllib.error.HTTPError) -> str:
    try:
        body = json.loads(error.read(4096) or b"{}")
    except (OSError, ValueError):
        return "unreadable"
    return str(body.get("error", "unknown")) if isinstance(body, dict) else "unknown"


def _daemon_log_tail(guard_home: Path, lines: int = 40) -> str:
    # The daemon writes background catalog-preparation faults to its own log,
    # not stdout. CI has no other way to see them once the run root is gone.
    logs = sorted(guard_home.glob("**/daemon.log"))
    if not logs:
        return "(no daemon.log)"
    return "\n".join(logs[0].read_text(encoding="utf-8", errors="replace").splitlines()[-lines:])


def _wait_for_catalog(origin: str, auth_token: str, guard_home: Path) -> None:
    # A fresh home prepares its extension catalog in the background and answers
    # 503 until that finishes. Hand the browser a warm daemon so specs never
    # race first-run preparation.
    request = urllib.request.Request(
        f"{origin}/v2/extension-controls/catalog/index",
        headers={"X-Guard-Token": auth_token},
    )
    deadline = time.monotonic() + 60
    last_failure = "no response"
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                if 200 <= response.status < 300:
                    return
                last_failure = f"HTTP {response.status}"
        except urllib.error.HTTPError as error:
            last_failure = f"HTTP {error.code} {_error_code(error)}"
            if error.code != 503:
                break
        except (urllib.error.URLError, OSError) as error:
            # The listener can still be coming up, or a slow preparation can
            # time a request out. Both are retried until the deadline.
            last_failure = f"{type(error).__name__}: {error}"
        time.sleep(0.25)
    print(_daemon_log_tail(guard_home), file=sys.stderr)
    raise RuntimeError(f"extension catalog never became ready: {last_failure}")


def main() -> None:
    root = Path(os.environ["DASHBOARD_E2E_ROOT"]).resolve()
    port = int(os.environ.get("DASHBOARD_E2E_PORT", "4791"))
    state_file = root / "state.json"
    state_file.unlink(missing_ok=True)
    guard_home = _fresh_directory(root / "guard-home")
    workspace = _fresh_directory(root / "workspace")

    # Local runs may borrow a released wheel for its native runtime while
    # serving this checkout's committed dashboard build. CI installs a wheel
    # built from this checkout, whose static directory is already the one
    # under test.
    static_override = os.environ.get("DASHBOARD_E2E_STATIC_DIR")
    if static_override:
        daemon_server._STATIC_DIR = Path(static_override).resolve(strict=True)  # pyright: ignore[reportPrivateUsage]

    password = secrets.token_urlsafe(36)
    store = GuardStore(guard_home, prime_policy_integrity=False)
    _use_file_secret_store(store, guard_home)
    # Seeds are the operator's own setup, written before the approval gate is
    # switched on, the way a user's history predates turning the gate on.
    # Everything the browser changes afterwards goes through the gate.
    seeded = run_seeds(SeedContext(store=store, guard_home=guard_home, workspace=workspace))
    _prepare_authority(store, guard_home, password)

    daemon = GuardDaemonServer(
        store,
        host="127.0.0.1",
        port=port,
        bundle_refresh_interval_seconds=None,
        aibom_refresh_interval_seconds=None,
        home_dir=guard_home,
        workspace_dir=workspace,
    )
    daemon.start()
    try:
        auth_token = daemon._server.auth_token  # pyright: ignore[reportPrivateUsage]
        origin = f"http://127.0.0.1:{port}"
        _wait_for_catalog(origin, auth_token, guard_home)
        state = {
            "origin": origin,
            "session": build_local_dashboard_session_token(auth_token=auth_token, surface="dashboard"),
            "daemonToken": auth_token,
            "approvalPassword": password,
            "guardHome": str(guard_home),
            "workspace": str(workspace),
            "seeded": seeded,
        }
        _write_private(state_file, json.dumps(state, sort_keys=True))
        stop_requested = threading.Event()
        signal.signal(signal.SIGTERM, lambda _signum, _frame: stop_requested.set())
        signal.signal(signal.SIGINT, lambda _signum, _frame: stop_requested.set())
        while not stop_requested.wait(3600):
            pass
    finally:
        state_file.unlink(missing_ok=True)
        daemon.stop()


if __name__ == "__main__":
    main()
