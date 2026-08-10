#!/usr/bin/env python3
"""Serve the installed HOL Guard dashboard for Extension Control Center browser CI.

This fixture intentionally imports only from the installed wheel's site-packages.
Authentication material is exchanged through mode-0600 handoff files rather than
stdout. The same isolated Guard home is reused across the workflow's deliberate
daemon restart so browser CI proves authority persistence from the installed wheel.
"""

from __future__ import annotations

import os
import secrets
import signal
import stat
import sys
import threading
from pathlib import Path

from codex_plugin_scanner import __version__
from codex_plugin_scanner.guard.approval_gate import public_config, update_settings
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.local_dashboard_session import build_local_dashboard_session_token
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_authority import AuthorityHealth
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_base import EncryptedFileSecretStore


def _installed_origin() -> Path:
    package_file = Path(sys.modules["codex_plugin_scanner"].__file__ or "").resolve(strict=True)
    if "site-packages" not in package_file.parts:
        raise RuntimeError("Extension Control Center browser CI must import Guard from installed site-packages")
    return package_file


def _write_secret(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_CLOEXEC | os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    os.fchmod(descriptor, 0o600)
    with os.fdopen(descriptor, "w", encoding="ascii") as stream:
        stream.write(value)
        stream.write("\n")


def _read_existing_secret(path: Path) -> str | None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise RuntimeError("unsafe installed-CI secret handoff path")
    if info.st_mode & 0o077:
        raise RuntimeError("installed-CI secret handoff is not private")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "r", encoding="ascii") as stream:
        value = stream.read(4096).strip()
    if not value:
        raise RuntimeError("installed-CI secret handoff is empty")
    return value


def _prepare_test_authority(store: GuardStore, guard_home: Path, password_file: Path) -> None:
    # GitHub-hosted Linux runners do not expose a desktop keyring. Bind this
    # isolated fixture to Guard's encrypted file secret store so the authority
    # key and anchor survive the deliberate daemon process restart. Production
    # Linux behavior is unchanged; this assignment exists only in this CI server.
    store._extension_control_authority_secret_store = EncryptedFileSecretStore(guard_home)  # pyright: ignore[reportPrivateUsage]

    password = _read_existing_secret(password_file)
    if password is None:
        password = secrets.token_urlsafe(36)
        _write_secret(password_file, password)
    if not public_config(guard_home).configured:
        update_settings(
            guard_home,
            {
                "enabled": True,
                "new_password": password,
                "confirm_password": password,
                "cooldown_seconds": 0,
            },
        )
    catalog_digest = BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest
    view = store.read_extension_control_authority(catalog_digest=catalog_digest)
    if view.health is AuthorityHealth.UNENROLLED:
        # This is an isolated CI fixture, not an operator enrollment path. A real
        # interactive terminal attestation is intentionally unavailable here, so
        # bootstrap an empty authenticated authority directly before the daemon is
        # started. Every policy mutation exercised by Chromium still goes through
        # the production daemon preview -> local approval proof -> apply flow.
        view = store._bootstrap_extension_control_authority(  # pyright: ignore[reportPrivateUsage]
            catalog_digest,
            key=None,
        )
    if view.health is not AuthorityHealth.PROTECTED:
        raise RuntimeError(f"installed-CI extension authority is not protected: {view.health.value}")


def main() -> None:
    expected_version = os.environ["HOL_GUARD_INSTALLED_EXPECTED_VERSION"]
    if __version__ != expected_version:
        raise RuntimeError(f"installed version mismatch: expected {expected_version}, got {__version__}")
    _ = _installed_origin()

    guard_home = Path(os.environ["HOL_GUARD_INSTALLED_HOME"]).resolve()
    workspace = Path(os.environ["HOL_GUARD_INSTALLED_WORKSPACE"]).resolve()
    session_file = Path(os.environ["HOL_GUARD_INSTALLED_SESSION_FILE"]).resolve()
    password_file = Path(os.environ["HOL_GUARD_INSTALLED_APPROVAL_FILE"]).resolve()
    ready_file = Path(os.environ["HOL_GUARD_INSTALLED_READY_FILE"]).resolve()
    port = int(os.environ.get("HOL_GUARD_INSTALLED_PORT", "4781"))

    guard_home.mkdir(parents=True, exist_ok=True)
    workspace.mkdir(parents=True, exist_ok=True)
    store = GuardStore(guard_home, prime_policy_integrity=False)
    _prepare_test_authority(store, guard_home, password_file)
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
        session = build_local_dashboard_session_token(auth_token=auth_token, surface="dashboard")
        _write_secret(session_file, session)
        ready_file.parent.mkdir(parents=True, exist_ok=True)
        ready_file.write_text(f"http://127.0.0.1:{port}\n", encoding="ascii")
        ready_file.chmod(0o600)

        stop_requested = threading.Event()
        signal.signal(signal.SIGTERM, lambda _signum, _frame: stop_requested.set())
        signal.signal(signal.SIGINT, lambda _signum, _frame: stop_requested.set())
        while not stop_requested.wait(3600):
            pass
    finally:
        session_file.unlink(missing_ok=True)
        ready_file.unlink(missing_ok=True)
        daemon.stop()


if __name__ == "__main__":
    main()
