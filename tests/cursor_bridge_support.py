"""Run a managed Cursor hook as Cursor does: behind the native bridge, with a live daemon."""

from __future__ import annotations

import json
import subprocess
import sys
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path

from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.store import GuardStore


@contextmanager
def keyed_guard_home(guard_home: Path) -> Iterator[Path]:
    """Seed the policy verifier key a resident needs before it will serve.

    The managed resident refuses to answer a hook until the policy verifier
    key exists in the Guard home it serves, and only the runtime can write
    it. A test that installs into a fresh home therefore reaches a resident
    that is live but will not answer, and the bridge fails the hook closed
    rather than reporting the decision the harness really makes. Provision
    the key the way the session-scoped native fixtures do, and close the
    residents this home spawned on the way out so none outlives the test.
    """

    from codex_plugin_scanner.guard.native_policy_snapshot import provision_native_policy_verifier_key
    from codex_plugin_scanner.guard.native_resident_client import close_native_residents

    from .mcp_policy_native_fixture import _FIXTURE_KEYS

    # Sign first, verify second: the store refuses to mint a policy signing
    # key once verifier material exists, so a home that is keyed before its
    # store is built can never publish a snapshot the resident accepts.
    store = GuardStore(guard_home)
    key, _key_id = store._policy_integrity_secret_material(create=True)
    assert key is not None
    (guard_home / "native-runtime").mkdir(mode=0o700, parents=True, exist_ok=True)
    provision_native_policy_verifier_key(guard_home, key)
    _FIXTURE_KEYS[guard_home] = key
    try:
        yield guard_home
    finally:
        _FIXTURE_KEYS.pop(guard_home, None)
        close_native_residents(guard_home)


@contextmanager
def live_cursor_daemon(guard_home: Path) -> Iterator[None]:
    """Serve the loopback daemon the bridge asks when no resident answers."""

    daemon = GuardDaemonServer(GuardStore(guard_home), host="127.0.0.1", port=0)
    daemon.start()
    try:
        yield
    finally:
        daemon.stop()


def run_cursor_hook(
    runtime: Path,
    hook_script: Path,
    payload: Mapping[str, object],
    *,
    env: Mapping[str, str],
    cwd: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run ``hook_script`` behind the native bridge for the payload's hook event."""

    event = str(payload.get("hook_event_name") or "")
    return subprocess.run(
        [str(runtime), "cursor-hook-bridge", sys.executable, "-I", str(hook_script), "--cursor-hook-event", event],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        cwd=cwd,
        env=dict(env),
        timeout=60,
        check=False,
    )
