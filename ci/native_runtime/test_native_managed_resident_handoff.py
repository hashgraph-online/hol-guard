from __future__ import annotations

import hashlib
import json
import subprocess
import time
from pathlib import Path

from native_hook_client_support import (
    _hold_native_client_lease,
    _policy_snapshot_push_bytes_v3,
    _push_snapshot,
    _request,
    _state_files,
)
from native_managed_test_support import managed_runtime as _managed_runtime_fixture  # noqa: F401
from native_managed_test_support import request
from native_process_test_support import process_is_alive


def _residents(state_dir: Path) -> dict[str, int]:
    residents: dict[str, int] = {}
    for state_file in _state_files(state_dir):
        state = json.loads(state_file.read_text(encoding="utf-8"))
        residents[state["runtime_sha256"]] = state["process_id"]
    return residents


def _older_runtime(runtime: Path, directory: Path) -> Path:
    # Same code, different bytes: the copy has its own runtime digest, like
    # the previous version left running by a side-by-side update.
    directory.mkdir(mode=0o700)
    older = directory / runtime.name
    older.write_bytes(runtime.read_bytes() + b"\0hol-guard-older-runtime\0")
    older.chmod(0o700)
    return older


def test_newer_client_leases_do_not_keep_an_orphaned_older_resident(managed_runtime: tuple[Path, Path]) -> None:
    runtime, guard_home = managed_runtime
    state_dir = guard_home / "native-runtime"
    older = _older_runtime(runtime, guard_home.parent / "older-runtime")
    older_digest = hashlib.sha256(older.read_bytes()).hexdigest()
    newer_digest = hashlib.sha256(runtime.read_bytes()).hexdigest()
    try:
        with _hold_native_client_lease(runtime, state_dir):
            # The older client owns its resident and exits after the push,
            # leaving only a newer client's lease in the Guard home.
            _push_snapshot(older, state_dir, _request(older, guard_home))
            older_process = _residents(state_dir)[older_digest]
            deadline = time.monotonic() + 5
            while process_is_alive(older_process) and time.monotonic() < deadline:
                time.sleep(0.05)
            assert not process_is_alive(older_process), "newer client leases kept the orphaned older resident alive"
            # The home generation floor survives the handoff, so the newer
            # publisher allocates the next generation, as production does.
            payload = _request(runtime, guard_home, generation=2)
            _push_snapshot(runtime, state_dir, payload)
            request(runtime, guard_home, payload)
            assert set(_residents(state_dir)) == {newer_digest}
    finally:
        subprocess.run(
            (str(older), "resident-stop", "--state-dir", str(state_dir)),
            check=False,
            capture_output=True,
            timeout=10,
        )


def test_an_older_resident_with_its_own_client_is_not_handed_over(managed_runtime: tuple[Path, Path]) -> None:
    runtime, guard_home = managed_runtime
    state_dir = guard_home / "native-runtime"
    older = _older_runtime(runtime, guard_home.parent / "older-runtime")
    older_digest = hashlib.sha256(older.read_bytes()).hexdigest()
    try:
        with _hold_native_client_lease(older, state_dir):
            _push_snapshot(older, state_dir, _request(older, guard_home))
            older_process = _residents(state_dir)[older_digest]
            # The older runtime still serves a client, so a newer client must
            # not stop it and fails closed on the foreign snapshot instead.
            snapshot = json.loads(_request(runtime, guard_home, generation=2))["policy_snapshot"]
            result = subprocess.run(
                (str(runtime), "resident-client", "--stdin", str(state_dir)),
                input=_policy_snapshot_push_bytes_v3(snapshot),
                check=False,
                capture_output=True,
                timeout=8,
            )
            assert json.loads(result.stdout or b"{}").get("status") != "accepted"
            assert process_is_alive(older_process)
    finally:
        subprocess.run(
            (str(older), "resident-stop", "--state-dir", str(state_dir)),
            check=False,
            capture_output=True,
            timeout=10,
        )
