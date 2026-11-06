from __future__ import annotations

import hashlib
import json
import subprocess
import sys
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


def _wait_for_exit(process_id: int) -> None:
    deadline = time.monotonic() + 5
    while process_is_alive(process_id) and time.monotonic() < deadline:
        time.sleep(0.05)


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


def test_a_newer_client_shuts_down_a_pinned_older_resident(managed_runtime: tuple[Path, Path]) -> None:
    runtime, guard_home = managed_runtime
    state_dir = guard_home / "native-runtime"
    older = _older_runtime(runtime, guard_home.parent / "older-runtime")
    older_digest = hashlib.sha256(older.read_bytes()).hexdigest()
    newer_digest = hashlib.sha256(runtime.read_bytes()).hexdigest()
    # The older client provisions the home, and its resident exits with it.
    _push_snapshot(older, state_dir, _request(older, guard_home))
    _wait_for_exit(_residents(state_dir)[older_digest])
    # Older supervisors count every lease in the home, so newer clients pin
    # their resident. A live owner pins it the same way without a lease of
    # its own runtime, so only the newer client's handoff can stop it.
    owner = subprocess.Popen((sys.executable, "-c", "import time; time.sleep(60)"))
    supervisor = subprocess.Popen(
        (
            str(older),
            "supervise-managed",
            "--state-dir",
            str(state_dir),
            "--generation",
            "2",
            "--owner-process-id",
            str(owner.pid),
            "--runtime-sha256",
            older_digest,
        ),
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        assert supervisor.stdin is not None
        supervisor.stdin.write(b"51" * 32 + b"\n")
        supervisor.stdin.close()
        deadline = time.monotonic() + 5
        while older_digest not in _residents(state_dir) and time.monotonic() < deadline:
            time.sleep(0.05)
        older_process = _residents(state_dir)[older_digest]
        payload = _request(runtime, guard_home, generation=2)
        _push_snapshot(runtime, state_dir, payload)
        request(runtime, guard_home, payload)
        assert not process_is_alive(older_process), "the newer client did not retire the older resident"
        assert set(_residents(state_dir)) == {newer_digest}
        assert supervisor.wait(timeout=5) is not None
    finally:
        owner.kill()
        owner.wait(timeout=5)
        subprocess.run(
            (str(older), "resident-stop", "--state-dir", str(state_dir)),
            check=False,
            capture_output=True,
            timeout=10,
        )
        if supervisor.poll() is None:
            supervisor.kill()
            supervisor.wait(timeout=5)


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
