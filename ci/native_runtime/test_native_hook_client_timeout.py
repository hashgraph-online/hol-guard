from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path

from ci.native_runtime.resident_test_support import process_is_alive
from ci.native_runtime.test_native_hook_client import (
    _request,
    _state_files,
)

pytest_plugins = ("ci.native_runtime.test_native_hook_client",)


def test_native_hook_client_start_timeout_contains_new_managed_processes(
    native_runtime: tuple[Path, Path],
    tmp_path: Path,
) -> None:
    runtime, state_dir = native_runtime
    request = _request(runtime, tmp_path, deadline_budget_ms=20)
    process = subprocess.Popen(
        (str(runtime), "hook-client", "--stdin", str(state_dir)),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert process.stdin is not None
    process.stdin.write(request)
    process.stdin.close()
    observed_process_ids: set[int] = set()
    deadline = time.monotonic() + 3
    while process.poll() is None and time.monotonic() < deadline:
        for path in _state_files(state_dir):
            state = json.loads(path.read_text(encoding="utf-8"))
            for key in ("process_id", "owner_process_id"):
                process_id = state.get(key)
                if isinstance(process_id, int) and process_id > 0:
                    observed_process_ids.add(process_id)
        time.sleep(0.01)
    if process.poll() is None:
        process.kill()
    stdout = process.stdout.read() if process.stdout is not None else b""
    stderr = process.stderr.read() if process.stderr is not None else b""
    process.wait(timeout=1)
    result = subprocess.CompletedProcess(
        process.args,
        process.returncode,
        stdout,
        stderr,
    )
    assert result.returncode is not None
    assert result.returncode != 0
    assert result.stderr in {
        b"native_client_deadline_exceeded\n",
        b"native_resident_start_timeout\n",
    }
    assert not any(process_is_alive(process_id) for process_id in observed_process_ids)
    assert not _state_files(state_dir)
