from __future__ import annotations

import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from native_hook_client_support import _push_snapshot, _request, _state_files
from native_managed_test_support import managed_runtime as _managed_runtime_fixture  # noqa: F401
from native_managed_test_support import request

_CLIENT = """
import os, sys
from pathlib import Path
from codex_plugin_scanner.guard.native_resident_client import native_resident_client_request
runtime, home = map(Path, sys.argv[1:])
result = native_resident_client_request(
    executable=runtime, guard_home=home, environment=os.environ,
    payload=sys.stdin.buffer.read(), timeout_seconds=5.0, raw_hook_envelope=True,
)
if result is None:
    raise SystemExit(2)
sys.stdout.buffer.write(result)
"""


def test_independent_production_clients_share_one_native_generation(managed_runtime: tuple[Path, Path]) -> None:
    runtime, guard_home = managed_runtime
    state_dir = guard_home / "native-runtime"
    payload = _request(runtime, guard_home)
    _push_snapshot(runtime, state_dir, payload)
    expected = request(runtime, guard_home, payload)
    states = _state_files(state_dir)
    assert len(states) == 1

    def invoke() -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            (sys.executable, "-c", _CLIENT, str(runtime), str(guard_home)),
            input=payload,
            capture_output=True,
            check=False,
            timeout=15,
            env={**os.environ, "HOL_GUARD_NATIVE": "force"},
        )

    with ThreadPoolExecutor(max_workers=4) as executor:
        results = [future.result(timeout=20) for future in [executor.submit(invoke) for _ in range(4)]]
    for result in results:
        assert result.returncode == 0, "isolated production native client failed"
        assert json.loads(result.stdout) == expected
    # Child interpreter exits must not stop the generation used by the parent.
    assert _state_files(state_dir) == states
    assert request(runtime, guard_home, payload) == expected
