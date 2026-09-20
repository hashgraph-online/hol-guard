from __future__ import annotations

import io
import os
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime import containment_executor as executor
from codex_plugin_scanner.guard.runtime.containment_backend_status import bwrap_execution_completed
from codex_plugin_scanner.guard.runtime.containment_contract import ContainmentBackend, ContainmentFailure
from tests.test_guard_containment_executor import _request


@pytest.mark.parametrize("code", (0, 1, 17, 255))
def test_private_backend_status_accepts_executed_child_exit(code: int) -> None:
    status = io.BytesIO(f'{{"child-pid":42,"mnt-namespace":100}}\n{{"exit-code":{code}}}\n'.encode())
    assert bwrap_execution_completed(status, code)


@pytest.mark.parametrize(
    "payload,code",
    (
        (b"", 0),
        (b'{"child-pid":42}\n', 1),
        (b'{"exit-code":0}\n', 0),
        (b'{"exit-code":0}\n{"child-pid":42}\n', 0),
        (b'{"child-pid":42}\n{"exit-code":1}\n', 0),
        (b'{"child-pid":true}\n{"exit-code":0}\n', 0),
        (b'{"child-pid":-1}\n{"exit-code":0}\n', 0),
        (b'{"child-pid":42}\n{"exit-code":false}\n', 0),
        (b'{"child-pid":42}\n{"exit-code":0}\n{"exit-code":0}\n', 0),
        (b'{"child-pid":42}\n{"child-pid":43}\n{"exit-code":0}\n', 0),
        (b'{"child-pid":42}\n{"exit-code":0}\n[]\n', 0),
        (b'{"child-pid":42}\n{"exit-code":0}\ninvalid', 0),
        (b'{"child-pid":42}\n{"exit-code":0}\n' + b" " * 8192, 0),
        (b'{"child-pid":42}\n{"exit-code":0}\n', None),
        (b'{"child-pid":42}\n{"exit-code":0}\n', -9),
    ),
)
def test_incomplete_or_invalid_backend_status_fails_closed(payload: bytes, code: int | None) -> None:
    assert not bwrap_execution_completed(io.BytesIO(payload), code)


@pytest.mark.skipif(os.name != "posix", reason="POSIX backend descriptor contract")
def test_application_stdout_cannot_attest_backend_startup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    backend = tmp_path / "fake-backend"
    backend.write_bytes(b"#!/bin/sh\nexit 0\n")
    backend.chmod(0o755)
    identity = executor._BackendIdentity(
        ContainmentBackend.LINUX_BWRAP, str(backend), executor.file_sha256(str(backend))
    )
    monkeypatch.setattr(executor, "_select_backend", lambda _platform: identity)
    # Simulate a failed backend printing convincing JSON only on stdout. The
    # private descriptor is intentionally untouched; no command is launched.
    monkeypatch.setattr(executor, "_linux_argv", lambda *_args: [str(backend)])
    original_popen = executor.subprocess.Popen

    def launch_fake_backend(argv, **kwargs):
        assert argv[1] == "--json-status-fd"
        assert kwargs["pass_fds"] == (int(argv[2]),)
        return original_popen(
            [sys.executable, "-c", "print('{\"child-pid\":42}'); print('{\"exit-code\":0}')"], **kwargs
        )

    monkeypatch.setattr(executor.subprocess, "Popen", launch_fake_backend)
    result = executor.execute_contained(_request(tmp_path.resolve(), (str(backend),)))
    assert result.exit_code is None
    assert not result.enforced
    assert result.attestation.failure is ContainmentFailure.APPLY_FAILED
    assert result.outputs == ()
    assert "exit-code" in result.stdout
