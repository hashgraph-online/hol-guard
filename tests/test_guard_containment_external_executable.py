from __future__ import annotations

import hashlib
import shutil
import stat
import sys
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard import contained_workspace_write_execution as write_module
from codex_plugin_scanner.guard.contained_workspace_write_execution import (
    try_execute_contained_workspace_write,
)
from codex_plugin_scanner.guard.runtime import containment_executor as executor_module
from codex_plugin_scanner.guard.runtime.containment_contract import (
    ContainmentBackend,
    ContainmentPolicy,
    ContainmentRequest,
)
from codex_plugin_scanner.guard.runtime.containment_health import (
    CONTAINMENT_POLICY_CONTRACT_DIGEST,
    ContainmentHealthEvidence,
)
from codex_plugin_scanner.guard.runtime.effect_decision import FinalDisposition


def _write_executable(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    _ = path.write_bytes(content)
    path.chmod(0o700)


def _request(
    workspace: Path,
    executable: Path,
    *,
    operation_id: str = "format-write",
    arguments: tuple[str, ...] = ("format", "module.py"),
) -> ContainmentRequest:
    source = workspace / "module.py"
    _ = source.write_text("value=1\n", encoding="utf-8")
    return ContainmentRequest(
        argv=(str(executable), *arguments),
        cwd=str(workspace),
        environment=(),
        policy=ContainmentPolicy(str(workspace), (str(workspace),)),
        inputs=(),
        launch_digest=hashlib.sha256(b"launch").hexdigest(),
        executable_digest=executor_module.file_sha256(str(executable)),
        operation_id=operation_id,
        declared_outputs=("module.py",),
    )


def _pin_executable(request: ContainmentRequest, temp_root: Path) -> str:
    pin = cast(
        Callable[..., str],
        vars(executor_module)["_pin_executable"],
    )
    return pin(request, temp_root, backend=ContainmentBackend.MACOS_SANDBOX)


def test_user_owned_external_executable_is_copied_and_digest_pinned(tmp_path: Path) -> None:
    workspace = (tmp_path / "workspace").resolve()
    workspace.mkdir()
    executable = (tmp_path / "user-bin" / "ruff").resolve()
    _write_executable(executable, b"external-ruff-binary\n")
    request = _request(workspace, executable)
    containment_root = (tmp_path / "containment").resolve()
    containment_root.mkdir()

    pinned = Path(_pin_executable(request, containment_root))

    assert pinned == containment_root / "guard-exec"
    assert pinned.read_bytes() == executable.read_bytes()
    assert executor_module.file_sha256(str(pinned)) == request.executable_digest
    assert stat.S_IMODE(pinned.stat().st_mode) == 0o500


@pytest.mark.parametrize(
    ("executable_name", "operation_id", "arguments"),
    (
        ("formatter", "format-write", ("format", "module.py")),
        ("ruff", "copy-generated", ("format", "module.py")),
        ("ruff", "format-write", ("--version",)),
    ),
)
def test_other_user_owned_executable_requests_remain_rejected(
    tmp_path: Path,
    executable_name: str,
    operation_id: str,
    arguments: tuple[str, ...],
) -> None:
    workspace = (tmp_path / "workspace").resolve()
    workspace.mkdir()
    executable = (tmp_path / "user-bin" / executable_name).resolve()
    _write_executable(executable, b"external-formatter-binary\n")
    request = _request(workspace, executable, operation_id=operation_id, arguments=arguments)
    containment_root = (tmp_path / "containment").resolve()
    containment_root.mkdir()

    with pytest.raises(ValueError, match="immutable system executable"):
        _ = _pin_executable(request, containment_root)


def test_external_executable_replacement_during_pin_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = (tmp_path / "workspace").resolve()
    workspace.mkdir()
    executable = (tmp_path / "user-bin" / "ruff").resolve()
    _write_executable(executable, b"reviewed-ruff-binary\n")
    request = _request(workspace, executable)
    containment_root = (tmp_path / "containment").resolve()
    containment_root.mkdir()
    real_file_sha256 = executor_module.file_sha256
    replaced = False

    def replace_after_identity_check(path: str) -> str:
        nonlocal replaced
        digest = real_file_sha256(path)
        if path == str(executable) and not replaced:
            replaced = True
            _ = executable.write_bytes(b"replacement-binary\n")
        return digest

    monkeypatch.setattr(executor_module, "file_sha256", replace_after_identity_check)

    with pytest.raises(ValueError, match="pinned executable copy failed identity verification"):
        _ = _pin_executable(request, containment_root)


@pytest.mark.skipif(sys.platform != "darwin", reason="requires the macOS sandbox backend")
def test_macos_external_ruff_formats_inside_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    resolved_ruff = shutil.which("ruff")
    if resolved_ruff is None:
        pytest.skip("requires an installed Ruff executable")
    ruff = Path(resolved_ruff).resolve(strict=True)
    if str(ruff).startswith(("/System/", "/usr/", "/bin/", "/sbin/")):
        pytest.skip("requires a Ruff executable outside immutable system prefixes")

    workspace = (tmp_path / "workspace").resolve()
    workspace.mkdir()
    source = workspace / "module.py"
    _ = source.write_text("value=1\n", encoding="utf-8")
    guard_home = (tmp_path / "guard-home").resolve()
    guard_home.mkdir()
    fingerprint = hashlib.sha256(b"runtime").hexdigest()

    def load_health(_home: Path) -> tuple[ContainmentHealthEvidence, str]:
        return (
            ContainmentHealthEvidence(
                backend=ContainmentBackend.MACOS_SANDBOX,
                backend_digest=executor_module.file_sha256("/usr/bin/sandbox-exec"),
                policy_contract_digest=CONTAINMENT_POLICY_CONTRACT_DIGEST,
                daemon_fingerprint=fingerprint,
                runtime_fingerprint=fingerprint,
                probe_at=datetime.now(timezone.utc).isoformat(),
                probe_enforced=True,
            ),
            fingerprint,
        )

    monkeypatch.setattr(write_module, "_load_current_containment_health", load_health)
    result = try_execute_contained_workspace_write(
        "format-write",
        workspace=workspace,
        guard_home=guard_home,
        source="module.py",
        target="module.py",
        environment={"PATH": str(ruff.parent)},
    )

    assert result is not None
    assert result.decision.disposition is FinalDisposition.SILENT_CONTAINED
    assert source.read_text(encoding="utf-8") == "value = 1\n"
