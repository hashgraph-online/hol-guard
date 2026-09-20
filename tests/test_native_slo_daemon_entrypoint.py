"""The private daemon requires an explicit diagnostic command-line opt-in."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from scripts.native_slo_daemon_entrypoint import main


@pytest.mark.parametrize("diagnostic", [False, True])
@pytest.mark.parametrize("workspace_count", [None, 10])
def test_private_daemon_entrypoint_preserves_arguments_and_explicit_diagnostic_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, diagnostic: bool, workspace_count: int | None
) -> None:
    runtime = tmp_path / "runtime"
    runtime.write_bytes(b"controlled path")
    arguments = ["fixture", "--serve", str(runtime), "normal", "none"]
    if workspace_count is not None:
        arguments.append(str(workspace_count))
    if diagnostic:
        arguments.append("--native-phases")
    monkeypatch.setattr(sys, "argv", arguments)
    calls: list[tuple[object, ...]] = []

    def serve(runtime: Path, setup: str, policy: str, workspace_count: int | None, *, native_phases: bool) -> int:
        calls.append((runtime, setup, policy, workspace_count, native_phases))
        return 7

    emitted: list[object] = []
    assert main(serve, emitted.append) == 7
    assert calls == [(runtime, "normal", "none", workspace_count, diagnostic)]
    assert not emitted
    assert sys.argv == arguments
