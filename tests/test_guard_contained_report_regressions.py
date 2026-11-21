"""Regressions for report-arm shell status and option-like echo labels."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime import contained_test_hook as sink
from codex_plugin_scanner.guard.runtime.contained_wrapper import peel_contained_wrapper


@pytest.fixture(autouse=True)
def _native_peel(native_contained_wrapper_runtime: Path) -> None:
    """Use Guard's native parser for every wrapper in these tests."""


def receipt() -> dict[str, object]:
    return {
        "decision": "deny",
        "policy_action": "sandbox-required",
        "reason_code": "native_pytest_readonly_containment_required",
        "required_execution_profile": "pytest-readonly-v2",
    }


@pytest.mark.parametrize(
    ("command", "core_status", "shell_status", "reported"),
    [
        ("pytest -q 2>&1 | tail -5 || echo FAIL", 1, 0, ""),
        ("pytest -q 2>&1 | tail -5 && echo PASS", 1, 0, "PASS\n"),
        ("pytest -q 2>&1 | tail -5", 1, 0, ""),
        ("pytest -q || echo FAIL", 1, 0, "FAIL\n"),
        ("pytest -q && echo PASS", 1, 1, ""),
        ("pytest -q; echo done", 1, 0, "done\n"),
    ],
)
def test_skipped_report_returns_shell_pipeline_status(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    command: str,
    core_status: int,
    shell_status: int,
    reported: str,
) -> None:
    monkeypatch.setattr(sink, "prepare_restricted_pytest", lambda *args, **kwargs: None)
    monkeypatch.setattr(sink, "run_restricted_pytest", lambda *args, **kwargs: core_status)
    outcome = sink.run_authorized_contained_test(
        {"tool_name": "bash", "tool_input": {"command": command}},
        workspace=tmp_path,
        timeout_seconds=20,
        authorize=lambda _: receipt(),
    )
    assert outcome == shell_status, command
    assert capsys.readouterr().out == reported


@pytest.mark.parametrize(
    "command",
    [
        "pytest -q && echo -n",
        "pytest -q; echo -e",
        "pytest -q || echo -E",
    ],
)
def test_echo_options_are_never_replayed_as_report_labels(tmp_path: Path, command: str) -> None:
    try:
        peeled = peel_contained_wrapper(command, workspace=tmp_path)
    except (OSError, RuntimeError, ValueError):
        return
    assert peeled is None, command
