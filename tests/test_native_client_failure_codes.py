from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.codex_hook_launch_runtime import BoundedHookProcessResult
from codex_plugin_scanner.guard.native_resident_client import (
    native_resident_client_failure_code,
    native_resident_client_request,
)


def test_native_client_records_only_allowlisted_failure_code(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.native_resident_client.run_isolated_hook_process",
        lambda *_args, **_kwargs: BoundedHookProcessResult(
            2,
            "",
            False,
            True,
            containment_failed=True,
            stderr="ignored\nnative_resident_start_timeout\nignored",
        ),
    )
    result = native_resident_client_request(
        executable=tmp_path / "runtime",
        guard_home=tmp_path / "guard-home",
        environment={},
        payload=b"{}",
        timeout_seconds=0.5,
    )
    assert result is None
    assert native_resident_client_failure_code() == "native_resident_start_timeout"


@pytest.mark.parametrize(
    ("process_result", "expected_code"),
    (
        (
            BoundedHookProcessResult(7, "", True, True, containment_failed=True),
            "native_client_containment_failed",
        ),
        (BoundedHookProcessResult(7, "", True, True), "native_client_timed_out"),
        (BoundedHookProcessResult(None, "", True, False), "native_client_output_limit_exceeded"),
        (BoundedHookProcessResult(None, "", False, False), "native_client_status_missing"),
        (BoundedHookProcessResult(7, "", False, False), "native_client_exit_nonzero"),
        (BoundedHookProcessResult(0, "", False, False), "native_client_output_missing"),
    ),
)
def test_native_client_classifies_bounded_failure_states(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    process_result: BoundedHookProcessResult,
    expected_code: str,
) -> None:
    def fake_run(*_args: object, **_kwargs: object) -> BoundedHookProcessResult:
        return process_result

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.native_resident_client.run_isolated_hook_process",
        fake_run,
    )
    assert (
        native_resident_client_request(
            executable=tmp_path / "runtime",
            guard_home=tmp_path / "guard-home",
            environment={},
            payload=b"{}",
            timeout_seconds=0.5,
        )
        is None
    )
    assert native_resident_client_failure_code() == expected_code
