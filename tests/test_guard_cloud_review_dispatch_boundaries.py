from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli import commands_dispatch_cloud_review as dispatch
from codex_plugin_scanner.guard.runtime.exact_cloud_review import ExactCloudReviewError
from codex_plugin_scanner.guard.store import GuardStore


def _args(command: str) -> argparse.Namespace:
    return argparse.Namespace(cloud_review_command=command, expires_in_days=30, json=True)


def test_refresh_worker_reports_restart_when_daemon_request_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_load(_guard_home: Path) -> object:
        raise RuntimeError("daemon unavailable")

    monkeypatch.setattr(dispatch, "load_guard_surface_daemon_client", fail_load)
    assert dispatch._refresh_cloud_review_worker(tmp_path) == {
        "status": "restart_required",
        "restart_command": "hol-guard daemon repair",
    }


def test_connect_consent_reports_capability_error_without_refreshing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")

    def fail_enable(*_args: object, **_kwargs: object) -> dict[str, object]:
        raise ExactCloudReviewError("capability_invalid")

    monkeypatch.setattr(dispatch, "enable_exact_cloud_review", fail_enable)
    monkeypatch.setattr(
        dispatch,
        "_refresh_cloud_review_worker",
        lambda _guard_home: pytest.fail("worker must not refresh after capability failure"),
    )
    result = dispatch.apply_connect_time_cloud_review_consent(
        args=argparse.Namespace(enable_cloud_review=True),
        store=store,
        guard_home=store.guard_home,
        payload={"status": "connected"},
        exit_code=0,
    )
    assert result["cloud_review"] == {"enabled": False, "reason": "capability_invalid"}


def test_cloud_review_requires_initialized_storage() -> None:
    with pytest.raises(RuntimeError, match="initialized Guard storage"):
        dispatch._run_guard_cloud_review_command(_args("status"))


@pytest.mark.parametrize(
    ("input_text", "expected_error"),
    [
        ("{" + '"x":"' + ("x" * (16 * 1024)) + '"}', "native_workspace_review_decision_invalid"),
        ("{", "native_workspace_review_decision_invalid"),
        ('{"b":1,"a":2}', "native_workspace_review_decision_noncanonical"),
    ],
)
def test_native_apply_cli_rejects_oversized_malformed_and_noncanonical_input(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    input_text: str,
    expected_error: str,
) -> None:
    result = dispatch._run_guard_cloud_review_command(
        _args("native-apply"),
        guard_home=tmp_path,
        store=GuardStore(tmp_path / "guard-home"),
        input_text=input_text,
    )
    assert result == 2
    assert json.loads(capsys.readouterr().out)["error"] == expected_error


def test_native_apply_cli_reports_verifier_errors_and_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    monkeypatch.setattr(
        dispatch,
        "apply_native_workspace_review_decision",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(dispatch.NativeWorkspaceReviewError("resident_rejected")),
    )
    assert (
        dispatch._run_guard_cloud_review_command(
            _args("native-apply"),
            guard_home=tmp_path,
            store=store,
            input_text="{}",
        )
        == 2
    )
    assert json.loads(capsys.readouterr().out)["error"] == "resident_rejected"

    monkeypatch.setattr(
        dispatch,
        "apply_native_workspace_review_decision",
        lambda *_args, **_kwargs: {"status": "verified", "request_id": "request-1"},
    )
    assert (
        dispatch._run_guard_cloud_review_command(
            _args("native-apply"),
            guard_home=tmp_path,
            store=store,
            input_text="{}",
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["status"] == "verified"


def test_cloud_review_disable_and_missing_subcommand_are_explicit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    monkeypatch.setattr(dispatch, "_refresh_cloud_review_worker", lambda _: {"status": "refreshed"})
    assert dispatch._run_guard_cloud_review_command(_args("disable"), guard_home=store.guard_home, store=store) == 0
    disabled = json.loads(capsys.readouterr().out)
    assert disabled["status"] == "disabled"
    assert disabled["worker"] == {"status": "refreshed"}

    assert dispatch._run_guard_cloud_review_command(_args("unknown"), guard_home=store.guard_home, store=store) == 2
    assert json.loads(capsys.readouterr().out)["error"] == "subcommand_required"
