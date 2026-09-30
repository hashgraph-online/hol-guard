"""An acknowledged enforcing snapshot still pauses native reviews."""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.test_native_review_fixtures import _edge, _worker


def _review(worker: object, tmp_path: Path, harness: str) -> dict[str, object]:
    response = worker.review_http_payload(  # type: ignore[attr-defined]
        payload={
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "gh api repos/example/example"},
        },
        params={},
        default_harness=harness,
        home_dir=tmp_path / "home",
        guard_home=tmp_path / "guard-home",
        workspace=tmp_path / "workspace",
    )
    assert isinstance(response, dict)
    return response


def test_protected_config_still_pauses_under_enforcing_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    edge = _edge("codex")
    result = edge["result"]
    assert isinstance(result, dict)
    result.update(
        policy_action="require-reapproval",
        minimum_action="require-reapproval",
        decision="deny",
        reason_code="native_policy_reapproval_required",
        reason="HOL Guard requires fresh approval under the installed native policy.",
    )
    worker, store = _worker(tmp_path, monkeypatch, edge)
    guard_home = tmp_path / "guard-home"
    (guard_home / "config.toml").write_text(
        'mode = "enforce"\nprotection_posture = "protected"\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(worker, "_native_policy_snapshot", lambda *_args, **_kwargs: {"mode": "enforce"})

    response = _review(worker, tmp_path, "codex")

    assert response.get("approval_request_id") or response.get("guardApprovalRequestId")
    assert store.list_approval_requests(status="pending")


@pytest.mark.parametrize("harness", ["codex", "devin"])
def test_watch_config_still_pauses_while_acknowledged_snapshot_enforces(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    harness: str,
) -> None:
    edge = _edge(harness)
    result = edge["result"]
    assert isinstance(result, dict)
    result.update(
        policy_action="require-reapproval",
        minimum_action="require-reapproval",
        decision="deny",
        reason_code="native_policy_reapproval_required",
        reason="HOL Guard requires fresh approval under the installed native policy.",
    )
    worker, store = _worker(tmp_path, monkeypatch, edge)
    guard_home = tmp_path / "guard-home"
    (guard_home / "config.toml").write_text(
        'mode = "observe"\nprotection_posture = "watch"\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(worker, "_native_policy_snapshot", lambda *_args, **_kwargs: {"mode": "enforce"})

    response = _review(worker, tmp_path, harness)

    assert response.get("approval_request_id") or response.get("guardApprovalRequestId")
    assert store.list_approval_requests(status="pending")
