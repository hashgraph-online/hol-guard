"""Daemon availability routes preserve managed structured withholding."""

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon import hook_worker
from codex_plugin_scanner.guard.runtime.structured_output_mediation import StructuredOutputResolution
from codex_plugin_scanner.guard.store import GuardStore


@pytest.mark.parametrize("harness", ["pi", "omp"])
@pytest.mark.parametrize("mode", ["off", "shadow"])
@pytest.mark.parametrize("required", [False, True])
@pytest.mark.parametrize("mode_surface", [False, True])
def test_daemon_unavailable_routes_withhold_only_required_structured_content(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    harness: str,
    mode: str,
    required: bool,
    mode_surface: bool,
) -> None:
    guard_home = tmp_path / "guard-home"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.setattr(hook_worker, "native_mode", lambda: mode)
    worker = hook_worker.HookWorker(store=GuardStore(guard_home))
    monkeypatch.setattr(
        worker,
        "_structured_output_resolution",
        lambda **_: StructuredOutputResolution(
            binding=None,
            required=required,
            reason_code="structured_managed_authority_unavailable" if required else None,
        ),
    )
    if not mode_surface:
        monkeypatch.setattr(worker, "_mode_surface_response", lambda *_, **__: None)
    try:
        result = worker.review_http_payload(
            payload={
                "hook_event_name": "PostToolUse",
                "tool_name": "Read",
                "tool_input": {"file_path": "note.json"},
                "tool_response": [{"type": "text", "text": '{"note":"synthetic"}'}],
                "structured_output_json": '{"note":"synthetic"}',
            },
            params={},
            default_harness=harness,
            guard_home=guard_home,
            home_dir=tmp_path,
            workspace=workspace,
        )
    finally:
        worker.close()
    assert result["decision"] == "allow"
    assert worker._last_native_decision_receipt is None
    if required:
        mediation = result["structured_content_mediation"]
        assert mediation["action"] == "withhold"
        assert mediation["reason_code"] == "structured_native_edge_unavailable"
        assert not mediation.get("native_decision_id")
    else:
        assert "structured_content_mediation" not in result
