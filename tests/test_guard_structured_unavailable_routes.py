"""Daemon availability routes preserve managed structured withholding."""

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon import hook_worker, hook_worker_structured
from codex_plugin_scanner.guard.store import GuardStore
from tests.structured_output_mediation_support import _config


@pytest.mark.parametrize("harness", ["pi", "omp"])
@pytest.mark.parametrize("required", [False, True])
def test_daemon_unavailable_routes_withhold_only_required_structured_content(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    harness: str,
    required: bool,
) -> None:
    guard_home = tmp_path / "guard-home"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    worker = hook_worker.HookWorker(store=GuardStore(guard_home))
    # The native resolution is what says whether the managed policy covers this
    # harness; pin it so the result does not depend on an installed runtime.
    monkeypatch.setattr(
        hook_worker_structured,
        "content_query",
        lambda *_args, **_kwargs: {
            "binding": None,
            "required": required,
            "reason_code": "structured_managed_authority_unavailable" if required else None,
        },
    )
    # A readable config; an unreadable one is always required, so reading the
    # real one would make the result depend on an installed runtime.
    monkeypatch.setattr(worker, "_load_config", lambda *_args, **_kwargs: _config())
    # Pin the native edge as unavailable so the result is independent of any
    # runtime binary installed on the machine running the test.
    monkeypatch.setattr(worker, "_review_raw_hook_native", lambda **_: None)
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
