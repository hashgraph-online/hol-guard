from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_hook_approval_context as transport
from codex_plugin_scanner.guard.runtime import extension_control_runtime


def _runtime_inputs(monkeypatch: pytest.MonkeyPatch, *, metadata: dict[str, object]) -> dict[str, object]:
    monkeypatch.setattr(extension_control_runtime, "current_extension_control_binding_digest", lambda: "d" * 64)
    artifact = SimpleNamespace(
        args=[],
        artifact_id="codex:project:tool",
        artifact_type="tool",
        command="tool",
        config_path="/workspace/.codex/config.toml",
        harness="codex",
        name="tool",
        publisher=None,
        source_scope="project",
        transport="stdio",
        metadata=metadata,
    )
    config = SimpleNamespace(workspace=None, guard_home=Path("/guard-home"), sandbox_analysis=None)
    return transport.runtime_hook_approval_context_inputs(
        artifact=artifact,
        content_hash="c" * 64,
        runtime_workspace=Path("/workspace"),
        action_envelope=None,
        config=config,
        policy_config={},
        evaluator_policy_version="v1",
        composition={},
        current_action="review",
        risk_classes=(),
        data_flow_signals=(),
        scanner_evidence=(),
        workflow_approval_record=None,
    )


def test_launch_free_runtime_inputs_do_not_carry_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GUARD_TEST_SURROGATE", "bad\udcff")
    unresolved = _runtime_inputs(monkeypatch, metadata={"shell_execution_context_hash": "h"})
    assert "ambient_env" not in unresolved
    launched = _runtime_inputs(monkeypatch, metadata={})
    assert launched["ambient_env"]["GUARD_TEST_SURROGATE"] == "bad\udcff"


def test_resident_rejection_raises_instead_of_degrading(monkeypatch: pytest.MonkeyPatch) -> None:
    def rejected(kind: str, fields: dict[str, object], **_kwargs: object) -> dict[str, object]:
        return {"status": "error", "code": "native_hook_approval_context_path_unresolved"}

    monkeypatch.setattr(transport, "native_context_digest", rejected)
    inputs = {"metadata": {"shell_execution_context_hash": "h"}, "workflow_record": None}
    with pytest.raises(ValueError, match="rejected:native_hook_approval_context_path_unresolved"):
        transport.native_hook_approval_context_token("runtime_hook_approval_context", inputs)
