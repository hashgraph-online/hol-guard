from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from scripts import native_slo_session as native_slo_session_module


def test_claude_slo_request_uses_authenticated_production_transport(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def authenticated_response(**kwargs: object) -> str:
        captured.update(kwargs)
        return '{"continue":true,"decision":"allow"}'

    monkeypatch.setattr(
        native_slo_session_module,
        "authenticated_claude_hook_response",
        authenticated_response,
    )

    response = native_slo_session_module._request(
        cast(native_slo_session_module.GuardDaemonServer, cast(object, SimpleNamespace())),
        guard_home=tmp_path / "guard-home",
        workspace=tmp_path / "workspace",
        harness="claude-code",
        request_payload={"hook_event_name": "PostToolUse"},
    )

    assert response["decision"] == "allow"
    assert captured["state_path"] == tmp_path / "guard-home" / "daemon-state.json"
    assert "workspace=" in str(captured["query"])
