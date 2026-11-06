"""The MCP proxy asks the resident once per distinct call projection."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.native_mcp_proxy_decision import NativeMcpProxyDecisionError
from codex_plugin_scanner.guard.proxy import runtime_mcp_projection
from codex_plugin_scanner.guard.proxy.runtime_mcp_projection import McpCallProjector

_PAYLOAD = {
    "safe_arguments": {"token": "*****"},
    "safe_params": {"name": "call", "arguments": {"token": "*****"}},
    "launch_target": "call {} [arguments-sha256:x]",
    "browser": None,
    "risk": None,
}


def test_repeated_projection_reuses_the_answer(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    queries: list[dict[str, object]] = []

    def decide(query: dict[str, object], *, guard_home: Path) -> dict[str, object]:
        queries.append(query)
        return dict(_PAYLOAD)

    monkeypatch.setattr(runtime_mcp_projection, "native_mcp_proxy_decide", decide)
    projector = McpCallProjector(tmp_path)
    params = {"name": "call", "arguments": {"token": "secret"}}
    first = projector.project("call", params)
    assert projector.project("call", params) is first
    assert first.safe_params == _PAYLOAD["safe_params"]
    assert first.display_launch_target == _PAYLOAD["launch_target"]
    assert (first.risk_categories, first.risk_summary) == ((), "")
    projector.project("call", {**params, "arguments": {"token": "other"}})
    assert len(queries) == 2
    assert queries[0] == {"check": "call_projection", "tool_name": "call", "params": params, "risk": None}


def test_browser_label_wins_for_display(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    payload = {**_PAYLOAD, "browser": {"launch_target": "chrome navigate a.example", "intent": {"intent": "x"}}}
    monkeypatch.setattr(runtime_mcp_projection, "native_mcp_proxy_decide", lambda query, *, guard_home: payload)
    projection = McpCallProjector(tmp_path).project("navigate", {"name": "navigate"})
    assert projection.display_launch_target == "chrome navigate a.example"
    assert projection.launch_target == _PAYLOAD["launch_target"]


@pytest.mark.parametrize(
    "failure",
    [NativeMcpProxyDecisionError("native_mcp_proxy_decision_refused"), {"safe_params": {}}],
)
def test_any_failure_is_the_projection_unavailable_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, failure: object
) -> None:
    def decide(query: dict[str, object], *, guard_home: Path) -> object:
        if isinstance(failure, Exception):
            raise failure
        return failure

    monkeypatch.setattr(runtime_mcp_projection, "native_mcp_proxy_decide", decide)
    with pytest.raises(ValueError, match=r"^native_mcp_arguments_projection_unavailable$") as raised:
        McpCallProjector(tmp_path).project("call", {"name": "call"})
    assert not isinstance(raised.value, NativeMcpProxyDecisionError)
