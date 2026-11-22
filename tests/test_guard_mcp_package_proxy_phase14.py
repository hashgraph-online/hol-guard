"""Phase 14 MCP package-routing regressions."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.native_mcp_proxy_decision import NativeMcpProxyDecisionError, native_package_answer

pytestmark = [
    pytest.mark.usefixtures("approval_questionnaire_mode"),
    pytest.mark.usefixtures("bundle_first_cloud"),
    pytest.mark.usefixtures("package_intent_native"),
]


@pytest.fixture(autouse=True)
def _native_package_proxy_home(tmp_path: Path, native_mcp_probe) -> None:
    native_mcp_probe(tmp_path / "guard-home")


def test_package_decision_v2_ignores_malformed_reason_items(tmp_path: Path) -> None:
    answer = native_package_answer(
        "queue_package",
        tool_name="install_package",
        server_name="registry",
        guard_home=tmp_path / "guard-home",
        policy_action="require-reapproval",
        evaluation={
            "reasons": ["malformed", {"code": "cloud_timeout", "message": "Cloud timed out."}],
            "risk_summary": "Current package safety data was unavailable.",
            "user_copy": {
                "title": "Review package request",
                "summary": "Current package safety data was unavailable.",
                "harness_message": "Review the package request.",
            },
        },
    )

    decision = answer["decision_v2"]
    assert [signal["signal_id"] for signal in decision["signals"]] == ["supply-chain.cloud_timeout"]
    assert decision["user_title"] == "Review package request"
    assert answer["risk_signals"] == ["", "Cloud timed out."]


def test_a_package_answer_the_resident_does_not_render_fails_closed(tmp_path: Path) -> None:
    with pytest.raises(NativeMcpProxyDecisionError):
        native_package_answer(
            "terminal_tool",
            tool_name="install_package",
            server_name="registry",
            guard_home=tmp_path / "guard-home",
            policy_action="allow",
        )


WORKSPACE_ID = "workspace-alpha"
