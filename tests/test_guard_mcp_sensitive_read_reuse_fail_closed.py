"""The sensitive-read reuse answer fails closed, and constructing an MCP proxy leaves no digest home bound."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.native_mcp_proxy_decision import NativeMcpProxyDecisionError


def test_malformed_reuse_answer_is_rejected_as_a_decision_error(monkeypatch: pytest.MonkeyPatch) -> None:
    from tests import native_mcp_sensitive_read_client as transport

    monkeypatch.setattr(transport, "native_mcp_proxy_decide", lambda *_a, **_k: {"policy_action": "allow"})

    with pytest.raises(NativeMcpProxyDecisionError):
        transport.sensitive_read_reuse(
            stage="initial",
            current_action="x",
            artifact_hash_value="y",
            lookup=None,
            claimed_allow_hash=None,
            tool_name="read_file",
            path_class="env",
            asks_for_approval=False,
            approval_center_present=False,
            store_present=False,
            guard_home=Path("/tmp/guardvec"),
        )
