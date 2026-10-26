"""The sensitive-read reuse answer fails closed, and constructing an MCP proxy leaves no digest home bound."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.native_mcp_proxy_decision import NativeMcpProxyDecisionError


def test_constructing_a_proxy_does_not_leave_a_digest_home_bound(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard import native_context
    from codex_plugin_scanner.guard.adapters.base import HarnessContext
    from codex_plugin_scanner.guard.proxy.runtime_mcp import RuntimeMcpGuardProxy
    from codex_plugin_scanner.guard.store import GuardStore

    before = native_context._BOUND_GUARD_HOME.get()
    RuntimeMcpGuardProxy(
        harness="hermes",
        server_name="test",
        command=["echo", "hello"],
        context=HarnessContext(home_dir=tmp_path, workspace_dir=tmp_path, guard_home=tmp_path / "home"),
        store=GuardStore(tmp_path / "home"),
        config=type("MockConfig", (), {})(),
        source_scope="global",
        config_path=str(tmp_path / "config.yaml"),
    )

    assert native_context._BOUND_GUARD_HOME.get() == before


def test_malformed_reuse_answer_is_rejected_as_a_decision_error(monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard import native_mcp_sensitive_read as transport

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
