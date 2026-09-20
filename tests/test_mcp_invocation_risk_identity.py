"""Real launch identity failures retain fresh authority without executing a child."""

from __future__ import annotations

from copy import deepcopy

from codex_plugin_scanner.guard.proxy import runtime_mcp

from .test_mcp_invocation_risk_pair import _assert_uncached_parity, _observed, _resolve
from .test_mcp_owned_preparation_pilot import _session


def test_real_unreadable_launch_identities_are_not_reused_or_masked(tmp_path):
    proxy, messages, _marker = _session(tmp_path)
    missing = tmp_path / "unavailable-mcp-server"
    assert not missing.exists()
    proxy.command = [str(missing)]
    producer = runtime_mcp.RuntimeMcpGuardProxy._session_executable_identity.__code__
    identities = []

    def observe(frame, event, value, _counts):
        if event == "return" and frame.f_code is producer:
            identities.append(deepcopy(value))

    with _observed(observe) as counts:
        first = _resolve(proxy, messages[-1])
        second = _resolve(proxy, messages[-1])
    assert counts == {"categories": 2, "signals": 2, "policy": 4}
    assert len(identities) == 2
    for authority, identity in zip((first, second), identities, strict=True):
        assert identity["status"] == "unreadable"
        assert isinstance(identity["reuse_nonce"], str) and identity["reuse_nonce"]
        assert authority.artifact.metadata["server_fingerprint"]["resolved_executable"] == identity
        _assert_uncached_parity(proxy, authority, messages[-1]["params"]["arguments"])
    assert identities[0]["reuse_nonce"] != identities[1]["reuse_nonce"]
    assert first.artifact_hash != second.artifact_hash
    assert proxy._active_executable_identity is None
