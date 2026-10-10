"""A sensitive read is never forwarded when the resident cannot answer."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.native_mcp_proxy_decision import NativeMcpProxyDecisionError
from codex_plugin_scanner.guard.proxy import stdio_sensitive_read as sensitive_read_module
from codex_plugin_scanner.guard.proxy.stdio import StdioGuardProxy

_ECHO_CHILD = "\n".join(
    [
        "import json, sys",
        "for line in sys.stdin:",
        "    message = json.loads(line)",
        "    print(json.dumps({'jsonrpc': '2.0', 'id': message.get('id'), 'result': {'forwarded': True}}))",
        "    sys.stdout.flush()",
    ]
)


def test_sensitive_read_is_blocked_when_the_resident_is_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def unavailable(*_args: object, **_kwargs: object) -> tuple[str, str]:
        raise NativeMcpProxyDecisionError("native_mcp_proxy_decision_unavailable")

    monkeypatch.setattr(sensitive_read_module, "sensitive_read_context", unavailable)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    proxy = StdioGuardProxy(
        command=[sys.executable, "-u", "-c", _ECHO_CHILD],
        cwd=workspace,
        harness="codex",
    )

    session = proxy.run_session(
        [
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "read_file", "arguments": {"path": ".env"}},
            }
        ]
    )

    error = session["responses"][0]["error"]
    assert error["data"]["guardPolicyAction"] == "block"
    assert error["data"]["transportOutcome"] == "not-forwarded"
    assert session["events"][0]["transport_outcome"] == "not-forwarded"
    assert "result" not in session["responses"][0]


def test_constructing_a_proxy_does_not_leave_a_digest_home_bound(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.native_context import context_digest_guard_home
    from codex_plugin_scanner.guard.store import GuardStore

    before = context_digest_guard_home()
    StdioGuardProxy(command=[sys.executable], guard_store=GuardStore(tmp_path / "home"), harness="codex")

    assert context_digest_guard_home() == before
