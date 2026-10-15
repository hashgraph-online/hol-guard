"""A benign MCP tools/call spends a bounded number of resident round trips.

Each resident round trip costs a few milliseconds, so the per-call count is a
latency budget: a new op, or a policy effect that re-enters the decide op, has
to fold into an existing round trip instead of adding one.
"""

from __future__ import annotations

import collections
import json
import sqlite3

import pytest

from codex_plugin_scanner.guard import native_context, native_execution
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.proxy import CodexMcpGuardProxy
from codex_plugin_scanner.guard.proxy import runtime_mcp as runtime_mcp_module
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_guard_runtime_mcp_saved_blocks import _child_command, _context, _messages

pytestmark = [pytest.mark.usefixtures("bundle_first_cloud"), pytest.mark.usefixtures("package_intent_native")]

# Resident ops one benign warm allow may spend, excluding the `tools/list` setup.
# Includes the single `mcp_tool_call_identity` round trip; the stdio exchange fusion lowers it further.
_TOTAL_BUDGET = 7
_CONNECTION_BUDGET = 2
# `native_context_digest` calls (cached ones included) cost Python time even when no resident round
# trip happens, so they are bounded too.
_DIGEST_BUDGET = 14
_PER_OPERATION_BUDGET = {
    "mcp_tool_policy_decide": 1,
    "policy_decision_lookup": 0,
    "mcp_proxy_decide": 0,
    "guard_store": 1,
}


def test_benign_tool_call_stays_within_the_resident_round_trip_budget(
    tmp_path, monkeypatch: pytest.MonkeyPatch, native_mcp_probe
) -> None:
    context = _context(tmp_path)
    native_mcp_probe(context.guard_home)
    proxy = CodexMcpGuardProxy(
        server_name="workspace-tools",
        command=_child_command(tmp_path / "marker.json"),
        context=context,
        store=GuardStore(context.guard_home),
        config=GuardConfig(
            mode="enforce",
            default_action="allow",
            guard_home=context.guard_home,
            workspace=context.workspace_dir,
        ),
        source_scope="project",
        config_path=str(context.workspace_dir / ".codex" / "config.toml"),
    )
    monkeypatch.setattr(runtime_mcp_module, "ensure_guard_daemon", lambda _home: "http://127.0.0.1:5474")
    monkeypatch.setattr(proxy, "_maybe_open_approval_center", lambda **_kwargs: None)
    operations: collections.Counter[str] = collections.Counter()
    real = native_execution.native_resident_client_request

    def spy(**kwargs):
        operations[json.loads(kwargs["payload"])["operation"]] += 1
        return real(**kwargs)

    monkeypatch.setattr(native_execution, "native_resident_client_request", spy)
    digests: list[str] = []
    real_digest = native_context.native_context_digest

    def digest_spy(kind, *args, **kwargs):
        digests.append(str(kind))
        return real_digest(kind, *args, **kwargs)

    monkeypatch.setattr(native_context, "native_context_digest", digest_spy)
    connections: list[str] = []
    real_connect = sqlite3.connect

    def counting_connect(*args, **kwargs):
        connections.append(str(args[0]) if args else "")
        return real_connect(*args, **kwargs)

    monkeypatch.setattr(sqlite3, "connect", counting_connect)
    messages = _messages(tool_name="safe_echo", arguments={"value": "hello"}, elicitation=False)
    proxy.run_session(messages[:2])  # initialize and tools/list
    setup = collections.Counter(operations)
    operations.clear()
    connections.clear()
    digests.clear()
    result = proxy.run_session(messages)
    assert "result" in result["responses"][2], result["responses"][2]
    spent = operations - setup
    for operation, budget in _PER_OPERATION_BUDGET.items():
        assert spent[operation] <= budget, (operation, dict(spent))
    assert sum(spent.values()) <= _TOTAL_BUDGET, dict(spent)
    assert len(digests) <= _DIGEST_BUDGET, collections.Counter(digests)
    # Each short-lived store connection costs about a millisecond of first-touch work. The extension
    # authority read, the policy lookup and every effect share one connection scope, and the receipt,
    # inventory and event writes share another, so this must not grow back to a connection per method.
    guard_db = [path for path in connections if path.endswith("guard.db")]
    assert len(guard_db) <= _CONNECTION_BUDGET, (len(guard_db), dict(spent))
