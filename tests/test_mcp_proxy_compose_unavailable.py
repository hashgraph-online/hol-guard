"""An unanswered compose query blocks the tool call instead of ending the session."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, cast

import pytest

from codex_plugin_scanner.guard.native_hook_artifact_compose import NativeHookComposeError
from codex_plugin_scanner.guard.proxy.runtime_mcp import RuntimeMcpGuardProxy


def _proxy(failure: Exception) -> Any:
    def _raise(**_kwargs: object) -> tuple[dict[str, object] | None, dict[str, object]]:
        raise failure

    return SimpleNamespace(
        _record_client_capabilities=lambda *_args: None,
        _call_projector=SimpleNamespace(project=lambda *_args: SimpleNamespace(safe_params={})),
        _invalidate_tools_catalog=lambda: None,
        _poison_tools_catalog=lambda: None,
        _drain_child_messages=lambda **_kwargs: None,
        _handle_tool_call=_raise,
    )


def _call(proxy: Any) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    return RuntimeMcpGuardProxy._handle_message_serialized(
        cast(Any, proxy),
        message={"id": 11, "jsonrpc": "2.0", "method": "tools/call", "params": {"name": "write_file"}},
        child_stdin=cast(Any, None),
        child_stdout=cast(Any, None),
        client_input=None,
        server_output=None,
        approval_callback=None,
    )


@pytest.mark.parametrize(
    "failure",
    [
        NativeHookComposeError("native_hook_artifact_compose_unavailable"),
        KeyError("decision"),
    ],
)
def test_a_tool_call_without_a_native_answer_is_blocked_and_the_loop_survives(failure: Exception) -> None:
    response, event = _call(_proxy(failure))

    assert isinstance(response, dict)
    assert response["id"] == 11
    assert event["decision"] == "native-decision-unavailable"
    assert event["policy_action"] == "block"
