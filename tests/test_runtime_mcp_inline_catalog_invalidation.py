"""Inline catalog invalidation must deny without remembering or replaying a call."""

from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import replace
from typing import Any, cast

import pytest

from codex_plugin_scanner.guard.proxy import runtime_mcp
from codex_plugin_scanner.guard.proxy.tool_call_binding import current_tool_call_binding
from codex_plugin_scanner.guard.runtime.supply_chain_package_eval import evaluate_package_request_artifact

from .test_mcp_owned_preparation_pilot import _session


@pytest.mark.usefixtures("bundle_first_cloud")
@pytest.mark.parametrize("package", [False, True], ids=["ordinary", "package"])
@pytest.mark.parametrize("change", ["catalog", "current_block", "request"])
def test_inline_catalog_invalidation_denies_before_remember_or_forward(tmp_path, monkeypatch, change, package):
    proxy, messages, marker = _session(tmp_path, action="review")
    approvals = []
    if package:
        params = cast(dict[str, Any], messages[-1]["params"])
        arguments = cast(dict[str, Any], params["arguments"])
        arguments["command"] = "npm install minimist@1.2.8"
        artifact = proxy._package_request_artifact(tool_name="safe_echo", arguments=arguments)
        assert artifact is not None
        evaluation = replace(
            evaluate_package_request_artifact(artifact=artifact, store=proxy.store, workspace_dir=tmp_path),
            decision="allow",
            policy_action="allow",
        )
        monkeypatch.setattr(runtime_mcp, "evaluate_package_request_artifact", lambda **_kwargs: evaluation)

    def must_not_allow(*_args, **_kwargs):
        pytest.fail("an invalidated inline approval must not be remembered or claimed")

    def approve(request):
        approvals.append(request["id"])
        proxy._invalidate_tools_catalog()
        if change == "current_block":
            proxy.config = replace(proxy.config, default_action="block")
        elif change == "request":
            binding = current_tool_call_binding()
            assert binding is not None
            binding.owned_message["params"]["arguments"]["text"] = "changed during approval"
        return {"action": "accept", "content": {"decision": "approve"}}

    monkeypatch.setattr(runtime_mcp, "allow_tool_call", must_not_allow)
    monkeypatch.setattr(proxy.store, "claim_approval_reuse_decisions", must_not_allow)
    if change == "catalog":
        again = deepcopy(messages[-1])
        again["id"] = "second-denied-id"
        messages.append(again)

    result = proxy.run_session(messages, inline_approval_callback=approve)
    (tmp_path / "inline-catalog-witness.json").write_text(
        json.dumps({"result": result, "child_received": marker.exists(), "approvals": approvals}, indent=2) + "\n"
    )
    assert not marker.exists()
    if change == "request":
        assert result["responses"][-1]["error"]["data"]["reason_code"] == "tool_call_request_changed"
        assert result["events"][-1]["session_terminal"] is True
        assert len(approvals) == 1
    else:
        expected_count = 2 if change == "catalog" else 1
        assert len(approvals) == expected_count
        assert len(result["responses"][2:]) == expected_count
        for response in result["responses"][2:]:
            assert response["error"]["code"] == -32001
            assert response["error"]["data"]["guardPolicyAction"] == (
                "require-reapproval" if change == "catalog" else "block"
            )
        assert all(not event.get("session_terminal") for event in result["events"][2:])
