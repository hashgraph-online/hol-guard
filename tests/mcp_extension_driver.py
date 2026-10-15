"""Drive the resident's MCP grant and contribution ops directly, for decision tests.

Production decides these in-process inside the tool-policy pass (see
``mcp_tool_policy_extension.rs``). These helpers ask the two standalone resident
ops the same question with the same non-authoritative inputs, so fixtures that
write real grant rows and layers can pin the Rust decisions without a full
tool call. They never hold an unanswered call for review: that composition is
covered by the Rust tests.
"""

from __future__ import annotations

from typing import Any
from uuid import uuid4

from codex_plugin_scanner.guard.local_cli_grant_decision import GRANT_REFINABLE_ACTIONS
from codex_plugin_scanner.guard.models import GuardAction, GuardArtifact
from codex_plugin_scanner.guard.native_context import ensure_resident_prerequisite
from codex_plugin_scanner.guard.native_execution import _resident_request
from codex_plugin_scanner.guard.native_local_cli_identity import LocalCliIdentityUnavailableError
from codex_plugin_scanner.guard.native_mcp_extension_input import build_extension_input

from .local_cli_native_fixture import ensure_keyed_home

_LOCAL = ("local_mcp_grant_decide", "local-mcp-grant-v1", "guard-local-mcp-grant")
_CONTRIBUTED = ("contributed_mcp_decide", "contributed-mcp-decision-v1", "guard-contributed-mcp-decision")
_LOCAL_TEXT = {
    "blocked": ("block", "This MCP tool is blocked by a custom extension on this device."),
    "allowed": ("allow", "This MCP tool is allowed by a custom extension on this device."),
    "review": (
        "review",
        "This tool is not in the reviewed catalog. Review its authority before execution.",
    ),
}


def _decide(op: tuple[str, str, str], store: Any, request: dict[str, object]) -> dict[str, Any]:
    operation, feature, schema = op
    guard_home = store.guard_home
    ensure_keyed_home(guard_home)
    if not ensure_resident_prerequisite(guard_home):
        raise LocalCliIdentityUnavailableError(f"{operation}_prerequisite_unavailable")
    response = _resident_request(
        operation=operation,
        request={"schema": f"{schema}-request.v1", "request_id": f"test-{uuid4().hex}", **request},
        guard_home=guard_home,
        timeout_seconds=10.0,
        required_feature=feature,
        response_schema=f"{schema}-result.v1",
    )
    if response is None or response.get("status") != "ok" or not isinstance(response.get("payload"), dict):
        raise LocalCliIdentityUnavailableError(str(None if response is None else response.get("code")))
    return response["payload"]


def matching_local_mcp_grant(*, store: Any, artifact: GuardArtifact, current_action: GuardAction) -> str | None:
    if current_action not in GRANT_REFINABLE_ACTIONS:
        return None
    ext = build_extension_input(store, artifact)
    if ext["local_unavailable"]:
        raise LocalCliIdentityUnavailableError("native_local_mcp_grant_unavailable")
    keys = ("store_path", "guard_home", "harness", "tool_name", "server", "connection_identity_hash")
    keys += ("tool_authority_hash", "launcher_path", "launcher_home")
    state = _decide(_LOCAL, store, {**{key: ext[key] for key in keys}, "current_action": current_action})["state"]
    return state if state in _LOCAL_TEXT else None


def apply_contributed_mcp_decision(
    store: Any, artifact: GuardArtifact, current_action: GuardAction
) -> tuple[str, str, str] | None:
    ext = build_extension_input(store, artifact)
    payload = _decide(
        _CONTRIBUTED,
        store,
        {
            "store_path": ext["store_path"],
            "guard_home": ext["guard_home"],
            "current_action": current_action,
            "server_identity": ext["server_identity"],
            "artifact_transport": ext["artifact_transport"],
            "server_name": ext["server_name"],
            "tool_name": ext["contributed_tool_name"],
            "layers": ext["layers"],
        },
    )
    if payload["state"] != "decided":
        return None
    return payload["action"], payload["source"], payload["reason"]


def apply_local_mcp_extension_decision(
    store: Any, artifact: GuardArtifact, current_action: GuardAction
) -> tuple[str, str, str] | None:
    matched = matching_local_mcp_grant(store=store, artifact=artifact, current_action=current_action)
    if matched is not None:
        action, summary = _LOCAL_TEXT[matched]
        return action, "local-mcp-extension", summary
    contributed = apply_contributed_mcp_decision(store, artifact, current_action)
    if contributed is None and current_action == "review":
        reasserted = apply_contributed_mcp_decision(store, artifact, "allow")
        if reasserted is not None and reasserted[0] == "review":
            return reasserted
    return contributed
