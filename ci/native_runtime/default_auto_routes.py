"""Fixed installed ingress corpus and mode checks for the default-auto probe."""

from __future__ import annotations

import importlib.util
import json
import os
from collections.abc import Mapping
from pathlib import Path

from ci.native_runtime.default_auto_failure import observe_delivery
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from scripts.native_slo_adapter import is_allowed

_REPO_ROOT = Path(__file__).resolve().parents[2]

_HOOK_CLIENT_SPEC = importlib.util.spec_from_file_location(
    "hol_guard_installed_hook_client",
    Path(__file__).with_name("installed_hook_client.py"),
)
if _HOOK_CLIENT_SPEC is None or _HOOK_CLIENT_SPEC.loader is None:
    raise RuntimeError("native_default_auto_probe_failed: installed hook client could not be loaded")
_HOOK_CLIENT_MODULE = importlib.util.module_from_spec(_HOOK_CLIENT_SPEC)
_HOOK_CLIENT_SPEC.loader.exec_module(_HOOK_CLIENT_MODULE)
_installed_hook_request = _HOOK_CLIENT_MODULE.installed_hook_request


def _require(condition: bool, detail: object) -> None:
    """Fail the CI probe even when Python assertions are optimized out."""
    if not condition:
        raise RuntimeError(f"native_default_auto_probe_failed: {detail}")


def _permission_decision(response: Mapping[str, object]) -> str | None:
    specific = response.get("hookSpecificOutput")
    if not isinstance(specific, Mapping):
        return None
    value = specific.get("permissionDecision")
    return value if isinstance(value, str) else None


def _delivery_diagnostic(response: Mapping[str, object]) -> dict[str, object]:
    """Fixed public codes only: never log source text or arbitrary reasons."""

    allowed = {
        "decision": {"allow", "deny", "block", "review", "ask"},
        "policy_action": {"allow", "warn", "block", "review", "suppress"},
        "reason_code": {
            "native_exact_safe_command",
            "native_command_control_authority_block",
            "native_command_control_mutation_in_progress",
            "native_request_invalid_json",
            "native_policy_warning",
            "native_policy_block",
            "native_policy_snapshot_unavailable",
            "native_hook_unavailable",
            "output_secret_match",
        },
    }
    result: dict[str, object] = {}
    for field, choices in allowed.items():
        value = response.get(field)
        result[field] = value if isinstance(value, str) and value in choices else (None if value is None else "other")
    permission = _permission_decision(response)
    result["permission_decision"] = permission if permission in {None, "allow", "deny", "ask"} else "other"
    return result


def _ownership_routes() -> dict[str, dict[str, str]]:
    path = _REPO_ROOT / "docs/guard/contracts/hook-data-plane-ownership.v2.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    routes = payload.get("harness_routes") if isinstance(payload, dict) else None
    if not isinstance(routes, dict):
        raise RuntimeError("native_default_auto_probe_failed: ownership routes missing")
    decoded: dict[str, dict[str, str]] = {}
    for harness, route in routes.items():
        if not isinstance(harness, str) or not isinstance(route, dict):
            raise RuntimeError("native_default_auto_probe_failed: ownership route invalid")
        pre = route.get("pre_tool_use")
        post = route.get("post_tool_use")
        if not isinstance(pre, str) or not isinstance(post, str):
            raise RuntimeError("native_default_auto_probe_failed: ownership route incomplete")
        decoded[harness] = {"pre_tool_use": pre, "post_tool_use": post}
    return decoded


def _exercise_installed_routes(
    daemon: GuardDaemonServer,
    guard_home: Path,
    workspace: Path,
    routes: dict[str, dict[str, str]],
    route_receipts: list[dict[str, str]],
    reason_codes: dict[str, int],
) -> None:
    for harness, route in sorted(routes.items()):
        events: list[tuple[str, dict[str, object]]] = []
        if route["pre_tool_use"].startswith("installed_"):
            events.append(
                (
                    "PreToolUse",
                    {
                        "hook_event_name": "PreToolUse",
                        "tool_name": "Bash",
                        "tool_input": {"command": "printf guard"},
                    },
                )
            )
        if route["post_tool_use"].startswith("installed_"):
            events.append(
                (
                    "PostToolUse",
                    {
                        "hook_event_name": "PostToolUse",
                        "tool_name": "Read",
                        "tool_response": [{"type": "text", "text": "guard baseline\n"}],
                    },
                )
            )
        for event, payload in events:
            response_payload = _installed_hook_request(daemon, guard_home, workspace, harness, event, payload)
            observe_delivery(daemon, harness, event, response_payload)
            if response_payload is None:
                raise RuntimeError(f"empty response for {harness} {event}")
            _require(
                is_allowed(event, response_payload),
                {
                    "harness": harness,
                    "event": event,
                    **_delivery_diagnostic(response_payload),
                },
            )
            reason = response_payload.get("reason_code")
            if isinstance(reason, str):
                reason_codes[reason] = reason_codes.get(reason, 0) + 1
            route_receipts.append({"harness": harness, "event": event, "route": "native_resident"})


def _exercise_mode_invariants(
    daemon: GuardDaemonServer,
    guard_home: Path,
    workspace: Path,
) -> dict[str, dict[str, object]]:
    mode_invariants: dict[str, dict[str, object]] = {}
    try:
        for mode in ("off", "shadow"):
            os.environ["HOL_GUARD_NATIVE"] = mode
            response = _installed_hook_request(
                daemon,
                guard_home,
                workspace,
                "claude-code",
                "PostToolUse",
                {
                    "hook_event_name": "PostToolUse",
                    "tool_name": "Read",
                    "tool_response": [{"type": "text", "text": "mode invariant\n"}],
                },
            )
            if not isinstance(response, dict):
                raise RuntimeError(f"native_default_auto_probe_failed: invalid mode response: {response}")
            _require(
                response.get("continue") is True
                and response.get("policy_action") == "allow"
                and response.get("reason_code") in {"native_hook_disabled", "native_shadow_diagnostic_disabled"},
                {"mode": mode, "response": response},
            )
            mode_invariants[mode] = {
                "decision": response.get("decision"),
                "reason_code": response.get("reason_code"),
                "python_oracle": daemon._server.hook_worker.test_oracle is not None,
            }
            _require(mode_invariants[mode]["python_oracle"] is False, mode_invariants[mode])
    finally:
        os.environ.pop("HOL_GUARD_NATIVE", None)
    return mode_invariants
