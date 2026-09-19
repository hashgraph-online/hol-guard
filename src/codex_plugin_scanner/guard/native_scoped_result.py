"""Validate scoped native results against the exact admitted request binding."""

from __future__ import annotations

from collections.abc import Mapping
from typing import cast

from .native_decision_receipt import receipt_matches_edge, validate_native_decision_receipt
from .native_policy_snapshot_codec import _valid_digest_v3

_BINDING_FIELDS = frozenset(
    {
        "policy_generation",
        "policy_digest",
        "source_input_digest",
        "runtime_identity",
        "resident_generation",
        "selected_decision_id",
    }
)
_RESULT_FIELDS = frozenset(
    {
        "schema",
        "authority",
        "request_id",
        "harness",
        "event_name",
        "payload_kind",
        "result",
        "observed_policy_action",
        "receipt",
        "policy_binding",
    }
)
_ACTIONS = frozenset({"allow", "warn", "review", "require-reapproval", "sandbox-required", "block"})
_POST_REQUIRED = frozenset({"decision", "model_output_action", "notice", "reason_code", "policy_action"})
_POST_OPTIONAL = frozenset(
    {"reason", "reviewed_output_sha256", "reviewed_excerpt", "observed_policy_action", "observe_mode"}
)


def _positive(value: object) -> bool:
    return type(value) is int and 0 < cast(int, value) <= (1 << 53) - 1


def _post_result_valid(result: Mapping[str, object], *, observe: bool, observed: object) -> bool:
    if not set(result) >= _POST_REQUIRED or set(result) - (_POST_REQUIRED | _POST_OPTIONAL):
        return False
    if not isinstance(result.get("decision"), str) or result["decision"] not in {"allow", "deny"}:
        return False
    if not isinstance(result.get("notice"), str) or result["notice"] not in {"none", "excerpt", "warning"}:
        return False
    if not isinstance(result.get("model_output_action"), str) or result["model_output_action"] not in {
        "allow_original",
        "replace_with_reviewed_excerpt",
        "block",
    }:
        return False
    if (result["decision"] == "deny") != (result["model_output_action"] == "block"):
        return False
    if not isinstance(result.get("policy_action"), str) or result["policy_action"] not in _ACTIONS:
        return False
    if not isinstance(result.get("reason_code"), str) or not 0 < len(cast(str, result["reason_code"])) <= 512:
        return False
    for key in ("reason", "reviewed_excerpt"):
        if key in result and (not isinstance(result[key], str) or len(cast(str, result[key])) > 6 * 1024 * 1024):
            return False
    if "reviewed_output_sha256" in result and not _valid_digest_v3(result["reviewed_output_sha256"]):
        return False
    output = result["model_output_action"]
    action = result["policy_action"]
    if output == "replace_with_reviewed_excerpt":
        if not isinstance(result.get("reviewed_excerpt"), str):
            return False
    elif "reviewed_excerpt" in result:
        return False
    # Validate the finite native result contract, including policy floors that
    # cannot produce an original output in Enforce. Observe preserves the
    # intrinsic output decision while reporting the composed policy action.
    if action in {"allow", "warn"} and output != "allow_original":
        return False
    if observe and output == "block" and action != "block":
        return False
    if (
        not observe
        and action not in {"allow", "warn"}
        and output != "block"
        and not (action == "review" and output == "replace_with_reviewed_excerpt")
    ):
        return False
    if type(result.get("observe_mode", False)) is not bool or result.get("observe_mode", False) is not observe:
        return False
    return result.get("observed_policy_action") == observed == (action if observe else None)


def decode_scoped_edge(payload: object, expected: Mapping[str, object] | None) -> dict[str, object] | None:
    """No source lookup or policy evaluation occurs on this decoding path."""
    from .native_hook_edge import _decode_pre_tool_result

    if not isinstance(payload, dict) or set(payload) != _RESULT_FIELDS or expected is None:
        return None
    value = cast(dict[str, object], payload)
    binding = value.get("policy_binding")
    result = value.get("result")
    harness = value.get("harness")
    event = value.get("event_name")
    if (
        value.get("schema") != "guard-hook-edge-result.v3"
        or value.get("authority") != "rust"
        or not isinstance(event, str)
        or event not in {"PreToolUse", "PostToolUse"}
        or not isinstance(value.get("payload_kind"), str)
        or value["payload_kind"] not in {"inline", "source_file_ref"}
        or not isinstance(harness, str)
        or not 0 < len(harness) <= 64
        or not isinstance(value.get("request_id"), str)
        or not 0 < len(cast(str, value["request_id"])) <= 256
        or not isinstance(result, dict)
        or not isinstance(binding, dict)
        or set(binding) != _BINDING_FIELDS
        or not isinstance(expected.get("mode"), str)
        or expected.get("mode") not in {"enforce", "observe"}
    ):
        return None
    if event == "PreToolUse":
        if (
            type(result.get("version")) is not int
            or not isinstance(result.get("action"), dict)
            or type(result["action"].get("version")) is not int
            or not _decode_pre_tool_result(result, harness=harness)
        ):
            return None
    elif binding.get("selected_decision_id") is not None or not _post_result_valid(
        result, observe=expected["mode"] == "observe", observed=value.get("observed_policy_action")
    ):
        return None
    if not all(_positive(expected.get(key)) for key in ("generation", "resident_generation")):
        return None
    if not all(_positive(binding[key]) for key in ("policy_generation", "resident_generation")):
        return None
    if binding["selected_decision_id"] is not None and not _positive(binding["selected_decision_id"]):
        return None
    if not all(_valid_digest_v3(binding[key]) for key in ("policy_digest", "source_input_digest", "runtime_identity")):
        return None
    if any(
        binding[key] != expected.get("generation" if key == "policy_generation" else key)
        for key in (
            "policy_generation",
            "policy_digest",
            "source_input_digest",
            "runtime_identity",
            "resident_generation",
        )
    ):
        return None
    receipt = validate_native_decision_receipt(value.get("receipt"))
    observed_action = value.get("observed_policy_action")
    if expected["mode"] == "observe":
        # An unchanged action has no projected policy decision. Its receipt
        # still carries the authenticated snapshot mode below.
        if observed_action is not None and (not isinstance(observed_action, str) or observed_action not in _ACTIONS):
            return None
    elif observed_action is not None:
        return None
    if (
        receipt is None
        or any(
            receipt[key] != binding[key]
            for key in (
                "policy_generation",
                "policy_digest",
                "runtime_identity",
            )
        )
        or not _valid_digest_v3(receipt.get("rule_digest"))
    ):
        return None
    # PreTool's strict result schema does not carry observe_mode. The receipt
    # must match the authenticated snapshot mode, not a caller-supplied flag.
    receipt_view = dict(
        value,
        result=dict(
            result,
            observe_mode=expected["mode"] == "observe",
            observed_policy_action=observed_action,
        ),
    )
    if not receipt_matches_edge(receipt_view, receipt):
        return None
    return value


def scoped_result_is_current(publisher: object, edge: Mapping[str, object]) -> bool:
    """Fence the frozen publication again after the native response arrives."""
    binding = edge.get("policy_binding")
    check = getattr(publisher, "result_binding_is_current", None)
    if edge.get("schema") != "guard-hook-edge-result.v3" or not isinstance(binding, Mapping) or not callable(check):
        return False
    try:
        return check(binding) is True
    except Exception:
        return False


def scoped_invocation_matches(
    edge: Mapping[str, object], *, request_id: str | None, harness: str, rule_digest: str, event: str = "PreToolUse"
) -> bool:
    """Bind the reply to this transport invocation, without interpreting payload."""
    canonical = harness.strip().lower().replace("_", "-") if harness.isascii() else ""
    aliases = {
        "claude": "claude-code",
        "cline-cli": "cline",
        "cline-vscode": "cline",
        "kimi-code": "kimi",
        "kimi-cli": "kimi",
        "grok-build": "grok",
        "grok-build-cli": "grok",
        "xai-grok": "grok",
        "pi-agent": "pi",
        "pi-coding-agent": "pi",
        "oh-my-pi": "omp",
        "zai": "zcode",
        "z-code": "zcode",
        "zai-zcode": "zcode",
    }
    receipt = edge.get("receipt")
    event_key = event.strip().lower().replace("_", "").replace("-", "")
    expected_event = None
    if event_key in {
        "pretool",
        "pretooluse",
        "beforeshellexecution",
        "beforereadfile",
        "beforewritefile",
        "beforemcpexecution",
    }:
        expected_event = "PreToolUse"
    elif event_key in {
        "posttool",
        "posttooluse",
        "aftershellexecution",
        "afterreadfile",
        "afterwritefile",
        "aftermcpexecution",
    }:
        expected_event = "PostToolUse"
    return (
        edge.get("schema") == "guard-hook-edge-result.v3"
        and isinstance(request_id, str)
        and bool(request_id)
        and edge.get("request_id") == request_id
        and edge.get("harness") == aliases.get(canonical, canonical)
        and expected_event is not None
        and edge.get("event_name") == expected_event
        and isinstance(receipt, Mapping)
        and receipt.get("request_id") == request_id
        and receipt.get("rule_digest") == rule_digest
    )
