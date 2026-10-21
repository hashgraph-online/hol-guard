"""Native response rendering embedded in the standalone hook client."""

BOUNDED_HOOK_NATIVE_TEMPLATE = """def _permission_decision(policy_action: str) -> str | None:
    if policy_action in {"allow", "warn"}:
        return "allow"
    if policy_action in {"review", "require-reapproval", "sandbox-required"}:
        # zcode discards the stdout envelope when a hook exits 2, and
        # sandbox-required keeps the blocking exit for zcode, so the envelope
        # must say deny instead of ask to stay consistent.
        if HARNESS == "zcode" and policy_action == "sandbox-required":
            return "deny"
        return "ask"
    if policy_action == "block":
        return "deny"
    return None


def _should_exit_block(event_name: str, policy_action: str) -> bool:
    compact = _compact(event_name)
    blocking_events = {"pretooluse", "userpromptsubmit", "pretoolcall"}
    if HARNESS == "devin":
        blocking_events.add("permissionrequest")
    if HARNESS in {"kimi", "grok", "hermes", "pi", "omp", "zcode", "devin"} and compact in blocking_events:
        # zcode discards stdout JSON when a hook exits 2 and denies the call,
        # so review-tier PreToolUse decisions exit 0 for their ask envelope to
        # reach zcode's native permission prompt.
        if HARNESS == "zcode" and compact == "pretooluse":
            return policy_action in {"sandbox-required", "block"}
        return policy_action in {"review", "require-reapproval", "sandbox-required", "block"}
    return False


def _is_permission_event(event_name: str) -> bool:
    return _compact(event_name) in {
        "permissionrequest",
        "permissionrequestv2",
        "copilotpermissionrequest",
    }


def _pauses_when_unavailable(event_name: str) -> bool:
    compact = _compact(event_name)
    if compact in {"userpromptsubmit", "userpromptsubmitted"}:
        return True
    if compact in _LIFECYCLE_EVENTS or compact.startswith("after"):
        return False
    return compact not in {"posttooluse", "posttool"}


def _copy_approval_metadata(source: dict[str, object], payload: dict[str, object]) -> None:
    for key in _APPROVAL_KEYS:
        value = source.get(key)
        if value is not None:
            payload[key] = value


def _hermes_policy(daemon_response: dict[str, object]) -> tuple[str, str]:
    decision = daemon_response.get("decision")
    reason = str(daemon_response.get("reason") or daemon_response.get("permission_decision_reason") or "")
    hook_specific = daemon_response.get("hookSpecificOutput")
    if isinstance(hook_specific, dict):
        nested_reason = hook_specific.get("permissionDecisionReason")
        if not reason and isinstance(nested_reason, str):
            reason = nested_reason
        permission = hook_specific.get("permissionDecision")
        if isinstance(permission, str) and permission.strip().lower() in {"deny", "ask"}:
            return "block", reason
        if isinstance(permission, str) and permission.strip().lower() == "allow":
            return "allow", reason
    if isinstance(decision, str) and decision.strip().lower() in {"block", "deny"}:
        return "block", reason
    if isinstance(decision, str) and decision.strip().lower() == "allow":
        return "allow", reason
    policy_action = daemon_response.get("policy_action")
    if isinstance(policy_action, str) and policy_action.strip():
        return policy_action.strip(), reason
    return "block", reason


def _to_native(daemon_response: dict[str, object], event_name: str) -> tuple[str, str, int]:
    if HARNESS == "grok" and not daemon_response and (
        _compact(event_name) in _GROK_OBSERVE_EVENTS
        or _compact(event_name) in {"userpromptsubmit", "userpromptsubmitted"}
    ):
        return "{}", "", 0
    if HARNESS == "hermes":
        policy_action, reason = _hermes_policy(daemon_response)
        decision = "allow" if policy_action in {"allow", "warn"} else "block"
        payload = {"decision": decision, "reason": reason}
        stdout = json.dumps(payload, ensure_ascii=True, separators=(",", ":"))
        return stdout, "", 2 if decision == "block" else 0
    if "hookSpecificOutput" in daemon_response or "decision" in daemon_response:
        native_response = dict(daemon_response)
        policy = str(native_response.get("policy_action") or "block")
        exit_code = 2 if _should_exit_block(event_name, policy) else 0
        if HARNESS == "devin" and exit_code == 2:
            native_response["decision"] = "block"
            if not native_response.get("reason"):
                native_response["reason"] = f"HOL Guard blocked this action ({policy})"
        stdout = json.dumps(native_response, ensure_ascii=True, separators=(",", ":"))
        if exit_code == 2 and HARNESS == "zcode":
            reason = native_response.get("reason")
            if not isinstance(reason, str) or not reason:
                hook_specific = native_response.get("hookSpecificOutput")
                reason = hook_specific.get("permissionDecisionReason") if isinstance(hook_specific, dict) else None
            if not isinstance(reason, str) or not reason:
                reason = f"HOL Guard blocked this action ({policy})"
            return stdout, _stderr_reason(reason), exit_code
        return stdout, "", exit_code
    policy_action = str(daemon_response.get("policy_action") or "block")
    reason = str(daemon_response.get("reason") or daemon_response.get("permission_decision_reason") or "")
    payload: dict[str, object] = {}
    if event_name == "UserPromptSubmit":
        if policy_action in {"review", "require-reapproval", "sandbox-required", "block"}:
            payload["decision"] = "block"
            payload["reason"] = reason or f"HOL Guard blocked this action ({policy_action})"
    else:
        permission_decision = _permission_decision(policy_action)
        hook_specific: dict[str, object] = {"hookEventName": event_name}
        if permission_decision is not None:
            hook_specific["permissionDecision"] = permission_decision
            if permission_decision != "allow" or "unreachable" in reason.lower():
                hook_specific["permissionDecisionReason"] = reason or f"HOL Guard {policy_action} this action"
        payload["hookSpecificOutput"] = hook_specific
        if HARNESS in {"grok", "openclaw"} and permission_decision is not None:
            payload["decision"] = "allow" if permission_decision == "allow" else "deny"
            payload["policy_action"] = policy_action
            if permission_decision != "allow" and reason:
                payload["reason"] = reason
            _copy_approval_metadata(daemon_response, payload)
    exit_code = 2 if _should_exit_block(event_name, policy_action) else 0
    if HARNESS == "devin" and exit_code == 2:
        payload["decision"] = "block"
        if not payload.get("reason"):
            payload["reason"] = reason or f"HOL Guard blocked this action ({policy_action})"
    stdout = json.dumps(payload, ensure_ascii=True, separators=(",", ":"))
    if exit_code == 2 and HARNESS in {"kimi", "devin"}:
        return stdout, reason, exit_code
    if exit_code == 2 and HARNESS == "zcode":
        return stdout, _stderr_reason(reason or f"HOL Guard blocked this action ({policy_action})"), exit_code
    return stdout, "", exit_code


def _failure_payload(event_name: str, reason: str) -> tuple[dict[str, object], int]:
    if HARNESS == "grok" and _compact(event_name) in _GROK_OBSERVE_EVENTS:
        return {}, 0
    # Local configuration cannot authenticate the mode of an unavailable evaluator.
    prompt_event = _compact(event_name) in {"userpromptsubmit", "userpromptsubmitted"}
    if prompt_event:
        prompt_reason = "HOL Guard could not complete native prompt review safely."
        if HARNESS == "copilot":
            return {"behavior": "deny", "message": prompt_reason, "interrupt": False}, 0
        payload = {
            "decision": "block",
            "reason": prompt_reason,
            "systemMessage": prompt_reason,
            "hookSpecificOutput": {"hookEventName": "UserPromptSubmit"},
        }
        if HARNESS == "codex":
            payload["continue"] = False
            payload["stopReason"] = prompt_reason
            payload["hookSpecificOutput"]["additionalContext"] = prompt_reason
        return payload, 0
    if not _pauses_when_unavailable(event_name):
        # Observations continue processing completed activity without authorizing a tool action.
        if HARNESS == "copilot":
            return {"permissionDecision": "allow"}, 0
        if HARNESS in _DECISION_HARNESSES:
            return {"decision": "allow", "reason": reason}, 0
        return {
            "continue": True,
            "systemMessage": reason,
            "hookSpecificOutput": {"hookEventName": event_name},
        }, 0
    if HARNESS == "copilot":
        if _is_permission_event(event_name):
            return {"behavior": "deny", "message": reason, "interrupt": False}, 0
        return {"permissionDecision": "deny", "permissionDecisionReason": reason}, 0
    if HARNESS in _DECISION_HARNESSES:
        decision = "block" if HARNESS == "hermes" else "deny"
        return {"decision": decision, "reason": reason}, (2 if HARNESS == "hermes" else 0)
    if _is_permission_event(event_name):
        return {"continue": False, "stopReason": reason, "systemMessage": reason}, 0
    return {
        "hookSpecificOutput": {
            "hookEventName": event_name,
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }, 2


def _fail(input_text: str, *, reason: str = _FAILURE_REASON) -> int:
    event_name = _event_name(input_text)
    if HARNESS == "grok" and _grok_pretool_event_conflict(input_text):
        event_name = "PreToolUse"
    payload, exit_code = _failure_payload(event_name, reason)
    sys.stdout.write(json.dumps(payload, ensure_ascii=True, separators=(",", ":")) + "\\n")
    if exit_code == 2 and HARNESS in {"kimi", "zcode", "devin"}:
        print(reason, file=sys.stderr)
    return exit_code


"""
