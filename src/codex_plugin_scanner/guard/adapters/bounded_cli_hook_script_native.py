"""Native response rendering embedded in the standalone hook client."""

BOUNDED_HOOK_NATIVE_TEMPLATE = """_GUARD_ACTIONS = frozenset(
    {"allow", "warn", "review", "require-reapproval", "sandbox-required", "block"}
)
_GUARD_DECISIONS = frozenset({"allow", "ask", "deny", "block"})


def _canonical_policy_action(policy_action: object) -> str:
    # An action this client cannot place -- one a newer resident introduced,
    # or a truncated or corrupted field -- is not evidence of permission, so
    # it reads as "block": what this client already answers for a missing
    # action, and what the native bridge that answers for this client reads
    # the same value as. Surrounding whitespace is stripped first, as the
    # bridge does, so a padded canonical action is not read as unplaceable.
    # Matching is otherwise exact and excludes the "ask" alias, as the
    # bridge's own is_guard_action does.
    if isinstance(policy_action, str) and policy_action.strip() in _GUARD_ACTIONS:
        return policy_action.strip()
    return "block"


def _decision_word(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    word = value.strip().lower()
    return word if word in _GUARD_DECISIONS else None


def _agreeing_native_response(
    native_response: dict[str, object], policy_action: str, event_name: str
) -> str:
    # Make an already-shaped response say what the canonical action says.
    #
    # A response that carries its harness's own decision fields is emitted as
    # it arrived, so those fields -- not the action beside them -- are what
    # the harness honours. An action this client cannot place reads as
    # "block", and without this an "allow" permission decision next to one
    # would still let the call run on a harness that reads the envelope
    # rather than the exit code. The native bridge that answers for this
    # client reconciles the same two fields, so both routes answer one
    # request alike.
    #
    # On an event that gates the call, a decision word this client cannot
    # place names no permission either, so it is written as "deny", and a
    # restrictive action whose envelope carries no decision at all has one
    # inserted: an empty envelope beside a restrictive action is what a
    # harness that reads the envelope rather than the exit code would run on.
    #
    # The envelope is only ever tightened: a restrictive decision beside a
    # permissive action lowers the action, never the other way round.
    compact = _compact(event_name)
    gating = compact in {"permissionrequest", "pretoolcall", "pretooluse", "userpromptsubmit"}
    hook_specific = native_response.get("hookSpecificOutput")
    entries = dict(hook_specific) if isinstance(hook_specific, dict) else None
    has_top = "decision" in native_response
    has_nested = entries is not None and "permissionDecision" in entries
    top = _decision_word(native_response.get("decision")) if has_top else None
    nested = _decision_word(entries.get("permissionDecision")) if has_nested else None
    if gating and has_top and top is None:
        top = "deny"
        native_response["decision"] = "deny"
    if gating and has_nested and nested is None and entries is not None:
        nested = "deny"
        entries["permissionDecision"] = "deny"
    restrictive = policy_action in {"review", "require-reapproval", "sandbox-required", "block"}
    if restrictive and compact == "userpromptsubmit" and top is None:
        top = "block"
        native_response["decision"] = "block"
    elif restrictive and compact in {"permissionrequest", "pretoolcall", "pretooluse"}:
        if entries is None and "hookSpecificOutput" in native_response:
            # The key is there but carries no envelope this client can read,
            # so the decision goes into one the harness can.
            entries = {"hookEventName": event_name}
        if entries is not None and nested is None:
            nested = "deny" if policy_action == "block" else "ask"
            entries["permissionDecision"] = nested
        if HARNESS in {"grok", "openclaw"} and top is None:
            top = "deny"
            native_response["decision"] = "deny"
    words = [word for word in (top, nested) if word is not None]
    if policy_action in {"allow", "warn"}:
        if any(word in {"deny", "block"} for word in words):
            policy_action = "block"
        elif "ask" in words:
            policy_action = "review"
    if policy_action == "block":
        # A decision field this client cannot place is handled the way an
        # unplaceable action is: it names no permission, so it reads as deny.
        if top is not None:
            native_response["decision"] = "block" if top == "block" else "deny"
        if nested is not None and entries is not None:
            entries["permissionDecision"] = "deny"
    elif policy_action in {"review", "require-reapproval", "sandbox-required"}:
        if top is not None:
            native_response["decision"] = "block" if top == "block" else "deny"
        if nested == "allow" and entries is not None:
            entries["permissionDecision"] = "ask"
    if entries is not None:
        native_response["hookSpecificOutput"] = entries
    if "policy_action" in native_response and native_response["policy_action"] != policy_action:
        # The action travels with the decision it produced, so a reader that
        # looks at the action alone cannot read permission out of a stale or
        # unplaceable value the decision fields no longer agree with.
        native_response["policy_action"] = policy_action
    return policy_action


def _permission_decision(policy_action: str) -> str | None:
    policy_action = _canonical_policy_action(policy_action)
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
    policy_action = _canonical_policy_action(policy_action)
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


_MUSE_WAITABLE_ACTIONS = frozenset({"review", "require-reapproval"})
_MUSE_RESTRICTIVE_ACTIONS = frozenset({"review", "require-reapproval", "sandbox-required", "block"})
# Events where Guard's answer decides whether the work happens. An answer that
# names no verdict is restrictive on these and silence everywhere else.
_MUSE_DECIDING_EVENTS = frozenset({"pretooluse", "pretoolcall", "permissionrequest", "userpromptsubmit"})
_MUSE_GATING_EVENTS = frozenset({"pretooluse", "pretoolcall", "permissionrequest", "permissionrequestv2"})
_MUSE_SESSION_CONTEXT = "HOL Guard protection is active for this workspace."
_MUSE_UNREADABLE_VERDICT = "HOL Guard could not read a verdict for this action."


def _muse_behavior(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    word = value.strip().lower()
    if word == "allow":
        return "allow"
    if word in {"deny", "block"}:
        return "block"
    if word == "ask":
        return "review"
    return None


def _muse_action(daemon_response: dict[str, object]) -> str | None:
    # Guard's action for this answer, or None when it names no verdict at all.
    # An action this client cannot place reads as "block", the way every other
    # unplaceable action here does.
    policy_action = daemon_response.get("policy_action")
    if isinstance(policy_action, str) and policy_action.strip():
        return _canonical_policy_action(policy_action)
    word = _muse_behavior(daemon_response.get("decision"))
    if word is not None:
        return word
    hook_specific = daemon_response.get("hookSpecificOutput")
    if isinstance(hook_specific, dict):
        word = _muse_behavior(hook_specific.get("permissionDecision"))
        if word is not None:
            return word
        # The PermissionRequest envelope carries its verdict one level deeper.
        nested = hook_specific.get("decision")
        if isinstance(nested, dict):
            word = _muse_behavior(nested.get("behavior"))
            if word is not None:
                return word
    proceed = daemon_response.get("continue")
    if proceed is True:
        return "allow"
    if proceed is False:
        return "block"
    return None


def _muse_reason(daemon_response: dict[str, object], action: str | None) -> str:
    for key in ("reason", "permission_decision_reason"):
        value = daemon_response.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    hook_specific = daemon_response.get("hookSpecificOutput")
    if isinstance(hook_specific, dict):
        value = hook_specific.get("permissionDecisionReason")
        if isinstance(value, str) and value.strip():
            return value.strip()
    if action is None:
        return _MUSE_UNREADABLE_VERDICT
    return "HOL Guard blocked this action (" + action + ")"


def _muse_context(daemon_response: dict[str, object]) -> str | None:
    hook_specific = daemon_response.get("hookSpecificOutput")
    if isinstance(hook_specific, dict):
        value = hook_specific.get("additionalContext")
        if isinstance(value, str) and value.strip():
            return value.strip()
    value = daemon_response.get("additional_context")
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _muse_payload(payload: dict[str, object]) -> tuple[str, str, int]:
    return json.dumps(payload, ensure_ascii=True, separators=(",", ":")), "", 0


def _muse_native(daemon_response: dict[str, object], event_name: str) -> tuple[str, str, int]:
    # Muse's wire contract, answered here the way the resident bridge answers
    # it. A permitted call is empty stdout and exit 0: Muse rejects an envelope
    # that says allow without the reviewed input, so this client never writes a
    # bare allow. Only an event that gates the call carries a verdict; an
    # observation event carries Guard's note as context or nothing at all.
    action = _muse_action(daemon_response)
    compact = _compact(event_name)
    restrictive = compact in _MUSE_DECIDING_EVENTS if action is None else action in _MUSE_RESTRICTIVE_ACTIONS
    reason = _muse_reason(daemon_response, action)
    if compact in {"userpromptsubmit", "userpromptsubmitted"}:
        if restrictive:
            return _muse_payload({"decision": "block", "reason": reason})
        context = _muse_context(daemon_response)
        if context is None:
            return "", "", 0
        prompt_entries = {"hookEventName": "UserPromptSubmit", "additionalContext": context}
        return _muse_payload({"hookSpecificOutput": prompt_entries})
    if compact in _MUSE_GATING_EVENTS:
        if not restrictive:
            return "", "", 0
        if compact.startswith("permissionrequest") and action in _MUSE_WAITABLE_ACTIONS:
            # Muse raises its own approval prompt for a call its PreToolUse
            # hook already sent to Guard; that verdict stays the boundary.
            return "", "", 0
        gating = "PreToolUse" if compact in {"pretooluse", "pretoolcall"} else "PermissionRequest"
        payload: dict[str, object] = {
            "decision": "deny",
            # The action travels with the decision so the approval wait below
            # can tell a review it may resume from a block it may not.
            "policy_action": action or "block",
            "reason": reason,
            "hookSpecificOutput": {
                "hookEventName": gating,
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            },
        }
        _copy_approval_metadata(daemon_response, payload)
        return _muse_payload(payload)
    context = _muse_context(daemon_response)
    if context is None and restrictive:
        context = reason
    if context is None and compact == "sessionstart":
        context = _MUSE_SESSION_CONTEXT
    if context is None:
        return "", "", 0
    canonical = {"sessionstart": "SessionStart", "stop": "Stop"}.get(compact, "PostToolUse")
    return _muse_payload({"hookSpecificOutput": {"hookEventName": canonical, "additionalContext": context}})


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
    if HARNESS == "muse":
        return _muse_native(daemon_response, event_name)
    if HARNESS == "hermes":
        policy_action, reason = _hermes_policy(daemon_response)
        decision = "allow" if policy_action in {"allow", "warn"} else "block"
        payload = {"decision": decision, "reason": reason}
        stdout = json.dumps(payload, ensure_ascii=True, separators=(",", ":"))
        return stdout, "", 2 if decision == "block" else 0
    if "hookSpecificOutput" in daemon_response or "decision" in daemon_response:
        native_response = dict(daemon_response)
        policy = _agreeing_native_response(
            native_response,
            _canonical_policy_action(native_response.get("policy_action") or "block"),
            event_name,
        )
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
    policy_action = _canonical_policy_action(daemon_response.get("policy_action") or "block")
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
    # Muse reads the JSON envelope on exit 0; exit 2 would discard it
    # and substitute stderr, so its deny travels in the envelope.
    return {
        "hookSpecificOutput": {
            "hookEventName": event_name,
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }, (0 if HARNESS == "muse" else 2)


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
