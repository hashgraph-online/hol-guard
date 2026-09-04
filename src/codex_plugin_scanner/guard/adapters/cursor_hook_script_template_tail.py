"""Second half of the generated Cursor hook script template."""

from __future__ import annotations

HOOK_SCRIPT_TEMPLATE_TAIL = """def _recording_only_from_guard_home(workspace: str | None = None) -> bool:
    try:
        from codex_plugin_scanner.guard.config import load_guard_config
        from codex_plugin_scanner.guard.protection_posture import protection_is_off

        workspace_path = Path(workspace) if workspace else None
        config = load_guard_config(Path(GUARD_HOME), workspace=workspace_path)
        return protection_is_off(posture=config.protection_posture, mode=config.mode)
    except Exception:
        return False


def _cursor_permission(policy_action: str, guard_payload: dict[str, object], workspace: str | None = None) -> str:
    if _recording_only_from_guard_home(workspace):
        return "allow"
    reason_code = str(guard_payload.get("reason_code") or "")
    try:
        from codex_plugin_scanner.guard.daemon.hook_availability_policy import hook_reason_continues_session

        if hook_reason_continues_session(reason_code):
            return "allow"
    except Exception:
        pass
    hook_output = guard_payload.get("hookSpecificOutput")
    if isinstance(hook_output, dict) and hook_output.get("permissionDecision") == "allow":
        return "allow"
    if guard_payload.get("decision") in {"allow", "warn"}:
        return "allow"
    if policy_action not in GUARD_ACTIONS:
        return "deny"
    if policy_action in {"block", "sandbox-required"}:
        return "deny"
    if policy_action in {"require-reapproval", "review"}:
        return "ask"
    return "allow"


def _emit_cursor_response(
    *,
    hook_event_name: str,
    policy_action: str,
    guard_payload: dict[str, object],
    workspace: str | None = None,
) -> tuple[dict[str, object], int]:
    permission = _cursor_permission(policy_action, guard_payload, workspace)
    reason = _cursor_reason(guard_payload)
    if hook_event_name.strip().lower() == "beforereadfile":
        read_permission = "deny" if permission in {"deny", "ask"} else "allow"
        response = {
            "permission": read_permission,
        }
        if read_permission == "deny":
            response["user_message"] = reason
        return response, 2 if read_permission == "deny" else 0
    response: dict[str, object] = {"permission": permission}
    if permission != "allow":
        response["user_message"] = reason
        response["agent_message"] = reason
    exit_code = 2 if permission == "deny" else 0
    return response, exit_code


def _cursor_generation_id(payload: Mapping[str, object]) -> str | None:
    for key in ("generation_id", "generationId"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _cursor_conversation_id(payload: Mapping[str, object]) -> str | None:
    for key in ("conversation_id", "conversationId", "session_id", "sessionId"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    session_id = os.environ.get("CURSOR_SESSION_ID")
    if isinstance(session_id, str) and session_id.strip():
        return session_id.strip()
    return None


def _normalize_cursor_shell_command(command: str) -> str:
    stripped = command.strip()
    if not stripped or len(stripped) > 8192:
        return stripped
    lowered = stripped.lower()
    needle = "lean-ctx"
    start = 0
    while True:
        idx = lowered.find(needle, start)
        if idx == -1:
            return stripped
        if idx == 0 or stripped[idx - 1] == "/":
            tail = stripped[idx + len(needle) :].lstrip()
            if tail.startswith("-c"):
                rest = tail[2:].lstrip()
                try:
                    tokens = shlex.split(rest, posix=True, comments=False)
                except ValueError:
                    tokens = None
                if tokens:
                    inner = tokens[0]
                    suffix = tokens[1:]
                    return " ".join((inner, *suffix)) if suffix else inner
                if rest.startswith("'"):
                    parts = []
                    index = 1
                    while index < len(rest):
                        character = rest[index]
                        if character != "'":
                            parts.append(character)
                            index += 1
                            continue
                        if index + 3 < len(rest) and rest[index : index + 4] == "'\\''":
                            parts.append("'")
                            index += 4
                            continue
                        inner = "".join(parts)
                        suffix = rest[index + 1 :].lstrip()
                        return " ".join((inner, suffix)) if suffix else inner
                return stripped
        start = idx + 1
    return stripped


# Installed hook helpers below mirror cursor_native_approval.py; keep both copies in sync.


def _cursor_hook_payload_is_mcp_execution(payload: Mapping[str, object]) -> bool:
    source_event = payload.get("cursor_source_hook_event")
    if isinstance(source_event, str) and source_event.strip().lower() == "beforemcpexecution":
        return True
    for key in ("hook_event_name", "hookEventName", "hook_name", "hookName", "event", "eventName"):
        value = payload.get(key)
        if isinstance(value, str):
            lowered = value.strip().lower()
            if lowered in {"beforemcpexecution", "aftermcpexecution"}:
                return True
    return False


def _is_shell_wrapper_command(command: str) -> bool:
    stripped = command.strip()
    if not stripped:
        return False
    try:
        parts = shlex.split(stripped, posix=True, comments=False)
    except ValueError:
        return False
    if not parts:
        return False
    binary = Path(parts[0]).name.lower()
    if binary == "lean-ctx":
        return True
    if binary not in {"ash", "bash", "dash", "fish", "sh", "zsh"}:
        return False
    return len(parts) > 1 and parts[1] == "-c"


def _nested_cursor_shell_command(tool_input: Mapping[str, object]) -> str | None:
    for key in ("command", "cmd", "shell_command", "shellCommand"):
        value = tool_input.get(key)
        if isinstance(value, str) and value.strip():
            return _normalize_cursor_shell_command(value)
    return None


def _cursor_shell_command(payload: Mapping[str, object]) -> str | None:
    tool_input = payload.get("tool_input")
    nested_command: str | None = None
    if isinstance(tool_input, dict):
        nested_command = _nested_cursor_shell_command(tool_input)
    command = payload.get("command")
    top_level: str | None = None
    if isinstance(command, str) and command.strip():
        top_level = _normalize_cursor_shell_command(command)
    if _cursor_hook_payload_is_mcp_execution(payload):
        if nested_command is not None:
            return nested_command
        return top_level
    if nested_command is not None and (
        top_level is None or (isinstance(command, str) and _is_shell_wrapper_command(command))
    ):
        return nested_command
    if top_level is not None:
        return top_level
    return nested_command


def _cursor_shell_binding_path(conversation_id: str, command: str) -> Path:
    cleaned = conversation_id.strip()
    if not cleaned or "/" in cleaned or "\\\\" in cleaned or cleaned in {".", ".."}:
        segment = hashlib.sha256(cleaned.encode("utf-8")).hexdigest()[:32] if cleaned else "missing-conversation"
    else:
        segment = cleaned
    normalized_command = _normalize_cursor_shell_command(command)
    fingerprint = hashlib.sha256(normalized_command.encode("utf-8")).hexdigest()[:24]
    return Path(GUARD_HOME) / "cursor-shell-bindings" / segment / fingerprint


def _read_cursor_shell_binding_file(conversation_id: str, command: str) -> str | None:
    binding_path = _cursor_shell_binding_path(conversation_id, command)
    try:
        binding = binding_path.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return binding or None


def _resolve_approval_binding(payload: Mapping[str, object]) -> str | None:
    binding = _cursor_generation_id(payload)
    if binding is not None:
        return binding
    conversation_id = _cursor_conversation_id(payload)
    command = _cursor_shell_command(payload)
    if conversation_id is None or command is None:
        return None
    return _read_cursor_shell_binding_file(conversation_id, command)


def _load_cursor_hook_attestation_secret() -> bytes | None:
    secret_path = Path(GUARD_HOME) / "secrets" / "cursor-hook-attestation.key"
    try:
        secret = secret_path.read_bytes()
    except OSError:
        return None
    return secret or None


def _compute_cursor_after_observer_proof(
    payload: Mapping[str, object],
    observer_event: str,
    approval_binding: str | None = None,
) -> str | None:
    conversation_id = _cursor_conversation_id(payload)
    command = _cursor_shell_command(payload)
    resolved_binding = approval_binding or _resolve_approval_binding(payload)
    secret = _load_cursor_hook_attestation_secret()
    if conversation_id is None or command is None or resolved_binding is None or secret is None:
        return None
    message = chr(0).join(
        (conversation_id, command, resolved_binding, observer_event.strip())
    ).encode("utf-8")
    return hmac.new(secret, message, hashlib.sha256).hexdigest()


def _cursor_availability_response(
    payload: Mapping[str, object],
    *,
    hook_event_name: str,
    workspace: str | None,
) -> tuple[dict[str, object], int]:
    workspace_path = Path(workspace) if workspace else None
    recording_only = _recording_only_from_guard_home(workspace)
    try:
        from codex_plugin_scanner.guard.daemon.hook_availability_policy import cursor_fallback_permission

        return cursor_fallback_permission(
            payload,
            hook_event_name=hook_event_name,
            workspace=workspace_path,
            guard_home=Path(GUARD_HOME),
            recording_only=recording_only,
        )
    except Exception:
        compact = hook_event_name.strip().lower().replace("_", "").replace("-", "")
        if compact in {"aftershellexecution", "aftermcpexecution"}:
            return {}, 0
        return {"permission": "allow"}, 0


_LAST_HOOK_EVENT_NAME = ""


def _cursor_hook_event_from_argv() -> str:
    args = sys.argv
    try:
        index = args.index("--cursor-hook-event")
    except ValueError:
        return ""
    if index + 1 >= len(args):
        return ""
    value = str(args[index + 1]).strip()
    return value


def _exit_unparseable_cursor_input() -> int:
    event_name = _cursor_hook_event_from_argv() or _LAST_HOOK_EVENT_NAME
    try:
        from codex_plugin_scanner.guard.daemon.hook_availability_policy import (
            cursor_unparseable_input_permission,
        )

        response, code = cursor_unparseable_input_permission(
            event_name,
            recording_only=_recording_only_from_guard_home(),
        )
    except Exception:
        compact = event_name.strip().lower().replace("_", "").replace("-", "")
        if compact in {"aftershellexecution", "aftermcpexecution"}:
            print("{}")
            return 0
        allow = _recording_only_from_guard_home() or compact in {"beforereadfile", ""}
        print(json.dumps({"permission": "allow" if allow else "deny"}))
        return 0 if allow else 2
    print("{}" if not response else json.dumps(response))
    return code


def main() -> int:
    try:
        return _main_inner()
    except Exception:
        return _exit_unparseable_cursor_input()


def _main_inner() -> int:
    global _LAST_HOOK_EVENT_NAME
    argv_event = _cursor_hook_event_from_argv()
    if argv_event:
        _LAST_HOOK_EVENT_NAME = argv_event
    raw = sys.stdin.read()
    if not raw.strip():
        return _exit_unparseable_cursor_input()
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return _exit_unparseable_cursor_input()
    if not isinstance(payload, dict):
        return _exit_unparseable_cursor_input()
    inferred = _infer_cursor_hook_event_name(payload)
    hook_event_name = str(inferred.get("hook_event_name") or inferred.get("hookEventName") or "preToolUse")
    _LAST_HOOK_EVENT_NAME = hook_event_name
    prepared = _prepare_cursor_hook_payload(inferred)
    workspace = _workspace_from_cursor_input(prepared)
    guard_argv = list(GUARD_HOOK_ARGV)
    if workspace:
        if "--workspace" in guard_argv:
            workspace_index = guard_argv.index("--workspace")
            if workspace_index + 1 < len(guard_argv):
                guard_argv[workspace_index + 1] = workspace
        else:
            guard_argv.extend(["--workspace", workspace])
    guard_env = _hook_process_env()
    guard_env["HOL_GUARD_MANAGED_CURSOR_HOOK"] = "1"
    if hook_event_name.strip().lower() in {"aftershellexecution", "aftermcpexecution"}:
        approval_binding = _resolve_approval_binding(prepared)
        proof = _compute_cursor_after_observer_proof(prepared, hook_event_name, approval_binding)
        if approval_binding:
            guard_env["HOL_GUARD_CURSOR_APPROVAL_BINDING"] = approval_binding
        if proof:
            guard_env["HOL_GUARD_CURSOR_AFTER_SHELL_PROOF"] = proof
    payload_json = json.dumps(prepared)
    deadline_monotonic = time.monotonic() + GUARD_HOOK_TIMEOUT_SECONDS
    daemon_result, daemon_failure_kind = _daemon_hook_result(
        payload_json,
        deadline_monotonic=deadline_monotonic,
        workspace=workspace,
        hook_env_overlay=_daemon_hook_env_overlay(guard_env),
    )
    if daemon_result is None:
        recover_kind = daemon_failure_kind or "transport-failure"
        if _recording_only_from_guard_home(workspace):
            availability, availability_code = _cursor_availability_response(
                prepared,
                hook_event_name=hook_event_name,
                workspace=workspace,
            )
            print(json.dumps(availability))
            return availability_code
        compact_event = hook_event_name.strip().lower().replace("_", "").replace("-", "")
        if compact_event == "beforereadfile":
            try:
                from codex_plugin_scanner.guard.daemon.hook_availability_policy import hook_action_is_emergency_safe

                workspace_path = Path(workspace) if workspace else None
                check_payload = dict(prepared)
                check_payload["hook_event_name"] = "PreToolUse"
                check_payload.setdefault("tool_name", "Read")
                safe_read = hook_action_is_emergency_safe(check_payload, workspace=workspace_path)
            except Exception:
                safe_read = False
            if safe_read:
                availability, availability_code = _cursor_availability_response(
                    prepared,
                    hook_event_name=hook_event_name,
                    workspace=workspace,
                )
                print(json.dumps(availability))
                return availability_code
        if recover_kind != "overload":
            _run_guard_recovery(
                recover_kind,
                guard_env=guard_env,
                deadline_monotonic=deadline_monotonic,
            )
            daemon_result, _retry_failure_kind = _daemon_hook_result(
                payload_json,
                deadline_monotonic=deadline_monotonic,
                workspace=workspace,
                hook_env_overlay=_daemon_hook_env_overlay(guard_env),
            )
    try:
        if daemon_result is not None:
            proc = subprocess.CompletedProcess(
                [*_resolved_guard_cli(), *guard_argv],
                daemon_result[0],
                stdout=daemon_result[1],
                stderr=daemon_result[2],
            )
        else:
            proc = _run_guard_fallback(
                guard_argv,
                payload_json=payload_json,
                guard_env=guard_env,
                deadline_monotonic=deadline_monotonic,
            )
    except (subprocess.TimeoutExpired, Exception):
        response, exit_code = _cursor_availability_response(
            prepared,
            hook_event_name=hook_event_name,
            workspace=workspace,
        )
        print(json.dumps(response))
        return exit_code
    guard_payload: dict[str, object] = {}
    if proc.stdout.strip():
        try:
            parsed = json.loads(proc.stdout)
            if isinstance(parsed, dict):
                guard_payload = parsed
        except json.JSONDecodeError:
            guard_payload = {}
    if hook_event_name.strip().lower() in {"aftershellexecution", "aftermcpexecution"}:
        print("{}")
        return 0
    raw_policy_action = guard_payload.get("policy_action")
    if not isinstance(raw_policy_action, str) or raw_policy_action not in GUARD_ACTIONS:
        if _recording_only_from_guard_home(workspace):
            print(json.dumps({"permission": "allow"}))
            return 0
        response, exit_code = _cursor_availability_response(
            prepared,
            hook_event_name=hook_event_name,
            workspace=workspace,
        )
        print(json.dumps(response))
        return exit_code
    policy_action = raw_policy_action
    if proc.returncode != 0 and not guard_payload:
        response, exit_code = _cursor_availability_response(
            prepared,
            hook_event_name=hook_event_name,
            workspace=workspace,
        )
        print(json.dumps(response))
        return exit_code
    response, exit_code = _emit_cursor_response(
        hook_event_name=hook_event_name,
        policy_action=policy_action,
        guard_payload=guard_payload,
        workspace=workspace,
    )
    print(json.dumps(response))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
"""
