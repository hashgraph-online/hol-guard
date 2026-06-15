"""Guard CLI helper definitions."""

# fmt: off
# ruff: noqa: F403, F405, I001

from __future__ import annotations

from ..models import GuardAction
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ._commands_shared import _NAMED_SECURITY_LEVELS, _SETTINGS_POLICY_RISK_ACTIONS, _guard_risk_action_key
    from .commands_support_hook_payload import _copilot_hook_permission_decision
    from .commands_support_runtime_policy import _ensure_terminal_punctuation, _native_hook_reason
    from .commands_support_runtime_resolution import _canonical_harness_name


from ._commands_shared import *
from .commands_parser_helpers import *


def _guard_action_or_default(value: str, default: GuardAction) -> GuardAction:
    if value == "allow":
        return "allow"
    if value == "warn":
        return "warn"
    if value == "review":
        return "review"
    if value == "block":
        return "block"
    if value == "sandbox-required":
        return "sandbox-required"
    if value == "require-reapproval":
        return "require-reapproval"
    return default

def _run_approval_password_settings_command(*, args: argparse.Namespace, guard_home: Path) -> dict[str, object]:
    command = str(getattr(args, "settings_approval_password_command", "")).strip().lower()
    if command == "status":
        gate = approval_gate_public_config(guard_home)
        return {"approval_gate": gate.to_dict()}
    if command == "enable":
        gate = approval_gate_public_config(guard_home)
        grant = None
        current_password = getattr(args, "current_password", None)
        totp_code = getattr(args, "totp_code", None)
        if gate.enabled:
            gate_input = ApprovalGateInput(password=current_password, totp_code=totp_code)
            grant = require_high_risk(guard_home, purpose="settings_write", approval_gate_input=gate_input)
        payload: dict[str, object] = {
            "enabled": True,
            "new_password": str(args.new_password),
            "confirm_password": str(args.confirm_password),
        }
        cooldown_seconds = getattr(args, "cooldown_seconds", None)
        if cooldown_seconds is not None:
            payload["cooldown_seconds"] = int(cooldown_seconds)
        payload["strict_all_decisions"] = bool(getattr(args, "strict_all_decisions", False))
        gate_updated = update_approval_gate_settings(guard_home, payload, approval_gate_grant=grant)
        return {"approval_gate": gate_updated.to_dict()}
    if command == "change":
        gate_input = ApprovalGateInput(password=str(args.current_password), totp_code=getattr(args, "totp_code", None))
        grant = require_high_risk(guard_home, purpose="settings_write", approval_gate_input=gate_input)
        gate_updated = update_approval_gate_settings(
            guard_home,
            {
                "enabled": True,
                "new_password": str(args.new_password),
                "confirm_password": str(args.confirm_password),
            },
            approval_gate_grant=grant,
        )
        return {"approval_gate": gate_updated.to_dict()}
    if command == "disable":
        gate_input = ApprovalGateInput(password=str(args.current_password), totp_code=getattr(args, "totp_code", None))
        grant = require_high_risk(guard_home, purpose="settings_write", approval_gate_input=gate_input)
        gate_updated = update_approval_gate_settings(
            guard_home,
            {"enabled": False},
            approval_gate_grant=grant,
        )
        return {"approval_gate": gate_updated.to_dict()}
    raise ValueError("Unsupported approval-password command.")

def _run_approval_totp_settings_command(*, args: argparse.Namespace, guard_home: Path) -> dict[str, object]:
    command = str(getattr(args, "settings_approval_totp_command", "")).strip().lower()
    if command == "status":
        gate = approval_gate_public_config(guard_home)
        return {"approval_gate": gate.to_dict()}
    if command == "enroll":
        enrollment = begin_totp_enrollment(
            guard_home,
            approval_gate_input=ApprovalGateInput(password=str(args.current_password)),
            device_label=str(getattr(args, "device_label", "local-device")),
        )
        return {"enrollment": enrollment, "approval_gate": approval_gate_public_config(guard_home).to_dict()}
    if command == "verify":
        gate = confirm_totp_enrollment(
            guard_home,
            approval_gate_input=ApprovalGateInput(
                password=str(args.current_password),
                totp_code=str(args.code),
            ),
        )
        return {"approval_gate": gate.to_dict()}
    if command == "disable":
        gate = disable_totp(
            guard_home,
            approval_gate_input=ApprovalGateInput(
                password=str(args.current_password),
                totp_code=str(args.code),
            ),
        )
        return {"approval_gate": gate.to_dict()}
    raise ValueError("Unsupported approval-totp command.")

def _update_guard_cli_settings(*, args: argparse.Namespace, config: GuardConfig, guard_home: Path) -> GuardConfig:
    settings_command = getattr(args, "settings_set_command", None)
    gate_input = prompt_for_approval_gate(guard_home, use_cooldown=False)
    approval_gate_grant = require_high_risk(
        guard_home,
        purpose="settings_write",
        approval_gate_input=gate_input,
    )

    def persist_settings(payload: dict[str, object]) -> GuardConfig:
        return update_guard_settings(guard_home, payload, approval_gate_grant=approval_gate_grant)

    if settings_command == "security-level":
        payload: dict[str, object] = {"security_level": args.security_level}
        if args.security_level in _NAMED_SECURITY_LEVELS:
            payload["risk_actions"] = {}
            payload["harness_risk_actions"] = {}
        elif args.security_level == "custom":
            payload["risk_actions"] = _current_effective_risk_actions(config)
        return persist_settings(payload)
    if settings_command == "preset":
        preset = str(args.preset)
        payload_preset: dict[str, object] = {"security_level": preset}
        if preset in _NAMED_SECURITY_LEVELS:
            payload_preset["risk_actions"] = {}
            payload_preset["harness_risk_actions"] = {}
        elif preset == "custom":
            payload_preset["risk_actions"] = _current_effective_risk_actions(config)
        return persist_settings(payload_preset)
    if settings_command == "secret-files":
        action_map = {"ask": "require-reapproval", "warn": "warn", "allow": "allow"}
        mapped = action_map.get(str(args.action), "warn")
        risk_actions = dict(config.risk_actions or {})
        risk_actions["local_secret_read"] = mapped
        return persist_settings({"risk_actions": risk_actions})
    if settings_command == "network":
        action_map_net = {"warn": "warn", "ask": "require-reapproval", "block": "block"}
        mapped_net = action_map_net.get(str(args.action), "warn")
        risk_actions_net = dict(config.risk_actions or {})
        risk_actions_net["network_egress"] = mapped_net
        return persist_settings({"risk_actions": risk_actions_net})
    if settings_command == "encoded-payloads":
        action_map_enc = {"warn": "warn", "ask": "require-reapproval", "block": "block"}
        mapped_enc = action_map_enc.get(str(args.action), "warn")
        risk_actions_enc = dict(config.risk_actions or {})
        risk_actions_enc["encoded_execution"] = mapped_enc
        risk_actions_enc["encoded_exfiltration"] = mapped_enc
        return persist_settings({"risk_actions": risk_actions_enc})
    if settings_command in _SETTINGS_POLICY_RISK_ACTIONS:
        policy = str(getattr(args, "policy", "")).strip().lower()
        mapped_actions = _SETTINGS_POLICY_RISK_ACTIONS[settings_command].get(policy)
        if mapped_actions is None:
            raise ValueError(f"Unsupported Guard settings policy '{policy}' for {settings_command}.")
        risk_actions = dict(config.risk_actions or {})
        risk_actions.update(mapped_actions)
        return persist_settings({"risk_actions": risk_actions})
    if settings_command == "risk":
        risk_class = _guard_risk_action_key(str(args.risk_class))
        action = str(args.action)
        harness = getattr(args, "harness", None)
        if isinstance(harness, str) and harness.strip():
            harness_key = _canonical_harness_name(harness.strip().lower())
            harness_actions = {
                name: dict(values)
                for name, values in (config.harness_risk_actions or {}).items()
                if isinstance(values, dict)
            }
            harness_actions.setdefault(harness_key, {})[risk_class] = _guard_action_or_default(action, "warn")
            return persist_settings(
                {
                    "harness_risk_actions": harness_actions,
                },
            )
        risk_actions = dict(config.risk_actions or {})
        risk_actions[risk_class] = _guard_action_or_default(action, "warn")
        return persist_settings(
            {
                "risk_actions": risk_actions,
            },
        )
    raise ValueError("Unsupported Guard settings command.")

def _current_effective_risk_actions(config: GuardConfig) -> dict[str, str]:
    risk_actions = editable_guard_settings(config).get("risk_actions")
    if isinstance(risk_actions, dict):
        return {
            key: value
            for key, value in risk_actions.items()
            if isinstance(key, str) and isinstance(value, str) and value in VALID_GUARD_ACTIONS
        }
    return {}

def _prompt_requires_hard_block(artifact: GuardArtifact) -> bool:
    prompt_classes = artifact.metadata.get("prompt_request_classes")
    if isinstance(prompt_classes, list):
        return "guard_bypass_intent" in {str(item) for item in prompt_classes}
    prompt_class = artifact.metadata.get("prompt_request_class")
    return isinstance(prompt_class, str) and prompt_class == "guard_bypass_intent"

def _prompt_request_classes(artifact: GuardArtifact) -> set[str]:
    prompt_classes = artifact.metadata.get("prompt_request_classes")
    values = prompt_classes if isinstance(prompt_classes, list) else [artifact.metadata.get("prompt_request_class")]
    return {str(item) for item in values if isinstance(item, str) and item.strip()}

def _native_prompt_context(artifact: GuardArtifact) -> str:
    if _prompt_requires_hard_block(artifact):
        return "HOL Guard blocked this prompt because it asks to bypass or disable Guard."
    prompt_classes = _prompt_request_classes(artifact)
    if "secret_read" in prompt_classes:
        return (
            "HOL Guard flagged this prompt because it asks for direct local secret access and is protecting your "
            "local secrets. "
            "If that is intentional, continue and Guard will ask again on the actual tool call."
        )
    return (
        "HOL Guard flagged this prompt as higher risk. Continue only if you expect the next tool call to need "
        "explicit approval."
    )

def _runtime_artifact_native_reason(artifact: GuardArtifact, response_payload: dict[str, object]) -> str:
    decision_message = _decision_v2_harness_message(response_payload)
    if decision_message is not None and _should_use_decision_v2_harness_message(response_payload, decision_message):
        return decision_message
    if artifact.artifact_type == "prompt_request":
        harness = response_payload.get("harness")
        prompt_classes = _prompt_request_classes(artifact)
        if harness == "codex" and "secret_read" in prompt_classes:
            prompt_summary = artifact.metadata.get("prompt_summary")
            if isinstance(prompt_summary, str) and "credential-looking local file" in prompt_summary:
                return (
                    "HOL Guard stopped this Codex prompt before Codex could open a credential-looking local file. "
                    "Codex does not expose native approval prompts for Read-tool file reads, so Guard blocks this "
                    "request at prompt time."
                )
            return (
                "HOL Guard stopped this Codex prompt before Codex could open a sensitive local file. Codex does not "
                "expose native approval prompts for Read-tool file reads, so Guard blocks this request at prompt time."
            )
        policy_action = response_payload.get("policy_action")
        if policy_action in {"block", "sandbox-required"} and not _prompt_requires_hard_block(artifact):
            return "HOL Guard blocked this prompt because it requests guarded local secret access."
        return _native_prompt_context(artifact)
    path_class = artifact.metadata.get("path_class")
    tool_name = artifact.metadata.get("tool_name")
    if isinstance(path_class, str) and isinstance(tool_name, str):
        harness = response_payload.get("harness")
        policy_action = response_payload.get("policy_action")
        if harness == "claude-code" and policy_action == "require-reapproval":
            return (
                f"HOL Guard intercepted Claude's attempt to use {tool_name} for {path_class} to protect your local "
                "secrets. The approval flow came from HOL Guard, not from Claude alone. HOL Guard will ask you to "
                "choose Allow once, Allow during this session, or Keep blocked before Claude retries this action."
            )
        harness_label = (
            {"claude-code": "Claude", "codex": "Codex"}.get(harness, "the harness")
            if isinstance(harness, str)
            else "the harness"
        )
        return (
            f"HOL Guard blocked {harness_label}'s attempt to use {tool_name} for {path_class} to protect your "
            "local secrets. "
            "This request cannot continue in the current approval flow."
        )
    risk_summary = response_payload.get("risk_summary")
    if isinstance(risk_summary, str) and risk_summary.strip():
        trimmed_summary = risk_summary.strip()
        if len(trimmed_summary) > 180:
            trimmed_summary = f"{trimmed_summary[:177].rstrip()}..."
        action_class = artifact.metadata.get("action_class")
        if (
            action_class == "credential exfiltration shell command"
            and "credential-looking output" not in trimmed_summary.lower()
        ):
            trimmed_summary = f"{trimmed_summary} Guard also detected credential-looking output."
        return f"HOL Guard flagged this request: {trimmed_summary}"
    return "HOL Guard flagged this request for review."

def _decision_v2_harness_message(response_payload: dict[str, object]) -> str | None:
    decision_v2 = response_payload.get("decision_v2_json")
    if not isinstance(decision_v2, Mapping):
        return None
    message = decision_v2.get("harness_message")
    if isinstance(message, str) and message.strip():
        return message.strip()
    return None

def _decision_v2_has_data_flow_signal(response_payload: dict[str, object]) -> bool:
    decision_v2 = response_payload.get("decision_v2_json")
    if not isinstance(decision_v2, Mapping):
        return False
    signals = decision_v2.get("signals")
    if not isinstance(signals, list):
        return False
    for item in signals:
        if not isinstance(item, Mapping):
            continue
        detector = item.get("detector")
        signal_id = item.get("signal_id")
        if detector == "data_flow.exfiltration":
            return True
        if isinstance(signal_id, str) and signal_id.startswith("data-flow:"):
            return True
    return False

def _should_use_decision_v2_harness_message(response_payload: dict[str, object], message: str) -> bool:
    if _decision_v2_has_data_flow_signal(response_payload):
        return True
    generic_messages = {
        "HOL Guard blocked this action.",
        "HOL Guard wants this action reviewed and run in a sandboxed path.",
    }
    if message in generic_messages:
        return False
    return not message.startswith("HOL Guard needs a fresh approval because this action changed.")

def _claude_prompt_additional_context(
    *,
    harness: str,
    event_name: str,
    policy_action: str,
    artifact: GuardArtifact,
    native_reason: str,
) -> str | None:
    if _canonical_harness_name(harness) != "claude-code":
        return None
    if event_name != "UserPromptSubmit":
        return None
    if policy_action != "require-reapproval":
        return None
    if _prompt_requires_hard_block(artifact):
        return None
    briefing_sentence = "HOL Guard will intercept Claude's next sensitive action and open a branded approval question."
    if "secret_read" in _prompt_request_classes(artifact):
        briefing_sentence = (
            "HOL Guard will intercept Claude's next attempt to access local secrets and open a branded approval "
            "question to protect you."
        )
    return (
        f"{_ensure_terminal_punctuation(native_reason)} "
        "Do not ask for approval at the prompt stage. Attempt the intended sensitive tool once so HOL Guard can "
        "evaluate the exact tool, path, and arguments, then route that concrete action into a HOL Guard approval "
        "question with Allow once, Allow during this session, and Keep blocked. First tell the user exactly: "
        f"'{briefing_sentence}' "
        "Attempt that sensitive tool at most once. If HOL Guard or Claude denies it, do not retry the same sensitive "
        "action automatically. Instead, tell the user approval is required in Claude to continue."
    )

def _claude_prompt_system_message(
    *,
    event_name: str,
    policy_action: str,
    artifact: GuardArtifact,
    native_reason: str,
) -> str | None:
    if event_name == "UserPromptSubmit":
        if policy_action == "require-reapproval" and not _prompt_requires_hard_block(artifact):
            if "secret_read" in _prompt_request_classes(artifact):
                return (
                    "HOL Guard intercepted this prompt because it asks Claude to access local secrets. "
                    "If Claude asks to continue, HOL Guard will route the decision through a branded approval prompt."
                )
            return (
                "HOL Guard intercepted this prompt because it leads to a sensitive action. "
                "If Claude asks to continue, HOL Guard will route the decision through a branded approval prompt."
            )
        if policy_action in {"block", "sandbox-required"}:
            return _ensure_terminal_punctuation(native_reason)
        return None
    if event_name == "PreToolUse" and policy_action in {"require-reapproval", "block", "sandbox-required"}:
        return _ensure_terminal_punctuation(native_reason)
    return None

def _codex_prompt_block_system_message(*, policy_action: str, native_reason: str) -> str | None:
    if policy_action not in {"block", "sandbox-required", "require-reapproval"}:
        return None
    if "open hol guard" not in native_reason.lower():
        return None
    return f"HOL Guard paused your Codex prompt. {native_reason}"

def _copilot_hook_reason(*values: object | None) -> str:
    reason = _native_hook_reason(*values)
    if reason.startswith("Guard "):
        reason = f"HOL {reason}"
    if "approve" in reason.lower():
        return reason
    return f"{reason} Approve it in HOL Guard, then retry."

def _guard_rerun_command(args: argparse.Namespace) -> str:
    command = ["hol-guard", "run", str(args.harness)]
    _append_guard_context_args(command, args)
    default_action = getattr(args, "default_action", None)
    if isinstance(default_action, str) and default_action:
        command.extend(["--default-action", default_action])
    passthrough_args = getattr(args, "passthrough_args", [])
    if isinstance(passthrough_args, list):
        for value in passthrough_args:
            if isinstance(value, str) and value:
                command.extend(["--arg", value])
    return _shell_join(command)

def _guard_diff_command(args: argparse.Namespace) -> str:
    command = ["hol-guard", "diff", str(args.harness)]
    _append_guard_context_args(command, args)
    return _shell_join(command)

def _guard_approvals_command(args: argparse.Namespace) -> str:
    command = ["hol-guard", "approvals"]
    _append_guard_context_args(command, args)
    return _shell_join(command)

def _shell_join(command: list[str]) -> str:
    if sys.platform.startswith("win"):
        return subprocess.list2cmdline(command)
    return shlex.join(command)

def _append_guard_context_args(command: list[str], args: argparse.Namespace) -> None:
    for option_name in ("home", "guard_home", "workspace"):
        value = getattr(args, option_name, None)
        if isinstance(value, str) and value:
            flag = f"--{option_name.replace('_', '-')}"
            command.extend([flag, value])

def _write_json_line(payload: dict[str, object], *, output_stream: TextIO | None = None) -> None:
    stream = output_stream or sys.stdout
    stream.write(f"{json.dumps(payload, separators=(',', ':'))}\n")
    stream.flush()

def _emit_copilot_hook_response(
    *,
    policy_action: str,
    reason: str,
    output_stream: TextIO | None = None,
) -> None:
    payload: dict[str, object] = {"permissionDecision": _copilot_hook_permission_decision(policy_action)}
    if payload["permissionDecision"] != "allow":
        payload["permissionDecisionReason"] = reason
    _write_json_line(payload, output_stream=output_stream)

def _emit_copilot_permission_request_response(
    *,
    behavior: str,
    message: str | None = None,
    interrupt: bool | None = None,
    output_stream: TextIO | None = None,
) -> None:
    payload: dict[str, object] = {"behavior": behavior}
    if isinstance(message, str) and message.strip():
        payload["message"] = message.strip()
    if isinstance(interrupt, bool):
        payload["interrupt"] = interrupt
    _write_json_line(payload, output_stream=output_stream)

__all__ = [
    "_append_guard_context_args",
    "_claude_prompt_additional_context",
    "_claude_prompt_system_message",
    "_codex_prompt_block_system_message",
    "_copilot_hook_reason",
    "_current_effective_risk_actions",
    "_decision_v2_harness_message",
    "_decision_v2_has_data_flow_signal",
    "_emit_copilot_hook_response",
    "_emit_copilot_permission_request_response",
    "_guard_approvals_command",
    "_guard_diff_command",
    "_guard_rerun_command",
    "_native_prompt_context",
    "_prompt_request_classes",
    "_prompt_requires_hard_block",
    "_run_approval_password_settings_command",
    "_run_approval_totp_settings_command",
    "_runtime_artifact_native_reason",
    "_shell_join",
    "_should_use_decision_v2_harness_message",
    "_update_guard_cli_settings",
    "_write_json_line",
]
