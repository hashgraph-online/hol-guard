"""Guard CLI helper definitions."""

# fmt: off
# ruff: noqa: F403, F405

from __future__ import annotations

import importlib
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..models import GuardAction
    from ._commands_shared import _NAMED_SECURITY_LEVELS, _SETTINGS_POLICY_RISK_ACTIONS, _guard_risk_action_key


from ..action_lattice import coerce_guard_action
from ..package_firewall_entitlement import package_firewall_entitlement_or_denied
from ._commands_shared import *
from .commands_parser_helpers import *


def _runtime_policy_module():
    return importlib.import_module(".commands_support_runtime_policy", __package__)


def _runtime_resolution_module():
    return importlib.import_module(".commands_support_runtime_resolution", __package__)


def _canonical_harness_name(value: str) -> str:
    return _runtime_resolution_module()._canonical_harness_name(value)


def _ensure_terminal_punctuation(message: str) -> str:
    return _runtime_policy_module()._ensure_terminal_punctuation(message)


def _native_hook_reason(*values: object | None) -> str:
    return _runtime_policy_module()._native_hook_reason(*values)


def _guard_action_from_cli(value: object) -> GuardAction:
    normalized = str(value).strip()
    action = coerce_guard_action(normalized)
    if action is not None:
        return action
    raise ValueError(f"Unsupported Guard action '{normalized}'.")

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
        gate_input = ApprovalGateInput(
            password=getattr(args, "current_password", None),
            totp_code=getattr(args, "totp_code", None),
        )
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
        gate_input = ApprovalGateInput(
            password=getattr(args, "current_password", None),
            totp_code=getattr(args, "totp_code", None),
        )
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
                password=getattr(args, "current_password", None),
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
        entitlement = package_firewall_entitlement_or_denied(GuardStore(guard_home))
        return update_guard_settings(
            guard_home,
            payload,
            approval_gate_grant=approval_gate_grant,
            cloud_sync_entitled=bool(entitlement.get("allowed")),
        )

    if settings_command == "protection":
        from ..harness_posture import protection_settings_payload

        return persist_settings(
            protection_settings_payload(
                getattr(args, "protection_posture", None),
                harness=getattr(args, "harness", None),
                inherit=bool(getattr(args, "inherit", False)),
            )
        )
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
        action = _guard_action_from_cli(args.action)
        harness = getattr(args, "harness", None)
        if isinstance(harness, str) and harness.strip():
            harness_key = _canonical_harness_name(harness.strip().lower())
            harness_actions = {
                name: dict(values)
                for name, values in (config.harness_risk_actions or {}).items()
                if isinstance(values, dict)
            }
            harness_actions.setdefault(harness_key, {})[risk_class] = action
            return persist_settings(
                {
                    "harness_risk_actions": harness_actions,
                },
            )
        risk_actions = dict(config.risk_actions or {})
        risk_actions[risk_class] = action
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
    return _claude_prompt_briefing(native_reason, secret="secret_read" in _prompt_request_classes(artifact))


def _claude_prompt_briefing(native_reason: str, *, secret: bool) -> str:
    """What Claude is told to do before a paused prompt's sensitive action."""

    briefing_sentence = "HOL Guard will intercept Claude's next sensitive action and open a branded approval question."
    if secret:
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


def _claude_prompt_intercept_message(*, secret: bool) -> str:
    """Why Claude paused a sensitive prompt it may still approve."""

    cause = "asks Claude to access local secrets" if secret else "leads to a sensitive action"
    return (
        f"HOL Guard intercepted this prompt because it {cause}. "
        "If Claude asks to continue, HOL Guard will route the decision through a branded approval prompt."
    )


def _claude_prompt_system_message(
    *,
    event_name: str,
    policy_action: str,
    artifact: GuardArtifact,
    native_reason: Callable[[], str],
) -> str | None:
    """The system message Claude is shown, or ``None``.

    The reason is read through a callable so a pass that needs no message
    never composes one.
    """

    if event_name == "UserPromptSubmit":
        if policy_action == "require-reapproval" and not _prompt_requires_hard_block(artifact):
            return _claude_prompt_intercept_message(secret="secret_read" in _prompt_request_classes(artifact))
        if policy_action in {"block", "sandbox-required"}:
            return _ensure_terminal_punctuation(native_reason())
        return None
    if event_name == "PreToolUse" and policy_action in {"require-reapproval", "block", "sandbox-required"}:
        return _ensure_terminal_punctuation(native_reason())
    return None

def _codex_prompt_block_system_message(*, policy_action: str, native_reason: Callable[[], str]) -> str | None:
    """What Codex is told about a paused prompt, or ``None``.

    The reason is read through a callable so a prompt that keeps running
    never composes one.
    """

    if policy_action not in {"review", "require-reapproval", "sandbox-required", "block"}:
        return None
    reason = native_reason()
    if "open hol guard" not in reason.lower():
        return None
    return f"HOL Guard paused your Codex prompt. {reason}"

def _guard_rerun_command(args: argparse.Namespace) -> str:
    command = ["hol-guard", "run", str(args.harness)]
    _append_guard_context_args(command, args)
    default_action = getattr(args, "default_action", None)
    if isinstance(default_action, str) and default_action:
        command.extend(["--default-action", default_action])
    grok_executable = getattr(args, "grok_executable", None)
    if isinstance(grok_executable, str) and grok_executable:
        command.extend(["--grok-executable", grok_executable])
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
    # stdout is the harness delivery channel; approval payloads must reach the operator.
    stream.write(f"{json.dumps(payload, separators=(',', ':'))}\n")  # codeql[py/clear-text-logging-sensitive-data]
    stream.flush()

__all__ = [
    "_append_guard_context_args",
    "_claude_prompt_additional_context",
    "_claude_prompt_briefing",
    "_claude_prompt_intercept_message",
    "_claude_prompt_system_message",
    "_codex_prompt_block_system_message",
    "_current_effective_risk_actions",
    "_guard_approvals_command",
    "_guard_diff_command",
    "_guard_rerun_command",
    "_prompt_request_classes",
    "_prompt_requires_hard_block",
    "_run_approval_password_settings_command",
    "_run_approval_totp_settings_command",
    "_shell_join",
    "_update_guard_cli_settings",
    "_write_json_line",
]
