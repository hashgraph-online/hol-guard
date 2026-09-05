"""Step-up authorization for commands that change Guard protection."""

from __future__ import annotations

import argparse
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TextIO, cast

from ..approval_gate import ApprovalGateError, public_config, recent_totp_satisfied, require_high_risk
from ..config import resolve_guard_home_for_user_home
from ..harness_disconnect_gate import disconnect_requires_fresh_authenticator
from ..windows_paths import trusted_windows_user_profile
from .approval_gate_prompt import consume_desktop_lifecycle_env, prompt_for_approval_gate

_ENROLLMENT_NOTICE = (
    "Local Guard approval protection is not enabled. Guard Cloud sign-in and account MFA are separate from this "
    "local gate. Run `hol-guard dashboard`, then open Settings > Approval gate, enable `Ask for proof on allow "
    "decisions`, and set an `Approval password`. Optionally connect an `Authenticator app` for high-risk "
    "approvals. This notice is advisory and does not block the current command."
)
_CANONICAL_AUTHORITY_ACTION_PREFIXES = (
    "apps.",
    "bootstrap.",
    "disconnect",
    "doctor.",
    "init.",
    "install",
    "uninstall",
    "update",
)


@dataclass(frozen=True)
class LifecycleGateRequirement:
    action: str
    subject: str


def lifecycle_gate_requirement(args: argparse.Namespace) -> LifecycleGateRequirement | None:
    # Every protection-mutating command must be listed here; unmatched commands are intentionally exempt.
    command = _string_attribute(args, "guard_command")
    if _bool_attribute(args, "dry_run"):
        return None
    if command in {"install", "uninstall", "update", "disconnect"}:
        return LifecycleGateRequirement(command, _command_subject(args))
    apps_command = _string_attribute(args, "apps_command")
    if command == "apps" and apps_command in {"connect", "repair", "disconnect"}:
        return LifecycleGateRequirement(f"apps.{apps_command}", _string_attribute(args, "harness") or "all")
    if command == "bootstrap" and not _bool_attribute(args, "skip_install"):
        return LifecycleGateRequirement("bootstrap.install", _string_attribute(args, "harness") or "detected")
    if command == "init" and not _bool_attribute(args, "skip_apps"):
        return LifecycleGateRequirement("init.install", "detected")
    if command == "device" and _string_attribute(args, "device_command") == "rotate":
        return LifecycleGateRequirement("device.rotate", "local-installation")
    commands_command = _string_attribute(args, "commands_command")
    if command == "commands" and commands_command in {"enable", "approve", "revoke"}:
        action = f"commands.{commands_command}"
        subject = _string_attribute(args, "job_id") or "remote-command-authority"
        return LifecycleGateRequirement(action, subject)
    cloud_review_command = _string_attribute(args, "cloud_review_command")
    if command == "cloud-review" and cloud_review_command in {"enable", "disable"}:
        return LifecycleGateRequirement(f"cloud-review.{cloud_review_command}", "exact-cloud-review")
    if command == "daemon" and _string_attribute(args, "daemon_command") == "stop":
        return LifecycleGateRequirement("daemon.stop", "local-daemon")
    trust_command = _string_attribute(args, "trust_command")
    if command == "trust" and trust_command in {"setup", "reset"}:
        return LifecycleGateRequirement(f"trust.{trust_command}", "local-trust")
    if command == "doctor" and _bool_attribute(args, "repair"):
        return LifecycleGateRequirement("doctor.repair", _string_attribute(args, "harness") or "all")
    return None


def enforce_lifecycle_gate(
    args: argparse.Namespace,
    *,
    guard_home: Path,
    error_stream: TextIO | None = None,
) -> None:
    requirement = lifecycle_gate_requirement(args)
    if requirement is None:
        return
    authority_home = lifecycle_authority_home(guard_home, requirement=requirement)
    gate = public_config(authority_home)
    desktop_proof = consume_desktop_lifecycle_env(
        totp_enabled=gate.totp_enabled,
        use_cooldown=False,
        cooldown_seconds=gate.cooldown_seconds,
    )
    if not gate.enabled:
        print(_ENROLLMENT_NOTICE, file=error_stream or sys.stderr)
        return
    if requirement.action == "apps.disconnect" and not _apps_disconnect_confirmation_matches(args):
        return
    require_fresh_totp = gate.totp_enabled and disconnect_requires_fresh_authenticator(requirement.action)
    if gate.totp_enabled and recent_totp_satisfied(authority_home) and not require_fresh_totp:
        gate_input = None
    elif desktop_proof is not None:
        gate_input = desktop_proof
    else:
        gate_input = prompt_for_approval_gate(
            authority_home,
            use_cooldown=False,
            require_fresh_totp=require_fresh_totp,
        )
    if require_fresh_totp and not ((gate_input.totp_code if gate_input is not None else None) or "").strip():
        raise ApprovalGateError("approval_gate_totp_required", "TOTP code is required.")
    _ = require_high_risk(
        authority_home,
        purpose="protection_lifecycle",
        approval_gate_input=gate_input,
        action=requirement.action,
        scope="local-protection",
        subject=requirement.subject,
    )


def lifecycle_authority_home(
    target_home: Path,
    *,
    requirement: LifecycleGateRequirement,
) -> Path:
    """Prefer the canonical gate for mutations that can affect global protection."""

    if not requirement.action.startswith(_CANONICAL_AUTHORITY_ACTION_PREFIXES):
        return target_home
    canonical_home = canonical_lifecycle_home()
    if canonical_home == target_home:
        return target_home
    if public_config(canonical_home).enabled:
        return canonical_home
    return target_home


def canonical_lifecycle_home() -> Path:
    return resolve_guard_home_for_user_home(trusted_user_home())


def trusted_user_home() -> Path:
    """Resolve the effective OS account home without ambient environment input."""

    if os.name == "nt":
        return trusted_windows_user_profile()
    import pwd

    return Path(pwd.getpwuid(os.geteuid()).pw_dir).resolve()


def _apps_disconnect_confirmation_matches(args: argparse.Namespace) -> bool:
    harness = _string_attribute(args, "harness")
    if not harness:
        return False
    try:
        from ..adapters import get_adapter
        from .install_commands import uninstall_confirmation_token

        expected = uninstall_confirmation_token(get_adapter(harness).harness)
    except ValueError:
        return False
    return _string_attribute(args, "confirm") == expected


def _command_subject(args: argparse.Namespace) -> str:
    command = _string_attribute(args, "guard_command")
    if command == "install":
        return "all" if _bool_attribute(args, "all") else _string_attribute(args, "harness") or "detected"
    if command == "uninstall":
        if _bool_attribute(args, "self_uninstall"):
            return "hol-guard"
        return "all" if _bool_attribute(args, "all") else _string_attribute(args, "harness") or "detected"
    if command == "disconnect":
        return _string_attribute(args, "source") or "default"
    return "hol-guard"


def _attribute(args: argparse.Namespace, name: str) -> object | None:
    return cast(dict[str, object], vars(args)).get(name)


def _string_attribute(args: argparse.Namespace, name: str) -> str:
    value = _attribute(args, name)
    return value if isinstance(value, str) else ""


def _bool_attribute(args: argparse.Namespace, name: str) -> bool:
    return _attribute(args, name) is True


__all__ = [
    "LifecycleGateRequirement",
    "canonical_lifecycle_home",
    "enforce_lifecycle_gate",
    "lifecycle_authority_home",
    "lifecycle_gate_requirement",
    "trusted_user_home",
]
