"""Guard local trust CLI dispatch helpers."""

from __future__ import annotations

import argparse
import importlib.metadata
import sys
from pathlib import Path
from typing import TextIO

from ..adapters.base import HarnessContext
from ..config import GuardConfig
from ..local_trust_contract import TrustStatus
from ..store import GuardStore, SystemKeyringSecretStore
from .commands_support_interaction import _emit


def _now() -> str:
    from ._commands_shared import _now as _shared_now

    return _shared_now()


def _require_guard_store(store: GuardStore | None) -> GuardStore:
    from ._commands_shared import _require_guard_store as _shared_require_guard_store

    return _shared_require_guard_store(store)


def _degraded_safe_trust_status() -> dict[str, object]:
    return TrustStatus(
        runtime_protection="degraded",
        remembered_rules="disabled_degraded",
        cloud_policies="setup_unavailable",
        backend="degraded-safe",
        setup_available=False,
    ).to_dict()


def _unsupported_backend_payload(*, command: str, backend: str) -> dict[str, object]:
    return {
        "generated_at": _now(),
        "command": command,
        "backend_requested": backend,
        "backend": backend,
        "runtime_protection": "degraded",
        "remembered_rules": "disabled_degraded",
        "cloud_policies": "setup_unavailable",
        "degraded_reasons": ["trust_backend_unavailable"],
        "degraded_reason_labels": {"trust_backend_unavailable": "Local trust backend unavailable"},
        "setup_available": backend == "macos-native",
        "no_ui_passive": True,
        "passive_prompt_allowed": False,
        "one_time_approvals": "available",
        "durable_local_rules": "limited",
        "cloud_policy_authority": "setup_unavailable",
        "error": (
            f"Backend {backend!r} is not available for passive {command}. "
            "Guard will not probe it in the background because that could open an OS credential prompt."
        ),
        "next_action": "Use --backend auto or run an explicit setup command when a backend is available.",
    }


def _trust_status_payload(store: GuardStore, *, command: str, backend: str) -> dict[str, object]:
    if backend == "degraded-safe":
        trust_status = _degraded_safe_trust_status()
    else:
        status_payload = store.get_policy_integrity_status()
        trust_status = status_payload.get("trust_status")
        if not isinstance(trust_status, dict):
            trust_status = TrustStatus.from_policy_integrity_state(status_payload).to_dict()
    degraded_reasons = trust_status.get("degraded_reasons")
    reasons = (
        [reason for reason in degraded_reasons if isinstance(reason, str)] if isinstance(degraded_reasons, list) else []
    )
    runtime_protection = str(trust_status.get("runtime_protection") or "unknown")
    remembered_rules = str(trust_status.get("remembered_rules") or "unknown")
    cloud_policies = str(trust_status.get("cloud_policies") or "unknown")
    return {
        "generated_at": _now(),
        "command": command,
        "backend_requested": backend,
        "backend": trust_status.get("backend") or "unknown",
        "runtime_protection": runtime_protection,
        "remembered_rules": remembered_rules,
        "cloud_policies": cloud_policies,
        "degraded_reasons": reasons,
        "degraded_reason_labels": trust_status.get("degraded_reason_labels") or {},
        "setup_available": bool(trust_status.get("setup_available")),
        "no_ui_passive": True,
        "passive_prompt_allowed": False,
        "one_time_approvals": "available",
        "durable_local_rules": "enforced" if remembered_rules == "enforced" else "limited",
        "cloud_policy_authority": cloud_policies,
        "message": (
            "Guard is blocking risky actions. Broad remembered local rules are limited until local trust is protected."
            if remembered_rules != "enforced"
            else "Guard local trust is protected. Remembered local rules are enforced."
        ),
    }


def _installed_trust_cli_payload() -> dict[str, object]:
    try:
        version = importlib.metadata.version("hol-guard")
    except importlib.metadata.PackageNotFoundError:
        version = None
    return {
        "package": "hol-guard",
        "version": version,
        "update_command": "hol-guard update",
        "dry_run_command": "hol-guard update --dry-run --json",
    }


def build_trust_doctor_payload(store: GuardStore, *, backend: str = "auto") -> dict[str, object]:
    payload = _trust_status_payload(store, command="doctor", backend=backend)
    remembered_rules = str(payload.get("remembered_rules") or "unknown")
    runtime_protection = str(payload.get("runtime_protection") or "unknown")
    if runtime_protection != "protected":
        payload["summary"] = (
            "Runtime protection is degraded. One-time approvals remain available, but broad remembered local rules "
            "stay limited until local trust is protected."
        )
    elif remembered_rules != "enforced":
        payload["summary"] = (
            "Runtime protection is active. Broad remembered local rules are limited until local trust is protected."
        )
    else:
        payload["summary"] = "Runtime protection and remembered local rules are protected."
    payload["checks"] = {
        "runtime_protection": runtime_protection == "protected",
        "one_time_approvals": payload.get("one_time_approvals") == "available",
        "passive_no_ui": payload.get("passive_prompt_allowed") is False,
        "local_rules_protected": remembered_rules == "enforced",
        "cloud_policy_authority": payload.get("cloud_policy_authority") == "available",
    }
    payload["recommended_actions"] = (
        [
            "Use one-time approvals for local-only work.",
            "Use Guard Cloud policies for durable team exceptions.",
            "Run `hol-guard guard trust test --no-ui --json` to verify passive checks stay prompt-free.",
        ]
        if remembered_rules != "enforced"
        else [
            "Run `hol-guard guard trust test --no-ui --json` after Guard updates.",
            "Use Guard Cloud policies for team-wide exceptions.",
        ]
    )
    payload["official_install"] = _installed_trust_cli_payload()
    return payload


def _macos_native_backend_supported(store: GuardStore) -> bool:
    secret_store = getattr(store, "_policy_integrity_secret_store", None)
    return (
        sys.platform == "darwin"
        and isinstance(secret_store, SystemKeyringSecretStore)
        and secret_store._supports_native_macos_security_reads()
    )


def _run_guard_trust_command(
    args: argparse.Namespace,
    *,
    guard_home: Path | None = None,
    workspace: Path | None = None,
    context: HarnessContext | None = None,
    store: GuardStore | None = None,
    config: GuardConfig | None = None,
    input_text: str | None = None,
    output_stream: TextIO | None = None,
) -> int:
    del guard_home, workspace, context, config, input_text, output_stream
    store = _require_guard_store(store)
    trust_command = getattr(args, "trust_command", None) or "status"
    backend = str(getattr(args, "backend", None) or "auto")
    if backend == "macos-native" and not _macos_native_backend_supported(store):
        payload = _unsupported_backend_payload(command=trust_command, backend=backend)
        _emit(f"trust.{trust_command}", payload, getattr(args, "json", False))
        return 2
    payload = (
        build_trust_doctor_payload(store, backend=backend)
        if trust_command == "doctor"
        else _trust_status_payload(store, command=trust_command, backend=backend)
    )
    if trust_command in {"status", "doctor"}:
        _emit(f"trust.{trust_command}", payload, getattr(args, "json", False))
        return 0
    if trust_command == "test":
        if not bool(getattr(args, "no_ui", False)):
            payload["error"] = "Use --no-ui so Guard can prove this probe will not open an OS credential prompt."
            _emit("trust.test", payload, getattr(args, "json", False))
            return 2
        payload["probe"] = "passive_no_ui"
        payload["ok"] = payload["passive_prompt_allowed"] is False
        payload["trust_health"] = "protected" if payload["remembered_rules"] == "enforced" else "degraded_safe"
        _emit("trust.test", payload, getattr(args, "json", False))
        return 0
    if trust_command in {"setup", "reset"}:
        if backend == "degraded-safe":
            payload["error"] = (
                "No explicit local trust backend is available for setup on this platform."
                if trust_command == "setup"
                else "No explicit local trust backend is active to reset."
            )
            payload["next_action"] = (
                "Runtime protection remains active. Broad remembered local rules stay limited."
                if trust_command == "setup"
                else "Nothing changed."
            )
            _emit(f"trust.{trust_command}", payload, getattr(args, "json", False))
            return 2
        if sys.platform != "darwin":
            payload["error"] = (
                "No explicit local trust backend is available for setup on this platform."
                if trust_command == "setup"
                else "No explicit local trust backend is active to reset."
            )
            payload["next_action"] = (
                "Guard already uses the default passive backend on this platform."
                if trust_command == "setup"
                else "Nothing changed."
            )
            _emit(f"trust.{trust_command}", payload, getattr(args, "json", False))
            return 2
        if not _macos_native_backend_supported(store):
            payload["error"] = (
                f"macOS native trust {trust_command} is unavailable. "
                "Guard will not fall back to a prompt-capable backend."
            )
            payload["next_action"] = "Use one-time approvals or Guard Cloud policies until native setup is available."
            _emit(f"trust.{trust_command}", payload, getattr(args, "json", False))
            return 2
        result = (
            store.setup_policy_integrity(now=_now())
            if trust_command == "setup"
            else store.reset_policy_integrity(now=_now())
        )
        trust_status = result.get("trust_status")
        if not isinstance(trust_status, dict):
            trust_status = TrustStatus.from_policy_integrity_state(result).to_dict()
        payload = {
            **payload,
            **result,
            "backend_requested": backend,
            "backend": trust_status.get("backend") or result.get("backend") or "unknown",
            "runtime_protection": trust_status.get("runtime_protection") or "unknown",
            "remembered_rules": trust_status.get("remembered_rules") or "unknown",
            "cloud_policies": trust_status.get("cloud_policies") or "unknown",
            "setup_available": bool(trust_status.get("setup_available")),
            "passive_prompt_allowed": False,
            "no_ui_passive": True,
            "one_time_approvals": "available",
            "durable_local_rules": (
                "enforced" if trust_status.get("remembered_rules") == "enforced" else "limited"
            ),
            "cloud_policy_authority": trust_status.get("cloud_policies") or "unknown",
            "ok": bool(result.get("mode") == "protected") if trust_command == "setup" else True,
        }
        if trust_command == "setup":
            payload["message"] = (
                "Local trust is protected. Broad remembered local rules can be enforced."
                if payload["ok"]
                else "Local trust setup did not finish. Guard stayed in degraded-safe mode."
            )
            if not payload["ok"]:
                payload["next_action"] = "Keep using one-time approvals, then run trust doctor for the degraded reason."
                _emit("trust.setup", payload, getattr(args, "json", False))
                return 2
        else:
            payload["message"] = (
                "Local trust material was removed. Runtime blocking stays active, "
                "and broad remembered local rules are limited."
            )
            payload["next_action"] = (
                "Run `hol-guard guard trust setup --backend macos-native --json` "
                "to protect local rules again."
            )
        _emit(f"trust.{trust_command}", payload, getattr(args, "json", False))
        return 0
    _emit("trust", {"error": "Use: hol-guard guard trust status|doctor|test|setup|reset"}, getattr(args, "json", False))
    return 2


__all__ = [
    "_run_guard_trust_command",
    "build_trust_doctor_payload",
]
