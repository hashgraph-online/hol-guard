"""Guard local trust CLI dispatch helpers."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import TextIO

from ..adapters.base import HarnessContext
from ..config import GuardConfig
from ..local_trust_contract import TrustStatus
from ..store import GuardStore
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
    if backend == "macos-native" and trust_command in {"status", "doctor", "test"}:
        payload = _unsupported_backend_payload(command=trust_command, backend=backend)
        _emit(f"trust.{trust_command}", payload, getattr(args, "json", False))
        return 2
    payload = _trust_status_payload(store, command=trust_command, backend=backend)
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
        if backend == "macos-native":
            payload["error"] = (
                f"macOS native trust {trust_command} is not enabled yet. Passive checks remain no-UI and degraded-safe."
            )
            payload["next_action"] = "Use one-time approvals or Guard Cloud policies until native setup is available."
        elif trust_command == "setup":
            payload["error"] = "No explicit local trust backend is available for setup on this platform."
            payload["next_action"] = "Runtime protection remains active. Broad remembered local rules stay limited."
        else:
            payload["error"] = "No explicit local trust backend is active to reset."
            payload["next_action"] = "Nothing changed."
        _emit(f"trust.{trust_command}", payload, getattr(args, "json", False))
        return 2
    _emit("trust", {"error": "Use: hol-guard guard trust status|doctor|test|setup|reset"}, getattr(args, "json", False))
    return 2


__all__ = [
    "_run_guard_trust_command",
]
