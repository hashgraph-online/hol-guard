"""Guard local trust CLI dispatch helpers."""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import TextIO

from ...version import __version__
from ..adapters.base import HarnessContext
from ..config import GuardConfig
from ..daemon.manager import _guard_daemon_url_port, _load_state, load_guard_daemon_url, read_approval_center_locator
from ..local_trust_contract import TrustStatus
from ..local_trust_controller import macos_native_backend_supported, resolve_passive_trust_state
from ..policy_integrity import is_remote_policy_source
from ..store import GuardStore
from .commands_support_interaction import _emit
from .update_commands import build_guard_install_surface_payload

_TRUST_SECRET_ASSIGNMENT_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"(?i)\b[a-z0-9_.-]*(?:token|secret|api[-_]?key|password|credential)[a-z0-9_.-]*\s*=\s*"
        r"(?:'[^']*'|\"[^\"]*\"|[^\s]+)"
    ),
    re.compile(
        r"(?i)\b[a-z0-9_.-]*(?:token|secret|api[-_]?key|password|credential)[a-z0-9_.-]*\s*:\s*"
        r"(?:bearer\s+[^\s,;]+|[a-f0-9]{16,}|[a-z0-9._-]{24,})"
    ),
)


def _parse_iso8601(value: str | None) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = f"{normalized[:-1]}+00:00"
    try:
        return datetime.fromisoformat(normalized)
    except ValueError:
        return None


def _approval_center_locator_is_fresh(
    locator_pid: int,
    locator_url: str,
    locator_started_at: str,
    state: dict[str, object] | None,
) -> bool:
    if not isinstance(state, dict):
        return True
    state_pid = state.get("pid")
    state_port = state.get("port")
    locator_port = _guard_daemon_url_port(locator_url)
    if isinstance(state_pid, int) and state_pid != locator_pid:
        return False
    if isinstance(state_port, int) and isinstance(locator_port, int) and locator_port != state_port:
        return False
    raw_started_at = state.get("started_at")
    state_started_at = _parse_iso8601(raw_started_at if isinstance(raw_started_at, str) else None)
    locator_started_at_dt = _parse_iso8601(locator_started_at)
    if state_started_at is None or locator_started_at_dt is None:
        return True
    try:
        return locator_started_at_dt >= state_started_at
    except TypeError:
        return True


def _sanitize_trust_text(value: str) -> str:
    sanitized = value
    for pattern in _TRUST_SECRET_ASSIGNMENT_PATTERNS:
        sanitized = pattern.sub("credential redacted", sanitized)
    return sanitized


def _sanitize_trust_value(value: object) -> object:
    if isinstance(value, dict):
        return {key: _sanitize_trust_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_sanitize_trust_value(item) for item in value]
    if isinstance(value, str):
        return _sanitize_trust_text(value)
    return value


def _sanitize_trust_payload(payload: dict[str, object]) -> dict[str, object]:
    return {key: _sanitize_trust_value(value) for key, value in payload.items()}


def _emit_trust_payload(command: str, payload: dict[str, object], as_json: bool) -> None:
    _emit(command, _sanitize_trust_payload(payload), as_json)


def _now() -> str:
    from ._commands_shared import _now as _shared_now

    return _shared_now()


def _require_guard_store(store: GuardStore | None) -> GuardStore:
    from ._commands_shared import _require_guard_store as _shared_require_guard_store

    return _shared_require_guard_store(store)


def _trust_status_payload(store: GuardStore, *, command: str, backend: str) -> dict[str, object]:
    resolved = resolve_passive_trust_state(store, backend_requested=backend)
    trust_status = resolved.trust_status.to_dict()
    degraded_reasons = trust_status.get("degraded_reasons")
    reasons = (
        [reason for reason in degraded_reasons if isinstance(reason, str)] if isinstance(degraded_reasons, list) else []
    )
    runtime_protection = str(trust_status.get("runtime_protection") or "unknown")
    remembered_rules = str(trust_status.get("remembered_rules") or "unknown")
    cloud_policies = str(trust_status.get("cloud_policies") or "unknown")
    actual_backend = trust_status.get("backend")
    backend_name = (
        str(actual_backend)
        if isinstance(actual_backend, str) and actual_backend and actual_backend != "unknown"
        else resolved.backend_selected
    )
    mode = resolved.mode
    if mode == "unsupported":
        message = "This local trust backend is unsupported on this platform. Runtime blocking stays active."
    elif mode == "setup_required":
        message = "Local trust setup is available. Broad remembered local rules stay limited until you finish it."
    elif remembered_rules != "enforced":
        message = (
            "Guard is blocking risky actions. Broad remembered local rules are limited until local trust is protected."
        )
    else:
        message = "Guard local trust is protected. Remembered local rules are enforced."
    return {
        "generated_at": _now(),
        "command": command,
        "mode": mode,
        "backend_requested": resolved.backend_requested,
        "backend_selected": resolved.backend_selected,
        "backend_supported": resolved.backend_supported,
        "backend": backend_name or "unknown",
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
        "cloud_policy_status": cloud_policies,
        "message": message,
    }


def _installed_trust_cli_payload() -> dict[str, object]:
    version = None
    installation_mode = "unknown"
    editable_install = False
    official_install = False
    install_surface = build_guard_install_surface_payload()
    binary_diagnostics = install_surface.get("binary_diagnostics")
    if not isinstance(binary_diagnostics, dict):
        binary_diagnostics = {}
    try:
        distribution = importlib.metadata.distribution("hol-guard")
    except importlib.metadata.PackageNotFoundError:
        distribution = None
    if distribution is not None:
        version = distribution.version
        direct_url_text = distribution.read_text("direct_url.json")
        if isinstance(direct_url_text, str) and direct_url_text.strip():
            try:
                direct_url_payload = json.loads(direct_url_text)
            except json.JSONDecodeError:
                direct_url_payload = None
            dir_info = direct_url_payload.get("dir_info") if isinstance(direct_url_payload, dict) else None
            editable_install = bool(isinstance(dir_info, dict) and dir_info.get("editable") is True)
        try:
            distribution_root = str(distribution.locate_file("")).replace("\\", "/")
        except Exception:
            distribution_root = ""
        official_install = (
            "pipx/venvs/hol-guard/" in distribution_root or "/venvs/hol-guard/" in distribution_root
        ) and not editable_install
        if official_install:
            installation_mode = "official-pipx"
        elif editable_install:
            installation_mode = "editable"
        else:
            installation_mode = "packaged"
    active_command_status = str(binary_diagnostics.get("path_status") or "unknown")
    active_command_verified = active_command_status in {
        "pipx_shim_detected",
        "uv_tool_shim_detected",
        "matches_installer",
    }
    return {
        "package": "hol-guard",
        "version": version,
        "installation_mode": installation_mode,
        "official_install": official_install,
        "official_install_verified": official_install and active_command_status == "pipx_shim_detected",
        "editable_install": editable_install,
        "installer": install_surface.get("installer"),
        "active_command_path": binary_diagnostics.get("resolved_hol_guard"),
        "active_command_status": active_command_status,
        "active_command_verified": active_command_verified,
        "expected_script_dir": binary_diagnostics.get("expected_script_dir"),
        "self_check_command": "command -v hol-guard && hol-guard --version",
        "update_command": "hol-guard update",
        "dry_run_command": "hol-guard update --dry-run --json",
    }


def _approval_center_status_payload(guard_home: Path) -> dict[str, object]:
    state = _load_state(guard_home)
    daemon_package_version = state.get("package_version") if isinstance(state, dict) else None
    restart_required = isinstance(daemon_package_version, str) and daemon_package_version != __version__
    locator = read_approval_center_locator(guard_home)
    if locator is not None and _approval_center_locator_is_fresh(
        locator.pid,
        locator.daemon_url,
        locator.started_at,
        state,
    ):
        detail = None
        if restart_required:
            detail = (
                f"Guard daemon is still serving hol-guard {daemon_package_version}. "
                f"Restart it so browser approvals use hol-guard {__version__}."
            )
        return {
            "active": True,
            "approval_url_base": locator.approval_url_base,
            "daemon_url": locator.daemon_url,
            "port": (
                _guard_daemon_url_port(locator.approval_url_base)
                if isinstance(locator.approval_url_base, str) and locator.approval_url_base.strip()
                else None
            ),
            "started_at": locator.started_at,
            "pid": locator.pid,
            "snapshot_fresh": True,
            "restart_required": restart_required,
            "daemon_package_version": daemon_package_version,
            "detail": detail,
        }
    daemon_url = load_guard_daemon_url(guard_home)
    if isinstance(daemon_url, str) and daemon_url.strip():
        detail = "Guard daemon is healthy, but the browser approval locator has not been refreshed yet."
        if restart_required:
            detail = (
                f"Guard daemon is still serving hol-guard {daemon_package_version}. "
                f"Restart it so browser approvals use hol-guard {__version__}."
            )
        return {
            "active": True,
            "approval_url_base": daemon_url,
            "daemon_url": daemon_url,
            "port": _guard_daemon_url_port(daemon_url),
            "detail": detail,
            "snapshot_fresh": False,
            "restart_required": restart_required,
            "daemon_package_version": daemon_package_version,
        }
    return {
        "active": False,
        "detail": "No active Guard approval center daemon detected.",
        "snapshot_fresh": False,
        "restart_required": False,
        "daemon_package_version": daemon_package_version,
    }


def _passive_read_guarantee() -> str:
    if sys.platform == "darwin":
        return "No passive macOS Keychain access"
    return "No passive OS credential prompts"


def build_trust_doctor_payload(store: GuardStore, *, backend: str = "auto") -> dict[str, object]:
    payload = _trust_status_payload(store, command="doctor", backend=backend)
    approval_center = _approval_center_status_payload(store.guard_home)
    install_info = _installed_trust_cli_payload()
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
        "cloud_policy_available": payload.get("cloud_policy_status") == "available",
        "approval_center_active": bool(approval_center.get("active")),
        "approval_center_route_current": bool(approval_center.get("snapshot_fresh")),
        "official_install_verified": bool(install_info.get("official_install_verified")),
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
    if not bool(approval_center.get("active")):
        payload["recommended_actions"].append(
            "Run `hol-guard dashboard` if browser approvals are unavailable and Guard needs a fresh local route."
        )
    elif bool(approval_center.get("restart_required")):
        payload["recommended_actions"].append(
            "Run `hol-guard daemon repair` or restart the Guard daemon so browser approvals reconnect to this install."
        )
    elif not bool(approval_center.get("snapshot_fresh")):
        payload["recommended_actions"].append(
            "Run `hol-guard dashboard` once to refresh the local browser approval route for the active daemon."
        )
    if bool(install_info.get("editable_install")):
        payload["recommended_actions"].append(
            "Use the official pipx install before relying on packaged update and daemon lifecycle checks."
        )
    if not bool(install_info.get("active_command_verified")):
        if install_info.get("active_command_status") == "not_on_path":
            payload["recommended_actions"].append(
                "hol-guard is not on PATH. Reinstall it or add the install script directory to PATH."
            )
        else:
            payload["recommended_actions"].append(
                "Run `command -v hol-guard` and `hol-guard --version` "
                "to confirm the active command matches this install."
            )
    payload["approval_center"] = approval_center
    payload["approval_url_base"] = approval_center.get("approval_url_base")
    payload["passive_read_guarantee"] = _passive_read_guarantee()
    payload["official_install"] = install_info
    return payload


def _trust_rule_authority(
    decision: dict[str, object],
    *,
    trust_status: dict[str, object],
) -> tuple[str, str, str]:
    source = str(decision.get("source") or "unknown")
    if is_remote_policy_source(source):
        return (
            "guard_cloud",
            "From Guard Cloud",
            "This policy came from a validated Guard Cloud sync path and stays read-only on this device.",
        )
    integrity_status = str(decision.get("integrity_status") or "unknown")
    remembered_rules = str(trust_status.get("remembered_rules") or "unknown")
    if integrity_status == "valid" and remembered_rules == "enforced":
        return (
            "remembered_rule_protected",
            "Remembered and protected",
            "Local trust is protected, so this remembered rule can be enforced durably on this device.",
        )
    if integrity_status == "valid":
        return (
            "remembered_rule_limited",
            "Remembered but limited",
            "Local trust is not fully protected, so Guard limits broad remembered rules "
            "and still prefers one-time approvals.",
        )
    integrity_message = decision.get("integrity_message")
    return (
        "remembered_rule_ignored",
        "Remembered but ignored",
        str(integrity_message or "Guard cannot trust this remembered rule after integrity verification."),
    )


def build_trust_explain_payload(store: GuardStore, *, rule_id: int, backend: str = "auto") -> dict[str, object]:
    decision = store.get_policy_decision(rule_id)
    if decision is None:
        return {
            "generated_at": _now(),
            "command": "explain",
            "rule_id": rule_id,
            "error": f"Remembered rule {rule_id} was not found.",
        }
    trust_payload = _trust_status_payload(store, command="explain", backend=backend)
    rule_status, rule_status_label, rule_status_reason = _trust_rule_authority(
        decision,
        trust_status=trust_payload,
    )
    safe_rule = {key: value for key, value in decision.items() if key not in {"integrity_key_id"}}
    return {
        "generated_at": _now(),
        "command": "explain",
        "rule_id": rule_id,
        "rule": safe_rule,
        "rule_status": rule_status,
        "rule_status_label": rule_status_label,
        "rule_status_reason": rule_status_reason,
        "trust_status": {
            "backend": trust_payload.get("backend"),
            "runtime_protection": trust_payload.get("runtime_protection"),
            "remembered_rules": trust_payload.get("remembered_rules"),
            "cloud_policies": trust_payload.get("cloud_policies"),
            "degraded_reasons": trust_payload.get("degraded_reasons"),
        },
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
    payload = (
        build_trust_doctor_payload(store, backend=backend)
        if trust_command == "doctor"
        else _trust_status_payload(store, command=trust_command, backend=backend)
    )
    if trust_command in {"status", "doctor"}:
        _emit_trust_payload(f"trust.{trust_command}", payload, getattr(args, "json", False))
        return 0
    if trust_command == "test":
        if not bool(getattr(args, "no_ui", False)):
            payload["error"] = "Use --no-ui so Guard can prove this probe will not open an OS credential prompt."
            _emit_trust_payload("trust.test", payload, getattr(args, "json", False))
            return 2
        payload["probe"] = "passive_no_ui"
        payload["ok"] = payload["passive_prompt_allowed"] is False and payload.get("mode") != "unsupported"
        payload["trust_health"] = str(payload.get("mode") or "degraded_safe")
        _emit_trust_payload("trust.test", payload, getattr(args, "json", False))
        return 0
    if trust_command == "explain":
        rule_id = getattr(args, "rule", None)
        if not isinstance(rule_id, int) or isinstance(rule_id, bool):
            _emit_trust_payload(
                "trust.explain",
                {
                    "generated_at": _now(),
                    "command": "explain",
                    "error": "Use `hol-guard guard trust explain --rule <decision_id>`.",
                },
                getattr(args, "json", False),
            )
            return 2
        payload = build_trust_explain_payload(store, rule_id=rule_id, backend=backend)
        _emit_trust_payload("trust.explain", payload, getattr(args, "json", False))
        return 0 if "error" not in payload else 2
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
            _emit_trust_payload(f"trust.{trust_command}", payload, getattr(args, "json", False))
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
            _emit_trust_payload(f"trust.{trust_command}", payload, getattr(args, "json", False))
            return 2
        if not macos_native_backend_supported(store):
            payload["error"] = (
                f"macOS native trust {trust_command} is unavailable. "
                "Guard will not fall back to a prompt-capable backend."
            )
            payload["next_action"] = "Use one-time approvals or Guard Cloud policies until native setup is available."
            _emit_trust_payload(f"trust.{trust_command}", payload, getattr(args, "json", False))
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
            "durable_local_rules": ("enforced" if trust_status.get("remembered_rules") == "enforced" else "limited"),
            "cloud_policy_status": trust_status.get("cloud_policies") or "unknown",
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
                _emit_trust_payload("trust.setup", payload, getattr(args, "json", False))
                return 2
        else:
            payload["message"] = (
                "Local trust material was removed. Runtime blocking stays active, "
                "and broad remembered local rules are limited."
            )
            payload["next_action"] = (
                "Run `hol-guard guard trust setup --backend macos-native --json` to protect local rules again."
            )
        _emit_trust_payload(f"trust.{trust_command}", payload, getattr(args, "json", False))
        return 0
    _emit_trust_payload(
        "trust",
        {"error": "Use: hol-guard guard trust status|doctor|test|setup|reset"},
        getattr(args, "json", False),
    )
    return 2


__all__ = [
    "_run_guard_trust_command",
    "build_trust_doctor_payload",
    "build_trust_explain_payload",
]
