"""Guard CLI command dispatch helpers."""

# ruff: noqa: F403, F405

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ._commands_shared import _now, _require_guard_config, _require_guard_context, _require_guard_store
    from .commands_support_connect import (
        _filter_policy_items,
        _guard_doctor_connect_health_payload,
        _resolve_policy_expiry,
        _validate_policy_scope,
    )
    from .commands_support_interaction import (
        _emit,
        _policy_write_needs_approval_gate,
        _policy_write_requires_approval_gate,
    )
    from .commands_support_runtime_policy import _runtime_detector_perf_payload, _runtime_detector_registry_payload
    from .commands_support_service import (
        _build_explain_payload_with_mode,
        _guard_sync_failure_message,
        _validated_supply_chain_sync_payload,
    )


from ..runtime.command_queue import command_queue_status, repair_command_queue_state
from ._commands_shared import *
from .commands_parser_helpers import *


def _run_guard_exceptions_command(
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
    store = _require_guard_store(store)
    policy_items = store.list_policy_decisions(getattr(args, "harness", None))
    active_items = _filter_policy_items(policy_items, active_only=True)
    items = [
        item for item in active_items if isinstance(item.get("expires_at"), str) and str(item["expires_at"]).strip()
    ]
    cloud_items = store.list_cloud_exceptions(getattr(args, "harness", None))
    items = cloud_items + items
    _emit("exceptions", {"generated_at": _now(), "items": items}, getattr(args, "json", False))
    return 0


def _run_guard_advisories_command(
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
    store = _require_guard_store(store)
    adv_sub = getattr(args, "advisories_subcommand", None)
    if adv_sub == "sync":
        try:
            payload = _validated_supply_chain_sync_payload(sync_supply_chain_bundle(store))
        except GuardSyncNotConfiguredError as error:
            status = (
                "auth_expired" if isinstance(error, GuardSyncAuthorizationExpiredError) else "no_cloud_sync_configured"
            )
            _emit(
                "advisories_sync",
                {"generated_at": _now(), "status": status, "error": _guard_sync_failure_message(error)},
                getattr(args, "json", False),
            )
        except RuntimeError as error:
            _emit(
                "advisories_sync",
                {"generated_at": _now(), "status": "supply_chain_sync_failed", "error": str(error)},
                getattr(args, "json", False),
            )
        else:
            _emit("advisories_sync", payload, getattr(args, "json", False))
    elif adv_sub == "explain":
        target_id = getattr(args, "advisory_id", None)
        all_advs = store.list_cached_advisories(limit=None)
        match = next(
            (a for a in all_advs if a.get("advisory_id") == target_id or a.get("id") == target_id),
            None,
        )
        if match:
            _emit("advisory_explain", match, getattr(args, "json", False))
        else:
            _emit("advisory_explain", {"error": f"advisory {target_id!r} not found"}, getattr(args, "json", False))
    else:
        all_advs = store.list_cached_advisories()
        sev_filter = getattr(args, "severity", None)
        if sev_filter and sev_filter in SEVERITY_RANK:
            min_rank = SEVERITY_RANK[sev_filter]
            all_advs = [a for a in all_advs if SEVERITY_RANK.get(str(a.get("severity", "")).lower(), -1) >= min_rank]
        _emit(
            "advisories",
            {"generated_at": _now(), "items": all_advs},
            getattr(args, "json", False),
        )
    return 0


def _run_guard_events_command(
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
    store = _require_guard_store(store)
    _emit(
        "events",
        {"generated_at": _now(), "items": store.list_events(event_name=getattr(args, "name", None))},
        getattr(args, "json", False),
    )
    return 0


def _run_guard_approvals_command(
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
    store = _require_guard_store(store)
    approvals_command = getattr(args, "approvals_command", None)
    if approvals_command == "open":
        payload, exit_code = run_approval_open_command(args, store=store)
        _emit("approvals", payload, getattr(args, "json", False))
        return exit_code
    if approvals_command == "retry-hint":
        payload, exit_code = run_approval_retry_hint_command(args, store=store)
        _emit("approvals", payload, getattr(args, "json", False))
        return exit_code
    if approvals_command == "resume":
        payload, exit_code = run_approval_resume_command(args, store=store)
        _emit("approvals", payload, getattr(args, "json", False))
        return exit_code
    payload = run_approval_command(args, store=store, workspace=workspace)
    _emit("approvals", payload, getattr(args, "json", False))
    exit_code = payload.get("exit_code")
    return exit_code if isinstance(exit_code, int) else 0


def _run_guard_explain_command(
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
    store = _require_guard_store(store)
    if str(args.target).strip().lower() == "install-connect":
        payload = build_install_connect_docs_payload()
    else:
        payload = _build_explain_payload_with_mode(store, args.target, cisco_mode=args.cisco_mode)
    _emit("explain", payload, getattr(args, "json", False))
    return 0


def _run_guard_policy_action_command(
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
    store = _require_guard_store(store)
    _validate_policy_scope(args.scope, args.artifact_id, workspace, getattr(args, "publisher", None))
    expires_at = _resolve_policy_expiry(args)
    try:
        approval_gate_grant = None
        if _policy_write_requires_approval_gate(store, action=args.policy_action, scope=args.scope):
            gate_input = (
                prompt_for_approval_gate(store.guard_home, use_cooldown=True)
                if _policy_write_needs_approval_gate(store, action=args.policy_action, scope=args.scope)
                else None
            )
            approval_gate_grant = require_approval_decision(
                store.guard_home,
                action=args.policy_action,
                scope=args.scope,
                approval_gate_input=gate_input,
            )
        payload = record_policy(
            store=store,
            harness=args.harness,
            action=args.policy_action,
            scope=args.scope,
            artifact_id=args.artifact_id,
            workspace=str(workspace) if workspace else None,
            publisher=getattr(args, "publisher", None),
            reason=args.reason,
            owner=getattr(args, "owner", None),
            expires_at=expires_at,
            approval_gate_grant=approval_gate_grant,
        )
    except ApprovalGateError as error:
        _emit(args.guard_command, approval_gate_cli_payload(error), getattr(args, "json", False))
        return 4
    _emit(args.guard_command, {"decision": payload}, getattr(args, "json", False))
    return 0


def _run_guard_doctor_command(
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
    if guard_home is None:
        raise RuntimeError("Guard home is required")
    store = _require_guard_store(store)
    context = _require_guard_context(context)
    config = _require_guard_config(config)
    if getattr(args, "notifications", False):
        approval_url = "hol-guard://notification-preview"
        if desktop_notification_setup_supported():
            try:
                approval_center_url = ensure_guard_daemon(guard_home)
                approval_url = f"{approval_center_url.rstrip('/')}/approvals/notification-preview"
            except Exception:
                approval_url = "hol-guard://notification-preview"
        result = ensure_desktop_notification_setup(
            guard_home,
            approval_url=approval_url,
            force=bool(getattr(args, "force_notification_settings", False)),
        )
        guidance = macos_notification_guidance(result.notifier_path) if result.platform == "Darwin" else None
        _emit(
            "doctor",
            {"desktop_notifications": desktop_notification_setup_payload(result, guidance=guidance)},
            getattr(args, "json", False),
        )
        return 0
    if getattr(args, "harnesses", False):
        from ..adapters.contracts import HARNESS_CONTRACTS

        contracts_payload = [
            {
                "harness": c.harness,
                "install_aliases": list(c.install_aliases),
                "config_paths": list(c.config_paths),
                "event_surfaces": list(c.event_surfaces),
                "native_approval": c.native_approval,
                "browser_fallback": c.browser_fallback,
                "resume_support": c.resume_support,
                "known_blind_spots": c.known_blind_spots,
                "smoke_command": c.smoke_command,
            }
            for c in HARNESS_CONTRACTS
        ]
        _emit("doctor", {"harnesses": contracts_payload}, getattr(args, "json", False))
        return 0
    if args.harness:
        adapter = get_adapter(args.harness)
        payload: dict[str, object] = adapter.diagnostics(context)
        payload["runtime_detector_registry"] = _runtime_detector_registry_payload(config)
        payload["connect_health"] = _guard_doctor_connect_health_payload(store)
        if args.harness == "codex":
            payload["codex_resume"] = inspect_codex_resume_capabilities(store)
    else:
        payload = {
            "tables": store.list_table_names(),
            "adapters": [detection.to_dict() for detection in detect_all(context)],
            "runtime_detector_registry": _runtime_detector_registry_payload(config),
        }
    if getattr(args, "perf", False):
        payload["detector_perf"] = _runtime_detector_perf_payload(config)
    package_shims_payload = package_shim_status(context)
    manager_details = package_shims_payload.get("manager_details")
    package_shim_issues = [
        {
            "kind": "package_shim_integrity",
            "manager": str(detail.get("manager")),
            "integrity": str(detail.get("integrity")),
            "repair": "Run `hol-guard doctor --repair` to regenerate package-manager shims.",
        }
        for detail in (manager_details if isinstance(manager_details, list) else [])
        if isinstance(detail, dict) and detail.get("integrity") in {"missing", "stale", "tampered"}
    ]
    installed_managers_value = package_shims_payload.get("installed_managers")
    if not bool(package_shims_payload.get("path_active")) and package_shims_payload.get("installed_managers"):
        package_shim_issues.append(
            {
                "kind": "package_shim_path",
                "repair": "Run `hol-guard doctor --repair`, then open a new shell if PATH changed.",
            }
        )
    if getattr(args, "repair", False):
        installed_managers = tuple(
            str(manager)
            for manager in (installed_managers_value if isinstance(installed_managers_value, list) else [])
            if isinstance(manager, str) and manager.strip()
        )
        if installed_managers:
            repair_payload = activate_package_shims(context, managers=installed_managers, repair=True)
            package_shims_payload["repair"] = repair_payload
            package_shims_payload["after_repair"] = repair_payload["package_shims"]
        else:
            package_shims_payload["repair"] = {"nothing_to_repair": True, "repaired": [], "repaired_count": 0}
    package_shims_payload["issues"] = package_shim_issues
    payload["package_shims"] = package_shims_payload
    command_queue_payload = command_queue_status(store)
    if getattr(args, "repair", False):
        command_queue_payload["repair"] = repair_command_queue_state(store)
    payload["command_queue"] = command_queue_payload
    payload["supply_chain"] = build_local_supply_chain_posture(store, config, now=_now())
    payload["aibom"] = build_aibom_status_payload(store, context, generated_at=_now())
    _emit("doctor", payload, getattr(args, "json", False))
    return 0


__all__ = [
    "_run_guard_advisories_command",
    "_run_guard_approvals_command",
    "_run_guard_doctor_command",
    "_run_guard_events_command",
    "_run_guard_exceptions_command",
    "_run_guard_explain_command",
    "_run_guard_policy_action_command",
]
