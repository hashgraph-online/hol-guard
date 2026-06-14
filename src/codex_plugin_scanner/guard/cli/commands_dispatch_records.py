"""Guard CLI command dispatch helpers."""

# fmt: off
# ruff: noqa: F403, F405, I001

from __future__ import annotations

from ..aibom_cli import AibomCliOptions, _AIBOM_CLOUD_SYNC_OPTIONS
from ._commands_shared import *
from .commands_parser_helpers import *

def _run_guard_diff_command(
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
    detection = detect_harness(args.harness, context)
    payload = evaluate_detection(detection, store, config, default_action="allow", persist=False)
    changed_artifacts = [item for item in payload["artifacts"] if bool(item["changed"])]
    payload["artifacts"] = changed_artifacts
    payload["changed"] = bool(changed_artifacts)
    _emit("diff", payload, getattr(args, "json", False))
    return 0

def _run_guard_receipts_command(
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
    _emit("receipts", {"generated_at": _now(), "items": store.list_receipts()}, getattr(args, "json", False))
    return 0

def _run_guard_history_command(
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
    history_cmd = getattr(args, "history_command", None)
    if history_cmd == "explain":
        receipt_id: str = args.receipt_id
        match = store.get_receipt(receipt_id)
        if match is None:
            msg = f"No receipt found for ID {receipt_id!r}"
            _emit("history.explain", {"error": msg}, getattr(args, "json", False))
            return 1
        evidence = store.list_evidence(request_id=receipt_id, limit=10_000)
        payload: dict[str, object] = {
            "receipt_id": receipt_id,
            "receipt": match,
            "evidence": [
                {
                    "evidence_id": e.get("evidence_id", ""),
                    "category": e.get("category", ""),
                    "severity": e.get("severity", ""),
                    "summary": e.get("summary", ""),
                    "action_identity": e.get("action_identity"),
                    "created_at": e.get("created_at", ""),
                }
                for e in evidence
            ],
        }
        _emit("history.explain", payload, getattr(args, "json", False))
        return 0
    _emit("history", {"error": "Use: hol-guard history explain <receipt_id>"}, getattr(args, "json", False))
    return 1

def _run_guard_inventory_command(
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
    generated_at = _now()
    if getattr(args, "json", False):
        payload = build_inventory_json_payload(
            store,
            context,
            generated_at=generated_at,
            options=_aibom_cli_options_from_args(args),
        )
    else:
        payload = {"generated_at": generated_at, "items": store.list_inventory()}
    _emit("inventory", payload, getattr(args, "json", False))
    return 0

def _run_guard_aibom_command(
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
    generated_at = _now()
    aibom_options = _aibom_cli_options_from_args(args)
    aibom_command = getattr(args, "aibom_command", None)
    if aibom_command == "status":
        payload = build_aibom_status_payload(
            store,
            context,
            generated_at=generated_at,
            options=aibom_options,
        )
        _emit("aibom.status", payload, getattr(args, "json", False))
        return 0
    if aibom_command == "sync":
        sync_options = AibomCliOptions(
            include_symlinks=aibom_options.include_symlinks,
            follow_unsafe_symlinks=aibom_options.follow_unsafe_symlinks,
            cisco_skill_scan=getattr(
                args,
                "cisco_skill_scan",
                _AIBOM_CLOUD_SYNC_OPTIONS.cisco_skill_scan,
            ),
            cisco_mcp_scan=getattr(
                args,
                "cisco_mcp_scan",
                _AIBOM_CLOUD_SYNC_OPTIONS.cisco_mcp_scan,
            ),
            cisco_timeout_seconds=getattr(
                args,
                "cisco_timeout_seconds",
                _AIBOM_CLOUD_SYNC_OPTIONS.cisco_timeout_seconds,
            ),
        )
        try:
            payload = sync_aibom_snapshots(
                store,
                context,
                generated_at=generated_at,
                options=sync_options,
            )
        except GuardSyncNotConfiguredError as error:
            message = _guard_sync_failure_message(error)
            if getattr(args, "json", False):
                _emit("aibom.sync", {"synced": False, "error": message}, True)
            else:
                print(message, file=sys.stderr)
            return 1
        except (OSError, RuntimeError) as error:
            message = str(error) if isinstance(error, RuntimeError) else "Guard Cloud AIBOM sync failed."
            if getattr(args, "json", False):
                _emit("aibom.sync", {"synced": False, "error": message}, True)
            else:
                print(message, file=sys.stderr)
            return 1
        _emit("aibom.sync", payload, getattr(args, "json", False))
        return 0
    export_format = getattr(args, "format", "json")
    resolved_format = export_format if export_format in {"json", "markdown"} else "json"
    payload = build_aibom_export_payload(
        store,
        context,
        generated_at=generated_at,
        options=aibom_options,
        export_format=resolved_format,
    )
    if resolved_format == "markdown" and not getattr(args, "json", False):
        print(str(payload.get("markdown", "")))
        return 0
    _emit("aibom", payload, True)
    return 0

def _run_guard_abom_command(
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
    payload = _build_abom_payload(store)
    if args.format == "markdown" and not getattr(args, "json", False):
        print(payload["markdown"])
        return 0
    _emit("abom", payload, True)
    return 0

def _run_guard_policies_command(
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
    if getattr(args, "policies_command", None) == "clear":
        harness = getattr(args, "harness", None)
        clear_all = bool(getattr(args, "all", False))
        if clear_all and harness is not None:
            _emit(
                "policies",
                {
                    "error": "Choose either --all or --harness <name> when clearing Guard policy decisions.",
                    "cleared": 0,
                    "harness": harness,
                    "source": getattr(args, "source", None),
                },
                getattr(args, "json", False),
            )
            return 2
        if not clear_all and harness is None:
            _emit(
                "policies",
                {
                    "error": "Choose --harness <name> or --all when clearing Guard policy decisions.",
                    "cleared": 0,
                },
                getattr(args, "json", False),
            )
            return 2
        scope = getattr(args, "scope", None)
        artifact_id = getattr(args, "artifact_id", None)
        policy_artifact_hash = getattr(args, "artifact_hash", None)
        workspace = getattr(args, "policy_workspace", None)
        publisher = getattr(args, "publisher", None)
        try:
            gate_input = prompt_for_approval_gate(store.guard_home, use_cooldown=False)
            approval_gate_grant = require_high_risk(
                store.guard_home,
                purpose="policy_clear",
                approval_gate_input=gate_input,
            )
            cleared = store.clear_policy_decisions(
                None if clear_all else harness,
                getattr(args, "source", None),
                scope=scope,
                artifact_id=artifact_id,
                artifact_hash=policy_artifact_hash,
                workspace=workspace,
                publisher=publisher,
                approval_gate_grant=approval_gate_grant,
            )
        except ApprovalGateError as error:
            _emit("policies", approval_gate_cli_payload(error), getattr(args, "json", False))
            return 4
        _emit(
            "policies",
            {
                "generated_at": _now(),
                "cleared": cleared,
                "harness": None if clear_all else harness,
                "source": getattr(args, "source", None),
                "scope": scope,
                "artifact_id": artifact_id,
                "artifact_hash": policy_artifact_hash,
                "workspace": workspace,
                "publisher": publisher,
            },
            getattr(args, "json", False),
        )
        return 0
    policy_items = store.list_policy_decisions(getattr(args, "harness", None))
    items = _filter_policy_items(policy_items, active_only=True)
    _emit("policies", {"generated_at": _now(), "items": items}, getattr(args, "json", False))
    return 0

def _run_guard_settings_command(
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
    settings_sub = getattr(args, "settings_command", None)
    if settings_sub == "set":
        try:
            config = _update_guard_cli_settings(args=args, config=config, guard_home=guard_home)
        except ApprovalGateError as error:
            _emit("settings", approval_gate_cli_payload(error), getattr(args, "json", False))
            return 4
        except ValueError as error:
            print(str(error), file=sys.stderr)
            return 2
    elif settings_sub == "explain":
        _emit("settings.explain", _guard_settings_explain_payload(config), getattr(args, "json", False))
        return 0
    elif settings_sub == "doctor":
        _emit("settings.doctor", _guard_settings_doctor_payload(config), getattr(args, "json", False))
        return 0
    elif settings_sub == "approval-password":
        try:
            payload = _run_approval_password_settings_command(args=args, guard_home=guard_home)
        except ApprovalGateError as error:
            _emit("settings.approval-password", approval_gate_cli_payload(error), getattr(args, "json", False))
            return 4
        except ValueError as error:
            print(str(error), file=sys.stderr)
            return 2
        _emit("settings.approval-password", payload, getattr(args, "json", False))
        return 0
    elif settings_sub == "approval-totp":
        try:
            payload = _run_approval_totp_settings_command(args=args, guard_home=guard_home)
        except ApprovalGateError as error:
            _emit("settings.approval-totp", approval_gate_cli_payload(error), getattr(args, "json", False))
            return 4
        except ValueError as error:
            print(str(error), file=sys.stderr)
            return 2
        _emit("settings.approval-totp", payload, getattr(args, "json", False))
        return 0
    _emit("settings", _guard_cli_settings_payload(config), getattr(args, "json", False))
    return 0

__all__ = [
    "_run_guard_abom_command",
    "_run_guard_aibom_command",
    "_run_guard_diff_command",
    "_run_guard_history_command",
    "_run_guard_inventory_command",
    "_run_guard_policies_command",
    "_run_guard_receipts_command",
    "_run_guard_settings_command",
]
