"""Guard CLI command dispatch helpers."""

# fmt: off
# ruff: noqa: F403, F405, I001

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ._commands_shared import _now, _require_guard_config, _require_guard_context, _require_guard_store
    from .commands_support_connect import _refresh_cloud_policy_bundle
    from .commands_support_hook_payload import _open_approval_center
    from .commands_support_interaction import _emit, _run_apps_command, _run_consumer_scan_with_mode
    from .commands_support_runtime_policy import _approval_delivery_payload, _localize_pending_approval_copy
    from .commands_support_workspace import _run_init_command
    from .protect_approvals import _queue_local_protect_approvals, _suppress_package_shim_allow_output


from ._commands_shared import *
from .commands_parser_helpers import *

def _run_guard_scan_command(
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
    if getattr(args, "deep", False):
        scan_type = str(args.target)
        if scan_type not in {"skills", "mcp"}:
            print("guard scan --deep supports 'skills' or 'mcp'.", file=sys.stderr)
            return 2
        home_override = getattr(args, "home", None)
        guard_home = resolve_guard_home(getattr(args, "guard_home", None) or home_override)
        workspace = Path(args.workspace).resolve() if getattr(args, "workspace", None) else Path.cwd().resolve()
        config = load_guard_config(guard_home, workspace=workspace)
        payload = build_cisco_deep_scan_payload(
            scan_type=scan_type,
            target=workspace,
            mode=args.cisco_mode,
            config=config,
        )
        payload["generated_at"] = _now()
        _emit("deep-scan", payload, getattr(args, "json", False))
        return 0
    payload = _run_consumer_scan_with_mode(Path(args.target).resolve(), cisco_mode=args.cisco_mode)
    _emit("scan", payload, args.json or args.consumer_mode)
    return 0

def _run_guard_preflight_command(
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
    payload = _run_consumer_scan_with_mode(
        Path(args.target).resolve(),
        intended_harness=getattr(args, "harness", None),
        cisco_mode=args.cisco_mode,
    )
    _emit("preflight", payload, getattr(args, "json", False))
    if getattr(args, "enforce", False):
        install_verdict = payload.get("install_verdict")
        if isinstance(install_verdict, dict) and str(install_verdict.get("action")) != "allow":
            return 2
    return 0

def _run_guard_update_command(
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
    dry_run = bool(getattr(args, "dry_run", False))
    store: GuardStore | None
    update_store_error: OSError | RuntimeError | sqlite3.Error | None = None
    if dry_run:
        store = None
    else:
        try:
            store = GuardStore(guard_home)
        except (OSError, RuntimeError, sqlite3.Error) as error:
            store = None
            update_store_error = error
    payload, exit_code = run_guard_update(
        dry_run=dry_run,
        context=context,
        store=store,
        workspace=str(workspace) if workspace else None,
        now=_now(),
        wheel=getattr(args, "wheel", None),
    )
    if update_store_error is not None:
        notes_value = payload.get("notes")
        notes = [str(item) for item in (notes_value if isinstance(notes_value, list) else []) if isinstance(item, str)]
        notes.append(f"Skipped local Guard repair during update: {update_store_error}")
        payload["notes"] = notes
    _emit("update", payload, getattr(args, "json", False))
    return exit_code

def _run_guard_protect_command(
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
    config = _require_guard_config(config)
    if guard_home is None:
        raise RuntimeError("Guard home is required")
    _refresh_cloud_policy_bundle(store, bundle_only=True)
    protect_command = list(getattr(args, "protect_command", []) or [])
    if len(protect_command) == 0:
        payload = build_supply_chain_status_payload(store=store, config=config, now=_now())
        _emit("protect", payload, getattr(args, "json", False))
        return 0
    payload, exit_code = build_protect_payload(
        command=protect_command,
        store=store,
        workspace_dir=workspace or Path.cwd(),
        dry_run=bool(getattr(args, "dry_run", False)),
        now=_now(),
        config=config,
        unsafe_raw_output=bool(getattr(args, "unsafe_raw_output", False)),
    )
    _queue_local_protect_approvals(
        payload,
        store=store,
        guard_home=guard_home,
        workspace=workspace or Path.cwd(),
        ensure_approval_daemon=ensure_guard_daemon,
        approval_delivery_payload=_approval_delivery_payload,
        localize_pending_approval_copy=lambda response_payload, harness: _localize_pending_approval_copy(
            response_payload,
            harness=harness,
        ),
    )
    if not _suppress_package_shim_allow_output(args, payload):
        _emit("protect", payload, getattr(args, "json", False))
    return exit_code

def _run_guard_start_command(
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
    context = _require_guard_context(context)
    store = _require_guard_store(store)
    config = _require_guard_config(config)
    payload = importlib.import_module(".product", __package__).build_guard_start_payload(context, store, config)
    _emit("start", payload, getattr(args, "json", False))
    return 0

def _run_guard_status_command(
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
    context = _require_guard_context(context)
    store = _require_guard_store(store)
    config = _require_guard_config(config)
    payload = importlib.import_module(".product", __package__).build_guard_status_payload(context, store, config)
    _emit("status", payload, getattr(args, "json", False))
    return 0

def _run_guard_init_command(
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
    context = _require_guard_context(context)
    store = _require_guard_store(store)
    config = _require_guard_config(config)
    return _run_init_command(args, context, store, config, workspace)

def _run_guard_dashboard_command(
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
    config = _require_guard_config(config)
    try:
        approval_center_url = ensure_guard_daemon(guard_home)
    except RuntimeError as error:
        if getattr(args, "json", False):
            _emit(
                "dashboard",
                {
                    "generated_at": _now(),
                    "opened": False,
                    "error": str(error),
                },
                True,
            )
        else:
            print(str(error), file=sys.stderr)
        return 1
    open_result = _open_approval_center(
        approval_center_url,
        store=store,
        config=config,
        open_key="dashboard",
        force_open=True,
    )
    _emit(
        "dashboard",
        {
            "generated_at": _now(),
            "approval_center_url": approval_center_url,
            "browser_url": open_result.get("browser_url"),
            "opened": bool(open_result.get("opened")),
            "reason": str(open_result.get("reason") or "unknown"),
        },
        getattr(args, "json", False),
    )
    return 0

def _run_guard_bootstrap_command(
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
    context = _require_guard_context(context)
    store = _require_guard_store(store)
    config = _require_guard_config(config)
    try:
        payload = build_guard_bootstrap_payload(
            context=context,
            store=store,
            config=config,
            requested_harness=getattr(args, "harness", None),
            skip_install=bool(getattr(args, "skip_install", False)),
            alias_name=str(getattr(args, "alias_name", DEFAULT_ALIAS_NAME)),
            write_shell_alias=bool(getattr(args, "write_shell_alias", False)),
        )
    except ValueError as error:
        print(str(error), file=sys.stderr)
        return 2
    _emit("bootstrap", payload, getattr(args, "json", False))
    return 0

def _run_guard_detect_command(
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
    context = _require_guard_context(context)
    detections = [detect_harness(args.harness, context)] if args.harness else detect_all(context)
    payload: dict[str, object] = {
        "generated_at": _now(),
        "harnesses": [detection.to_dict() for detection in detections],
    }
    _emit("detect", payload, getattr(args, "json", False))
    return 0

def _run_guard_apps_command(
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
    context = _require_guard_context(context)
    store = _require_guard_store(store)
    return _run_apps_command(args, context, store, str(workspace) if workspace else None)

def _run_guard_install_command(
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
    context = _require_guard_context(context)
    store = _require_guard_store(store)
    try:
        payload = apply_managed_install(
            "install",
            args.harness,
            bool(getattr(args, "all", False)),
            context,
            store,
            str(workspace) if workspace else None,
            _now(),
        )
    except ValueError as error:
        print(str(error), file=sys.stderr)
        return 2
    _emit("install", payload, getattr(args, "json", False))
    return 0

__all__ = [
    "_run_guard_apps_command",
    "_run_guard_bootstrap_command",
    "_run_guard_dashboard_command",
    "_run_guard_detect_command",
    "_run_guard_init_command",
    "_run_guard_install_command",
    "_run_guard_preflight_command",
    "_run_guard_protect_command",
    "_run_guard_scan_command",
    "_run_guard_start_command",
    "_run_guard_status_command",
    "_run_guard_update_command",
]
