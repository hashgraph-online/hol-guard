"""Guard CLI command dispatch helpers."""

# fmt: off
# ruff: noqa: F403, F405, I001

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ._commands_shared import _now, _require_guard_config, _require_guard_context, _require_guard_store
    from .commands_support_connect import _refresh_cloud_policy_bundle, _synced_policy_payload
    from .commands_support_interaction import _emit, _run_apps_command, _run_consumer_scan_with_mode
    from .commands_support_runtime_policy import _approval_delivery_payload, _localize_pending_approval_copy
    from .commands_support_workspace import _run_init_command
    from .protect_approvals import _queue_local_protect_approvals, _suppress_package_shim_allow_output


from ._commands_shared import *
from .commands_parser_helpers import *

def _run_guard_command_inspection_command(
    args: argparse.Namespace,
    *,
    input_text: str | None = None,
    output_stream: TextIO | None = None,
) -> int:
    from ..runtime.command_inspection import command_extensions_payload, inspect_command

    command_command = str(getattr(args, "command_command", ""))
    try:
        if command_command == "setup":
            from ..runtime.command_ecosystem_detection import command_setup_detection_payload

            workspace = Path(str(getattr(args, "workspace", "."))).resolve()
            if not workspace.is_dir():
                raise ValueError("Command setup workspace must be an existing directory")
            payload = command_setup_detection_payload(workspace)
            _emit("command-setup", payload, bool(getattr(args, "json", False)))
            return 0
        if command_command == "extensions":
            payload = command_extensions_payload(getattr(args, "extension_id", None))
            _emit("command-extensions", payload, bool(getattr(args, "json", False)))
            return 0
        if command_command not in {"test", "explain"}:
            print("Choose command test, command explain, command extensions, or command setup.", file=sys.stderr)
            return 2
        payload = inspect_command(str(getattr(args, "command_text", "")), cwd=Path.cwd(), home_dir=Path.home())
    except ValueError as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2
    payload["mode"] = command_command
    _emit("command-inspection", payload, bool(getattr(args, "json", False)))
    return 0

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
    from ..mdm.policy import load_managed_policy

    managed_policy = load_managed_policy()
    if managed_policy.status in {"invalid", "inaccessible", "tampered"} or (
        managed_policy.policy is not None and managed_policy.policy.install_owner == "mdm"
    ):
        _emit(
            "update",
            {
                "status": "managed",
                "changed": False,
                "reason_code": (
                    "managed_policy_invalid" if managed_policy.policy is None else "managed_update_owned_by_mdm"
                ),
                "message": "Version changes are owned by the device management service.",
            },
            getattr(args, "json", False),
        )
        return 0
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
    if not dry_run and exit_code == 0 and context is not None:
        from .update_commands import refresh_guard_daemon_after_update

        daemon_refresh, daemon_refresh_note = refresh_guard_daemon_after_update(context)
        if daemon_refresh is not None:
            payload["daemon_refresh"] = daemon_refresh
        if daemon_refresh_note is not None:
            notes_value = payload.get("notes")
            note_items = notes_value if isinstance(notes_value, list) else []
            notes = [str(item) for item in note_items if isinstance(item, str)]
            notes.append(daemon_refresh_note)
            payload["notes"] = notes
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
    protect_workspace = workspace or Path.cwd()

    def current_protect_config() -> GuardConfig:
        local_config = load_guard_config(guard_home, workspace=protect_workspace)
        return overlay_synced_guard_policy(local_config, _synced_policy_payload(store))

    payload, exit_code = build_protect_payload(
        command=protect_command,
        store=store,
        workspace_dir=protect_workspace,
        dry_run=bool(getattr(args, "dry_run", False)),
        now=_now(),
        config=config,
        current_config_provider=current_protect_config,
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
    from ..dashboard_launcher import open_dashboard

    result = open_dashboard(
        guard_home=guard_home,
        store=store,
        config=config,
        force_open=True,
        open_key="dashboard",
    )
    _emit(
        "dashboard",
        {
            "generated_at": _now(),
            "approval_center_url": result.approval_center_url,
            "browser_url": result.browser_url,
            "opened": result.opened,
            "reason": result.reason,
            **({"error": result.error} if result.error else {}),
        },
        getattr(args, "json", False),
    )
    return 0 if result.opened or result.reason in {"policy-disabled", "already-opened", "live-client"} else 1

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
        if bool(getattr(args, "dry_run", False)):
            payload = build_managed_install_plan(args.harness, bool(getattr(args, "all", False)), context, store)
        else:
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


def _run_guard_mcp_command(
    args: argparse.Namespace,
    *,
    input_text: str | None = None,
    output_stream: object | None = None,
) -> int:
    """Start the local Guard MCP server over stdio transport.

    This is an early handler: it resolves its own guard_home and manages
    its own GuardStore lifecycle. Stdout is protocol-only; diagnostics
    go to stderr.
    """
    from codex_plugin_scanner.guard.mcp.server import GuardMCPServer

    home_override = getattr(args, "home", None)
    guard_home = resolve_guard_home(getattr(args, "guard_home", None) or home_override)

    mcp_command = getattr(args, "mcp_command", None)
    if mcp_command != "serve":
        print("Error: only 'serve' subcommand is supported", file=sys.stderr)
        return 2

    server = GuardMCPServer(guard_home=guard_home)
    return server.run_stdio()


def _run_guard_tray_command(
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
    """Dispatch ``hol-guard tray`` subcommands."""
    if guard_home is None:
        raise RuntimeError("Guard home is required")
    tray_command = str(getattr(args, "tray_command", ""))
    use_json = bool(getattr(args, "json", False))
    package_version = _guard_package_version()

    if tray_command == "run":
        # Internal: run the tray icon in-process.
        # Platform adapters (LaunchAgent/Run-key/XDG autostart) invoke this
        # path at login, so it MUST write the locator before entering the
        # pystray main loop and remove it on exit. Without this, `tray status`
        # would not see login-started trays.
        from ..tray.runtime import TrayRuntime, detect_capability
        from ..tray.state import (
            build_locator_for_current_process,
            remove_locator,
            reset_crash_count,
            write_locator,
        )

        run_guard_home_arg = getattr(args, "guard_home", None)
        run_guard_home = Path(str(run_guard_home_arg)) if run_guard_home_arg is not None else guard_home
        if run_guard_home is None:
            print("guard_home is required for tray run", file=sys.stderr)
            return 1

        capability = detect_capability()
        if not capability.supported:
            print(f"Tray not supported: {capability.details}", file=sys.stderr)
            return 1

        # Write locator before starting so `tray status` sees this process.
        locator = build_locator_for_current_process(
            guard_home=run_guard_home,
            package_version=package_version,
            backend=capability.backend,
        )
        try:
            write_locator(run_guard_home, locator)
            reset_crash_count(run_guard_home)
        except OSError as error:
            print(f"Failed to write tray locator: {error}", file=sys.stderr)
            return 1

        runtime = TrayRuntime(
            guard_home=run_guard_home,
            store=store or _require_guard_store(store),
            config=config or _require_guard_config(config),
            capability=capability,
        )
        try:
            return runtime.run()
        finally:
            with suppress(Exception):
                remove_locator(run_guard_home)

    from ..tray.lifecycle import (
        get_status,
        install_registration,
        remove_registration,
        repair_tray,
        start_tray,
        stop_tray,
    )
    from ..tray.platforms import detect_platform_adapter

    if tray_command == "status":
        state, capability, locator = get_status(guard_home, package_version=package_version)
        payload: dict[str, object] = {
            "generated_at": _now(),
            "state": state.value,
            "platform": capability.platform.value if capability.platform else None,
            "backend": capability.backend.value,
            "supported": capability.supported,
            "reason": capability.reason.value,
            "details": capability.details,
            "locator": locator.to_payload() if locator else None,
        }
        _emit("tray-status", payload, use_json)
        return 0

    if tray_command == "start":
        result = start_tray(guard_home, package_version=package_version, force=bool(getattr(args, "force", False)))
        _emit(
            "tray-start",
            {
                "generated_at": _now(),
                "ok": result.ok,
                "state": result.state.value,
                "reason": result.reason.value,
                "message": result.message,
                **({"recovery_command": result.recovery_command} if result.recovery_command else {}),
            },
            use_json,
        )
        return 0 if result.ok else 1

    if tray_command == "stop":
        result = stop_tray(guard_home)
        _emit(
            "tray-stop",
            {
                "generated_at": _now(),
                "ok": result.ok,
                "state": result.state.value,
                "reason": result.reason.value,
                "message": result.message,
                **({"recovery_command": result.recovery_command} if result.recovery_command else {}),
            },
            use_json,
        )
        return 0 if result.ok else 1

    if tray_command == "restart":
        stop_result = stop_tray(guard_home)
        start_result = start_tray(guard_home, package_version=package_version, force=True)
        _emit(
            "tray-restart",
            {
                "generated_at": _now(),
                "ok": start_result.ok,
                "state": start_result.state.value,
                "reason": start_result.reason.value,
                "message": start_result.message,
                "stop_reason": stop_result.reason.value,
                **({"recovery_command": start_result.recovery_command} if start_result.recovery_command else {}),
            },
            use_json,
        )
        return 0 if start_result.ok else 1

    if tray_command == "repair":
        result = repair_tray(guard_home)
        _emit(
            "tray-repair",
            {
                "generated_at": _now(),
                "ok": result.ok,
                "state": result.state.value,
                "reason": result.reason.value,
                "message": result.message,
            },
            use_json,
        )
        return 0 if result.ok else 1

    if tray_command == "install":
        adapter = detect_platform_adapter()
        if adapter is None:
            _emit(
                "tray-install",
                {"generated_at": _now(), "ok": False, "reason": "unsupported_platform"},
                use_json,
            )
            return 1
        result = install_registration(
            guard_home,
            adapter=adapter,
            run_at_login=not bool(getattr(args, "no_run_at_login", False)),
        )
        _emit(
            "tray-install",
            {
                "generated_at": _now(),
                "ok": result.ok,
                "state": result.state.value,
                "reason": result.reason.value,
                "message": result.message,
            },
            use_json,
        )
        return 0 if result.ok else 1

    if tray_command == "uninstall":
        adapter = detect_platform_adapter()
        if adapter is None:
            _emit(
                "tray-uninstall",
                {"generated_at": _now(), "ok": False, "reason": "unsupported_platform"},
                use_json,
            )
            return 1
        result = remove_registration(guard_home, adapter=adapter)
        _emit(
            "tray-uninstall",
            {
                "generated_at": _now(),
                "ok": result.ok,
                "state": result.state.value,
                "reason": result.reason.value,
                "message": result.message,
            },
            use_json,
        )
        return 0 if result.ok else 1

    print(f"Unknown tray command: {tray_command}", file=sys.stderr)
    return 2


def _guard_package_version() -> str:
    """Return the installed guard package version, or empty string."""
    try:
        from importlib.metadata import version

        return version("codex-plugin-scanner")
    except Exception:
        return ""

__all__ = [
    "_run_guard_apps_command",
    "_run_guard_bootstrap_command",
    "_run_guard_command_inspection_command",
    "_run_guard_dashboard_command",
    "_run_guard_detect_command",
    "_run_guard_init_command",
    "_run_guard_install_command",
    "_run_guard_mcp_command",
    "_run_guard_preflight_command",
    "_run_guard_protect_command",
    "_run_guard_scan_command",
    "_run_guard_start_command",
    "_run_guard_status_command",
    "_run_guard_tray_command",
    "_run_guard_update_command",
]
