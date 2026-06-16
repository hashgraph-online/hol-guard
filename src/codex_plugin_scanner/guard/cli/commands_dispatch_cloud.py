"""Guard CLI command dispatch helpers."""

# ruff: noqa: F403, F405

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ._commands_shared import _now, _require_guard_config, _require_guard_context, _require_guard_store
    from .commands_support_connect import (
        _announce_guard_device_connect_copy,
        _build_guard_device_connect_payload,
        _finalize_guard_connect_payload,
        _guard_ci_safe_connect_options,
        _manual_guard_login_payload,
    )
    from .commands_support_interaction import _emit
    from .commands_support_service import (
        _guard_service_login_payload,
        _guard_service_status_payload,
        _guard_service_sync_failure_message,
        _guard_service_sync_payload,
        _guard_sync_failure_message,
        _handle_daemon_repair,
        _handle_daemon_status,
        _handle_daemon_stop,
        _validated_supply_chain_sync_payload,
    )


from ..runtime.command_queue import command_queue_status
from ._commands_shared import *
from .commands_parser_helpers import *


def _run_guard_login_command(
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
    manual_login = _manual_guard_login_payload(args=args, store=store)
    if manual_login is not None:
        payload, exit_code = manual_login
        if payload is not None:
            _emit("login", payload, getattr(args, "json", False))
        return exit_code
    payload, exit_code = _build_guard_device_connect_payload(
        store=store,
        connect_url=args.connect_url,
        use_browser_oauth=False,
        open_device_browser=True,
        wait_timeout_seconds=int(getattr(args, "wait_timeout_seconds", 180) or 180),
        announce_copy=None if getattr(args, "json", False) else _announce_guard_device_connect_copy,
    )
    if payload is None:
        return exit_code
    _emit("connect", payload, getattr(args, "json", False))
    return exit_code


def _run_guard_remote_pair_command(
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
    context = _require_guard_context(context)
    return dispatch_guard_remote_pair_command(
        args=args,
        store=store,
        context=context,
        emit=_emit,
        finalize_connect_payload=_finalize_guard_connect_payload,
        now=_now(),
    )


def _run_guard_connect_command(
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
    connect_subcommand = getattr(args, "connect_command", None)
    if connect_subcommand == "repair":
        payload = run_guard_connect_repair_command(
            store=store,
            sync_url=args.sync_url,
            connect_url=args.connect_url,
        )
        _emit("connect", payload, getattr(args, "json", False))
        return 0
    if connect_subcommand in {"status", "re-pair"}:
        payload = build_connect_status_payload(
            store=store,
            sync_url=args.sync_url,
            connect_url=args.connect_url,
            action=str(connect_subcommand),
        )
        _emit("connect", payload, getattr(args, "json", False))
        return 0
    try:
        ci_safe, machine_label = _guard_ci_safe_connect_options(args)
    except ValueError as error:
        print(str(error), file=sys.stderr)
        return 2
    if not bool(getattr(args, "headless", False)):
        payload, exit_code = _build_guard_device_connect_payload(
            store=store,
            connect_url=args.connect_url,
            use_browser_oauth=False,
            open_device_browser=True,
            wait_timeout_seconds=int(getattr(args, "wait_timeout_seconds", 180) or 180),
            announce_copy=None if getattr(args, "json", False) else _announce_guard_device_connect_copy,
        )
        if payload is None:
            return exit_code
        _emit("connect", payload, getattr(args, "json", False))
        return exit_code
    if bool(getattr(args, "headless", False)):
        payload, exit_code = _build_guard_device_connect_payload(
            store=store,
            connect_url=args.connect_url,
            use_browser_oauth=False,
            open_device_browser=bool(getattr(args, "open_browser", False)),
            wait_timeout_seconds=int(getattr(args, "wait_timeout_seconds", 180) or 180),
            announce_copy=None if getattr(args, "json", False) else _announce_guard_device_connect_copy,
            ci_safe=ci_safe,
            machine_label=machine_label,
        )
        if payload is None:
            return exit_code
        _emit("connect", payload, getattr(args, "json", False))
        return exit_code
    return 2


def _run_guard_disconnect_command(
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
    try:
        payload = run_guard_disconnect_command(
            store=store,
            revoke_cloud_grant=bool(getattr(args, "revoke_cloud_grant", False)),
            now=_now(),
        )
    except (RuntimeError, TimeoutError, urllib.error.URLError, http.client.HTTPException) as error:
        if getattr(args, "json", False):
            _emit("disconnect", {"status": "error", "error": str(error)}, True)
        else:
            print(str(error), file=sys.stderr)
        return 1
    _emit("disconnect", payload, getattr(args, "json", False))
    return 0


def _run_guard_bridge_command(
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
    poll_interval = getattr(args, "poll_interval", 10) or 10
    guard_url = getattr(args, "guard_url", None)
    dry_run = getattr(args, "dry_run", False)

    backend = None
    telegram_token = getattr(args, "telegram_token", None)
    telegram_chat_id = getattr(args, "telegram_chat_id", None)
    webhook_url = getattr(args, "webhook_url", None)
    webhook_include_artifact_details = getattr(args, "webhook_include_artifact_details", False)
    hermes_chat_id = getattr(args, "hermes_chat_id", None)

    if telegram_token and telegram_chat_id:
        backend = TelegramBackend(telegram_token, telegram_chat_id)
    elif webhook_url:
        backend = WebhookBackend(
            webhook_url,
            include_artifact_details=webhook_include_artifact_details,
        )
    elif hermes_chat_id:
        backend = HermesBackend(hermes_chat_id)

    bridge_config = BridgeConfig(guard_url=guard_url, poll_interval=poll_interval, dry_run=dry_run)
    bridge = GuardBridge(config=bridge_config, store=store, backend=backend)
    bridge.run()
    return 0


def _run_guard_sync_command(
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
    context = _require_guard_context(context)
    try:
        payload = sync_receipts(
            store,
            home_dir=context.home_dir,
            workspace_dir=context.workspace_dir,
        )
    except GuardSyncNotConfiguredError as error:
        message = _guard_sync_failure_message(error)
        if getattr(args, "json", False):
            _emit("sync", {"synced": False, "error": message}, True)
        else:
            print(message, file=sys.stderr)
        return 1
    except RuntimeError as error:
        if getattr(args, "json", False):
            _emit("sync", {"synced": False, "error": str(error)}, True)
        else:
            print(str(error), file=sys.stderr)
        return 1
    _emit("sync", payload, getattr(args, "json", False))
    return 0


def _run_guard_cloud_command(
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
    cloud_command = getattr(args, "cloud_command", None)
    if cloud_command == "sync-intel":
        try:
            payload = _validated_supply_chain_sync_payload(sync_supply_chain_bundle(store))
        except GuardSyncNotConfiguredError as error:
            message = _guard_sync_failure_message(error)
            if getattr(args, "json", False):
                _emit("cloud-sync-intel", {"synced": False, "error": message}, True)
            else:
                print(message, file=sys.stderr)
            return 1
        except RuntimeError as error:
            if getattr(args, "json", False):
                _emit("cloud-sync-intel", {"synced": False, "error": str(error)}, True)
            else:
                print(str(error), file=sys.stderr)
            return 1
        payload["supply_chain"] = build_local_supply_chain_posture(store, config, now=_now())
        _emit("cloud-sync-intel", payload, getattr(args, "json", False))
        return 0
    print("cloud subcommand is required", file=sys.stderr)
    return 2


def _run_guard_supply_chain_command(
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
    supply_chain_command = getattr(args, "supply_chain_command", None)
    workspace_dir = workspace or Path.cwd()
    if supply_chain_command == "scan":
        payload, exit_code = build_workspace_scan_payload(
            store=store,
            config=config,
            workspace_dir=workspace_dir,
            now=_now(),
        )
        _emit("supply-chain-scan", payload, getattr(args, "json", False))
        return exit_code
    if supply_chain_command == "audit":
        before_workspace = getattr(args, "before_workspace", None)
        after_workspace = getattr(args, "after_workspace", None)
        payload, exit_code = build_workspace_audit_payload(
            store=store,
            config=config,
            workspace_dir=workspace_dir,
            now=_now(),
            command_name="audit",
            sbom_paths=tuple(str(item) for item in getattr(args, "sbom", []) if isinstance(item, str)),
            ci=bool(getattr(args, "ci", False)),
            fail_on=str(getattr(args, "fail_on", "high")),
            before_workspace_dir=(
                Path(str(before_workspace)).expanduser() if isinstance(before_workspace, str) else None
            ),
            after_workspace_dir=(Path(str(after_workspace)).expanduser() if isinstance(after_workspace, str) else None),
        )
        _emit("supply-chain-audit", payload, getattr(args, "json", False))
        return exit_code
    if supply_chain_command == "sync":
        try:
            payload = _validated_supply_chain_sync_payload(sync_supply_chain_bundle(store))
        except GuardSyncNotConfiguredError as error:
            message = _guard_sync_failure_message(error)
            if getattr(args, "json", False):
                _emit("supply-chain-sync", {"synced": False, "error": message}, True)
            else:
                print(message, file=sys.stderr)
            return 1
        except RuntimeError as error:
            if getattr(args, "json", False):
                _emit("supply-chain-sync", {"synced": False, "error": str(error)}, True)
            else:
                print(str(error), file=sys.stderr)
            return 1
        payload["supply_chain"] = build_local_supply_chain_posture(store, config, now=_now())
        _emit("supply-chain-sync", payload, getattr(args, "json", False))
        return 0
    if supply_chain_command == "explain":
        payload, exit_code = build_supply_chain_explain_payload(
            store=store,
            config=config,
            workspace_dir=workspace_dir,
            package_spec=str(args.package),
            ecosystem=str(args.ecosystem),
            now=_now(),
        )
        _emit("supply-chain-explain", payload, getattr(args, "json", False))
        return exit_code
    print("supply-chain subcommand is required", file=sys.stderr)
    return 2


def _run_guard_service_command(
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
    service_command = getattr(args, "service_command", None)
    if service_command == "login":
        payload, exit_code = _guard_service_login_payload(args=args, store=store)
        _emit("service-login", payload, getattr(args, "json", False))
        return exit_code
    if service_command == "sync":
        try:
            payload = _guard_service_sync_payload(store)
        except (GuardSyncNotConfiguredError, RuntimeError) as error:
            message = (
                _guard_service_sync_failure_message(error)
                if isinstance(error, GuardSyncNotConfiguredError)
                else str(error)
            )
            if getattr(args, "json", False):
                _emit("service-sync", {"synced": False, "error": message}, True)
            else:
                print(message, file=sys.stderr)
            return 1
        _emit("service-sync", payload, getattr(args, "json", False))
        return 0
    if service_command == "status":
        payload = _guard_service_status_payload(store)
        _emit("service-status", payload, getattr(args, "json", False))
        return 0
    print("service subcommand is required", file=sys.stderr)
    return 2


def _run_guard_device_command(
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
    command = getattr(args, "device_command", None)
    now = _now()
    if command == "show":
        payload: dict[str, object] = {"device": store.get_device_metadata()}
        _emit("device", payload, getattr(args, "json", False))
        return 0
    if command == "rotate":
        metadata = store.rotate_installation_id(now)
        store.add_event("device_rotated", {"installation_id": metadata["installation_id"]}, now)
        _emit("device", {"device": metadata, "rotated": True}, getattr(args, "json", False))
        return 0
    if command == "label":
        label_command = getattr(args, "device_label_command", None)
        if label_command != "set":
            print("device label subcommand is required", file=sys.stderr)
            return 2
        metadata = store.set_device_label(getattr(args, "label", ""), now)
        store.add_event("device_labeled", {"device_label": metadata["device_label"]}, now)
        _emit("device", {"device": metadata, "updated": True}, getattr(args, "json", False))
        return 0
    print("device subcommand is required", file=sys.stderr)
    return 2


def _run_guard_daemon_command(
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
    if guard_home is None:
        raise RuntimeError("Guard home is required")
    daemon_command = getattr(args, "daemon_command", None)
    if daemon_command == "status":
        return _handle_daemon_status(guard_home, getattr(args, "json", False))
    if daemon_command == "repair":
        return _handle_daemon_repair(guard_home, getattr(args, "json", False))
    if daemon_command == "stop":
        return _handle_daemon_stop(guard_home, getattr(args, "json", False))
    daemon = GuardDaemonServer(store, port=args.port or 0)
    if args.serve:
        daemon.serve()
        return 0
    _emit("doctor", {"daemon_url": f"http://127.0.0.1:{daemon.port}"}, getattr(args, "json", False))
    return 0


def _run_guard_commands_command(
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
    commands_command = getattr(args, "commands_command", None)
    if commands_command == "status":
        _emit("commands", command_queue_status(store), getattr(args, "json", False))
        return 0
    print("commands subcommand is required", file=sys.stderr)
    return 2


__all__ = [
    "_run_guard_bridge_command",
    "_run_guard_cloud_command",
    "_run_guard_commands_command",
    "_run_guard_connect_command",
    "_run_guard_daemon_command",
    "_run_guard_device_command",
    "_run_guard_disconnect_command",
    "_run_guard_login_command",
    "_run_guard_remote_pair_command",
    "_run_guard_service_command",
    "_run_guard_supply_chain_command",
    "_run_guard_sync_command",
]
