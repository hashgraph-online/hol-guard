"""Guard CLI command dispatch helpers."""

# ruff: noqa: F403, F405

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ._commands_shared import _now, _require_guard_config, _require_guard_context, _require_guard_store
    from .commands_support_connect import _refresh_cloud_policy_bundle, _synced_policy_payload
    from .commands_support_hook_payload import _headless_approval_resolver
    from .commands_support_interaction import _emit
    from .commands_support_prompts import _guard_approvals_command, _guard_diff_command, _guard_rerun_command
    from .commands_support_runtime_resolution import _run_hermes_mcp_proxy
    from .commands_support_workspace import _package_firewall_block_payload, _package_firewall_cli_gate_input


from ._commands_shared import *
from .commands_parser_helpers import *


def _current_proxy_config(context: HarnessContext, store: GuardStore) -> GuardConfig:
    local_config = load_guard_config(context.guard_home, workspace=context.workspace_dir)
    return overlay_synced_guard_policy(local_config, _synced_policy_payload(store))


def _run_guard_codex_mcp_proxy_command(
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
    proxy = CodexMcpGuardProxy(
        server_name=args.server_name,
        command=[args.server_command, *list(args.server_args)],
        context=context,
        store=store,
        config=config,
        source_scope=args.source_scope,
        config_path=args.config_path,
        transport=args.transport,
        server_id=args.server_id,
        server_env_keys=tuple(args.server_env_keys),
        current_config_provider=lambda: _current_proxy_config(context, store),
    )
    return proxy.serve()


def _run_guard_cursor_mcp_proxy_command(
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
    proxy = CursorMcpGuardProxy(
        server_name=args.server_name,
        command=[args.server_command, *list(args.server_args)],
        context=context,
        store=store,
        config=config,
        source_scope=args.source_scope,
        config_path=args.config_path,
        transport=args.transport,
        server_id=args.server_id,
        server_env_keys=tuple(args.server_env_keys),
        current_config_provider=lambda: _current_proxy_config(context, store),
    )
    return proxy.serve()


def _run_guard_opencode_mcp_proxy_command(
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
    proxy = OpenCodeMcpGuardProxy(
        server_name=args.server_name,
        command=[args.server_command, *list(args.server_args)],
        context=context,
        store=store,
        config=config,
        source_scope=args.source_scope,
        config_path=args.config_path,
        transport=args.transport,
        server_id=args.server_id,
        server_env_keys=tuple(args.server_env_keys),
        current_config_provider=lambda: _current_proxy_config(context, store),
    )
    return proxy.serve()


def _run_guard_copilot_mcp_proxy_command(
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
    proxy = CopilotMcpGuardProxy(
        server_name=args.server_name,
        command=[args.server_command, *list(args.server_args)],
        context=context,
        store=store,
        config=config,
        source_scope=args.source_scope,
        config_path=args.config_path,
        transport=args.transport,
        server_id=args.server_id,
        server_env_keys=tuple(args.server_env_keys),
        current_config_provider=lambda: _current_proxy_config(context, store),
    )
    return proxy.serve()


def _run_guard_hermes_mcp_proxy_command(
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
    return _run_hermes_mcp_proxy(args=args, context=context, store=store, config=config)


def _run_guard_uninstall_command(
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
    if bool(getattr(args, "self_uninstall", False)):
        from ..mdm.policy import load_managed_policy

        managed_policy = load_managed_policy()
        if managed_policy.status in {"invalid", "inaccessible", "tampered"} or (
            managed_policy.policy is not None and managed_policy.policy.install_owner == "mdm"
        ):
            _emit(
                "uninstall",
                {
                    "status": "managed",
                    "changed": False,
                    "reason_code": "managed_removal_authorization_required",
                    "message": "Removal is owned by the device management service.",
                },
                getattr(args, "json", False),
            )
            return 3
        if getattr(args, "harness", None) is not None or bool(getattr(args, "all", False)):
            print("Guard self uninstall does not accept a harness or --all.", file=sys.stderr)
            return 2
        payload, exit_code = run_guard_self_uninstall(
            dry_run=bool(getattr(args, "dry_run", False)),
            context=context,
            store=store,
            now=_now(),
        )
        _emit("uninstall", payload, getattr(args, "json", False))
        return exit_code
    if bool(getattr(args, "dry_run", False)):
        print("Guard uninstall --dry-run requires --self.", file=sys.stderr)
        return 2
    try:
        payload = apply_managed_install(
            "uninstall",
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
    _emit("uninstall", payload, getattr(args, "json", False))
    return 0


def _run_guard_package_shims_command(
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
    requested_managers = tuple(
        manager
        for manager in getattr(args, "package_shim_managers", [])
        if isinstance(manager, str) and manager.strip()
    )
    shim_command = getattr(args, "package_shims_command", "status")
    entitlement = resolve_package_firewall_entitlement_with_refresh(store)
    current_status = package_shim_status(context)
    if shim_command == "status":
        payload = current_status
        payload["actions"] = package_firewall_action_states(
            entitlement,
            has_installed_managers=bool(current_status.get("installed_managers")),
        )
        payload["entitlement"] = entitlement
        payload["generated_at"] = _now()
        _emit("package-shims", payload, getattr(args, "json", False))
        return 0
    if shim_command not in {"repair", "uninstall"} and not bool(entitlement["allowed"]):
        _status, payload = _package_firewall_block_payload(
            entitlement=entitlement,
            has_installed_managers=bool(current_status.get("installed_managers")),
            operation="remove" if shim_command == "uninstall" else shim_command,
        )
        payload["generated_at"] = _now()
        _emit("package-shims", payload, getattr(args, "json", False))
        return 2
    try:
        if shim_command in {"install", "repair", "uninstall"}:
            gate_input = _package_firewall_cli_gate_input(args, store.guard_home)
            require_high_risk(
                store.guard_home,
                purpose="supply_chain_firewall",
                approval_gate_input=gate_input,
            )
        if shim_command == "install":
            payload = activate_package_shims(context, managers=requested_managers or None)
        elif shim_command == "repair":
            payload = activate_package_shims(
                context,
                managers=requested_managers or None,
                repair=True,
            )
        elif shim_command == "uninstall":
            payload = uninstall_package_shims(context, managers=requested_managers or None)
        else:
            payload = package_shim_status(context)
    except ApprovalGateError as error:
        _emit("package-shims", approval_gate_cli_payload(error), getattr(args, "json", False))
        return 2
    payload["entitlement"] = entitlement
    payload["generated_at"] = _now()
    _emit("package-shims", payload, getattr(args, "json", False))
    return 0


def _run_guard_run_command(
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
    grok_executable = getattr(args, "grok_executable", None)
    if isinstance(grok_executable, str) and grok_executable.strip():
        try:
            selected_harness = get_adapter(str(args.harness)).harness
        except ValueError:
            selected_harness = str(args.harness)
        if selected_harness != "grok":
            print("Error: --grok-executable can only be used with the Grok harness.", file=sys.stderr)
            return 2
    store = _require_guard_store(store)
    context = _require_guard_context(context)
    config = _require_guard_config(config)
    _refresh_cloud_policy_bundle(store)
    config = overlay_synced_guard_policy(config, _synced_policy_payload(store))
    interactive_resolver_fn = None
    blocked_resolver_fn = None
    if not getattr(args, "json", False) and not bool(args.dry_run) and config.mode == "prompt" and sys.stdin.isatty():
        from .prompt import build_prompt_artifacts, resolve_interactive_decisions

        def _interactive_resolver_impl(detection, payload):
            return resolve_interactive_decisions(
                store=store,
                evaluation=payload,
                prompt_artifacts=build_prompt_artifacts(
                    harness=detection.harness,
                    artifacts=list(detection.artifacts),
                    evaluation_artifacts=[item for item in payload.get("artifacts", []) if isinstance(item, dict)],
                ),
                workspace=str(workspace) if workspace else None,
                now=_now(),
            )

        interactive_resolver_fn = _interactive_resolver_impl
    elif not bool(args.dry_run) and config.mode == "prompt":
        blocked_resolver_fn = _headless_approval_resolver(args=args, context=context, store=store, config=config)

    def current_run_config() -> GuardConfig:
        local_config = load_guard_config(context.guard_home, workspace=context.workspace_dir)
        return overlay_synced_guard_policy(local_config, _synced_policy_payload(store))

    payload = guard_run(
        args.harness,
        context=context,
        store=store,
        config=config,
        dry_run=bool(args.dry_run),
        passthrough_args=list(args.passthrough_args),
        default_action=args.default_action,
        interactive_resolver=interactive_resolver_fn,
        blocked_resolver=blocked_resolver_fn,
        current_config_provider=current_run_config,
    )
    payload["dry_run"] = bool(args.dry_run)
    payload["rerun_command"] = _guard_rerun_command(args)
    payload["diff_command"] = _guard_diff_command(args)
    payload["approvals_command"] = _guard_approvals_command(args)
    _emit("run", payload, getattr(args, "json", False))
    if payload.get("blocked"):
        return 1
    return_code = payload.get("return_code")
    return int(return_code) if isinstance(return_code, int) else 0


__all__ = [
    "_run_guard_codex_mcp_proxy_command",
    "_run_guard_copilot_mcp_proxy_command",
    "_run_guard_cursor_mcp_proxy_command",
    "_run_guard_hermes_mcp_proxy_command",
    "_run_guard_opencode_mcp_proxy_command",
    "_run_guard_package_shims_command",
    "_run_guard_run_command",
    "_run_guard_uninstall_command",
]
