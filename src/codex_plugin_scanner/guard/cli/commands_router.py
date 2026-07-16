"""Guard CLI command entrypoint."""

# fmt: off
# ruff: noqa: F403, F405

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .commands_support_connect import _synced_policy_payload
    from .commands_support_workspace import _resolve_guard_workspace


from ._commands_shared import *
from .commands_parser_helpers import *

_EARLY_HANDLERS = {
    "mdm": "_run_guard_mdm_command",
    "command": "_run_guard_command_inspection_command",
    "scan": "_run_guard_scan_command",
    "preflight": "_run_guard_preflight_command",
    "mcp": "_run_guard_mcp_command",
}

_PRESTORE_HANDLERS = {
    "update": "_run_guard_update_command",
}

_COMMON_HANDLERS = {
    "protect": "_run_guard_protect_command",
    "start": "_run_guard_start_command",
    "status": "_run_guard_status_command",
    "init": "_run_guard_init_command",
    "dashboard": "_run_guard_dashboard_command",
    "admin": "_run_guard_dashboard_command",
    "bootstrap": "_run_guard_bootstrap_command",
    "detect": "_run_guard_detect_command",
    "apps": "_run_guard_apps_command",
    "install": "_run_guard_install_command",
    "codex-mcp-proxy": "_run_guard_codex_mcp_proxy_command",
    "cursor-mcp-proxy": "_run_guard_cursor_mcp_proxy_command",
    "opencode-mcp-proxy": "_run_guard_opencode_mcp_proxy_command",
    "copilot-mcp-proxy": "_run_guard_copilot_mcp_proxy_command",
    "hermes-mcp-proxy": "_run_guard_hermes_mcp_proxy_command",
    "uninstall": "_run_guard_uninstall_command",
    "package-shims": "_run_guard_package_shims_command",
    "run": "_run_guard_run_command",
    "diff": "_run_guard_diff_command",
    "test-eval": "_run_guard_test_eval_command",
    "receipts": "_run_guard_receipts_command",
    "history": "_run_guard_history_command",
    "inventory": "_run_guard_inventory_command",
    "aibom": "_run_guard_aibom_command",
    "abom": "_run_guard_abom_command",
    "policies": "_run_guard_policies_command",
    "trust": "_run_guard_trust_command",
    "settings": "_run_guard_settings_command",
    "exceptions": "_run_guard_exceptions_command",
    "advisories": "_run_guard_advisories_command",
    "events": "_run_guard_events_command",
    "approvals": "_run_guard_approvals_command",
    "explain": "_run_guard_explain_command",
    "allow": "_run_guard_policy_action_command",
    "deny": "_run_guard_policy_action_command",
    "doctor": "_run_guard_doctor_command",
    "login": "_run_guard_login_command",
    "remote-pair": "_run_guard_remote_pair_command",
    "connect": "_run_guard_connect_command",
    "disconnect": "_run_guard_disconnect_command",
    "bridge": "_run_guard_bridge_command",
    "sync": "_run_guard_sync_command",
    "cloud": "_run_guard_cloud_command",
    "supply-chain": "_run_guard_supply_chain_command",
    "service": "_run_guard_service_command",
    "device": "_run_guard_device_command",
    "commands": "_run_guard_commands_command",
    "daemon": "_run_guard_daemon_command",
    "hook": "_run_guard_hook_command",
}


def _resolve_guard_handler(mapping: dict[str, str], command: str) -> object | None:
    handler_name = mapping.get(command)
    if handler_name is None:
        return None
    return globals().get(handler_name)


def _normalize_guard_handler_result(result: object) -> int:
    if result is None:
        return 0
    return result if isinstance(result, int) else 1


def run_guard_command(
    args: argparse.Namespace,
    *,
    input_text: str | None = None,
    output_stream: TextIO | None = None,
) -> int:
    "Execute a Guard subcommand."
    handler = _resolve_guard_handler(_EARLY_HANDLERS, args.guard_command)
    if callable(handler):
        result = handler(args, input_text=input_text, output_stream=output_stream)
        return _normalize_guard_handler_result(result)

    home_override = getattr(args, "home", None)
    guard_home = resolve_guard_home(getattr(args, "guard_home", None) or home_override)
    workspace = _resolve_guard_workspace(args, guard_home=guard_home)
    executable_overrides: dict[str, str] = {}
    grok_executable = getattr(args, "grok_executable", None)
    if isinstance(grok_executable, str) and grok_executable.strip():
        executable_overrides["grok"] = grok_executable.strip()
    context = HarnessContext(
        home_dir=Path(home_override).resolve() if home_override else Path.home().resolve(),
        workspace_dir=workspace,
        guard_home=guard_home,
        executable_overrides=executable_overrides,
    )

    handler = _resolve_guard_handler(_PRESTORE_HANDLERS, args.guard_command)
    if callable(handler):
        result = handler(
            args,
            guard_home=guard_home,
            workspace=workspace,
            context=context,
            input_text=input_text,
            output_stream=output_stream,
        )
        return _normalize_guard_handler_result(result)

    source = getattr(args, "source", "default")
    try:
        store = GuardStore(guard_home, source=source, prime_policy_integrity=args.guard_command != "hook")
    except ValueError as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2
    config = load_guard_config(guard_home, workspace=workspace)
    config = overlay_synced_guard_policy(config, _synced_policy_payload(store))

    handler = _resolve_guard_handler(_COMMON_HANDLERS, args.guard_command)
    if callable(handler):
        result = handler(
            args,
            guard_home=guard_home,
            workspace=workspace,
            context=context,
            store=store,
            config=config,
            input_text=input_text,
            output_stream=output_stream,
        )
        return _normalize_guard_handler_result(result)
    return 1

__all__ = [
    "run_guard_command",
]
