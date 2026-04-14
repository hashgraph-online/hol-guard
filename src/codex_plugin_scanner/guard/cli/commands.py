"""Guard CLI command handlers."""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import webbrowser
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ...models import ScanOptions
from ..adapters import get_adapter
from ..adapters.base import HarnessContext
from ..approvals import approval_center_hint, queue_blocked_approvals, wait_for_approval_requests
from ..config import load_guard_config, overlay_synced_guard_policy, resolve_guard_home
from ..consumer import artifact_hash, detect_all, detect_harness, evaluate_detection, record_policy, run_consumer_scan
from ..daemon import GuardDaemonServer, ensure_guard_daemon
from ..incident import build_incident_context
from ..models import GuardArtifact, HarnessDetection
from ..policy.engine import SAFE_CHANGED_HASH_ACTION, VALID_GUARD_ACTIONS
from ..protect import build_protect_payload
from ..receipts import build_receipt
from ..risk import artifact_risk_signals, artifact_risk_summary
from ..runtime import guard_run, sync_receipts
from ..runtime.secret_file_requests import build_file_read_request_artifact, extract_sensitive_file_read_request
from ..store import GuardStore
from .approval_commands import add_approval_parser, run_approval_command
from .bootstrap import DEFAULT_ALIAS_NAME, build_guard_bootstrap_payload
from .install_commands import apply_managed_install
from .product import build_guard_connect_payload, build_guard_start_payload, build_guard_status_payload
from .prompt import build_prompt_artifacts, resolve_interactive_decisions
from .render import emit_guard_payload


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def add_guard_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Register Guard as a nested command family."""

    program_name = Path(sys.argv[0]).name or "plugin-scanner"
    guard_parser = subparsers.add_parser(
        "guard",
        help="Run local harness protection workflows",
        description=(
            "HOL Guard watches local harness config, records approval receipts, and surfaces "
            "changed tools before launch."
        ),
        epilog=(
            "Examples:\n"
            f"  {program_name} guard detect\n"
            f"  {program_name} guard doctor cursor\n"
            f"  {program_name} guard run codex --dry-run\n"
            f"  {program_name} guard install claude-code --workspace ."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _configure_guard_parser(guard_parser)


def add_guard_root_parser(parser: argparse.ArgumentParser) -> None:
    """Register Guard as the top-level CLI surface."""

    parser.description = "Protect local harnesses before new or changed tools run."
    parser.set_defaults(command="guard")
    _configure_guard_parser(parser)


def _configure_guard_parser(guard_parser: argparse.ArgumentParser) -> None:
    """Attach Guard subcommands to a parser."""
    guard_subparsers = guard_parser.add_subparsers(
        dest="guard_command",
        required=True,
        metavar=(
            "{start,status,bootstrap,detect,install,uninstall,run,protect,preflight,scan,diff,receipts,inventory,abom,"
            "approvals,explain,allow,deny,policies,exceptions,advisories,events,doctor,connect,login,sync}"
        ),
    )

    start_parser = guard_subparsers.add_parser("start", help="Show the first Guard steps for a local harness")
    _add_guard_common_args(start_parser)
    start_parser.add_argument("--json", action="store_true")

    status_parser = guard_subparsers.add_parser("status", help="Show current Guard protection status")
    _add_guard_common_args(status_parser)
    status_parser.add_argument("--json", action="store_true")

    connect_parser = guard_subparsers.add_parser(
        "connect",
        help="Pair local Guard with Guard Cloud and show the next local-to-cloud actions",
    )
    _add_guard_common_args(connect_parser)
    connect_parser.add_argument("--sync-url")
    connect_parser.add_argument("--token")
    connect_parser.add_argument("--save-only", action="store_true")
    connect_parser.add_argument("--json", action="store_true")

    bootstrap_parser = guard_subparsers.add_parser(
        "bootstrap",
        help="Detect a harness, start the approval center, and install Guard for the best local target",
    )
    bootstrap_parser.add_argument("harness", nargs="?")
    _add_guard_common_args(bootstrap_parser)
    bootstrap_parser.add_argument("--skip-install", action="store_true")
    bootstrap_parser.add_argument("--alias-name", default=DEFAULT_ALIAS_NAME)
    bootstrap_parser.add_argument("--write-shell-alias", action="store_true")
    bootstrap_parser.add_argument("--json", action="store_true")

    detect_parser = guard_subparsers.add_parser("detect", help="Discover supported harnesses and local artifacts")
    detect_parser.add_argument("harness", nargs="?")
    _add_guard_common_args(detect_parser)
    detect_parser.add_argument("--json", action="store_true")

    install_parser = guard_subparsers.add_parser("install", help="Enable Guard management for one or more harnesses")
    install_parser.add_argument("harness", nargs="?")
    install_parser.add_argument("--all", action="store_true")
    _add_guard_common_args(install_parser)
    install_parser.add_argument("--json", action="store_true")

    uninstall_parser = guard_subparsers.add_parser(
        "uninstall",
        help="Disable Guard management for one or more harnesses",
    )
    uninstall_parser.add_argument("harness", nargs="?")
    uninstall_parser.add_argument("--all", action="store_true")
    _add_guard_common_args(uninstall_parser)
    uninstall_parser.add_argument("--json", action="store_true")

    run_parser = guard_subparsers.add_parser("run", help="Evaluate local policy, then launch the harness")
    run_parser.add_argument("harness")
    _add_guard_common_args(run_parser)
    run_parser.add_argument("--json", action="store_true")
    run_parser.add_argument("--dry-run", action="store_true")
    run_parser.add_argument(
        "--default-action",
        choices=("allow", "warn", "review", "block", "sandbox-required", "require-reapproval"),
    )
    run_parser.add_argument("--arg", dest="passthrough_args", action="append", default=[])

    protect_parser = guard_subparsers.add_parser(
        "protect",
        help="Wrap an install or harness registration command and stop risky artifacts before they land",
    )
    _add_guard_common_args(protect_parser)
    protect_parser.add_argument("--dry-run", action="store_true")
    protect_parser.add_argument("--json", action="store_true")
    protect_parser.add_argument("protect_command", nargs=argparse.REMAINDER)

    preflight_parser = guard_subparsers.add_parser(
        "preflight",
        help="Scan an artifact before you add it to a harness config or install path",
    )
    preflight_parser.add_argument("target", nargs="?", default=".")
    preflight_parser.add_argument("--harness")
    preflight_parser.add_argument("--enforce", action="store_true")
    preflight_parser.add_argument("--json", action="store_true")
    _add_guard_cisco_mode_arg(preflight_parser)

    scan_parser = guard_subparsers.add_parser("scan", help="Run a consumer-mode scan for a local artifact")
    scan_parser.add_argument("target", nargs="?", default=".")
    scan_parser.add_argument("--consumer-mode", action="store_true")
    scan_parser.add_argument("--json", action="store_true")
    _add_guard_cisco_mode_arg(scan_parser)

    diff_parser = guard_subparsers.add_parser("diff", help="Compare current harness artifacts to stored snapshots")
    diff_parser.add_argument("harness")
    _add_guard_common_args(diff_parser)
    diff_parser.add_argument("--json", action="store_true")

    receipts_parser = guard_subparsers.add_parser("receipts", help="List local Guard receipts")
    _add_guard_common_args(receipts_parser)
    receipts_parser.add_argument("--json", action="store_true")

    inventory_parser = guard_subparsers.add_parser("inventory", help="List the local Guard artifact inventory")
    _add_guard_common_args(inventory_parser)
    inventory_parser.add_argument("--json", action="store_true")

    abom_parser = guard_subparsers.add_parser("abom", help="Export a local Guard artifact bill of materials")
    _add_guard_common_args(abom_parser)
    abom_parser.add_argument("--json", action="store_true")
    abom_parser.add_argument("--format", choices=("markdown", "json"), default="markdown")

    add_approval_parser(guard_subparsers, _add_guard_common_args)

    explain_parser = guard_subparsers.add_parser(
        "explain",
        help=(
            "Show the latest evidence for a local artifact or local path with offline Cisco MCP evidence when available"
        ),
    )
    explain_parser.add_argument("target")
    _add_guard_common_args(explain_parser)
    explain_parser.add_argument("--json", action="store_true")
    _add_guard_cisco_mode_arg(explain_parser)

    for name, action in (("allow", "allow"), ("deny", "block")):
        policy_parser = guard_subparsers.add_parser(name, help=f"{name.title()} a harness artifact")
        policy_parser.add_argument("harness")
        policy_parser.add_argument("--artifact-id")
        policy_parser.add_argument(
            "--scope",
            choices=("global", "harness", "workspace", "artifact", "publisher"),
            default="harness",
        )
        policy_parser.add_argument("--reason")
        policy_parser.add_argument("--publisher")
        policy_parser.add_argument("--owner")
        policy_parser.add_argument("--expires-in-hours", type=float)
        _add_guard_common_args(policy_parser)
        policy_parser.add_argument("--json", action="store_true")
        policy_parser.set_defaults(policy_action=action)

    policies_parser = guard_subparsers.add_parser("policies", help="List stored Guard policy decisions")
    policies_parser.add_argument("--harness")
    _add_guard_common_args(policies_parser)
    policies_parser.add_argument("--json", action="store_true")

    exceptions_parser = guard_subparsers.add_parser("exceptions", help="List active Guard exceptions with expiry")
    exceptions_parser.add_argument("--harness")
    _add_guard_common_args(exceptions_parser)
    exceptions_parser.add_argument("--json", action="store_true")

    advisories_parser = guard_subparsers.add_parser("advisories", help="List cached Guard advisories and verdicts")
    _add_guard_common_args(advisories_parser)
    advisories_parser.add_argument("--json", action="store_true")

    events_parser = guard_subparsers.add_parser("events", help="List local Guard lifecycle events")
    _add_guard_common_args(events_parser)
    events_parser.add_argument("--name")
    events_parser.add_argument("--json", action="store_true")

    doctor_parser = guard_subparsers.add_parser("doctor", help="Emit Guard diagnostics for a harness")
    doctor_parser.add_argument("harness", nargs="?")
    _add_guard_common_args(doctor_parser)
    doctor_parser.add_argument("--json", action="store_true")

    login_parser = guard_subparsers.add_parser("login", help="Store Guard sync endpoint credentials")
    login_parser.add_argument("--sync-url", required=True)
    login_parser.add_argument("--token", required=True)
    login_parser.add_argument("--home")
    login_parser.add_argument("--guard-home")
    login_parser.add_argument("--json", action="store_true")

    sync_parser = guard_subparsers.add_parser("sync", help="Sync receipts to the configured Guard endpoint")
    sync_parser.add_argument("--home")
    sync_parser.add_argument("--guard-home")
    sync_parser.add_argument("--json", action="store_true")

    hook_parser = guard_subparsers.add_parser("hook", help=argparse.SUPPRESS)
    _add_guard_common_args(hook_parser)
    hook_parser.add_argument("--harness", default="claude-code")
    hook_parser.add_argument("--artifact-id")
    hook_parser.add_argument("--artifact-name")
    hook_parser.add_argument(
        "--policy-action",
        choices=("allow", "warn", "review", "block", "sandbox-required", "require-reapproval"),
    )
    hook_parser.add_argument("--event-file")
    hook_parser.add_argument("--json", action="store_true")

    daemon_parser = guard_subparsers.add_parser("daemon", help=argparse.SUPPRESS)
    _add_guard_common_args(daemon_parser)
    daemon_parser.add_argument("--serve", action="store_true")
    daemon_parser.add_argument("--port", type=int)
    daemon_parser.add_argument("--json", action="store_true")
    guard_subparsers._choices_actions = [
        action for action in guard_subparsers._choices_actions if action.dest not in {"hook", "daemon"}
    ]


def _add_guard_common_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--home")
    parser.add_argument("--guard-home")
    parser.add_argument("--workspace")


def _add_guard_cisco_mode_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--cisco-mode",
        choices=("auto", "on", "off"),
        default="auto",
        help="Control optional Cisco scanner evidence for local consumer-mode artifact scans.",
    )


def _build_cisco_scan_options(mode: str) -> ScanOptions:
    return ScanOptions(cisco_skill_scan=mode, cisco_mcp_scan=mode)


def _resolve_cisco_scan_options(mode: str) -> ScanOptions | None:
    if mode == "auto":
        return None
    return _build_cisco_scan_options(mode)


def _run_consumer_scan_with_mode(
    target: Path,
    *,
    intended_harness: str | None = None,
    cisco_mode: str,
) -> dict[str, object]:
    options = _resolve_cisco_scan_options(cisco_mode)
    if options is None:
        return run_consumer_scan(target, intended_harness=intended_harness)
    return run_consumer_scan(target, intended_harness=intended_harness, options=options)


def run_guard_command(args: argparse.Namespace) -> int:
    """Execute a Guard subcommand."""

    if args.guard_command == "scan":
        payload = _run_consumer_scan_with_mode(Path(args.target).resolve(), cisco_mode=args.cisco_mode)
        _emit("scan", payload, args.json or args.consumer_mode)
        return 0

    if args.guard_command == "preflight":
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

    home_override = getattr(args, "home", None)
    guard_home = resolve_guard_home(getattr(args, "guard_home", None) or home_override)
    workspace = Path(args.workspace).resolve() if getattr(args, "workspace", None) else None
    context = HarnessContext(
        home_dir=Path(home_override).resolve() if home_override else Path.home().resolve(),
        workspace_dir=workspace,
        guard_home=guard_home,
    )
    config = load_guard_config(guard_home, workspace=workspace)
    store = GuardStore(guard_home)
    config = overlay_synced_guard_policy(config, _synced_policy_payload(store))

    if args.guard_command == "protect":
        _refresh_cloud_policy_bundle(store)
        protect_command = list(getattr(args, "protect_command", []) or [])
        if len(protect_command) == 0:
            print("guard protect requires a command to wrap.", file=sys.stderr)
            return 2
        payload, exit_code = build_protect_payload(
            command=protect_command,
            store=store,
            workspace_dir=workspace or Path.cwd(),
            dry_run=bool(getattr(args, "dry_run", False)),
            now=_now(),
        )
        _emit("protect", payload, getattr(args, "json", False))
        return exit_code

    if args.guard_command == "start":
        payload = build_guard_start_payload(context, store, config)
        _emit("start", payload, getattr(args, "json", False))
        return 0

    if args.guard_command == "status":
        payload = build_guard_status_payload(context, store, config)
        _emit("status", payload, getattr(args, "json", False))
        return 0

    if args.guard_command == "connect":
        try:
            raw_sync_url = getattr(args, "sync_url", None)
            raw_token = getattr(args, "token", None)
            sync_url = raw_sync_url.strip() if isinstance(raw_sync_url, str) else None
            token = raw_token.strip() if isinstance(raw_token, str) else None
            credentials_requested = raw_sync_url is not None or raw_token is not None
            if credentials_requested and (not sync_url or not token):
                raise ValueError("connect requires non-empty --sync-url and --token when saving credentials")
            if bool(sync_url) != bool(token):
                raise ValueError("connect requires non-empty --sync-url and --token when saving credentials")
        except ValueError as error:
            print(str(error), file=sys.stderr)
            return 2
        credentials_saved = False
        if isinstance(sync_url, str) and isinstance(token, str):
            store.set_sync_credentials(sync_url, token, _now())
            store.add_event("sign_in", {"sync_url": sync_url, "source": "local-cli-connect"}, _now())
            credentials_saved = True
        if not credentials_saved or bool(getattr(args, "save_only", False)):
            payload = build_guard_connect_payload(
                context,
                store,
                config,
                credentials_saved=credentials_saved,
                sync_attempted=False,
                sync_succeeded=False,
            )
            _emit("connect", payload, getattr(args, "json", False))
            return 0
        try:
            sync_payload = sync_receipts(store)
        except (RuntimeError, urllib.error.URLError, json.JSONDecodeError) as exc:
            payload = build_guard_connect_payload(
                context,
                store,
                config,
                credentials_saved=credentials_saved,
                sync_attempted=True,
                sync_succeeded=False,
                sync_error=str(exc),
            )
            _emit("connect", payload, getattr(args, "json", False))
            return 1
        payload = build_guard_connect_payload(
            context,
            store,
            config,
            credentials_saved=credentials_saved,
            sync_attempted=True,
            sync_succeeded=True,
        )
        payload["sync_result"] = sync_payload
        _emit("connect", payload, getattr(args, "json", False))
        return 0

    if args.guard_command == "bootstrap":
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

    if args.guard_command == "detect":
        detections = [detect_harness(args.harness, context)] if args.harness else detect_all(context)
        payload = {
            "generated_at": _now(),
            "harnesses": [detection.to_dict() for detection in detections],
        }
        _emit("detect", payload, getattr(args, "json", False))
        return 0

    if args.guard_command == "install":
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

    if args.guard_command == "uninstall":
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

    if args.guard_command == "run":
        _refresh_cloud_policy_bundle(store)
        config = overlay_synced_guard_policy(config, _synced_policy_payload(store))
        interactive_resolver = None
        blocked_resolver = None
        if (
            not getattr(args, "json", False)
            and not bool(args.dry_run)
            and config.mode == "prompt"
            and sys.stdin.isatty()
        ):

            def interactive_resolver(detection, payload):
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
        elif not bool(args.dry_run) and config.mode == "prompt":
            blocked_resolver = _headless_approval_resolver(args=args, context=context, store=store, config=config)

        payload = guard_run(
            args.harness,
            context=context,
            store=store,
            config=config,
            dry_run=bool(args.dry_run),
            passthrough_args=list(args.passthrough_args),
            default_action=args.default_action,
            interactive_resolver=interactive_resolver,
            blocked_resolver=blocked_resolver,
        )
        _emit("run", payload, getattr(args, "json", False))
        if payload.get("blocked"):
            return 1
        return_code = payload.get("return_code")
        return int(return_code) if isinstance(return_code, int) else 0

    if args.guard_command == "diff":
        detection = detect_harness(args.harness, context)
        payload = evaluate_detection(detection, store, config, default_action="allow", persist=False)
        changed_artifacts = [item for item in payload["artifacts"] if bool(item["changed"])]
        payload["artifacts"] = changed_artifacts
        payload["changed"] = bool(changed_artifacts)
        _emit("diff", payload, getattr(args, "json", False))
        return 0

    if args.guard_command == "receipts":
        _emit("receipts", {"generated_at": _now(), "items": store.list_receipts()}, getattr(args, "json", False))
        return 0

    if args.guard_command == "inventory":
        _emit("inventory", {"generated_at": _now(), "items": store.list_inventory()}, getattr(args, "json", False))
        return 0

    if args.guard_command == "abom":
        payload = _build_abom_payload(store)
        if args.format == "markdown" and not getattr(args, "json", False):
            print(payload["markdown"])
            return 0
        _emit("abom", payload, True)
        return 0

    if args.guard_command == "policies":
        policy_items = store.list_policy_decisions(getattr(args, "harness", None))
        items = _filter_policy_items(policy_items, active_only=True)
        _emit("policies", {"generated_at": _now(), "items": items}, getattr(args, "json", False))
        return 0

    if args.guard_command == "exceptions":
        policy_items = store.list_policy_decisions(getattr(args, "harness", None))
        active_items = _filter_policy_items(policy_items, active_only=True)
        items = [
            item for item in active_items if isinstance(item.get("expires_at"), str) and str(item["expires_at"]).strip()
        ]
        _emit("exceptions", {"generated_at": _now(), "items": items}, getattr(args, "json", False))
        return 0

    if args.guard_command == "advisories":
        _emit(
            "advisories",
            {"generated_at": _now(), "items": store.list_cached_advisories()},
            getattr(args, "json", False),
        )
        return 0

    if args.guard_command == "events":
        _emit(
            "events",
            {"generated_at": _now(), "items": store.list_events(event_name=getattr(args, "name", None))},
            getattr(args, "json", False),
        )
        return 0

    if args.guard_command == "approvals":
        payload = run_approval_command(args, store=store, workspace=workspace)
        _emit("approvals", payload, getattr(args, "json", False))
        return 0

    if args.guard_command == "explain":
        payload = _build_explain_payload_with_mode(store, args.target, cisco_mode=args.cisco_mode)
        _emit("explain", payload, getattr(args, "json", False))
        return 0

    if args.guard_command in {"allow", "deny"}:
        _validate_policy_scope(args.scope, args.artifact_id, workspace, getattr(args, "publisher", None))
        expires_at = _resolve_policy_expiry(args)
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
        )
        _emit(args.guard_command, {"decision": payload}, getattr(args, "json", False))
        return 0

    if args.guard_command == "doctor":
        if args.harness:
            adapter = get_adapter(args.harness)
            payload = adapter.diagnostics(context)
        else:
            payload = {
                "tables": store.list_table_names(),
                "adapters": [detection.to_dict() for detection in detect_all(context)],
            }
        _emit("doctor", payload, getattr(args, "json", False))
        return 0

    if args.guard_command == "login":
        store.set_sync_credentials(args.sync_url, args.token, _now())
        store.add_event("sign_in", {"sync_url": args.sync_url, "source": "local-cli"}, _now())
        _emit("login", {"logged_in": True, "sync_url": args.sync_url}, getattr(args, "json", False))
        return 0

    if args.guard_command == "sync":
        payload = sync_receipts(store)
        _emit("sync", payload, getattr(args, "json", False))
        return 0

    if args.guard_command == "daemon":
        daemon = GuardDaemonServer(store, port=args.port or 0)
        if args.serve:
            daemon.serve()
            return 0
        _emit("doctor", {"daemon_url": f"http://127.0.0.1:{daemon.port}"}, getattr(args, "json", False))
        return 0

    if args.guard_command == "hook":
        payload = _load_hook_payload(getattr(args, "event_file", None))
        runtime_artifact = _hook_file_read_artifact(
            harness=args.harness,
            payload=payload,
            home_dir=context.home_dir,
            workspace=workspace,
        )
        if runtime_artifact is not None:
            runtime_artifact_hash = artifact_hash(runtime_artifact)
            artifact_id = runtime_artifact.artifact_id
            artifact_name = runtime_artifact.name
            policy_action = _coalesce_string(
                getattr(args, "policy_action", None),
                payload.get("policy_action"),
                store.resolve_policy(
                    args.harness,
                    artifact_id,
                    runtime_artifact_hash,
                    str(workspace) if workspace else None,
                ),
            )
            if policy_action not in VALID_GUARD_ACTIONS:
                policy_action = SAFE_CHANGED_HASH_ACTION
            changed_capabilities = ["file_read_request"]
            risk_signals = list(artifact_risk_signals(runtime_artifact))
            risk_summary = artifact_risk_summary(runtime_artifact)
            incident = build_incident_context(
                harness=args.harness,
                artifact=runtime_artifact,
                artifact_id=artifact_id,
                artifact_name=artifact_name,
                artifact_type=runtime_artifact.artifact_type,
                source_scope=runtime_artifact.source_scope,
                config_path=runtime_artifact.config_path,
                changed_fields=changed_capabilities,
                policy_action=policy_action,  # type: ignore[arg-type]
                launch_target=_runtime_request_summary(runtime_artifact),
                risk_summary=risk_summary,
            )
            receipt = build_receipt(
                harness=args.harness,
                artifact_id=artifact_id,
                artifact_hash=runtime_artifact_hash,
                policy_decision=policy_action,
                capabilities_summary=_runtime_capabilities_summary(runtime_artifact),
                changed_capabilities=changed_capabilities,
                provenance_summary=f"runtime tool request evaluated from {runtime_artifact.config_path}",
                artifact_name=artifact_name,
                source_scope=runtime_artifact.source_scope,
                user_override=_optional_string(payload.get("user_override")),
            )
            store.add_receipt(receipt)
            response_payload = {
                "recorded": True,
                "artifact_id": artifact_id,
                "artifact_name": artifact_name,
                "artifact_type": runtime_artifact.artifact_type,
                "policy_action": policy_action,
                "risk_signals": risk_signals,
                "risk_summary": risk_summary,
                "artifact_label": incident["artifact_label"],
                "source_label": incident["source_label"],
                "trigger_summary": incident["trigger_summary"],
                "why_now": incident["why_now"],
                "launch_summary": incident["launch_summary"],
                "risk_headline": incident["risk_headline"],
                "path_summary": _runtime_requested_path(runtime_artifact),
            }
            if policy_action in {"block", "sandbox-required", "require-reapproval"}:
                approval_center_url = ensure_guard_daemon(guard_home)
                queued = queue_blocked_approvals(
                    detection=_runtime_detection(args.harness, runtime_artifact),
                    evaluation={
                        "artifacts": [
                            {
                                "artifact_id": artifact_id,
                                "artifact_name": artifact_name,
                                "artifact_hash": runtime_artifact_hash,
                                "policy_action": policy_action,
                                "changed_fields": changed_capabilities,
                                "artifact_type": runtime_artifact.artifact_type,
                                "source_scope": runtime_artifact.source_scope,
                                "config_path": runtime_artifact.config_path,
                                "launch_target": _runtime_request_summary(runtime_artifact),
                            }
                        ]
                    },
                    store=store,
                    approval_center_url=approval_center_url,
                    now=_now(),
                )
                response_payload["approval_requests"] = queued
                response_payload["approval_center_url"] = approval_center_url
                response_payload["review_hint"] = approval_center_hint(
                    context=context,
                    harness=args.harness,
                    approval_center_url=approval_center_url,
                    queued=queued,
                )
            if _should_emit_copilot_hook_response(args):
                _emit_copilot_hook_response(
                    policy_action=policy_action,
                    reason=_copilot_hook_reason(
                        response_payload.get("why_now"),
                        response_payload.get("review_hint"),
                        response_payload.get("risk_headline"),
                    ),
                )
                return 0
            _emit("hook", response_payload, getattr(args, "json", False))
            return 1 if policy_action in {"block", "require-reapproval"} else 0
        artifact_id = _coalesce_string(
            getattr(args, "artifact_id", None),
            payload.get("artifact_id"),
            _artifact_id_from_event(args.harness, payload),
        )
        artifact_name = _coalesce_string(
            getattr(args, "artifact_name", None),
            payload.get("artifact_name"),
            payload.get("tool_name"),
            artifact_id,
        )
        policy_action = _coalesce_string(
            getattr(args, "policy_action", None),
            payload.get("policy_action"),
            store.resolve_policy(
                args.harness,
                artifact_id,
                str(payload.get("artifact_hash")) if isinstance(payload.get("artifact_hash"), str) else None,
                str(workspace) if workspace else None,
            ),
            config.default_action,
        )
        if policy_action not in VALID_GUARD_ACTIONS:
            policy_action = SAFE_CHANGED_HASH_ACTION
        changed_capabilities = _string_list(payload.get("changed_capabilities"))
        if not changed_capabilities and isinstance(payload.get("event"), str):
            changed_capabilities = [str(payload["event"])]
        receipt = build_receipt(
            harness=args.harness,
            artifact_id=artifact_id,
            artifact_hash=str(payload.get("artifact_hash", f"hook:{artifact_id}")),
            policy_decision=policy_action,
            capabilities_summary=_coalesce_string(
                payload.get("capabilities_summary"),
                f"hook artifact • {args.harness}",
            ),
            changed_capabilities=changed_capabilities or ["hook"],
            provenance_summary=_coalesce_string(
                payload.get("provenance_summary"),
                f"hook event for {artifact_name}",
            ),
            artifact_name=artifact_name,
            source_scope=_coalesce_string(payload.get("source_scope"), "project"),
            user_override=_optional_string(payload.get("user_override")),
        )
        store.add_receipt(receipt)
        if _should_emit_copilot_hook_response(args):
            _emit_copilot_hook_response(
                policy_action=policy_action,
                reason=_copilot_hook_reason(payload.get("permission_decision_reason")),
            )
            return 0
        _emit(
            "hook",
            {
                "recorded": True,
                "artifact_id": artifact_id,
                "artifact_name": artifact_name,
                "policy_action": policy_action,
            },
            getattr(args, "json", False),
        )
        return 1 if policy_action in {"block", "require-reapproval"} else 0

    return 1


def _emit(command: str, payload: dict[str, object], as_json: bool) -> None:
    emit_guard_payload(command, payload, as_json)


def _should_emit_copilot_hook_response(args: argparse.Namespace) -> bool:
    return args.harness == "copilot" and not getattr(args, "json", False)


def _copilot_hook_reason(*values: object | None) -> str:
    for value in values:
        if isinstance(value, str) and value.strip():
            return value.strip()
    return "Guard blocked this tool call."


def _emit_copilot_hook_response(*, policy_action: str, reason: str) -> None:
    if policy_action in {"block", "sandbox-required", "require-reapproval"}:
        payload = {
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    else:
        payload = {"permissionDecision": "allow"}
    print(json.dumps(payload, separators=(",", ":")))


def _headless_approval_resolver(
    *,
    args: argparse.Namespace,
    context: HarnessContext,
    store: GuardStore,
    config,
):
    def resolve(detection, payload):
        approval_flow = get_adapter(args.harness).approval_flow()
        approval_center_url = ensure_guard_daemon(context.guard_home)
        queued = queue_blocked_approvals(
            detection=detection,
            evaluation=payload,
            store=store,
            approval_center_url=approval_center_url,
            now=_now(),
        )
        payload["approval_requests"] = queued
        payload["approval_center_url"] = approval_center_url
        payload["review_hint"] = approval_center_hint(
            context=context,
            harness=args.harness,
            approval_center_url=approval_center_url,
            queued=queued,
        )
        _open_approval_center(approval_center_url)
        if approval_flow["tier"] != "native-or-center":
            payload["approval_wait"] = {
                "resolved": False,
                "pending_request_ids": [str(item["request_id"]) for item in queued if "request_id" in item],
                "items": [],
            }
            return payload
        wait_result = wait_for_approval_requests(
            store=store,
            request_ids=[str(item["request_id"]) for item in queued if "request_id" in item],
            timeout_seconds=config.approval_wait_timeout_seconds,
        )
        payload["approval_wait"] = wait_result
        if bool(wait_result.get("resolved")):
            resolved_items = [item for item in wait_result.get("items", []) if isinstance(item, dict)]
            payload["blocked"] = any(str(item.get("resolution_action")) == "block" for item in resolved_items)
            if not payload["blocked"]:
                payload["review_hint"] = "Approval received. Guard is resuming the harness launch."
        else:
            payload["review_hint"] = (
                f"Approval is still pending. Open {approval_center_url} and resolve request "
                f"{', '.join(str(item) for item in wait_result.get('pending_request_ids', []))}."
            )
        return payload

    return resolve


def _open_approval_center(approval_center_url: str) -> None:
    try:
        webbrowser.open(approval_center_url)
    except Exception:
        return


def _load_hook_payload(event_file: str | None) -> dict[str, object]:
    if event_file:
        payload = json.loads(Path(event_file).read_text(encoding="utf-8"))
        return _normalize_hook_payload(payload) if isinstance(payload, dict) else {}
    raw = sys.stdin.read().strip()
    if not raw:
        return {}
    payload = json.loads(raw)
    return _normalize_hook_payload(payload) if isinstance(payload, dict) else {}


def _normalize_hook_payload(payload: dict[str, object]) -> dict[str, object]:
    normalized = dict(payload)
    for source_key, target_key in (
        ("artifactId", "artifact_id"),
        ("artifactHash", "artifact_hash"),
        ("artifactName", "artifact_name"),
        ("changedCapabilities", "changed_capabilities"),
        ("policyAction", "policy_action"),
        ("sourceScope", "source_scope"),
        ("toolName", "tool_name"),
        ("userOverride", "user_override"),
    ):
        if target_key not in normalized and source_key in payload:
            normalized[target_key] = payload[source_key]
    arguments = _normalize_hook_arguments(
        normalized.get("tool_input"),
        normalized.get("arguments"),
        payload.get("toolArgs"),
        payload.get("toolInput"),
    )
    if arguments is not None:
        normalized["tool_input"] = arguments
        normalized["arguments"] = arguments
    return normalized


def _normalize_hook_arguments(*values: object | None) -> object | None:
    for value in values:
        normalized = _normalize_hook_argument_value(value)
        if normalized is not None:
            return normalized
    return None


def _normalize_hook_argument_value(value: object | None) -> object | None:
    if value is None:
        return None
    if isinstance(value, (dict, list)):
        return value
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return None
        try:
            parsed = json.loads(stripped)
        except json.JSONDecodeError:
            return stripped
        if isinstance(parsed, (dict, list, str)):
            return parsed
        return stripped
    return value


def _coalesce_string(*values: object | None) -> str:
    for value in values:
        if isinstance(value, str) and value.strip():
            return value.strip()
    return "unknown-artifact"


def _optional_string(value: object | None) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _artifact_id_from_event(harness: str, payload: dict[str, object]) -> str:
    source_scope = _coalesce_string(payload.get("source_scope"), "project")
    tool_name = payload.get("tool_name")
    if isinstance(tool_name, str) and tool_name.strip():
        return f"{harness}:{source_scope}:{tool_name.strip()}"
    event_name = payload.get("event")
    if isinstance(event_name, str) and event_name.strip():
        return f"{harness}:{source_scope}:{event_name.strip().lower()}"
    return f"{harness}:{source_scope}:hook"


def _string_list(value: object | None) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if isinstance(item, str) and item.strip()]


def _hook_file_read_artifact(
    *,
    harness: str,
    payload: dict[str, object],
    home_dir: Path,
    workspace: Path | None,
) -> GuardArtifact | None:
    request = extract_sensitive_file_read_request(
        payload.get("tool_name"),
        payload.get("tool_input", payload.get("arguments")),
        cwd=workspace,
        home_dir=home_dir,
    )
    if request is None:
        return None
    source_scope = _coalesce_string(payload.get("source_scope"), "project")
    return build_file_read_request_artifact(
        harness=harness,
        request=request,
        config_path=str(_runtime_policy_path(harness, home_dir, workspace)),
        source_scope=source_scope,
    )


def _runtime_policy_path(harness: str, home_dir: Path, workspace: Path | None) -> Path:
    if harness == "claude-code":
        if workspace is not None:
            return workspace / ".claude" / "settings.local.json"
        return home_dir / ".claude" / "settings.json"
    if harness == "codex":
        if workspace is not None:
            return workspace / ".codex" / "config.toml"
        return home_dir / ".codex" / "config.toml"
    if harness == "copilot":
        if workspace is not None:
            return workspace / ".github" / "hooks" / "hol-guard-copilot.json"
        return home_dir / ".copilot" / "config.json"
    if workspace is not None:
        return workspace / ".mcp.json"
    return home_dir / ".mcp.json"


def _runtime_detection(harness: str, artifact: GuardArtifact) -> HarnessDetection:
    return HarnessDetection(
        harness=harness,
        installed=True,
        command_available=True,
        config_paths=(artifact.config_path,),
        artifacts=(artifact,),
    )


def _runtime_capabilities_summary(artifact: GuardArtifact) -> str:
    tool_name = artifact.metadata.get("tool_name")
    if isinstance(tool_name, str) and tool_name:
        return f"file read request • {tool_name}"
    return "file read request"


def _runtime_request_summary(artifact: GuardArtifact) -> str | None:
    summary = artifact.metadata.get("request_summary")
    if isinstance(summary, str) and summary:
        return summary
    return None


def _runtime_requested_path(artifact: GuardArtifact) -> str | None:
    normalized_path = artifact.metadata.get("normalized_path")
    if isinstance(normalized_path, str) and normalized_path:
        return normalized_path
    return None


def _validate_policy_scope(
    scope: str,
    artifact_id: str | None,
    workspace: Path | None,
    publisher: str | None,
) -> None:
    if scope == "artifact" and not artifact_id:
        print("--artifact-id is required when --scope artifact", file=sys.stderr)
        raise SystemExit(2)
    if scope == "workspace" and workspace is None:
        print("--workspace is required when --scope workspace", file=sys.stderr)
        raise SystemExit(2)
    if scope == "publisher" and not publisher:
        print("--publisher is required when --scope publisher", file=sys.stderr)
        raise SystemExit(2)


def _resolve_policy_expiry(args: argparse.Namespace) -> str | None:
    hours = getattr(args, "expires_in_hours", None)
    if hours is None:
        return None
    if hours <= 0:
        print("--expires-in-hours must be greater than 0.", file=sys.stderr)
        raise SystemExit(2)
    return (datetime.now(timezone.utc) + timedelta(hours=float(hours))).isoformat()


def _synced_policy_payload(store: GuardStore) -> dict[str, object] | None:
    payload = store.get_sync_payload("policy")
    return payload if isinstance(payload, dict) else None


def _refresh_cloud_policy_bundle(store: GuardStore) -> None:
    if store.get_sync_credentials() is None:
        return
    try:
        sync_receipts(store)
    except Exception:
        return


def _filter_policy_items(items: list[dict[str, object]], *, active_only: bool) -> list[dict[str, object]]:
    if not active_only:
        return items
    current_time = datetime.now(timezone.utc)
    filtered: list[dict[str, object]] = []
    for item in items:
        expires_at = item.get("expires_at")
        if not isinstance(expires_at, str) or not expires_at.strip():
            filtered.append(item)
            continue
        try:
            expires_on = datetime.fromisoformat(expires_at)
        except ValueError:
            filtered.append(item)
            continue
        if expires_on > current_time:
            filtered.append(item)
    return filtered


def _build_abom_payload(store: GuardStore) -> dict[str, object]:
    inventory = store.list_inventory()
    artifacts = []
    markdown_lines = [
        "# HOL Guard ABOM",
        "",
        "| Artifact | Harness | Type | Scope | Verdict | Present | Last changed |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for item in inventory:
        trust_verdict = str(item.get("last_policy_action") or "unknown")
        artifacts.append({**item, "trust_verdict": trust_verdict})
        markdown_lines.append(
            "| "
            f"{item['artifact_name']} | {item['harness']} | {item['artifact_type']} | {item['source_scope']} | "
            f"{trust_verdict} | {'yes' if item['present'] else 'no'} | {item.get('last_changed_at') or 'never'} |"
        )
    return {
        "generated_at": _now(),
        "artifact_count": len(artifacts),
        "artifacts": artifacts,
        "markdown": "\n".join(markdown_lines) + "\n",
    }


def _build_explain_payload(
    store: GuardStore,
    target: str,
    options: ScanOptions | None = None,
) -> dict[str, object]:
    target_path = Path(target).expanduser()
    if target_path.exists():
        return run_consumer_scan(target_path.resolve(), options=options)
    inventory_item = store.find_inventory_item(target)
    if inventory_item is None:
        raise ValueError(f"Guard does not know artifact {target}.")
    advisories = _matching_advisories(store, inventory_item.get("publisher"))
    latest_receipt = store.get_latest_receipt(str(inventory_item["harness"]), str(inventory_item["artifact_id"]))
    latest_diff = store.get_latest_diff(str(inventory_item["harness"]), str(inventory_item["artifact_id"]))
    return {
        "generated_at": _now(),
        "artifact": inventory_item,
        "latest_receipt": latest_receipt,
        "latest_diff": latest_diff,
        "advisories": advisories,
    }


def _build_explain_payload_with_mode(store: GuardStore, target: str, cisco_mode: str) -> dict[str, object]:
    options = _resolve_cisco_scan_options(cisco_mode)
    if options is None:
        return _build_explain_payload(store, target)
    return _build_explain_payload(store, target, options=options)


def _matching_advisories(store: GuardStore, publisher: object) -> list[dict[str, object]]:
    if not isinstance(publisher, str) or not publisher.strip():
        return []
    return [item for item in store.list_cached_advisories() if item.get("publisher") == publisher]
