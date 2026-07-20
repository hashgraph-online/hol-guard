"""Guard CLI helper definitions."""

# fmt: off
# ruff: noqa: F403, F405, I001

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ._commands_shared import _now
    from .commands_support_codex_git import _git_repo_root
    from .commands_support_connect import (
        _announce_guard_device_connect_copy,
        _finalize_guard_connect_payload,
        _run_guard_device_connect_flow,
    )
    from .commands_support_hook_payload import _open_approval_center
    from .commands_support_interaction import _emit


from ._commands_shared import *
from .commands_parser_helpers import *

def _add_guard_common_args(
    parser: argparse.ArgumentParser,
    *,
    suppress_defaults: bool = False,
) -> None:
    default = argparse.SUPPRESS if suppress_defaults else None
    parser.add_argument("--home", default=default)
    parser.add_argument("--guard-home", default=default)
    parser.add_argument("--workspace", default=default)

def _add_aibom_cli_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--include-symlinks",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Include symlink source-of-truth metadata in AIBOM output (default: enabled).",
    )
    parser.add_argument(
        "--follow-unsafe-symlinks",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Follow symlink targets outside safe roots (default: disabled).",
    )

def _aibom_cli_options_from_args(args: argparse.Namespace) -> AibomCliOptions:
    return AibomCliOptions(
        include_symlinks=bool(getattr(args, "include_symlinks", True)),
        follow_unsafe_symlinks=bool(getattr(args, "follow_unsafe_symlinks", False)),
    )

def _add_guard_cisco_mode_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--cisco-mode",
        choices=("auto", "on", "off"),
        default="auto",
        help="Control optional Cisco scanner evidence for local consumer-mode artifact scans.",
    )

def _package_firewall_cli_gate_input(args: argparse.Namespace, guard_home: Path) -> ApprovalGateInput | None:
    password = getattr(args, "approval_password", None)
    totp_code = getattr(args, "approval_totp", None)
    if isinstance(password, str) and password:
        return ApprovalGateInput(password=password, totp_code=totp_code)
    if isinstance(totp_code, str) and totp_code:
        return ApprovalGateInput(password=None, totp_code=totp_code)
    return prompt_for_approval_gate(guard_home, use_cooldown=False)

def _package_firewall_block_payload(
    *,
    entitlement: dict[str, object],
    has_installed_managers: bool,
    operation: str,
) -> tuple[int, dict[str, object]]:
    status, error_code, message = package_firewall_block_details(entitlement)
    return (
        status,
        {
            "available_actions": package_firewall_available_actions(
                entitlement,
                has_installed_managers=has_installed_managers,
            ),
            "cli_fallback": {
                "connect": "hol-guard connect",
                "status": "hol-guard package-shims status --json",
            },
            "entitlement": entitlement,
            "error": error_code,
            "message": message,
            "operation": operation,
        },
    )

def _guard_http_url(value: str) -> str:
    parsed = urllib.parse.urlparse(value.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise argparse.ArgumentTypeError("Guard URLs must be absolute http(s) URLs.")
    return value

def _build_init_plan(args: argparse.Namespace) -> list[dict[str, object]]:
    del args
    return [
        {
            "id": "dashboard",
            "title": "Open local Guard dashboard",
            "detail": (
                "Starts the local daemon and opens the dashboard so you can see what Guard will protect "
                "before anything is changed."
            ),
            "command": "hol-guard dashboard",
            "skip_flag": None,
        },
        {
            "id": "apps",
            "title": "Protect detected AI apps",
            "detail": (
                "Discovers supported harnesses and installs Guard-managed launch commands for each detected app. "
                "This is reversible with `hol-guard uninstall --all`."
            ),
            "command": "hol-guard install --all",
            "skip_flag": "skip_apps",
        },
        {
            "id": "cloud",
            "title": "Connect Guard Cloud",
            "detail": (
                "Opens the browser pairing flow only after you approve it, then syncs receipts and policy memory "
                "when Cloud is available."
            ),
            "command": "hol-guard connect",
            "skip_flag": "skip_cloud",
        },
        {
            "id": "notifications",
            "title": "Enable desktop notifications",
            "detail": (
                "Sends one preview notification and opens OS notification settings only after you approve it."
            ),
            "command": "hol-guard doctor --notifications --force-notification-settings",
            "skip_flag": "skip_notifications",
        },
        {
            "id": "tray",
            "title": "Install menu bar / tray icon",
            "detail": (
                "Adds a persistent HOL Guard icon to your menu bar (macOS) or system tray (Windows/Linux) "
                "so you can open the dashboard without the terminal. Starts at login and can be toggled off later."
            ),
            "command": "hol-guard guard tray install && hol-guard guard tray start",
            "skip_flag": "skip_tray",
        },
    ]

def _print_init_plan_preview(plan: list[dict[str, object]]) -> None:
    print("HOL Guard init will ask before each setup action.", file=sys.stderr)
    for index, step in enumerate(plan, start=1):
        print(f"{index}. {step.get('title')}", file=sys.stderr)
        detail = step.get("detail")
        if isinstance(detail, str) and detail:
            print(f"   {detail}", file=sys.stderr)

def _prompt_init_step(step: dict[str, object]) -> str:
    title = str(step.get("title") or "Guard init step")
    detail = str(step.get("detail") or "")
    command = str(step.get("command") or "")
    print(f"\n{title}", file=sys.stderr)
    if detail:
        print(detail, file=sys.stderr)
    if command:
        print(f"Command: {command}", file=sys.stderr)
    sys.stderr.write("Run this step? [y/N] ")
    sys.stderr.flush()
    return sys.stdin.readline().strip().lower()

def _approve_init_step(
    args: argparse.Namespace,
    step: dict[str, object],
    *,
    interactive: bool,
) -> bool:
    skip_flag = step.get("skip_flag")
    if isinstance(skip_flag, str) and bool(getattr(args, skip_flag, False)):
        step["decision"] = "skipped"
        step["reason"] = skip_flag
        return False
    if bool(getattr(args, "yes", False)):
        step["decision"] = "approved"
        step["reason"] = "yes_flag"
        return True
    if not interactive:
        step["decision"] = "skipped"
        step["reason"] = "needs_approval"
        return False
    answer = _prompt_init_step(step)
    if answer in {"y", "yes"}:
        step["decision"] = "approved"
        step["reason"] = "user_approved"
        return True
    step["decision"] = "skipped"
    step["reason"] = "user_skipped"
    return False

def _skip_init_step_payload(step: dict[str, object]) -> dict[str, object]:
    return {"skipped": True, "reason": str(step.get("reason") or "skipped")}

def _print_init_step_complete(step: dict[str, object], payload: dict[str, object]) -> None:
    title = str(step.get("title") or step.get("id") or "Init step")
    if bool(payload.get("skipped")):
        reason = str(payload.get("reason") or "skipped").replace("_", " ")
        print(f"Skipped: {title} ({reason})", file=sys.stderr)
        return
    if payload.get("error"):
        print(f"Needs attention: {title} ({payload.get('error')})", file=sys.stderr)
        return
    print(f"Completed: {title}", file=sys.stderr)

def _run_init_command(
    args: argparse.Namespace,
    context: HarnessContext,
    store: GuardStore,
    config: GuardConfig,
    workspace: Path | None,
) -> int:
    init_plan = _build_init_plan(args)
    interactive = sys.stdin.isatty() and not bool(getattr(args, "json", False))
    if interactive and not bool(getattr(args, "yes", False)) and not bool(getattr(args, "json", False)):
        _print_init_plan_preview(init_plan)
    approved_any = False
    init_failed = False
    approval_center_url: str | None = None
    dashboard_payload: dict[str, object] | None = None
    apps_payload: dict[str, object] = {}
    cloud_payload: dict[str, object] = {}
    notification_payload: dict[str, object] = {}
    tray_payload: dict[str, object] = {}

    for step in init_plan:
        step_id = str(step.get("id") or "")
        step_payload: dict[str, object]
        if not _approve_init_step(args, step, interactive=interactive):
            step_payload = _skip_init_step_payload(step)
        else:
            approved_any = True
            if step_id == "dashboard":
                try:
                    dashboard_url = ensure_guard_daemon(context.guard_home)
                    approval_center_url = dashboard_url
                    open_result = _open_approval_center(
                        dashboard_url,
                        store=store,
                        config=config,
                        open_key="init",
                        force_open=True,
                    )
                    step_payload = {
                        "approval_center_url": approval_center_url,
                        "browser_url": open_result.get("browser_url"),
                        "opened": bool(open_result.get("opened")),
                        "reason": str(open_result.get("reason") or "unknown"),
                    }
                except RuntimeError as error:
                    init_failed = True
                    step_payload = {"opened": False, "error": str(error)}
            elif step_id == "apps":
                try:
                    step_payload = apply_managed_install(
                        "install",
                        None,
                        True,
                        context,
                        store,
                        str(workspace) if workspace else None,
                        _now(),
                    )
                    step_payload["skipped"] = False
                except ValueError as error:
                    init_failed = True
                    step_payload = {"skipped": False, "error": str(error), "managed_installs": []}
            elif step_id == "cloud":
                try:
                    step_payload = _run_guard_device_connect_flow(
                        store=store,
                        connect_url=args.connect_url,
                        wait_timeout_seconds=int(getattr(args, "wait_timeout_seconds", 180) or 180),
                        announce_copy=None
                        if getattr(args, "json", False)
                        else _announce_guard_device_connect_copy,
                        open_browser=webbrowser.open,
                    )
                    step_payload = _finalize_guard_connect_payload(
                        store=store,
                        connect_url=args.connect_url,
                        payload=step_payload,
                        now=_now(),
                    )
                    step_payload["skipped"] = False
                except Exception as error:
                    init_failed = True
                    step_payload = {"skipped": False, "connected": False, "error": str(error)}
            elif step_id == "notifications":
                try:
                    approval_url = (
                        f"{approval_center_url.rstrip('/')}/approvals/notification-preview"
                        if isinstance(approval_center_url, str) and approval_center_url
                        else "hol-guard://notification-preview"
                    )
                    result = ensure_desktop_notification_setup(
                        context.guard_home,
                        approval_url=approval_url,
                        force=True,
                    )
                    step_payload = desktop_notification_setup_payload(
                        result,
                        guidance=macos_notification_guidance(result.notifier_path)
                        if result.platform == "Darwin"
                        else None,
                    )
                    step_payload["skipped"] = False
                except Exception as error:
                    init_failed = True
                    step_payload = {"skipped": False, "supported": True, "error": str(error)}
            elif step_id == "tray":
                # Install the persistent tray/menu-bar icon. Errors are
                # non-fatal: Guard protection is already active; the tray is
                # a convenience layer. The user can retry via
                # `hol-guard guard tray install` if it fails here.
                try:
                    from ..tray.contracts import TrayState
                    from ..tray.lifecycle import (
                        get_status,
                        install_registration,
                        start_tray,
                    )
                    from ..tray.platforms import detect_platform_adapter

                    adapter = detect_platform_adapter()
                    if adapter is None:
                        step_payload = {
                            "skipped": False,
                            "installed": False,
                            "state": TrayState.UNSUPPORTED.value,
                            "error": "unsupported_platform",
                        }
                    else:
                        install_registration(
                            context.guard_home,
                            adapter=adapter,
                            run_at_login=True,
                        )
                        start_tray(context.guard_home)
                        state, _capability, _locator = get_status(context.guard_home)
                        step_payload = {
                            "installed": state in (TrayState.RUNNING, TrayState.INSTALLED),
                            "running": state == TrayState.RUNNING,
                            "state": state.value,
                        }
                    step_payload["skipped"] = False
                except Exception as error:
                    # Non-fatal: tray is a convenience, not protection.
                    step_payload = {
                        "skipped": False,
                        "installed": False,
                        "error": str(error),
                    }
            else:
                init_failed = True
                step_payload = {"skipped": True, "reason": "unknown_step"}

        if step_id == "dashboard":
            dashboard_payload = step_payload
        elif step_id == "apps":
            apps_payload = step_payload
        elif step_id == "cloud":
            cloud_payload = step_payload
        elif step_id == "notifications":
            notification_payload = step_payload
        elif step_id == "tray":
            tray_payload = step_payload
        if interactive:
            _print_init_step_complete(step, step_payload)

    payload: dict[str, object] = {
        "generated_at": _now(),
        "status": "needs_attention" if init_failed else ("initialized" if approved_any else "approval_required"),
        "mode": "auto_approved" if bool(getattr(args, "yes", False)) else "progressive",
        "plan": init_plan,
        "dashboard": dashboard_payload,
        "apps": apps_payload,
        "cloud": cloud_payload,
        "desktop_notifications": notification_payload,
        "tray": tray_payload,
        "next_command": "hol-guard init --yes" if not approved_any else "hol-guard status",
        "next_steps": [
            {
                "title": "Open dashboard settings",
                "command": "hol-guard dashboard",
                "detail": "Use Settings for notification setup and protection tuning.",
            },
            {
                "title": "Check coverage",
                "command": "hol-guard status",
                "detail": "Confirm apps are protected and Cloud pairing is healthy.",
            },
        ],
    }
    _emit("init", payload, getattr(args, "json", False))
    return 1 if init_failed else 0

def _normalize_explicit_workspace_path(value: str | None) -> Path | None:
    """Drop sentinel workspace strings and trailing `/None` path segments."""

    if value is None:
        return None
    stripped = value.strip()
    if not stripped or stripped.lower() in {"none", "null"}:
        return None
    path = Path(stripped).expanduser()
    if path.name == "None":
        path = path.parent
        if not str(path).strip():
            return None
    try:
        return path.resolve()
    except OSError:
        return path

_INSTALL_WORKSPACE_COMMANDS = frozenset({"install", "uninstall"})

_PROJECT_ROOT_MARKERS = (
    ".git",
    "pyproject.toml",
    "package.json",
    "Cargo.toml",
    "go.mod",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
)

def _requested_install_harness(args: argparse.Namespace) -> str | None:
    if bool(getattr(args, "all", False)):
        return None
    harness = str(getattr(args, "harness", "") or "").strip()
    return harness or None

def _workspace_from_cursor_project_dir() -> Path | None:
    project_dir = os.environ.get("CURSOR_PROJECT_DIR", "").strip()
    if not project_dir:
        return None
    return _normalize_explicit_workspace_path(project_dir)

def _workspace_has_project_markers(path: Path) -> bool:
    try:
        resolved = path.resolve()
    except OSError:
        return False
    return any((resolved / marker).exists() for marker in _PROJECT_ROOT_MARKERS)

def _workspace_from_harness_detection(
    harness: str,
    *,
    cwd: Path,
    guard_home: Path,
) -> Path | None:
    try:
        adapter = get_adapter(harness)
    except ValueError:
        return None
    detection = adapter.detect(
        HarnessContext(
            home_dir=Path.home().resolve(),
            workspace_dir=cwd,
            guard_home=guard_home,
        )
    )
    for config_path in detection.config_paths:
        try:
            resolved_path = Path(config_path).expanduser().resolve()
        except OSError:
            continue
        if resolved_path.is_relative_to(cwd):
            return cwd
    return None

def _resolve_default_install_workspace(
    args: argparse.Namespace,
    *,
    guard_home: Path,
) -> Path | None:
    """Pick a project workspace for install/uninstall when --workspace is omitted."""

    cwd = Path.cwd().resolve()
    harness = _requested_install_harness(args)
    cursor_project_dir = _workspace_from_cursor_project_dir()
    if cursor_project_dir is not None and (harness is None or harness == "cursor"):
        return cursor_project_dir

    if _workspace_has_project_markers(cwd):
        return cwd

    git_root = _git_repo_root(cwd)
    if git_root is not None:
        return git_root

    if harness is not None:
        detected = _workspace_from_harness_detection(harness, cwd=cwd, guard_home=guard_home)
        if detected is not None:
            return detected
    return None

def _resolve_guard_workspace(
    args: argparse.Namespace,
    *,
    guard_home: Path,
) -> Path | None:
    explicit_workspace = getattr(args, "workspace", None)
    if explicit_workspace:
        return _normalize_explicit_workspace_path(str(explicit_workspace))
    guard_command = getattr(args, "guard_command", None)
    if guard_command in _INSTALL_WORKSPACE_COMMANDS:
        return _resolve_default_install_workspace(args, guard_home=guard_home)
    if guard_command == "sync":
        return Path.cwd().resolve()
    if guard_command != "apps":
        return None
    if getattr(args, "apps_command", None) not in {"connect", "disconnect", "repair", "test"}:
        return None
    harness = str(getattr(args, "harness", "")).strip()
    if not harness:
        return None
    return _workspace_from_harness_detection(harness, cwd=Path.cwd().resolve(), guard_home=guard_home)

__all__ = [
    "_INSTALL_WORKSPACE_COMMANDS",
    "_PROJECT_ROOT_MARKERS",
    "_add_aibom_cli_args",
    "_add_guard_cisco_mode_arg",
    "_add_guard_common_args",
    "_aibom_cli_options_from_args",
    "_approve_init_step",
    "_build_init_plan",
    "_guard_http_url",
    "_normalize_explicit_workspace_path",
    "_package_firewall_block_payload",
    "_package_firewall_cli_gate_input",
    "_print_init_plan_preview",
    "_print_init_step_complete",
    "_prompt_init_step",
    "_requested_install_harness",
    "_resolve_default_install_workspace",
    "_resolve_guard_workspace",
    "_run_init_command",
    "_skip_init_step_payload",
    "_workspace_from_cursor_project_dir",
    "_workspace_from_harness_detection",
    "_workspace_has_project_markers",
]
