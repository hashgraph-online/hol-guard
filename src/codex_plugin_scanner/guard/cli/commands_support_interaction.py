"""Guard CLI helper definitions."""

# fmt: off
# ruff: noqa: F403, F405

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING

from ..browser_opener import open_browser_url
from ..live_process_identity import CODEX_BROWSER_WAIT_PROCESS_KEY, process_identity_matches

if TYPE_CHECKING:
    from ._commands_shared import _now
    from .commands_support_hook_payload import _browser_url_with_guard_params


from ._commands_shared import *
from .commands_parser_helpers import *


def _runtime_artifacts_module():
    return importlib.import_module(".commands_support_runtime_artifacts", __package__)


def _runtime_resolution_module():
    return importlib.import_module(".commands_support_runtime_resolution", __package__)


def _optional_string(value: object | None) -> str | None:
    return _runtime_artifacts_module()._optional_string(value)


def _canonical_harness_name(value: str) -> str:
    return _runtime_resolution_module()._canonical_harness_name(value)

def _run_apps_command(
    args: argparse.Namespace,
    context: HarnessContext,
    store: GuardStore,
    workspace: str | None,
) -> int:
    apps_command = getattr(args, "apps_command", None)
    if apps_command is None:
        from ..adapters.harness_mcp_discovery import observe_configured_mcp_servers

        observe_configured_mcp_servers(store, context=context, seen_at=_now())
        _emit(
            "apps",
            {
                "generated_at": _now(),
                "items": list_harness_setup_items(context, store),
            },
            getattr(args, "json", False),
        )
        return 0

    harness = str(getattr(args, "harness", "")).strip()
    if not harness:
        print("guard apps requires a harness.", file=sys.stderr)
        return 2
    if apps_command == "repair" and (
        bool(getattr(args, "restore_authority", False)) or getattr(args, "authority_request", None)
        or getattr(args, "authority_request_sha256", None)
        or getattr(args, "authority_deadline_epoch", None) is not None
        or getattr(args, "authority_verification_workspace", None) is not None
    ):
        from .codex_authority_repair import run_codex_authority_repair

        code, payload = run_codex_authority_repair(args, context, store, Path(workspace) if workspace else None)
        _emit("apps", payload, getattr(args, "json", False))
        return code
    if apps_command == "test":
        try:
            payload = build_harness_verification(harness, context, store, surface=getattr(args, "surface", None))
        except ValueError as error:
            print(str(error), file=sys.stderr)
            return 2
        _emit("apps", payload, getattr(args, "json", False))
        return 0

    if apps_command in {"connect", "repair"} and bool(getattr(args, "dry_run", False)):
        try:
            payload = build_harness_setup_plan(
                apps_command,
                harness,
                context,
                dry_run=True,
                surface=getattr(args, "surface", None),
            )
        except ValueError as error:
            print(str(error), file=sys.stderr)
            return 2
        _emit("apps", payload, getattr(args, "json", False))
        return 0

    if apps_command == "disconnect":
        try:
            canonical_harness = get_adapter(harness).harness
        except ValueError as error:
            print(str(error), file=sys.stderr)
            return 2
        expected_confirmation = uninstall_confirmation_token(canonical_harness)
        if getattr(args, "confirm", None) != expected_confirmation:
            payload: dict[str, object] = {
                "error": "confirmation_required",
                "harness": canonical_harness,
                "confirmation_phrase": expected_confirmation,
                "confirm_command": _apps_disconnect_confirm_command(
                    canonical_harness,
                    expected_confirmation,
                    surface=getattr(args, "surface", None),
                ),
            }
            _emit("apps", payload, getattr(args, "json", False))
            return 2

    install_command = "uninstall" if apps_command == "disconnect" else "install"
    try:
        payload = apply_managed_install(
            install_command,
            harness,
            False,
            context,
            store,
            workspace,
            _now(),
            surface=getattr(args, "surface", None),
        )
    except ValueError as error:
        print(str(error), file=sys.stderr)
        return 2
    payload["action"] = apps_command
    if apps_command in {"connect", "repair"}:
        managed_install = payload.get("managed_install")
        canonical_harness = (
            str(managed_install.get("harness"))
            if isinstance(managed_install, dict) and managed_install.get("harness")
            else harness
        )
        try:
            payload["cloud_app"] = _open_guard_cloud_app(
                harness=canonical_harness,
                guard_home=context.guard_home,
                opener=open_browser_url,
            )
        except (RuntimeError, OSError) as error:
            payload["cloud_app"] = _guard_cloud_app_error_payload(
                harness=canonical_harness,
                error=str(error),
            )
    _emit("apps", payload, getattr(args, "json", False))
    return 0

def _apps_disconnect_confirm_command(harness: str, confirmation_phrase: str, *, surface: str | None) -> str:
    surface_args = f" --surface {surface}" if surface else ""
    return f"hol-guard apps disconnect {harness}{surface_args} --confirm {confirmation_phrase}"

def _open_guard_cloud_app(
    *,
    harness: str,
    guard_home: Path,
    opener: GuardBrowserOpener,
) -> dict[str, object]:
    daemon_url = ensure_guard_daemon(guard_home)
    auth_token = load_guard_daemon_auth_token(guard_home)
    public_url, browser_url = _guard_cloud_app_urls(
        harness=harness,
        daemon_url=daemon_url,
        auth_token=auth_token,
    )
    browser_opened = bool(browser_url and opener(browser_url))
    payload: dict[str, object] = {
        "app_url": public_url,
        "browser_opened": browser_opened,
        "daemon_url": daemon_url,
        "status": "opened" if browser_opened else "manual_open_required",
    }
    if not browser_opened:
        payload["next_action"] = {
            "label": f"Run hol-guard apps connect {harness}",
            "reason": "Browser did not open automatically and the local token is never printed.",
            "target": f"hol-guard apps connect {harness}",
        }
    return payload

def _guard_cloud_app_error_payload(*, harness: str, error: str) -> dict[str, object]:
    public_url, _browser_url = _guard_cloud_app_urls(
        harness=harness,
        daemon_url="",
        auth_token=None,
    )
    return {
        "app_url": public_url,
        "browser_opened": False,
        "daemon_url": None,
        "error": error,
        "next_action": {
            "label": f"Run hol-guard apps connect {harness}",
            "reason": "Local Guard daemon did not start, so Cloud cannot connect from the browser yet.",
            "target": f"hol-guard apps connect {harness}",
        },
        "status": "daemon_unavailable",
    }

def _guard_cloud_app_urls(
    *,
    harness: str,
    daemon_url: str,
    auth_token: str | None,
) -> tuple[str, str | None]:
    safe_harness = urllib.parse.quote(harness.strip() or "codex", safe="")
    parsed = urllib.parse.urlparse(f"{DEFAULT_GUARD_APPS_URL}/{safe_harness}")
    public_url = urllib.parse.urlunparse(parsed._replace(fragment=""))
    if auth_token is None:
        return public_url, None
    browser_url = _browser_url_with_guard_params(
        public_url,
        auth_token=auth_token,
        surface="cloud-dashboard",
        daemon_url=daemon_url,
    )
    return public_url, browser_url

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

def _policy_write_needs_approval_gate(store: GuardStore, *, action: str, scope: str) -> bool:
    if not _policy_write_requires_approval_gate(store, action=action, scope=scope):
        return False
    gate = approval_gate_public_config(store.guard_home)
    if scope == "global":
        return True
    if gate.cooldown_active and not gate.totp_enabled:
        return False
    if action == "allow":
        return True
    return gate.strict_all_decisions

def _policy_write_requires_approval_gate(store: GuardStore, *, action: str, scope: str) -> bool:
    gate = approval_gate_public_config(store.guard_home)
    if not gate.enabled:
        return False
    if action == "allow" or scope == "global":
        return True
    return gate.strict_all_decisions

def _emit(command: str, payload: dict[str, object], as_json: bool) -> None:
    from .render import emit_guard_payload

    emit_guard_payload(command, payload, as_json)

def _codex_can_use_browser_approval(args: argparse.Namespace, *, event_name: str, policy_action: str) -> bool:
    return (
        _canonical_harness_name(args.harness) == "codex"
        and not getattr(args, "json", False)
        and event_name in {"PreToolUse", "PostToolUse", "UserPromptSubmit"}
        and policy_action in {"review", "require-reapproval"}
    )

def _codex_json_bridge_can_use_browser_approval(
    args: argparse.Namespace,
    *,
    event_name: str,
    policy_action: str,
) -> bool:
    # --json output changes rendering, not approval semantics: when the hook
    # already has an authenticated daemon bridge for the queued request, the
    # wait/revalidation contract still applies — except for PreToolUse, where
    # the deny document is the terminal answer and the caller retries the
    # action after resolving the queued approval. A worker-spawned bridge
    # (codex_browser_wait_process in the payload) still owns the PreToolUse
    # wait through the dedicated branch in _codex_hook_waits_for_browser_approval.
    return (
        _canonical_harness_name(args.harness) == "codex"
        and bool(getattr(args, "json", False))
        and event_name in {"PostToolUse", "UserPromptSubmit"}
        and policy_action in {"review", "require-reapproval"}
    )

def _codex_hook_waits_for_browser_approval(
    args: argparse.Namespace,
    *,
    event_name: str,
    policy_action: str,
    payload: Mapping[str, object] | None = None,
    json_daemon_bridge: bool = False,
) -> bool:
    if (
        _canonical_harness_name(args.harness) == "codex"
        and event_name == "PreToolUse"
        and policy_action in {"review", "require-reapproval"}
        and _codex_bridge_wait_process(payload) is not None
    ):
        return True
    return _codex_can_use_browser_approval(
        args=args, event_name=event_name, policy_action=policy_action
    ) or (
        json_daemon_bridge
        and _codex_json_bridge_can_use_browser_approval(
            args, event_name=event_name, policy_action=policy_action
        )
    )

def _codex_bridge_wait_process(payload: Mapping[str, object] | None) -> dict[str, object] | None:
    if not isinstance(payload, Mapping):
        return None
    process_identity: object = payload.get(CODEX_BROWSER_WAIT_PROCESS_KEY)
    if isinstance(process_identity, dict) and process_identity_matches(process_identity):
        return process_identity
    return None


def _attach_primary_approval_link(
    response_payload: dict[str, object],
    *,
    harness: str,
    approval_center_url: str | None,
) -> None:
    attach_primary_approval_link(
        response_payload,
        harness=harness,
        approval_center_url=approval_center_url,
    )

def _primary_approval_lookup_kwargs(response_payload: dict[str, object], *, harness: str) -> dict[str, str | None]:
    return {
        "harness": harness,
        "approval_center_url": _optional_string(response_payload.get("approval_center_url")),
        "request_id": _optional_string(response_payload.get("primary_approval_request_id")),
        "artifact_id": _optional_string(response_payload.get("artifact_id")),
    }

def _preferred_approval_review_url(response_payload: Mapping[str, object], *, harness: str) -> str | None:
    approval_center_url = _optional_string(response_payload.get("approval_center_url"))
    queued = response_payload.get("approval_requests")
    lookup_kwargs = _primary_approval_lookup_kwargs(dict(response_payload), harness=harness)
    artifact_id = lookup_kwargs.get("artifact_id")
    queued_has_artifact_metadata = (
        any(_optional_string(item.get("artifact_id")) is not None for item in queued if isinstance(item, Mapping))
        if isinstance(queued, list)
        else False
    )
    queued_url = (
        first_approval_url(
            queued,
            **lookup_kwargs,
        )
        if isinstance(queued, list)
        else None
    )
    if queued_url is None and isinstance(queued, list) and artifact_id is not None:
        queued_url = first_approval_url(
            queued,
            harness=harness,
            approval_center_url=approval_center_url,
            artifact_id=artifact_id,
        )
    if queued_url is None and isinstance(queued, list) and (artifact_id is None or not queued_has_artifact_metadata):
        queued_url = first_approval_url(
            queued,
            harness=harness,
            approval_center_url=approval_center_url,
        )
    if queued_url is not None:
        return queued_url
    primary_url = _optional_string(response_payload.get("primary_approval_url"))
    if primary_url is not None:
        return canonical_local_approval_url(
            primary_url,
            approval_center_url=approval_center_url,
        )
    return approval_center_url

__all__ = [
    "_apps_disconnect_confirm_command", "_attach_primary_approval_link",
    "_build_cisco_scan_options",
    "_codex_bridge_wait_process",
    "_codex_can_use_browser_approval",
    "_codex_hook_waits_for_browser_approval",
    "_codex_json_bridge_can_use_browser_approval", "_emit",
    "_guard_cloud_app_error_payload", "_guard_cloud_app_urls",
    "_open_guard_cloud_app", "_policy_write_needs_approval_gate", "_policy_write_requires_approval_gate",
    "_preferred_approval_review_url", "_primary_approval_lookup_kwargs",
    "_resolve_cisco_scan_options", "_run_apps_command", "_run_consumer_scan_with_mode",
]
