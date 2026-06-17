"""Guard CLI helper definitions."""

# fmt: off
# ruff: noqa: F403, F405, I001

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..daemon.manager import _guard_daemon_pid_is_running, _guard_daemon_pid_matches_command
    from ._commands_shared import _now
    from .commands_support_connect import _guard_service_runtime_profile
    from .commands_support_interaction import _emit, _resolve_cisco_scan_options
    from .commands_support_runtime_artifacts import _optional_string


from ._commands_shared import *
from .commands_parser_helpers import *

def _guard_service_login_payload(
    *,
    args: argparse.Namespace,
    store: GuardStore,
) -> tuple[dict[str, object], int]:
    runtime = str(args.runtime)
    label = str(args.label).strip()
    workspace = _optional_string(getattr(args, "workspace", None)) or ""
    if getattr(args, "token", None) is not None:
        return {
            "logged_in": False,
            "error": (
                "Hosted runtime token login is retired. "
                "Run `hol-guard connect --headless` or `hol-guard connect` instead."
            ),
            "service": {
                "runtime": runtime,
                "label": label,
                "workspace": workspace or None,
            },
        }, 2
    next_command = "hol-guard connect --headless"
    next_message = "Use OAuth Device Code to connect headless or hosted runtimes."
    if workspace:
        next_command = (
            "hol-guard connect --headless --ci-safe "
            f"--workspace {shlex.quote(workspace)} --label {shlex.quote(label)}"
        )
        next_message = "Use CI-safe OAuth Device Code to connect a hosted runtime with explicit workspace metadata."
    return {
        "logged_in": False,
        "next_action": {
            "command": next_command,
            "message": next_message,
        },
        "service": {
            "runtime": runtime,
            "label": label,
            "workspace": workspace or None,
        },
    }, 2

def _guard_service_sync_prerequisite_message() -> str:
    return "Hosted Guard runtime is not configured yet. Run `hol-guard connect` first."

def _guard_service_sync_failure_message(error: GuardSyncNotConfiguredError) -> str:
    if isinstance(error, GuardSyncAuthorizationExpiredError):
        return str(error)
    return _guard_service_sync_prerequisite_message()

def _guard_service_status_payload(store: GuardStore) -> dict[str, object]:
    cloud_profile = store.get_cloud_sync_profile()
    service_profile = _guard_service_runtime_profile(store)
    return {
        "configured": cloud_profile is not None and service_profile is not None,
        "connection": {
            "configured": cloud_profile is not None,
            "sync_url": cloud_profile["sync_url"] if cloud_profile is not None else None,
        },
        "service": service_profile,
        "runtime": store.get_sync_payload("runtime_session_summary") or {},
        "receipts": store.get_sync_payload("sync_summary") or {},
    }

def _guard_service_sync_payload(store: GuardStore) -> dict[str, object]:
    service_profile = _guard_service_runtime_profile(store)
    if service_profile is None:
        raise GuardSyncNotConfiguredError(_guard_service_sync_prerequisite_message())
    runtime_summary = sync_runtime_session(
        store,
        session={
            "harness": service_profile["runtime"],
            "surface": service_profile["surface"],
            "status": "active",
            "client_name": service_profile["client_name"],
            "client_title": service_profile["client_title"],
            "client_version": service_profile["client_version"],
            "workspace": service_profile["workspace"],
            "capabilities": ["hosted-runtime", "guard-cloud-sync"],
        },
    )
    receipts_summary = sync_receipts(store)
    store.add_event(
        "service_sync",
        {
            "runtime": service_profile["runtime"],
            "workspace": service_profile["workspace"] or None,
            "runtime_session_id": runtime_summary.get("runtime_session_id"),
            "synced_at": receipts_summary.get("synced_at"),
        },
        _now(),
    )
    return {
        "synced": True,
        "service": service_profile,
        "runtime": runtime_summary,
        "receipts": receipts_summary,
    }

def _validated_supply_chain_sync_payload(payload: object) -> dict[str, object]:
    if not isinstance(payload, dict):
        raise RuntimeError("Guard Cloud sync returned an invalid response.")
    return payload

def _guard_sync_prerequisite_message() -> str:
    return (
        "Guard Cloud is not connected yet. Run `hol-guard connect` to sign in and pair this machine, "
        "or use `hol-guard login` as a compatibility alias for the same browser flow."
    )

def _guard_sync_failure_message(error: GuardSyncNotConfiguredError) -> str:
    if isinstance(error, GuardSyncAuthorizationExpiredError):
        return str(error)
    return _guard_sync_prerequisite_message()

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

def _handle_daemon_status(guard_home: Path, as_json: bool) -> int:
    from codex_plugin_scanner.version import __version__

    url = load_guard_daemon_url(guard_home)
    running = False
    port: int | None = None
    pid: int | None = None
    state_path = guard_home / "daemon-state.json"
    if state_path.is_file():
        import json as _json

        try:
            state = _json.loads(state_path.read_text())
            pid = state.get("pid") if isinstance(state, dict) else None
            port = state.get("port") if isinstance(state, dict) else None
            if (
                isinstance(pid, int)
                and pid > 0
                and _guard_daemon_pid_is_running(pid)
                and _guard_daemon_pid_matches_command(pid, expected_guard_home=guard_home)
            ):
                running = True
        except Exception:
            pass
    payload: dict[str, object] = {
        "running": running,
        "guard_home": str(guard_home),
        "version": __version__,
    }
    if port is not None:
        payload["port"] = port
    if pid is not None:
        payload["pid"] = pid
    if url is not None:
        payload["url"] = url
    _emit("daemon", payload, as_json)
    return 0

def _handle_daemon_repair(guard_home: Path, as_json: bool) -> int:
    result = repair_approval_center_locator(guard_home)
    _emit("daemon", result, as_json)
    return 0

def _handle_daemon_stop(guard_home: Path, as_json: bool) -> int:
    import json as _json
    import os
    import signal as _signal

    state_path = guard_home / "daemon-state.json"
    stopped = False
    pid: int | None = None
    if state_path.is_file():
        try:
            state = _json.loads(state_path.read_text())
            pid = state.get("pid") if isinstance(state, dict) else None
            if (
                isinstance(pid, int)
                and pid > 0
                and _guard_daemon_pid_is_running(pid)
                and _guard_daemon_pid_matches_command(pid, expected_guard_home=guard_home)
            ):
                os.kill(pid, _signal.SIGTERM)
                stopped = True
        except (ProcessLookupError, PermissionError, OSError, _json.JSONDecodeError, ValueError):
            pass
    from codex_plugin_scanner.guard.daemon.manager import clear_guard_daemon_state

    with suppress(OSError):
        clear_guard_daemon_state(guard_home)
    payload: dict[str, object] = {"stopped": stopped, "running": False}
    if pid is not None:
        payload["pid"] = pid
    _emit("daemon", payload, as_json)
    return 0

__all__ = [
    "_build_abom_payload",
    "_build_explain_payload",
    "_build_explain_payload_with_mode",
    "_guard_service_login_payload",
    "_guard_service_status_payload",
    "_guard_service_sync_failure_message",
    "_guard_service_sync_payload",
    "_guard_service_sync_prerequisite_message",
    "_guard_sync_failure_message",
    "_guard_sync_prerequisite_message",
    "_handle_daemon_repair",
    "_handle_daemon_status",
    "_handle_daemon_stop",
    "_matching_advisories",
    "_validated_supply_chain_sync_payload",
]
