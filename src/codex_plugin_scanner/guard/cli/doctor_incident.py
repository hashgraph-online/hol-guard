"""Small, read-only Codex incident report independent of GuardStore and daemon RPC."""

from __future__ import annotations

import json
import os
import re
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import TextIO, cast

from ...version import __version__
from ..adapters.base import HarnessContext
from ..adapters.codex import CodexHarnessAdapter, _hook_manifest_spec
from ..codex_config import tomllib
from ..codex_hook_manifest import verify_live_hook_manifest
from ..daemon.discovery import load_authenticated_daemon_state
from ..daemon.lifecycle_journal import load_bounded_incident_lifecycle_events

_MAX_CONFIG_BYTES = 1024 * 1024
_MAX_REPORT_BYTES = 8192
_SAFE_CODE = re.compile(r"^[a-z][a-z0-9_]{0,79}$")
_SAFE_EXCEPTION_CLASS = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}$")
_SAFE_VERSION = re.compile(r"^[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}$")
_SAFE_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_EVENTS = ("PreToolUse", "PermissionRequest", "UserPromptSubmit", "PostToolUse")


def _safe_code(value: object, fallback: str) -> str:
    return value if isinstance(value, str) and _SAFE_CODE.fullmatch(value) else fallback


def _safe_version(value: object) -> str | None:
    return value if isinstance(value, str) and _SAFE_VERSION.fullmatch(value) else None


def _safe_digest(value: object) -> str | None:
    return value if isinstance(value, str) and _SAFE_DIGEST.fullmatch(value) else None


def _safe_generation(value: object) -> str | None:
    return value if isinstance(value, str) and len(value) <= 64 and re.fullmatch(r"[0-9T:.+\-Z]+", value) else None


def _bounded_regular_bytes(path: Path) -> tuple[bytes | None, str]:
    try:
        before = path.lstat()
    except FileNotFoundError:
        return None, "missing"
    except OSError:
        return None, "unreadable"
    if not stat.S_ISREG(before.st_mode):
        return None, "unsafe_file_type"
    if before.st_size > _MAX_CONFIG_BYTES:
        return None, "too_large"
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        return None, "unreadable"
    try:
        opened = os.fstat(descriptor)
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            return None, "changed_during_read"
        if not stat.S_ISREG(opened.st_mode):
            return None, "unsafe_file_type"
        if opened.st_size > _MAX_CONFIG_BYTES:
            return None, "too_large"
        chunks: list[bytes] = []
        remaining = _MAX_CONFIG_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
    except OSError:
        return None, "unreadable"
    finally:
        os.close(descriptor)
    if not all(
        getattr(opened, field) == getattr(after, field)
        for field in ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
    ):
        return None, "changed_during_read"
    if remaining == 0 or sum(map(len, chunks)) > _MAX_CONFIG_BYTES:
        return None, "too_large"
    return b"".join(chunks), "read"


def _read_codex_hook_files(config_path: Path, hooks_path: Path) -> tuple[object, dict[str, str | bool | None]]:
    raw, status = _bounded_regular_bytes(config_path)
    if raw is None and status != "missing":
        return None, {"config_status": status, "hooks_enabled": None}
    config: dict[str, object] = {}
    if raw is not None:
        try:
            config = tomllib.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, tomllib.TOMLDecodeError, RecursionError):
            return None, {"config_status": "malformed", "hooks_enabled": None}
    features = config.get("features")
    hooks_enabled = not isinstance(features, dict) or features.get("hooks") is not False
    hooks = config.get("hooks")
    if isinstance(hooks, dict):
        return hooks, {"config_status": status, "hooks_enabled": hooks_enabled}
    raw_hooks, hooks_status = _bounded_regular_bytes(hooks_path)
    if raw_hooks is None:
        return None, {"config_status": status, "hooks_enabled": hooks_enabled, "hooks_status": hooks_status}
    try:
        decoded = json.loads(raw_hooks)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
        return None, {"config_status": status, "hooks_enabled": hooks_enabled, "hooks_status": "malformed"}
    if not isinstance(decoded, dict):
        return None, {"config_status": status, "hooks_enabled": hooks_enabled, "hooks_status": "malformed"}
    return decoded.get("hooks"), {"config_status": status, "hooks_enabled": hooks_enabled, "hooks_status": "read"}


def _configured_codex_hooks(context: HarnessContext) -> tuple[object, dict[str, str | bool | None]]:
    return _read_codex_hook_files(
        CodexHarnessAdapter._hook_config_path(context),
        CodexHarnessAdapter._hooks_path(context),
    )


def _hook_shape_counts(hooks: object) -> tuple[dict[str, int | None], dict[str, int | None]] | tuple[None, None]:
    """Count configured shapes without attributing ownership or loaded-session state."""
    if not isinstance(hooks, dict):
        return None, None
    hook_table = cast(dict[str, object], hooks)
    groups_by_event: dict[str, int | None] = {}
    handlers_by_event: dict[str, int | None] = {}
    for event in _EVENTS:
        groups = hook_table.get(event, [])
        if not isinstance(groups, list):
            groups_by_event[event] = None
            handlers_by_event[event] = None
            continue
        typed_groups = cast(list[object], groups)
        if any(not isinstance(group, dict) for group in typed_groups):
            groups_by_event[event] = None
            handlers_by_event[event] = None
            continue
        groups_by_event[event] = len(typed_groups)
        handler_count = 0
        valid_handlers = True
        for group in typed_groups:
            handlers = cast(dict[str, object], group).get("hooks")
            if not isinstance(handlers, list):
                valid_handlers = False
                break
            typed_handlers = cast(list[object], handlers)
            if any(not isinstance(handler, dict) for handler in typed_handlers):
                valid_handlers = False
                break
            handler_count += len(typed_handlers)
        # A partial count would imply that malformed configured entries were absent.
        handlers_by_event[event] = handler_count if valid_handlers else None
    return groups_by_event, handlers_by_event


def _workspace_hook_observation(context: HarnessContext) -> dict[str, object]:
    if context.workspace_dir is None:
        return {"selected": False}
    config_path, hooks_path = CodexHarnessAdapter._config_hook_pairs(context)[1]
    hooks, status = _read_codex_hook_files(config_path, hooks_path)
    group_counts, handler_counts = _hook_shape_counts(hooks)
    return {
        "selected": True,
        **status,
        "authentication": "unverified_local_configuration",
        "event_group_counts": group_counts,
        "event_handler_counts": handler_counts,
    }


def codex_incident_report(context: HarnessContext) -> dict[str, object]:
    hooks, config = _configured_codex_hooks(context)
    group_counts, handler_counts = _hook_shape_counts(hooks)
    hooks_unavailable = config.get("hooks_status") in {
        "unreadable",
        "malformed",
        "too_large",
        "unsafe_file_type",
        "changed_during_read",
    }
    if config["config_status"] in {"read", "missing"} and not hooks_unavailable:
        try:
            integrity = verify_live_hook_manifest(_hook_manifest_spec(context), hooks=hooks)
        except Exception as error:
            status, reason = "unverified", "codex_integrity_probe_failed"
            exception_name = type(error).__name__
            probe_exception_class = exception_name if _SAFE_EXCEPTION_CLASS.fullmatch(exception_name) else "unknown"
            matches = {event: False for event in _EVENTS}
            manifest_version = None
            manifest_generation = None
            bridge_digest = None
            interpreter_digest = None
        else:
            probe_exception_class = None
            status = _safe_code(integrity.get("integrity_status"), "unknown")
            reason = _safe_code(integrity.get("integrity_reason"), "codex_hook_integrity_unknown")
            event_matches = integrity.get("event_matches")
            matches = {event: isinstance(event_matches, dict) and event_matches.get(event) is True for event in _EVENTS}
            if status == "valid":
                manifest_version = _safe_version(integrity.get("manifest_package_version"))
                manifest_generation = _safe_generation(integrity.get("manifest_generated_at"))
                bridge_digest = _safe_digest(integrity.get("bridge_sha256"))
                interpreter_digest = _safe_digest(integrity.get("interpreter_sha256"))
            else:
                manifest_version = manifest_generation = bridge_digest = interpreter_digest = None
    else:
        probe_exception_class = None
        status, reason = "unverified", "codex_hooks_unavailable" if hooks_unavailable else "codex_config_unavailable"
        matches = {event: False for event in _EVENTS}
        manifest_version = None
        manifest_generation = None
        bridge_digest = None
        interpreter_digest = None
    try:
        daemon_state = load_authenticated_daemon_state(context.guard_home)
    except (OSError, UnicodeError, ValueError, RecursionError, TypeError):
        daemon_state = None
    daemon = {
        "discovery_authentication": "verified" if daemon_state is not None else "unverified",
        "package_version": _safe_version(daemon_state.get("package_version")) if daemon_state else None,
        "compatibility_version": (
            daemon_state.get("compatibility_version")
            if daemon_state and type(daemon_state.get("compatibility_version")) is int
            else None
        ),
        "liveness": "unknown",
    }
    try:
        events, timeline_status = load_bounded_incident_lifecycle_events(context.guard_home)
    except OSError:
        events, timeline_status = [], "journal_unavailable"
    return {
        "schema": "hol-guard.codex-incident.v1",
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "harness": "codex",
        "cli_package_version": __version__,
        "configured": {
            **config,
            "event_group_counts": group_counts,
            "event_handler_counts": handler_counts,
            "manifest_integrity": status,
            "reason_code": reason,
            "integrity_probe_exception_class": probe_exception_class,
            "manifest_package_version": manifest_version,
            "manifest_generated_at": manifest_generation,
            "bridge_sha256": bridge_digest,
            "interpreter_sha256": interpreter_digest,
            "managed_events": matches,
        },
        "workspace": _workspace_hook_observation(context),
        "daemon": daemon,
        "loaded_harness": {"state": "unknown", "reason_code": "loaded_session_not_observable"},
        "authenticated_hook_decision": {"state": "unknown", "reason_code": "decision_not_probed"},
        "timeline": {
            "status": timeline_status,
            "scope": "recent_bounded_journal",
            "authentication": "unverified_local_observations",
            "events": [
                {"event": event["event"], "reason": event.get("reason"), "recorded_at_ns": event["recorded_at_ns"]}
                for event in events
            ],
        },
    }


def run_codex_incident_export(args: object, context: HarnessContext, output_stream: TextIO | None = None) -> int:
    output = output_stream or sys.stdout
    if getattr(args, "harness", None) != "codex" or any(
        bool(getattr(args, flag, False))
        for flag in ("repair", "harnesses", "perf", "notifications", "force_notification_settings")
    ):
        print(json.dumps({"error": "incident_export_requires_codex_without_other_doctor_actions"}), file=output)
        return 2
    report = codex_incident_report(context)
    encoded = json.dumps(report, sort_keys=True, separators=(",", ":"))
    if len(encoded.encode("utf-8")) > _MAX_REPORT_BYTES:
        print(json.dumps({"error": "incident_report_size_limit"}), file=output)
        return 2
    print(encoded, file=output)
    return 0
