"""Daemon payload, runtime deadline, and environment helpers."""

from __future__ import annotations

from . import server as _server


def _headless_cloud_sync_store_key(store: _server.GuardStore) -> str:
    return str(store.guard_home.expanduser().resolve())


def _build_snapshot_payload(context: _server.HarnessContext) -> dict[str, object]:
    """Return a lightweight snapshot dict including package manager shim coverage."""
    status = _server.package_shim_status(context)
    return {
        "package_manager_coverage": {
            "detected_managers": status.get("detected_managers", []),
            "path_active": status.get("active_managers", []),
            "shims_installed": status.get("active_managers", []),
            "undetected_managers": status.get("undetected_managers", []),
            "unsupported_managers": [],
        }
    }


def _is_decision_scope(value: str) -> _server.TypeGuard[_server.DecisionScope]:
    return value in _server.DECISION_SCOPE_VALUES


def _is_string_object_dict(value: object) -> _server.TypeGuard[dict[str, object]]:
    return isinstance(value, dict) and all(isinstance(key, str) for key in value)


def _safe_int(value: object) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value if value >= 0 else 0
    return 0


def _runtime_hook_remaining_hint(payload: dict[str, object]) -> float:
    raw_seconds = payload.pop("guard_remaining_seconds", None)
    raw_milliseconds = payload.pop("guard_remaining_ms", None)
    if (
        isinstance(raw_seconds, (int, float))
        and not isinstance(raw_seconds, bool)
        and _server.math.isfinite(float(raw_seconds))
    ):
        return float(raw_seconds)
    if (
        isinstance(raw_milliseconds, (int, float))
        and not isinstance(raw_milliseconds, bool)
        and _server.math.isfinite(float(raw_milliseconds))
    ):
        return float(raw_milliseconds) / 1000.0
    return _server._RUNTIME_HOOK_ADMISSION_TIMEOUT_SECONDS


def _codex_live_replay_authority(
    request: object,
    previous: object,
) -> tuple[str | None, str | None]:
    """Return already-claimed exact context only for a terminal allow replay."""

    if not isinstance(request, _server.Mapping) or not isinstance(previous, _server.Mapping):
        return None, None
    if request.get("resolution_action") != "allow" or previous.get("resolution_action") != "allow":
        return None, None
    if previous.get("status") not in {"resumed", "sent"}:
        return None, None
    artifact_hash = request.get("artifact_hash")
    request_id = request.get("request_id")
    if not isinstance(artifact_hash, str) or not artifact_hash:
        return None, None
    if not isinstance(request_id, str) or not request_id:
        return None, None
    return artifact_hash, request_id


def _runtime_hook_env_overlay_from_payload(payload: _server.Mapping[str, object]) -> dict[str, str]:
    raw_overlay = payload.get("hook_env")
    if not isinstance(raw_overlay, _server.Mapping):
        return {}
    overlay: dict[str, str] = {}
    for key, value in raw_overlay.items():
        if not isinstance(key, str) or key not in _server._RUNTIME_HOOK_ENV_ALLOWLIST:
            continue
        if isinstance(value, str) and value:
            overlay[key] = value
    return overlay
