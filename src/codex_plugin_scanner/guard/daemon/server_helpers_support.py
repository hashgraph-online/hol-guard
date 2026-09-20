"""Persistence health, session tokens, and daemon URLs."""

from __future__ import annotations

from . import server as _server


def _repair_command_activity_persistence_health(store: _server.GuardStore) -> None:
    evaluation = _server.evaluate_command(_server._PROTECTION_REPAIR_PROBE_COMMAND)
    occurred_at = _server.datetime.now(_server.timezone.utc)
    activity_id = f"activity:protection-repair-probe:{_server.uuid.uuid4().hex}"
    decision_reason = (
        _server.ActivityDecisionReason.EXTENSION_MATCH
        if evaluation.matches
        else _server.ActivityDecisionReason.NO_MATCH
    )
    evidence = _server.build_pre_hook_evidence(
        evaluation,
        _server.CommandActivityDecisionFacts(
            policy_action="allow",
            decision_reason_code=decision_reason,
            prompted=False,
            approval_reuse_status=_server.ActivityApprovalReuseStatus.NOT_APPLICABLE,
            receipt_id=None,
        ),
        activity_id=activity_id,
        occurred_at=occurred_at,
        harness="codex",
        request_correlation=None,
    )
    shadow = None
    shadow_evaluation_succeeded = True
    try:
        shadow = _server.build_command_shadow_observation(
            evaluation,
            authoritative_action="allow",
            proposal=_server.baseline_command_shadow_proposal(evaluation),
            activity_id=activity_id,
            occurred_at=occurred_at,
            control=_server.CommandShadowControl(
                enabled=True,
                kill_switch=False,
                release_cohorts=frozenset({_server.CommandShadowCohort.BASELINE}),
                disabled_cohorts=frozenset(),
                sample_basis_points=10_000,
            ),
        )
    except (RuntimeError, TypeError, ValueError):
        shadow = None
        shadow_evaluation_succeeded = False
    store.probe_command_activity_persistence(
        evidence,
        shadow=shadow,
        shadow_evaluation_succeeded=shadow_evaluation_succeeded,
    )


def _approval_center_browser_url(approval_center_url: str, auth_token: str) -> str:
    parsed = _server.urlparse(approval_center_url)
    fragment_pairs = [
        (key, value)
        for key, value in _server.parse_qsl(parsed.fragment, keep_blank_values=True)
        if key != "guard-token"
    ]
    fragment_pairs.append(
        (
            "guard-token",
            _server.build_local_dashboard_session_token(auth_token=auth_token, surface="approval-center"),
        )
    )
    return _server.urlunparse(parsed._replace(fragment=_server.urlencode(fragment_pairs)))


def _build_local_url(host: str, port: int, path: str) -> str:
    if host not in {"127.0.0.1", "::1"}:
        raise ValueError("Guard local URLs require a loopback host.")
    host_part = f"[{host}]" if ":" in host else host
    return f"http://{host_part}:{port}{path}"  # NOSONAR(S5332) loopback-only authenticated local IPC


def _build_resolution_copy(action: str, harness: str) -> dict[str, str]:
    title = "Approved. Retry in chat." if action == "allow" else "Blocked. Decision saved."
    return {"title": title, "body": _server._HARNESS_RETRY_COPY.get(harness, _server._DEFAULT_RETRY_COPY)}


def _settings_response_payload(guard_home: _server.Path, settings: dict[str, object]) -> dict[str, object]:
    from ..protection_capabilities import protection_capability_payloads

    return {
        "guard_home": str(guard_home),
        "config_path": str(guard_home / "config.toml"),
        "settings": settings,
        "protection_capabilities": protection_capability_payloads(),
    }


def _settings_export_payload(config: _server.GuardConfig) -> dict[str, object]:
    return {
        "schema_version": 1,
        "privacy_warning": "Exports include local Guard preferences but not secrets or receipt evidence.",
        "settings": _server.editable_guard_settings(config),
    }


def _dashboard_session_signature(payload: str, auth_token: str) -> str:
    digest = _server.hmac.new(auth_token.encode("utf-8"), payload.encode("utf-8"), _server.hashlib.sha256).digest()
    return _server.base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def _decode_dashboard_session_payload(payload: str) -> dict[str, object]:
    padding = "=" * (-len(payload) % 4)
    try:
        decoded = _server.base64.urlsafe_b64decode(f"{payload}{padding}".encode("ascii")).decode("utf-8")
        parsed = _server.json.loads(decoded)
    except (UnicodeDecodeError, ValueError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _parse_iso_timestamp(value: str) -> float:
    normalized = value.replace("Z", "+00:00")
    return _server.datetime.fromisoformat(normalized).timestamp()


def _normalized_iso_timestamp_string(value: object) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None

    try:
        parsed = _server.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=_server.timezone.utc)
    return parsed.astimezone(_server.timezone.utc).isoformat()


def _now() -> str:
    return _server.datetime.now(_server.timezone.utc).isoformat()


def _validate_dashboard_bundle() -> None:
    if not _server._INDEX_PATH.is_file() or not _server._ENTRY_PATH.is_file():
        raise RuntimeError(
            "Guard dashboard bundle is missing. Run `pnpm install && pnpm run build` in the dashboard directory."
        )


def _guard_daemon_idle_timeout_seconds(
    guard_home: _server.Path,
    *,
    idle_timeout_seconds: float | None = None,
) -> float | None:
    if idle_timeout_seconds is not None:
        return idle_timeout_seconds if idle_timeout_seconds > 0 else None
    configured_timeout = _server.os.environ.get("GUARD_DAEMON_IDLE_TIMEOUT_SECONDS")
    if isinstance(configured_timeout, str) and configured_timeout.strip():
        try:
            parsed_timeout = float(configured_timeout.strip())
        except ValueError:
            parsed_timeout = None
        if isinstance(parsed_timeout, float) and parsed_timeout > 0:
            return parsed_timeout
        if parsed_timeout == 0:
            return None
    if _server._guard_home_is_ephemeral(guard_home):
        return _server._EPHEMERAL_GUARD_DAEMON_IDLE_TIMEOUT_SECONDS
    return None


def _guard_home_is_ephemeral(guard_home: _server.Path) -> bool:
    resolved_parts = guard_home.resolve().parts
    return any(part.startswith("pytest-") or "pytest-of-" in part for part in resolved_parts)


def _int_query_value(query: str, key: str) -> int:
    values = _server.parse_qs(query).get(key, ["0"])
    raw_value = values[-1]
    try:
        return int(str(raw_value))
    except ValueError:
        return 0
