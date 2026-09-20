"""Metrics.

Shared state and replaceable dependencies belong to the runner facade.
"""

from __future__ import annotations

from . import runner


def _pain_signal_item(
    event: dict[str, object],
    *,
    warn_occurrences: dict[tuple[str, str], int] | None = None,
) -> dict[str, object] | None:
    event_name = runner._optional_string(event.get("event_name"))
    payload = event.get("payload")
    occurred_at = runner._optional_string(event.get("occurred_at"))
    if event_name is None or not isinstance(payload, dict) or occurred_at is None:
        return None
    artifact_id, artifact_name = runner._pain_signal_artifact_identity(event_name, payload)
    if artifact_id is None or artifact_name is None:
        return None
    if not runner._should_emit_pain_signal(
        event_name=event_name,
        payload=payload,
        warn_occurrences=warn_occurrences,
    ):
        return None
    harness = (
        runner._optional_string(payload.get("harness")) or runner._optional_string(payload.get("executor")) or "unknown"
    )
    artifact_type = runner._artifact_type_for_signal(payload, artifact_id)
    latest_summary = runner._pain_signal_summary(event_name, payload)
    return {
        "signalId": f"{event_name}:{harness}:{artifact_id}",
        "signalName": event_name,
        "artifactId": artifact_id,
        "artifactName": artifact_name,
        "artifactType": artifact_type,
        "harness": harness,
        "latestSummary": latest_summary,
        "occurredAt": occurred_at,
        "source": "scanner",
        "publisher": runner._optional_string(payload.get("publisher")),
    }


def _artifact_type_for_signal(payload: dict[str, object], artifact_id: str) -> str:
    artifact_type = runner._optional_string(payload.get("artifact_type"))
    if artifact_type in {"plugin", "skill"}:
        return artifact_type
    if artifact_id.startswith("skill:"):
        return "skill"
    return "plugin"


def _pain_signal_summary(event_name: str, payload: dict[str, object]) -> str:
    reason = runner._optional_string(payload.get("reason"))
    if reason is not None:
        return reason
    changed_fields = payload.get("changed_fields")
    if event_name == "changed_artifact_caught" and isinstance(changed_fields, list):
        changed_labels = [str(item) for item in changed_fields if isinstance(item, str)]
        if changed_labels:
            return f"Artifact changed across: {', '.join(changed_labels)}."
    risk_signals = payload.get("risk_signals")
    if isinstance(risk_signals, list):
        labels = [str(item) for item in risk_signals if isinstance(item, str)]
        if labels:
            return f"Guard flagged install-time risk: {', '.join(labels)}."
    expires_at = runner._optional_string(payload.get("expires_at"))
    if event_name == "exception_expiring" and expires_at is not None:
        return f"Guard exception expires at {expires_at}."
    return f"Guard recorded {event_name.replace('_', ' ')} for this artifact."


def _build_value_metrics(store: runner.GuardStore) -> dict[str, dict[str, object]]:
    events = store.list_events(limit=5000)
    installs_stopped = 0
    scripts_prevented = 0
    tokens_protected = 0
    for event in events:
        event_name = runner._optional_string(event.get("event_name")) or ""
        payload = event.get("payload")
        if not isinstance(payload, dict):
            continue
        if event_name in runner._INSTALL_TIME_STOP_EVENTS:
            installs_stopped += 1
            install_kind = (runner._optional_string(payload.get("install_kind")) or "").lower()
            risk_signals = payload.get("risk_signals")
            script_signal = isinstance(risk_signals, list) and any(
                "script" in str(signal).lower() for signal in risk_signals
            )
            if "script" in install_kind or script_signal:
                scripts_prevented += 1
        if event_name == "changed_artifact_caught":
            changed_fields = payload.get("changed_fields")
            risk_signals = payload.get("risk_signals")
            touched_launch_surface = isinstance(changed_fields, list) and any(
                str(item) in {"command", "args"} for item in changed_fields
            )
            secret_signal = isinstance(risk_signals, list) and any(
                any(token in str(signal).lower() for token in ("token", "secret", ".env", "credential"))
                for signal in risk_signals
            )
            if touched_launch_surface and secret_signal:
                tokens_protected += 1
    return {
        "installs_stopped_before_execution": {
            "value": installs_stopped,
            "source": "guard_events:install_time_block|review|require-reapproval|sandbox-required",
        },
        "scripts_prevented": {
            "value": scripts_prevented,
            "source": "guard_events:risk_signals|install_kind",
        },
        "tokens_protected": {
            "value": tokens_protected,
            "source": "guard_events:changed_artifact_caught",
        },
    }


def _build_weekly_firewall_digest(*, metrics: dict[str, dict[str, object]], now: str) -> dict[str, object]:
    installs_stopped = runner._metric_count(metrics, "installs_stopped_before_execution")
    scripts_prevented = runner._metric_count(metrics, "scripts_prevented")
    tokens_protected = runner._metric_count(metrics, "tokens_protected")
    headline = (
        "Package firewall summary: "
        f"{installs_stopped} installs stopped before execution, "
        f"{scripts_prevented} scripts prevented, "
        f"{tokens_protected} token-protection incidents."
    )
    return {
        "subject": "HOL Guard weekly package firewall summary",
        "generated_at": now,
        "period_days": 7,
        "headline": headline,
        "body_preview": (
            "HOL Guard weekly digest\n"
            f"{headline}\n"
            "Review the approval queue and sync health to keep package protection current."
        ),
    }


def _pain_signal_artifact_identity(event_name: str, payload: dict[str, object]) -> tuple[str | None, str | None]:
    artifact_id = runner._optional_string(payload.get("artifact_id"))
    artifact_name = runner._optional_string(payload.get("artifact_name"))
    if artifact_id is not None and artifact_name is not None:
        return (artifact_id, artifact_name)
    if event_name == "supply_chain_bundle_refresh_requested":
        fallback_id = artifact_id or "guard:supply-chain:feed"
        return (fallback_id, artifact_name or fallback_id)
    if event_name == "approval_gate/remote_policy_sync_blocked":
        return ("guard:policy:disable", "remote policy sync disabled")
    return (None, None)


def _warning_occurrence_key(payload: dict[str, object]) -> tuple[str, str] | None:
    artifact_id = runner._optional_string(payload.get("artifact_id"))
    harness = runner._optional_string(payload.get("harness")) or runner._optional_string(payload.get("executor"))
    if artifact_id is None or harness is None:
        return None
    return (harness, artifact_id)


def _should_emit_pain_signal(
    *,
    event_name: str,
    payload: dict[str, object],
    warn_occurrences: dict[tuple[str, str], int] | None,
) -> bool:
    if event_name in runner._INSTALL_TIME_STOP_EVENTS:
        return True
    if event_name == "install_time_warn":
        warn_key = runner._warning_occurrence_key(payload)
        if warn_key is None:
            return False
        if warn_occurrences is None:
            return False
        return warn_occurrences.get(warn_key, 0) >= 2
    if event_name == "changed_artifact_caught":
        policy_action = runner._optional_string(payload.get("policy_action"))
        return policy_action in {"review", "require-reapproval", "sandbox-required", "block"}
    if event_name == "supply_chain_bundle_refresh_requested":
        reason = runner._optional_string(payload.get("reason"))
        return reason == "feed_stale"
    return event_name == "approval_gate/remote_policy_sync_blocked"


def _record_synced_alert_events(
    *,
    store: runner.GuardStore,
    advisories: runner.Sequence[dict[str, object]],
    alert_preferences: dict[str, object] | None,
    exceptions: runner.Sequence[dict[str, object]],
    now: str,
) -> None:
    advisories_enabled = not (
        isinstance(alert_preferences, dict) and alert_preferences.get("advisoriesEnabled") is False
    )
    if advisories_enabled:
        for item in advisories:
            artifact_id = runner._optional_string(item.get("artifactId"))
            if artifact_id is None:
                continue
            store.add_event(
                "premium_advisory",
                {
                    "artifact_id": artifact_id,
                    "artifact_name": runner._optional_string(item.get("artifactName")) or artifact_id,
                    "severity": runner._optional_string(item.get("severity")),
                    "reason": runner._optional_string(item.get("reason")),
                },
                now,
            )
    current_time = runner._parse_iso_timestamp(now)
    for item in exceptions:
        artifact_id = runner._optional_string(item.get("artifactId"))
        expires_at = runner._optional_string(item.get("expiresAt"))
        if artifact_id is None or expires_at is None:
            continue
        expiry_time = runner._parse_iso_timestamp(expires_at)
        if expiry_time is None or current_time is None:
            continue
        if (
            expiry_time <= current_time
            or (expiry_time - current_time).total_seconds() > runner._EXCEPTION_EXPIRY_ALERT_WINDOW_HOURS * 60 * 60
        ):
            continue
        store.add_event(
            "exception_expiring",
            {
                "artifact_id": artifact_id,
                "artifact_name": runner._optional_string(item.get("artifactName")) or artifact_id,
                "expires_at": expires_at,
                "reason": runner._optional_string(item.get("reason")),
                "owner": runner._optional_string(item.get("owner")),
            },
            now,
        )
