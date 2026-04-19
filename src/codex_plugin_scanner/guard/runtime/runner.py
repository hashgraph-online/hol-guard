"""Guard wrapper-mode runtime execution."""

from __future__ import annotations

import hashlib
import json
import os
import re
import socket
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ...version import __version__
from ..adapters import get_adapter
from ..adapters.base import HarnessContext
from ..config import GuardConfig
from ..consumer import detect_harness, evaluate_detection
from ..models import GuardArtifact, HarnessDetection, PolicyDecision
from ..store import GuardStore

_APPROVAL_METADATA_KEYS = (
    "approval_center_url",
    "approval_delivery",
    "approval_requests",
    "approval_wait",
    "review_hint",
)
_PAIN_SIGNAL_EVENTS = frozenset(
    {
        "changed_artifact_caught",
        "exception_expiring",
        "install_time_block",
        "premium_advisory",
    }
)
_EXCEPTION_EXPIRY_ALERT_WINDOW_HOURS = 7 * 24
_ENV_PROMPT_PATTERN = re.compile(r"(?<![\w-])\.env(?:\.[\w.-]+)?\b")
_GUARD_SYNC_USER_AGENT = f"hol-guard/{__version__}"


class GuardSyncNotConfiguredError(RuntimeError):
    """Raised when Guard Cloud sync is requested before the machine is paired."""


def guard_run(
    harness: str,
    context: HarnessContext,
    store: GuardStore,
    config: GuardConfig,
    dry_run: bool,
    passthrough_args: list[str],
    default_action: str | None = None,
    interactive_resolver: Callable[[HarnessDetection, dict[str, Any]], dict[str, Any]] | None = None,
    blocked_resolver: Callable[[HarnessDetection, dict[str, Any]], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Evaluate local harness state and optionally launch the harness."""

    detection = _detection_with_prompt_artifacts(detect_harness(harness, context), context, passthrough_args)
    if blocked_resolver is None:
        evaluation = evaluate_detection(detection, store, config, default_action=default_action, persist=True)
    else:
        evaluation = evaluate_detection(detection, store, config, default_action=default_action, persist=False)
        if not evaluation["blocked"]:
            evaluation = evaluate_detection(detection, store, config, default_action=default_action, persist=True)

    if not dry_run and interactive_resolver is not None and evaluation["blocked"]:
        evaluation = interactive_resolver(detection, evaluation)
    elif not dry_run and blocked_resolver is not None and evaluation["blocked"]:
        pending_evaluation = blocked_resolver(detection, evaluation)
        detection = _detection_with_prompt_artifacts(detect_harness(harness, context), context, passthrough_args)
        reevaluated = evaluate_detection(detection, store, config, default_action=default_action, persist=True)
        for key in _APPROVAL_METADATA_KEYS:
            if key in pending_evaluation:
                reevaluated[key] = pending_evaluation[key]
        evaluation = reevaluated
    if evaluation["blocked"] or dry_run:
        evaluation["launched"] = False
        evaluation["launch_command"] = []
        return evaluation

    adapter = get_adapter(harness)
    command = adapter.launch_command(context, passthrough_args)
    evaluation["launch_command"] = command
    environment = os.environ.copy()
    environment["HOME"] = str(context.home_dir)
    if os.name == "nt":
        environment["USERPROFILE"] = str(context.home_dir)
    environment.update(adapter.launch_environment(context))
    try:
        result = subprocess.run(command, cwd=context.workspace_dir or Path.cwd(), check=False, env=environment)
    except FileNotFoundError as error:
        evaluation["launched"] = False
        evaluation["return_code"] = 127
        evaluation["launch_error"] = str(error)
        return evaluation
    evaluation["launched"] = True
    evaluation["return_code"] = result.returncode
    return evaluation


def _detection_with_prompt_artifacts(
    detection: HarnessDetection,
    context: HarnessContext,
    passthrough_args: list[str],
) -> HarnessDetection:
    prompt_artifact = _prompt_env_artifact(detection, context, passthrough_args)
    if prompt_artifact is None:
        return detection
    return HarnessDetection(
        harness=detection.harness,
        installed=detection.installed,
        command_available=detection.command_available,
        config_paths=detection.config_paths,
        artifacts=(*detection.artifacts, prompt_artifact),
        warnings=detection.warnings,
    )


def _prompt_env_artifact(
    detection: HarnessDetection,
    context: HarnessContext,
    passthrough_args: list[str],
) -> GuardArtifact | None:
    prompt_text = " ".join(value.strip() for value in passthrough_args if value.strip())
    normalized_prompt = " ".join(prompt_text.split()).lower()
    if not normalized_prompt or not _requests_direct_env_read(normalized_prompt):
        return None
    prompt_hash = hashlib.sha256(normalized_prompt.encode("utf-8")).hexdigest()
    prompt_summary = "Prompt asks the harness to read a local .env file directly."
    return GuardArtifact(
        artifact_id=f"{detection.harness}:session:prompt-env-read:{prompt_hash}",
        name="direct .env prompt access",
        harness=detection.harness,
        artifact_type="prompt_request",
        source_scope="session",
        config_path=str(_prompt_policy_path(detection, context)),
        metadata={
            "prompt_signals": ["asks the harness to read a local .env file directly"],
            "prompt_summary": prompt_summary,
        },
    )


def _requests_direct_env_read(prompt_text: str) -> bool:
    return _ENV_PROMPT_PATTERN.search(prompt_text) is not None


def _prompt_policy_path(detection: HarnessDetection, context: HarnessContext) -> Path:
    config_candidates = _prompt_config_candidates(detection, context)
    if context.workspace_dir is not None:
        for config_path in config_candidates:
            candidate = Path(config_path)
            if candidate.is_relative_to(context.workspace_dir):
                return candidate
    if config_candidates:
        return Path(config_candidates[0])
    if detection.harness == "opencode":
        if context.workspace_dir is not None:
            return context.workspace_dir / "opencode.json"
        return context.home_dir / ".config" / "opencode" / "opencode.json"
    if context.workspace_dir is not None:
        return context.workspace_dir / ".codex" / "config.toml"
    return context.home_dir / ".codex" / "config.toml"


def _prompt_config_candidates(detection: HarnessDetection, context: HarnessContext) -> tuple[str, ...]:
    if detection.harness == "opencode":
        configured_path = os.getenv("OPENCODE_CONFIG")
        configured_candidate = None
        if configured_path:
            candidate = Path(configured_path).expanduser()
            if not candidate.is_absolute():
                if context.workspace_dir is not None:
                    candidate = context.workspace_dir / candidate
                else:
                    candidate = Path.cwd() / candidate
            configured_candidate = str(candidate)
        return tuple(
            config_path
            for config_path in detection.config_paths
            if Path(config_path).name in {"opencode.json", "opencode.jsonc"} or config_path == configured_candidate
        )
    return detection.config_paths


def sync_receipts(store: GuardStore) -> dict[str, object]:
    """Push local receipts to the configured sync endpoint."""

    credentials = store.get_sync_credentials()
    if credentials is None:
        raise GuardSyncNotConfiguredError("Guard is not logged in.")
    sync_url = _normalized_receipts_sync_url(str(credentials["sync_url"]))
    receipts = store.list_receipts(limit=200)
    inventory = store.list_inventory()
    body = json.dumps({"receipts": _cloud_sync_receipts_payload(receipts)}).encode("utf-8")
    request = urllib.request.Request(
        sync_url,
        data=body,
        method="POST",
        headers=_guard_sync_headers(str(credentials["token"])),
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        raise RuntimeError(_sync_http_error_message(error)) from error
    except urllib.error.URLError as error:
        raise RuntimeError(_sync_url_error_message(error)) from error
    now = _sync_timestamp(payload)
    advisories = payload.get("advisories")
    advisories_stored = 0
    if isinstance(advisories, list):
        advisory_items = [item for item in advisories if isinstance(item, dict)]
        advisories_stored = store.cache_advisories(advisory_items, now)
    policy = payload.get("policy")
    if isinstance(policy, dict):
        store.set_sync_payload("policy", policy, now)
    else:
        store.set_sync_payload("policy", {}, now)
    alert_preferences = payload.get("alertPreferences")
    if isinstance(alert_preferences, dict):
        store.set_sync_payload("alert_preferences", alert_preferences, now)
    else:
        store.set_sync_payload("alert_preferences", {}, now)
    team_policy_pack = payload.get("teamPolicyPack")
    if isinstance(team_policy_pack, dict):
        store.set_sync_payload("team_policy_pack", team_policy_pack, now)
    else:
        store.set_sync_payload("team_policy_pack", {}, now)
    exceptions = payload.get("exceptions")
    remote_decisions = _build_remote_policy_decisions(payload)
    store.replace_remote_policies(remote_decisions, now)
    _record_synced_alert_events(
        store=store,
        advisories=advisories if isinstance(advisories, list) else [],
        alert_preferences=alert_preferences if isinstance(alert_preferences, dict) else None,
        exceptions=exceptions if isinstance(exceptions, list) else [],
        now=now,
    )
    pain_signals_uploaded = sync_pain_signals(store)
    summary = {
        "synced_at": payload.get("syncedAt"),
        "receipts_stored": payload.get("receiptsStored"),
        "advisories_stored": advisories_stored,
        "exceptions_stored": len(exceptions) if isinstance(exceptions, list) else 0,
        "remote_policies_stored": len(remote_decisions),
        "pain_signals_uploaded": pain_signals_uploaded,
        "receipts": len(receipts),
        "inventory": 0,
        "inventory_tracked": len(inventory),
    }
    store.set_sync_payload("sync_summary", summary, now)
    return summary


def sync_runtime_session(
    store: GuardStore,
    *,
    session: dict[str, object],
) -> dict[str, object]:
    """Publish the active Guard runtime session so the dashboard can show the machine immediately."""

    credentials = store.get_sync_credentials()
    if credentials is None:
        raise GuardSyncNotConfiguredError("Guard is not logged in.")
    sync_url = _normalized_runtime_sessions_sync_url(str(credentials["sync_url"]))
    session_payload = _cloud_runtime_session_payload(session)
    body = json.dumps({"session": session_payload}).encode("utf-8")
    request = urllib.request.Request(
        sync_url,
        data=body,
        method="POST",
        headers=_guard_sync_headers(str(credentials["token"])),
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        if error.code == 404:
            recorded_at = _now()
            summary = {
                "synced_at": None,
                "runtime_session_synced_at": None,
                "runtime_session_id": session_payload["sessionId"],
                "runtime_sessions_visible": 0,
                "runtime_session_sync_skipped": True,
                "runtime_session_sync_reason": "runtime_session_endpoint_unavailable",
            }
            store.set_sync_payload("runtime_session_summary", summary, recorded_at)
            return summary
        raise RuntimeError(_sync_http_error_message(error)) from error
    if not isinstance(payload, dict):
        raise RuntimeError("Invalid sync response")
    synced_at = _sync_timestamp(payload)
    summary = {
        "synced_at": synced_at,
        "runtime_session_synced_at": synced_at,
        "runtime_session_id": session_payload["sessionId"],
        "runtime_sessions_visible": len(payload.get("items", [])) if isinstance(payload.get("items"), list) else 0,
    }
    store.set_sync_payload("runtime_session_summary", summary, synced_at)
    return summary


def sync_pain_signals(store: GuardStore) -> int:
    credentials = store.get_sync_credentials()
    if credentials is None:
        return 0
    normalized_sync_url = _normalized_receipts_sync_url(str(credentials["sync_url"]))
    cursor_payload = store.get_sync_payload("pain_signal_cursor")
    last_event_id = _last_uploaded_event_id(cursor_payload)
    uploaded_count = 0
    current_event_id = last_event_id
    while True:
        candidates = store.list_events_after(
            current_event_id,
            limit=500,
            event_names=tuple(sorted(_PAIN_SIGNAL_EVENTS)),
        )
        if not candidates:
            break
        last_processed_event_id = int(candidates[-1]["event_id"])
        signal_items = [payload for item in candidates if (payload := _pain_signal_item(item)) is not None]
        if signal_items:
            request = urllib.request.Request(
                _pain_signal_sync_url(normalized_sync_url),
                data=json.dumps({"items": signal_items}).encode("utf-8"),
                method="POST",
                headers=_guard_sync_headers(str(credentials["token"])),
            )
            try:
                with urllib.request.urlopen(request, timeout=10):
                    pass
            except urllib.error.HTTPError as error:
                if error.code == 404:
                    current_event_id = last_processed_event_id
                    store.set_sync_payload(
                        "pain_signal_cursor",
                        {"event_id": current_event_id},
                        _now(),
                    )
                    return uploaded_count
                raise RuntimeError(_sync_http_error_message(error)) from error
            except urllib.error.URLError as error:
                raise RuntimeError(_sync_url_error_message(error)) from error
            uploaded_count += len(signal_items)
        current_event_id = last_processed_event_id
        store.set_sync_payload(
            "pain_signal_cursor",
            {"event_id": current_event_id},
            _now(),
        )
        if len(candidates) < 500:
            break
    return uploaded_count


def _build_remote_policy_decisions(payload: dict[str, object]) -> list[PolicyDecision]:
    decisions: list[PolicyDecision] = []
    exceptions = payload.get("exceptions")
    if isinstance(exceptions, list):
        for item in exceptions:
            if not isinstance(item, dict):
                continue
            scope = item.get("scope")
            if scope not in {"artifact", "publisher", "harness", "global", "workspace"}:
                continue
            workspace = _remote_workspace(item)
            if scope == "workspace" and workspace is None:
                continue
            harness = _remote_harness(item.get("harness"), allow_wildcard=scope != "harness")
            if harness is None:
                continue
            decisions.append(
                PolicyDecision(
                    harness=harness,
                    scope=scope,
                    action="allow",
                    artifact_id=_optional_string(item.get("artifactId")),
                    workspace=workspace,
                    publisher=_optional_string(item.get("publisher")),
                    reason=_optional_string(item.get("reason")),
                    owner=_optional_string(item.get("owner")),
                    source="cloud-sync",
                    expires_at=_normalized_timestamp_string(item.get("expiresAt")),
                )
            )
    team_policy_pack = payload.get("teamPolicyPack")
    if isinstance(team_policy_pack, dict):
        policy_name = _optional_string(team_policy_pack.get("name")) or "team policy"
        blocked_artifacts = team_policy_pack.get("blockedArtifacts")
        if isinstance(blocked_artifacts, list):
            for artifact_id in blocked_artifacts:
                if not isinstance(artifact_id, str) or not artifact_id.strip():
                    continue
                decisions.append(
                    PolicyDecision(
                        harness="*",
                        scope="artifact",
                        action="block",
                        artifact_id=artifact_id,
                        reason=f"Blocked by {policy_name}.",
                        source="team-policy",
                    )
                )
        allowed_publishers = team_policy_pack.get("allowedPublishers")
        if isinstance(allowed_publishers, list):
            for publisher in allowed_publishers:
                if not isinstance(publisher, str) or not publisher.strip():
                    continue
                decisions.append(
                    PolicyDecision(
                        harness="*",
                        scope="publisher",
                        action="allow",
                        publisher=publisher,
                        reason=f"Allowed by {policy_name}.",
                        source="team-policy",
                    )
                )
    return decisions


def _guard_sync_headers(token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": _GUARD_SYNC_USER_AGENT,
    }


def _sync_http_error_message(error: urllib.error.HTTPError) -> str:
    try:
        raw_body = error.read().decode("utf-8")
    except OSError:
        raw_body = ""
    try:
        payload = json.loads(raw_body) if raw_body else None
    except json.JSONDecodeError:
        payload = None
    if isinstance(payload, dict):
        message = payload.get("error")
        if isinstance(message, str) and message.strip():
            return message.strip()
    normalized_body = raw_body.strip()
    if normalized_body:
        return normalized_body
    return f"HTTP Error {error.code}: {error.reason}"


def _sync_url_error_message(error: urllib.error.URLError) -> str:
    reason = getattr(error, "reason", None)
    if reason is not None:
        reason_text = str(reason).strip()
        if reason_text:
            return f"Guard sync failed: {reason_text}"
    return "Guard sync failed because the remote endpoint could not be reached."


def _remote_harness(value: object, *, allow_wildcard: bool = True) -> str | None:
    if isinstance(value, str) and value.strip():
        return value
    return "*" if allow_wildcard else None


def _remote_workspace(item: dict[str, object]) -> str | None:
    return _optional_string(item.get("workspace")) or _optional_string(item.get("workspacePath"))


def _optional_string(value: object) -> str | None:
    if isinstance(value, str) and value.strip():
        return value
    return None


def _normalized_timestamp_string(value: object) -> str | None:
    raw_value = _optional_string(value)
    if raw_value is None:
        return None
    parsed = _parse_iso_timestamp(raw_value)
    if parsed is None:
        return None
    return parsed.isoformat()


def _last_uploaded_event_id(payload: dict[str, object] | list[object] | None) -> int:
    if not isinstance(payload, dict):
        return 0
    event_id = payload.get("event_id")
    return event_id if isinstance(event_id, int) and event_id > 0 else 0


def _pain_signal_item(event: dict[str, object]) -> dict[str, object] | None:
    event_name = _optional_string(event.get("event_name"))
    payload = event.get("payload")
    occurred_at = _optional_string(event.get("occurred_at"))
    if event_name is None or not isinstance(payload, dict) or occurred_at is None:
        return None
    artifact_id = _optional_string(payload.get("artifact_id"))
    artifact_name = _optional_string(payload.get("artifact_name"))
    if artifact_id is None or artifact_name is None:
        return None
    harness = _optional_string(payload.get("harness")) or _optional_string(payload.get("executor")) or "unknown"
    artifact_type = _artifact_type_for_signal(payload, artifact_id)
    latest_summary = _pain_signal_summary(event_name, payload)
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
        "publisher": _optional_string(payload.get("publisher")),
    }


def _artifact_type_for_signal(payload: dict[str, object], artifact_id: str) -> str:
    artifact_type = _optional_string(payload.get("artifact_type"))
    if artifact_type in {"plugin", "skill"}:
        return artifact_type
    if artifact_id.startswith("skill:"):
        return "skill"
    return "plugin"


def _pain_signal_summary(event_name: str, payload: dict[str, object]) -> str:
    reason = _optional_string(payload.get("reason"))
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
    expires_at = _optional_string(payload.get("expires_at"))
    if event_name == "exception_expiring" and expires_at is not None:
        return f"Guard exception expires at {expires_at}."
    return f"Guard recorded {event_name.replace('_', ' ')} for this artifact."


def _pain_signal_sync_url(sync_url: str) -> str:
    parsed = urllib.parse.urlsplit(sync_url)
    path = parsed.path.rstrip("/")
    segments = [segment for segment in path.split("/") if segment]
    if len(segments) >= 2 and segments[-2:] in (["receipts", "sync"], ["inventory", "sync"]):
        next_segments = [*segments[:-2], "signals", "pain"]
    elif segments and segments[-1] in {"receipts", "inventory"}:
        next_segments = [*segments[:-1], "signals", "pain"]
    else:
        next_segments = [*segments, "signals", "pain"]
    return urllib.parse.urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            "/" + "/".join(next_segments),
            parsed.query,
            parsed.fragment,
        )
    )


def _normalized_receipts_sync_url(sync_url: str) -> str:
    parsed = urllib.parse.urlsplit(sync_url)
    if parsed.path.rstrip("/") == "/registry/api/v1":
        return urllib.parse.urlunsplit(
            (
                parsed.scheme,
                parsed.netloc,
                "/api/guard/receipts/sync",
                parsed.query,
                "",
            )
        )
    return sync_url


def _normalized_runtime_sessions_sync_url(sync_url: str) -> str:
    normalized_receipts_url = _normalized_receipts_sync_url(sync_url)
    parsed = urllib.parse.urlsplit(normalized_receipts_url)
    if parsed.path.rstrip("/") == "/api/guard/receipts/sync":
        return urllib.parse.urlunsplit(
            (
                parsed.scheme,
                parsed.netloc,
                "/api/guard/runtime/sessions/sync",
                parsed.query,
                "",
            )
        )
    if parsed.path.rstrip("/") == "/guard/receipts/sync":
        return urllib.parse.urlunsplit(
            (
                parsed.scheme,
                parsed.netloc,
                "/guard/runtime/sessions/sync",
                parsed.query,
                "",
            )
        )
    return urllib.parse.urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path.rstrip("/") + "/runtime/sessions/sync",
            parsed.query,
            "",
        )
    )


def _cloud_sync_receipts_payload(receipts: list[dict[str, object]]) -> list[dict[str, object]]:
    device_id, device_name = _guard_device_metadata()
    return [_cloud_sync_receipt_payload(receipt, device_id=device_id, device_name=device_name) for receipt in receipts]


def _cloud_sync_receipt_payload(
    receipt: dict[str, object],
    *,
    device_id: str,
    device_name: str,
) -> dict[str, object]:
    receipt_fingerprint = _cloud_sync_receipt_fingerprint(receipt)
    artifact_id = _optional_string(receipt.get("artifact_id")) or f"guard:local-receipt:{receipt_fingerprint[:24]}"
    artifact_name = _optional_string(receipt.get("artifact_name")) or artifact_id
    policy_decision = _optional_string(receipt.get("policy_decision")) or "review"
    changed_capabilities = [str(item) for item in receipt.get("changed_capabilities", []) if isinstance(item, str)]
    capabilities_summary = _optional_string(receipt.get("capabilities_summary"))
    if changed_capabilities:
        capabilities = changed_capabilities
    elif capabilities_summary is not None:
        capabilities = [capabilities_summary]
    else:
        capabilities = []
    payload: dict[str, object] = {
        "receiptId": _optional_string(receipt.get("receipt_id")) or f"guard-receipt-{receipt_fingerprint}",
        "artifactId": artifact_id,
        "artifactName": artifact_name,
        "artifactType": _cloud_sync_artifact_type(artifact_id),
        "artifactSlug": _cloud_sync_artifact_slug(artifact_name, artifact_id),
        "artifactHash": _optional_string(receipt.get("artifact_hash"))
        or hashlib.sha256(artifact_id.encode("utf-8")).hexdigest(),
        "capabilities": capabilities,
        "capturedAt": _optional_string(receipt.get("timestamp")) or _now(),
        "changedSinceLastApproval": bool(changed_capabilities)
        or policy_decision in {"require-reapproval", "sandbox-required"},
        "deviceId": device_id,
        "deviceName": device_name,
        "harness": _optional_string(receipt.get("harness")) or "unknown",
        "policyDecision": policy_decision,
        "recommendation": _cloud_sync_recommendation(policy_decision),
        "summary": _optional_string(receipt.get("provenance_summary"))
        or capabilities_summary
        or f"Guard recorded a {policy_decision} decision.",
    }
    publisher = _optional_string(receipt.get("publisher"))
    if publisher is not None:
        payload["publisher"] = publisher
    return payload


def _cloud_runtime_session_payload(session: dict[str, object]) -> dict[str, object]:
    device_id, device_name = _guard_device_metadata()
    workspace = _optional_string(session.get("workspace")) or os.getcwd()
    session_id = (
        _optional_string(session.get("session_id") or session.get("sessionId"))
        or hashlib.sha256(f"{device_id}:{workspace}".encode()).hexdigest()[:24]
    )
    created_at = _optional_string(session.get("created_at") or session.get("createdAt")) or _now()
    updated_at = _optional_string(session.get("updated_at") or session.get("updatedAt")) or created_at
    capabilities = [str(item) for item in session.get("capabilities", []) if isinstance(item, str)]
    return {
        "sessionId": session_id,
        "harness": _optional_string(session.get("harness")) or "hol-guard",
        "surface": _optional_string(session.get("surface")) or "cli",
        "status": _optional_string(session.get("status")) or "active",
        "clientName": _optional_string(session.get("client_name") or session.get("clientName")) or "hol-guard",
        "clientTitle": _optional_string(session.get("client_title") or session.get("clientTitle"))
        or f"HOL Guard on {device_name}",
        "clientVersion": _optional_string(session.get("client_version") or session.get("clientVersion")) or __version__,
        "workspace": workspace,
        "capabilities": capabilities,
        "operations": [],
        "createdAt": created_at,
        "updatedAt": updated_at,
    }


def _cloud_sync_receipt_fingerprint(receipt: dict[str, object]) -> str:
    encoded_receipt = json.dumps(receipt, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded_receipt.encode("utf-8")).hexdigest()


def _cloud_sync_artifact_type(artifact_id: str) -> str:
    if artifact_id.startswith("skill:") or ":skill:" in artifact_id:
        return "skill"
    return "plugin"


def _cloud_sync_artifact_slug(artifact_name: str, artifact_id: str) -> str:
    base_value = artifact_name.strip() or artifact_id.strip() or "artifact"
    slug = re.sub(r"[^a-z0-9]+", "-", base_value.lower()).strip("-")
    if slug:
        return slug
    fallback = re.sub(r"[^a-z0-9]+", "-", artifact_id.lower()).strip("-")
    return fallback or "artifact"


def _cloud_sync_recommendation(policy_decision: str) -> str:
    if policy_decision == "block":
        return "block"
    if policy_decision in {"review", "require-reapproval", "sandbox-required"}:
        return "review"
    return "monitor"


def _guard_device_metadata() -> tuple[str, str]:
    device_name = socket.gethostname().strip() or "Local machine"
    device_id = hashlib.sha256(device_name.encode("utf-8")).hexdigest()[:24]
    return device_id, device_name


def _record_synced_alert_events(
    *,
    store: GuardStore,
    advisories: list[object],
    alert_preferences: dict[str, object] | None,
    exceptions: list[object],
    now: str,
) -> None:
    advisories_enabled = not (
        isinstance(alert_preferences, dict) and alert_preferences.get("advisoriesEnabled") is False
    )
    if advisories_enabled:
        for item in advisories:
            if not isinstance(item, dict):
                continue
            artifact_id = _optional_string(item.get("artifactId"))
            if artifact_id is None:
                continue
            store.add_event(
                "premium_advisory",
                {
                    "artifact_id": artifact_id,
                    "artifact_name": _optional_string(item.get("artifactName")) or artifact_id,
                    "severity": _optional_string(item.get("severity")),
                    "reason": _optional_string(item.get("reason")),
                },
                now,
            )
    current_time = _parse_iso_timestamp(now)
    for item in exceptions:
        if not isinstance(item, dict):
            continue
        artifact_id = _optional_string(item.get("artifactId"))
        expires_at = _optional_string(item.get("expiresAt"))
        if artifact_id is None or expires_at is None:
            continue
        expiry_time = _parse_iso_timestamp(expires_at)
        if expiry_time is None or current_time is None:
            continue
        if (
            expiry_time <= current_time
            or (expiry_time - current_time).total_seconds() > _EXCEPTION_EXPIRY_ALERT_WINDOW_HOURS * 60 * 60
        ):
            continue
        store.add_event(
            "exception_expiring",
            {
                "artifact_id": artifact_id,
                "artifact_name": _optional_string(item.get("artifactName")) or artifact_id,
                "expires_at": expires_at,
                "reason": _optional_string(item.get("reason")),
                "owner": _optional_string(item.get("owner")),
            },
            now,
        )


def _sync_timestamp(payload: dict[str, object]) -> str:
    synced_at = _optional_string(payload.get("syncedAt"))
    if synced_at is not None and _parse_iso_timestamp(synced_at) is not None:
        return synced_at
    return _now()


def _parse_iso_timestamp(value: str) -> datetime | None:
    normalized = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
