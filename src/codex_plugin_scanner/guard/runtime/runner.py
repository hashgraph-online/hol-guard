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
from ..types import PromptRequest, RemediationAction

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
_SECRET_REQUEST_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(?<![\w-])\.env(?:\.[\w.-]+)?\b"), "local .env file"),
    (re.compile(r"(?:^|[\s'\"`])~?/.ssh(?:/|\b)"), "SSH material"),
    (re.compile(r"(?:^|[\s'\"`])~?/.aws/(?:credentials|config)\b"), "AWS credentials"),
    (re.compile(r"(?:^|[\s'\"`])~?/.kube/config\b"), "kubeconfig"),
    (re.compile(r"(?:^|[\s'\"`])~?/.docker/config\.json\b"), "Docker credentials"),
    (re.compile(r"(?<![\w-])\.npmrc\b"), "npm registry credentials"),
    (re.compile(r"(?<![\w-])\.pypirc\b"), "Python package credentials"),
    (re.compile(r"(?<![\w-])\.git-credentials\b"), "Git credential store"),
)
_SECRET_ABSOLUTE_HINTS: tuple[tuple[str, str], ...] = (
    ("/.ssh/", "SSH material"),
    ("/.aws/credentials", "AWS credentials"),
    ("/.aws/config", "AWS credentials"),
    ("/.kube/config", "kubeconfig"),
    ("/.docker/config.json", "Docker credentials"),
)
_SECRET_READ_INTENT_PATTERN = re.compile(
    r"\b("
    r"read|open|print|show|dump|cat|head|tail|less|copy|cp|scp|reveal|display|summari[sz]e|inspect|extract|"
    r"contain(?:s)?|contents?\s+of|what(?:'s| is)\s+in"
    r")\b",
    re.IGNORECASE,
)
_EXFIL_PROMPT_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"\b(?:upload|exfiltrate|transfer|paste|gist|webhook)\b.{0,80}\b"
        r"(?:file|contents?|data|payload|secret|token|key|credential|credentials|config|output)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:send|post|upload|transfer|paste|sync)\b.{0,80}\b"
        r"(?:contents?|data|payload|file|secret|token|key|credential|credentials|config|output)\b"
        r"(?:.{0,40}\b(?:to|into|onto|via|through)\b)?",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:send|post|upload|transfer|paste|sync)\b.{0,80}\b"
        r"(?:to|into|onto|via|through)\b.{0,40}\b"
        r"(?:webhook|gist|pastebin|slack|discord|telegram|server|endpoint|url)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:send|post|upload|transfer|paste|sync)\b.{0,120}"
        r"(?:"
        r"(?<![\w-])\.env(?:\.[\w.-]+)?\b|"
        r"(?:^|[\s'\"`])~?/.ssh(?:/|\b)|"
        r"(?:^|[\s'\"`])~?/.aws/(?:credentials|config)\b|"
        r"(?:^|[\s'\"`])~?/.kube/config\b|"
        r"(?:^|[\s'\"`])~?/.docker/config\.json\b|"
        r"(?<![\w-])\.npmrc\b|"
        r"(?<![\w-])\.pypirc\b|"
        r"(?<![\w-])\.git-credentials\b|"
        r"/.ssh/|"
        r"/.aws/credentials|"
        r"/.aws/config|"
        r"/.kube/config|"
        r"/.docker/config\.json"
        r")"
        r".{0,80}\b(?:to|into|onto|via|through)\b.{0,80}"
        r"(?:[a-z][a-z0-9+.-]*://|webhook|gist|pastebin|slack|discord|telegram|server|endpoint|url)\b",
        re.IGNORECASE,
    ),
)
_DESTRUCTIVE_PROMPT_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"\b(?:run|execute|use|call|invoke)\b.{0,40}\b(?:rm\s+-rf|rm\s+|del\s+|truncate\s+|chmod\s+|chown\s+|mv\s+)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:^|[\s'\"`(])(?:rm\s+-rf|rm\s+\S|del\s+\S|truncate\s+\S|chmod\s+\S|chown\s+\S|mv\s+\S)",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:delete|remove|overwrite|truncate)\b.{0,60}\b(?:file|directory|repo|workspace|contents?)\b",
        re.IGNORECASE,
    ),
)
_SUBPROCESS_PROMPT_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"\b(?:run|execute|use|call|invoke|launch|spawn)\b.{0,60}\b"
        r"(?:bash\s+-c|sh\s+-c|zsh\s+-c|powershell|cmd\s+/c|subprocess|exec\(|spawn\()",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:^|[\s'\"`(])(?:bash\s+-c\b|sh\s+-c\b|zsh\s+-c\b|powershell(?:\.exe)?(?:\s|$)|cmd\s+/c(?:\s|$)|subprocess\.(?:run|Popen|call|check_call|check_output)\b|exec\(|spawn\()",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:use|call|invoke)\b.{0,40}\bsubprocess\b",
        re.IGNORECASE,
    ),
)
_GUARD_BYPASS_PROMPT_PATTERN = re.compile(
    r"\b(hol-guard\s+(?:disable|off|uninstall)|disable\s+hol-guard|approval_policy\s*=\s*\"never\"|guard[_-]?bypass)\b",
    re.IGNORECASE,
)
_PROMPT_SENTENCE_BOUNDARY_PATTERN = re.compile(r"[!?;]|[.](?=\s|$)")
_GUARD_SYNC_USER_AGENT = f"hol-guard/{__version__}"
_SYNC_HTTP_TIMEOUT_SECONDS = 20
_SYNC_HTTP_RETRY_TIMEOUT_SECONDS = 120
_RUNTIME_SYNC_TIMEOUT_SECONDS = 10
_RUNTIME_SYNC_RETRY_TIMEOUT_SECONDS = 90
_PAIN_SIGNAL_TIMEOUT_SECONDS = 10
_PAIN_SIGNAL_RETRY_TIMEOUT_SECONDS = 90


class GuardSyncNotConfiguredError(RuntimeError):
    """Raised when Guard Cloud sync is requested before the machine is paired."""


class GuardSyncNotAvailableError(RuntimeError):
    """Raised when the sync endpoint returns 403 (free-plan restriction)."""


def _prompt_sentence_start(text: str, index: int) -> int:
    matches = list(_PROMPT_SENTENCE_BOUNDARY_PATTERN.finditer(text, 0, index))
    return matches[-1].end() if matches else 0


def _prompt_sentence_end(text: str, index: int) -> int:
    match = _PROMPT_SENTENCE_BOUNDARY_PATTERN.search(text, index)
    return match.end() if match is not None else len(text)


def _prompt_secret_intent_region(text: str, *, start: int, end: int) -> str:
    current_sentence_start = _prompt_sentence_start(text, start)
    region_start = _prompt_sentence_start(text, max(0, current_sentence_start - 1))
    first_sentence_end = _prompt_sentence_end(text, end)
    second_sentence_end = (
        _prompt_sentence_end(text, first_sentence_end) if first_sentence_end < len(text) else first_sentence_end
    )
    return text[region_start:second_sentence_end]


def _prompt_has_secret_read_intent(prompt_text: str, *, start: int, end: int) -> bool:
    return (
        _SECRET_READ_INTENT_PATTERN.search(
            _prompt_secret_intent_region(prompt_text, start=start, end=end),
        )
        is not None
    )


def _first_match(patterns: tuple[re.Pattern[str], ...], text: str) -> re.Match[str] | None:
    for pattern in patterns:
        match = pattern.search(text)
        if match is not None:
            return match
    return None


def _iter_hint_occurrences(text: str, hint: str) -> list[tuple[int, int]]:
    occurrences: list[tuple[int, int]] = []
    current_pos = 0
    while True:
        start = text.find(hint, current_pos)
        if start == -1:
            return occurrences
        end = start + len(hint)
        occurrences.append((start, end))
        current_pos = start + 1


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
    if "config_paths" not in evaluation:
        evaluation["config_paths"] = list(detection.config_paths) or _guard_run_config_paths(
            detection=detection,
            context=context,
            passthrough_args=passthrough_args,
        )
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


def _guard_run_config_paths(
    *,
    detection: HarnessDetection,
    context: HarnessContext,
    passthrough_args: list[str],
) -> list[str]:
    if detection.config_paths:
        return list(detection.config_paths)
    prompt_text = " ".join(value.strip() for value in passthrough_args if value.strip())
    if prompt_text:
        return [str(_prompt_policy_path(detection, context))]
    return []


def _detection_with_prompt_artifacts(
    detection: HarnessDetection,
    context: HarnessContext,
    passthrough_args: list[str],
) -> HarnessDetection:
    prompt_text = " ".join(value.strip() for value in passthrough_args if value.strip())
    prompt_requests = extract_prompt_requests(prompt_text)
    if not prompt_requests:
        return detection
    prompt_artifacts = prompt_requests_to_artifacts(
        detection=detection,
        context=context,
        requests=prompt_requests,
    )
    return HarnessDetection(
        harness=detection.harness,
        installed=detection.installed,
        command_available=detection.command_available,
        config_paths=detection.config_paths,
        artifacts=(*detection.artifacts, *prompt_artifacts),
        warnings=detection.warnings,
    )


def extract_prompt_requests(prompt_text: str) -> list[PromptRequest]:
    """Extract structured prompt intent requests from passthrough arguments."""

    normalized_prompt = " ".join(prompt_text.split())
    lowered = normalized_prompt.lower()
    if not lowered:
        return []
    requests: list[PromptRequest] = []
    seen_secret_labels: set[str] = set()

    def add_secret_request(*, label: str, matched: str) -> None:
        if label in seen_secret_labels:
            return
        seen_secret_labels.add(label)
        summary = (
            "Prompt asks the harness to read a local .env file directly."
            if label == "local .env file"
            else f"Prompt asks for direct access to {label}."
        )
        requests.append(
            PromptRequest(
                request_id=_prompt_request_id("secret_read", matched, lowered),
                request_class="secret_read",
                summary=summary,
                matched_text=matched,
                severity=8,
                confidence=0.9,
                remediation=(
                    RemediationAction(kind="approve_once", label="Approve once", detail="Allow a one-time access."),
                    RemediationAction(
                        kind="rotate_exposed_secret",
                        label="Rotate secret",
                        detail="Rotate credentials if this read is unexpected.",
                    ),
                ),
            )
        )

    for pattern, label in _SECRET_REQUEST_PATTERNS:
        for match in pattern.finditer(normalized_prompt):
            if not _prompt_has_secret_read_intent(normalized_prompt, start=match.start(), end=match.end()):
                continue
            add_secret_request(label=label, matched=match.group(0).strip())
            break
    for hint, label in _SECRET_ABSOLUTE_HINTS:
        for start, end in _iter_hint_occurrences(lowered, hint):
            if _prompt_has_secret_read_intent(normalized_prompt, start=start, end=end):
                add_secret_request(label=label, matched=hint)
                break
    exfil_match = _first_match(_EXFIL_PROMPT_PATTERNS, normalized_prompt)
    if exfil_match is not None:
        matched_text = exfil_match.group(0).strip()
        requests.append(
            PromptRequest(
                request_id=_prompt_request_id("exfil_intent", matched_text, lowered),
                request_class="exfil_intent",
                summary="Prompt includes exfiltration-oriented transfer intent.",
                matched_text=matched_text,
                severity=8,
                confidence=0.84,
                remediation=(
                    RemediationAction(
                        kind="review_network_destination",
                        label="Review destination",
                        detail="Validate destination before data transfer.",
                    ),
                    RemediationAction(kind="defer_and_notify_team", label="Notify team", detail="Escalate for review."),
                ),
            )
        )
    destructive_match = _first_match(_DESTRUCTIVE_PROMPT_PATTERNS, normalized_prompt)
    if destructive_match is not None:
        matched_text = destructive_match.group(0).strip()
        requests.append(
            PromptRequest(
                request_id=_prompt_request_id(
                    "destructive_intent",
                    matched_text,
                    lowered,
                ),
                request_class="destructive_intent",
                summary="Prompt includes destructive filesystem mutation intent.",
                matched_text=matched_text,
                severity=8,
                confidence=0.87,
                remediation=(
                    RemediationAction(
                        kind="approve_once",
                        label="Approve once",
                        detail="Require explicit one-time approval.",
                    ),
                    RemediationAction(
                        kind="open_investigation",
                        label="Open investigation",
                        detail="Track destructive intent.",
                    ),
                ),
            )
        )
    subprocess_match = _first_match(_SUBPROCESS_PROMPT_PATTERNS, normalized_prompt)
    if subprocess_match is not None:
        matched_text = subprocess_match.group(0).strip()
        requests.append(
            PromptRequest(
                request_id=_prompt_request_id(
                    "subprocess_intent",
                    matched_text,
                    lowered,
                ),
                request_class="subprocess_intent",
                summary="Prompt asks for subprocess or shell-wrapper execution.",
                matched_text=matched_text,
                severity=7,
                confidence=0.8,
                remediation=(
                    RemediationAction(
                        kind="approve_once",
                        label="Approve once",
                        detail="Constrain this run to one approval.",
                    ),
                    RemediationAction(
                        kind="run_in_sandbox",
                        label="Run in sandbox",
                        detail="Execute in isolated mode.",
                    ),
                ),
            )
        )
    if _GUARD_BYPASS_PROMPT_PATTERN.search(normalized_prompt):
        requests.append(
            PromptRequest(
                request_id=_prompt_request_id("guard_bypass_intent", "guard-bypass", lowered),
                request_class="guard_bypass_intent",
                summary="Prompt includes Guard bypass or disable intent.",
                matched_text="guard-bypass",
                severity=10,
                confidence=0.93,
                remediation=(
                    RemediationAction(
                        kind="block_and_remove",
                        label="Block",
                        detail="Do not allow bypass behavior.",
                    ),
                    RemediationAction(
                        kind="open_investigation",
                        label="Investigate",
                        detail="Escalate bypass attempt.",
                    ),
                ),
            )
        )
    deduped: dict[str, PromptRequest] = {}
    for request in requests:
        deduped[request.request_id] = request
    return list(deduped.values())


def prompt_requests_to_artifacts(
    *,
    detection: HarnessDetection,
    context: HarnessContext,
    requests: list[PromptRequest],
) -> list[GuardArtifact]:
    """Convert typed prompt requests into pseudo-artifacts for policy evaluation."""

    config_path = str(_prompt_policy_path(detection, context))
    artifacts: list[GuardArtifact] = []
    for request in requests:
        if request.request_class == "secret_read" and ".env" in request.matched_text.lower():
            artifact_id = f"{detection.harness}:session:prompt-env-read:{request.request_id[:24]}"
        else:
            artifact_id = f"{detection.harness}:session:prompt:{request.request_class}:{request.request_id[:24]}"
        artifacts.append(
            GuardArtifact(
                artifact_id=artifact_id,
                name=f"prompt {request.request_class.replace('_', ' ')}",
                harness=detection.harness,
                artifact_type="prompt_request",
                source_scope="session",
                config_path=config_path,
                metadata={
                    "prompt_signals": [request.summary],
                    "prompt_summary": request.summary,
                    "prompt_matched_text": request.matched_text,
                    "prompt_request_class": request.request_class,
                    "prompt_confidence": request.confidence,
                    "prompt_severity": request.severity,
                },
            )
        )
    return artifacts


def should_force_reapproval(prompt_reqs: list[PromptRequest], prior_policy: dict[str, object] | None) -> bool:
    """Return whether current prompt requests exceed prior approved scope."""

    if not prompt_reqs:
        return False
    if prior_policy is None:
        return True
    approved_classes = prior_policy.get("approved_prompt_classes")
    approved = (
        {str(item) for item in approved_classes if isinstance(item, str)}
        if isinstance(approved_classes, list)
        else set()
    )
    return any(request.request_class not in approved or request.severity >= 8 for request in prompt_reqs)


def _prompt_request_id(request_class: str, matched_text: str, normalized_prompt: str) -> str:
    fingerprint = hashlib.sha256(f"{request_class}:{matched_text}:{normalized_prompt}".encode()).hexdigest()
    return fingerprint


def _prompt_policy_path(detection: HarnessDetection, context: HarnessContext) -> Path:
    config_candidates = _prompt_config_candidates(detection, context)
    if context.workspace_dir is not None:
        for config_path in config_candidates:
            candidate = Path(config_path)
            if candidate.is_relative_to(context.workspace_dir):
                return candidate
    if config_candidates:
        return Path(config_candidates[0])
    return get_adapter(detection.harness).policy_path(context)


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
    body = json.dumps({"receipts": _cloud_sync_receipts_payload(store, receipts)}).encode("utf-8")
    request = urllib.request.Request(
        sync_url,
        data=body,
        method="POST",
        headers=_guard_sync_headers(str(credentials["token"])),
    )
    try:
        payload = _urlopen_json_with_timeout_retry(
            request=request,
            timeout_seconds=_SYNC_HTTP_TIMEOUT_SECONDS,
            retry_timeout_seconds=_SYNC_HTTP_RETRY_TIMEOUT_SECONDS,
        )
    except urllib.error.HTTPError as error:
        if error.code == 403:
            _is_plan, _msg = _check_plan_restriction_403(error)
            if _is_plan:
                raise GuardSyncNotAvailableError(_msg) from error
            raise RuntimeError(_msg) from error
        raise RuntimeError(_sync_http_error_message(error)) from error
    except OSError as error:
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
    summary["guard_events_v1"] = sync_guard_events(store)
    store.set_sync_payload("sync_summary", summary, now)
    return summary


def sync_guard_events(store: GuardStore) -> dict[str, object]:
    """Push pending GuardEventV1 envelopes to Guard Cloud."""

    credentials = store.get_sync_credentials()
    if credentials is None:
        raise GuardSyncNotConfiguredError("Guard is not logged in.")
    sync_url = _guard_events_sync_url(str(credentials["sync_url"]))
    total_events = 0
    total_accepted = 0
    synced_at = _now()
    while True:
        pending_events = store.list_guard_events_v1(uploaded=False, limit=200)
        if not pending_events:
            break
        body = json.dumps({"events": [event["payload"] for event in pending_events]}).encode("utf-8")
        request = urllib.request.Request(
            sync_url,
            data=body,
            method="POST",
            headers=_guard_sync_headers(str(credentials["token"])),
        )
        try:
            payload = _urlopen_json_with_timeout_retry(
                request=request,
                timeout_seconds=_SYNC_HTTP_TIMEOUT_SECONDS,
                retry_timeout_seconds=_SYNC_HTTP_RETRY_TIMEOUT_SECONDS,
            )
        except urllib.error.HTTPError as error:
            if error.code == 404:
                summary = {
                    "synced_at": synced_at,
                    "events": total_events,
                    "accepted": total_accepted,
                    "sync_skipped": True,
                    "sync_reason": "guard_events_endpoint_unavailable",
                }
                store.set_sync_payload("guard_events_v1_summary", summary, synced_at)
                return summary
            if error.code == 403:
                is_plan, message = _check_plan_restriction_403(error)
                if is_plan:
                    raise GuardSyncNotAvailableError(message) from error
                raise RuntimeError(message) from error
            raise RuntimeError(_sync_http_error_message(error)) from error
        except OSError as error:
            raise RuntimeError(_sync_url_error_message(error)) from error
        completed_ids = _completed_guard_event_ids(payload)
        synced_at = _sync_timestamp(payload)
        uploaded = store.mark_guard_events_v1_uploaded(completed_ids, synced_at)
        total_events += len(pending_events)
        total_accepted += uploaded
        if uploaded == 0 or len(pending_events) < 200:
            break
    summary = {"synced_at": synced_at, "events": total_events, "accepted": total_accepted}
    store.set_sync_payload("guard_events_v1_summary", summary, synced_at)
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
    session_payload = _cloud_runtime_session_payload(store, session)
    body = json.dumps({"session": session_payload}).encode("utf-8")
    request = urllib.request.Request(
        sync_url,
        data=body,
        method="POST",
        headers=_guard_sync_headers(str(credentials["token"])),
    )
    try:
        payload = _urlopen_json_with_timeout_retry(
            request=request,
            timeout_seconds=_RUNTIME_SYNC_TIMEOUT_SECONDS,
            retry_timeout_seconds=_RUNTIME_SYNC_RETRY_TIMEOUT_SECONDS,
        )
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
    except OSError as error:
        raise RuntimeError(_sync_url_error_message(error)) from error
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
                _urlopen_with_timeout_retry(
                    request=request,
                    timeout_seconds=_PAIN_SIGNAL_TIMEOUT_SECONDS,
                    retry_timeout_seconds=_PAIN_SIGNAL_RETRY_TIMEOUT_SECONDS,
                )
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
            except OSError as error:
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


_PLAN_403_KEYWORDS: frozenset[str] = frozenset(
    {
        "sync_not_available",
        "plan_restriction",
        "requires a pro",
        "requires a team",
        "upgrade your plan",
        "upgrade to",
        "subscription required",
        "not included in your plan",
        "guard sync requires",
    }
)


def _check_plan_restriction_403(
    error: urllib.error.HTTPError,
) -> tuple[bool, str]:
    """Read a 403 response body exactly once.

    Returns (is_plan_restriction, error_message) so callers never
    drain the stream more than once regardless of which branch they take.
    Checks both machine-readable fields (syncEnabled, error, code) and
    human-readable error messages for plan-restriction signals.
    """
    try:
        raw_body = error.read().decode("utf-8", errors="replace")
    except OSError:
        raw_body = ""
    try:
        payload: object = json.loads(raw_body) if raw_body else None
    except json.JSONDecodeError:
        payload = None
    fallback = raw_body.strip() or f"HTTP Error {error.code}: {error.reason}"
    if not isinstance(payload, dict):
        return False, fallback
    message = payload.get("error")
    message_str = message.strip() if isinstance(message, str) and message.strip() else fallback
    if payload.get("syncEnabled") is False:
        return True, message_str
    error_field = str(payload.get("error") or "").lower()
    code_field = str(payload.get("code") or "").lower()
    combined = f"{error_field} {code_field}"
    if any(kw in combined for kw in _PLAN_403_KEYWORDS):
        return True, message_str
    return False, message_str


def _sync_url_error_message(error: OSError) -> str:
    reason = getattr(error, "reason", error)
    if reason is not None:
        reason_text = str(reason).strip()
        if reason_text:
            return f"Guard sync failed: {reason_text}"
    return "Guard sync failed because the remote endpoint could not be reached."


def _is_timeout_error(error: OSError) -> bool:
    if isinstance(error, TimeoutError | socket.timeout):
        return True
    reason = getattr(error, "reason", error)
    if isinstance(reason, TimeoutError | socket.timeout):
        return True
    reason_text = str(reason).strip().lower()
    if not reason_text:
        return False
    return reason_text == "timed out" or reason_text.endswith(" timed out") or "timed out" in reason_text


def _urlopen_json_with_timeout_retry(
    *,
    request: urllib.request.Request,
    timeout_seconds: int,
    retry_timeout_seconds: int,
) -> dict[str, object]:
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except OSError as error:
        if not _is_timeout_error(error):
            raise
        with urllib.request.urlopen(request, timeout=retry_timeout_seconds) as response:
            payload = json.loads(response.read().decode("utf-8"))
    if not isinstance(payload, dict):
        raise RuntimeError("Invalid sync response")
    return payload


def _urlopen_with_timeout_retry(
    *,
    request: urllib.request.Request,
    timeout_seconds: int,
    retry_timeout_seconds: int,
) -> None:
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds):
            return
    except OSError as error:
        if not _is_timeout_error(error):
            raise
        with urllib.request.urlopen(request, timeout=retry_timeout_seconds):
            return


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


def _guard_events_sync_url(sync_url: str) -> str:
    parsed = urllib.parse.urlsplit(_normalized_receipts_sync_url(sync_url))
    if parsed.path.rstrip("/").endswith("/api/v1/guard/events"):
        return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), parsed.query, ""))
    path = parsed.path.rstrip("/")
    for suffix in (
        "/api/guard/receipts/sync",
        "/guard/receipts/sync",
        "/registry/api/v1/guard/receipts/sync",
    ):
        if path.endswith(suffix):
            path = path[: -len(suffix)]
            break
    return urllib.parse.urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            path.rstrip("/") + "/api/v1/guard/events",
            parsed.query,
            "",
        )
    )


def _completed_guard_event_ids(payload: dict[str, object]) -> list[str]:
    statuses = payload.get("statuses")
    if not isinstance(statuses, list):
        return []
    completed: list[str] = []
    for item in statuses:
        if not isinstance(item, dict):
            continue
        status = str(item.get("status") or "")
        event_id = item.get("eventId")
        if status in {"accepted", "duplicate", "rejected"} and isinstance(event_id, str):
            completed.append(event_id)
    return completed


def _cloud_sync_receipts_payload(store: GuardStore, receipts: list[dict[str, object]]) -> list[dict[str, object]]:
    device_id, device_name = _guard_device_metadata(store)
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


def _cloud_runtime_session_payload(store: GuardStore, session: dict[str, object]) -> dict[str, object]:
    device_id, device_name = _guard_device_metadata(store)
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


def _guard_device_metadata(store: GuardStore) -> tuple[str, str]:
    metadata = store.get_device_metadata()
    return str(metadata["installation_id"]), str(metadata["device_label"])


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
