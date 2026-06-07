"""Guard wrapper-mode runtime execution."""
from __future__ import annotations
import hashlib
import io
import json
import os
import re
import socket
import subprocess
import threading
import urllib.error
import urllib.parse
import urllib.request
from base64 import urlsafe_b64encode
from collections.abc import Callable
from contextlib import contextmanager, suppress
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from ...version import __version__
from ..adapters import get_adapter
from ..adapters.base import HarnessContext
from ..approval_gate import ApprovalGateError
from ..cli.oauth_client import (
    GuardDpopKeyMaterial,
    resolve_guard_oauth_client_config,
    validate_guard_sync_endpoint,
)
from ..config import GuardConfig
from ..consumer import detect_harness, evaluate_detection
from ..edge_events import build_runtime_session_event
from ..models import GuardArtifact, HarnessDetection, PolicyDecision
from ..package_firewall_entitlement import build_oauth_package_firewall_entitlement
from ..policy_bundle_parser import (
    non_empty_string,
    POLICY_BUNDLE_DEFAULT_ENVIRONMENTS,
    POLICY_BUNDLE_RULE_ACTIONS,
    POLICY_BUNDLE_RULE_MATCHER_FAMILIES,
    validated_policy_bundle_payload as _validated_policy_bundle_payload,
)
from ..redaction import redact_sensitive_text
from ..shims import package_shim_cloud_coverage
from ..store import GuardStore
from ..types import PromptRequest, RemediationAction
from .actions import GuardActionEnvelope, redacted_workspace_label
from .composition_rules import compose_action_from_signals
from .detectors import DetectorContext, DetectorRegistry, DetectorRunResult, register_default_detectors
from .prompt_injection import detect_prompt_injection_requests
from .supply_chain_bundle import (
    SupplyChainBundleError,
    load_supply_chain_bundle_response,
    load_supply_chain_verification_keys,
    verify_supply_chain_bundle_response,
)
from .supply_chain_support import ecosystem_support_matrix

_APPROVAL_METADATA_KEYS = (
    "approval_center_url",
    "approval_delivery",
    "approval_requests",
    "approval_wait",
    "review_hint",
)


_DEFAULT_DETECTOR_REGISTRY: tuple[Callable[[], tuple[Any, ...]], DetectorRegistry] | None = None
_DEFAULT_DETECTOR_REGISTRY_LOCK = threading.Lock()


def _get_default_detector_registry() -> DetectorRegistry:
    global _DEFAULT_DETECTOR_REGISTRY
    factory = register_default_detectors
    cached = _DEFAULT_DETECTOR_REGISTRY
    if cached is not None and cached[0] is factory:
        return cached[1]
    with _DEFAULT_DETECTOR_REGISTRY_LOCK:
        cached = _DEFAULT_DETECTOR_REGISTRY
        if cached is None or cached[0] is not factory:
            cached = (factory, DetectorRegistry(factory()))
            _DEFAULT_DETECTOR_REGISTRY = cached
    return cached[1]


@contextmanager
def _guard_sync_auth_lock(store: GuardStore):
    with store.hold_oauth_refresh_lock():
        yield


_PAIN_SIGNAL_EVENTS = frozenset(
    {
        "changed_artifact_caught",
        "install_time_block",
        "install_time_review",
        "install_time_warn",
        "supply_chain_bundle_refresh_requested",
        "approval_gate/remote_policy_sync_blocked",
    }
)
_EXCEPTION_EXPIRY_ALERT_WINDOW_HOURS = 7 * 24
_SECRET_REQUEST_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(?<![\w-])\.env(?!\.example\b)(?:\.[\w.-]+)?\b"), "local .env file"),
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
    r"use|include|grab|"
    r"contain(?:s)?|contents?\s+of|what(?:'s| is)\s+in"
    r")\b",
    re.IGNORECASE,
)
_NEGATED_SECRET_READ_PATTERN = re.compile(
    r"\b(?:never|do\s+not|don't|dont|must\s+not|should\s+not|cannot|can't)\b[^.!?;\n]{0,80}"
    r"\b(?:read|open|print|show|dump|cat|head|tail|less|copy|cp|scp|reveal|display|summari[sz]e|inspect|extract|"
    r"use|include|grab)\b",
    re.IGNORECASE,
)
_FOLLOWING_SECRET_REFERENCE_PATTERN = re.compile(
    r"\b(?:it|them|these|those|file|files|secret|secrets|contents?|credentials?|token|tokens?|key|keys)\b",
    re.IGNORECASE,
)
_EXFIL_ACTIONS = r"(?:send|post|upload|transfer|paste|sync)"
_EXFIL_ARTIFACTS = r"(?:contents?|data|payload|file|secret|token|key|credential|credentials|config|output)"
_EXFIL_DESTINATIONS = r"(?:to|into|onto|via|through|over|at)"
_EXFIL_NAMED_REMOTE_TARGETS = r"(?:webhook|gist|pastebin|slack|discord|telegram|server|endpoint|url)"
_EXFIL_REMOTE_TARGETS = (
    r"(?:(?:[a-z][a-z0-9+.-]*://)|(?:[a-z0-9-]+\.)+[a-z]{2,}|(?:\d{1,3}\.){3}\d{1,3}|"
    rf"{_EXFIL_NAMED_REMOTE_TARGETS})"
)
_SAME_SENTENCE_80 = r"[^.!?;\n]{0,80}"
_SAME_SENTENCE_40 = r"[^.!?;\n]{0,40}"
_EXFIL_PROMPT_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        rf"\b(?:upload|exfiltrate|transfer|paste|gist|webhook)\b{_SAME_SENTENCE_80}\b"
        rf"{_EXFIL_ARTIFACTS}\b",
        re.IGNORECASE,
    ),
    re.compile(
        rf"\b{_EXFIL_ACTIONS}\b{_SAME_SENTENCE_80}\b"
        rf"{_EXFIL_ARTIFACTS}\b"
        rf"{_SAME_SENTENCE_40}\b{_EXFIL_DESTINATIONS}\b{_SAME_SENTENCE_40}\b"
        rf"{_EXFIL_REMOTE_TARGETS}\b",
        re.IGNORECASE,
    ),
    re.compile(
        rf"\b{_EXFIL_ACTIONS}\b{_SAME_SENTENCE_80}\b"
        rf"{_EXFIL_DESTINATIONS}\b{_SAME_SENTENCE_40}\b"
        rf"{_EXFIL_NAMED_REMOTE_TARGETS}\b",
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
_RECEIPT_SYNC_BATCH_SIZE = 50
_RECEIPT_SYNC_CURSOR_PAGE_SIZE = 200
_RECEIPT_SYNC_CURSOR_BACKFILL_ROWS = 200
_PAIN_SIGNAL_TIMEOUT_SECONDS = 10
_PAIN_SIGNAL_RETRY_TIMEOUT_SECONDS = 90
_GUARD_EVENTS_ENDPOINT_UNAVAILABLE_RETRY_HOURS = 24


class GuardSyncNotConfiguredError(RuntimeError):
    """Raised when Guard Cloud sync is requested before the machine is paired."""


class GuardSyncNotAvailableError(RuntimeError):
    """Raised when the sync endpoint returns 403 (free-plan restriction)."""


class GuardSyncAuthorizationExpiredError(GuardSyncNotConfiguredError):
    """Raised when local OAuth material can no longer mint a runtime access token."""


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
    sentence = _secret_match_sentence(prompt_text, start=start, end=end)
    sentence_end = _prompt_sentence_end(prompt_text, end)
    sentence_intents = tuple(_SECRET_READ_INTENT_PATTERN.finditer(sentence))
    if sentence_intents:
        if any(not _secret_read_intent_is_negated(sentence, match.start(), match.end()) for match in sentence_intents):
            return True
        return _following_sentence_has_secret_read_intent(prompt_text, sentence_end)
    if _NEGATED_SECRET_READ_PATTERN.search(sentence) is not None:
        return _following_sentence_has_secret_read_intent(prompt_text, sentence_end)
    region = _prompt_secret_intent_region(prompt_text, start=start, end=end)
    for match in _SECRET_READ_INTENT_PATTERN.finditer(region):
        if not _secret_read_intent_is_negated(region, match.start(), match.end()):
            return True
    return False


def _secret_match_sentence(prompt_text: str, *, start: int, end: int) -> str:
    sentence_start = _prompt_sentence_start(prompt_text, start)
    sentence_end = _prompt_sentence_end(prompt_text, end)
    return prompt_text[sentence_start:sentence_end]


def _following_sentence_has_secret_read_intent(prompt_text: str, sentence_end: int) -> bool:
    if sentence_end >= len(prompt_text):
        return False
    next_end = _prompt_sentence_end(prompt_text, sentence_end)
    following = prompt_text[sentence_end:next_end]
    has_positive_intent = any(
        not _secret_read_intent_is_negated(following, match.start(), match.end())
        for match in _SECRET_READ_INTENT_PATTERN.finditer(following)
    )
    if not has_positive_intent:
        return False
    return _FOLLOWING_SECRET_REFERENCE_PATTERN.search(following) is not None


def _secret_read_intent_is_negated(region: str, intent_start: int, intent_end: int) -> bool:
    window_start = max(0, intent_start - 90)
    prefix = region[window_start:intent_start]
    clause_start = window_start
    for boundary in (".", "!", "?", ";", ",", " and ", " but ", " then "):
        boundary_index = prefix.rfind(boundary)
        if boundary_index >= 0:
            clause_start = max(clause_start, window_start + boundary_index + len(boundary))
    scoped_start = clause_start
    scoped_region = region[scoped_start:intent_end]
    return _NEGATED_SECRET_READ_PATTERN.search(scoped_region) is not None


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

    action_envelope = _guard_run_action_envelope(harness, context, passthrough_args)
    if evaluation["blocked"]:
        evaluation = _evaluation_with_action_envelope(evaluation, action_envelope)

    if not dry_run and interactive_resolver is not None and evaluation["blocked"]:
        evaluation = interactive_resolver(detection, evaluation)
    elif not dry_run and blocked_resolver is not None and evaluation["blocked"]:
        pending_evaluation = blocked_resolver(detection, evaluation)
        detection = _detection_with_prompt_artifacts(detect_harness(harness, context), context, passthrough_args)
        reevaluated = evaluate_detection(detection, store, config, default_action=default_action, persist=True)
        if reevaluated["blocked"]:
            reevaluated = _evaluation_with_action_envelope(reevaluated, action_envelope)
        for key in _APPROVAL_METADATA_KEYS:
            if key in pending_evaluation:
                reevaluated[key] = pending_evaluation[key]
        evaluation = reevaluated
    evaluation = _evaluation_with_detector_registry(
        evaluation,
        action_envelope,
        context,
        config,
    )
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


def _guard_run_action_envelope(
    harness: str,
    context: HarnessContext,
    passthrough_args: list[str],
) -> GuardActionEnvelope:
    workspace = context.workspace_dir
    workspace_hash = None
    if workspace is not None:
        workspace_path = workspace.expanduser()
        with suppress(OSError):
            workspace_path = workspace_path.resolve()
        workspace_hash = hashlib.sha256(str(workspace_path).encode("utf-8")).hexdigest()
    return GuardActionEnvelope(
        schema_version=1,
        action_id="",
        harness=harness,
        event_name="HarnessStart",
        action_type="harness_start",
        workspace=redacted_workspace_label(workspace, home_dir=context.home_dir),
        workspace_hash=workspace_hash,
        tool_name=None,
        command=None,
        prompt_excerpt=None,
        prompt_text=None,
        target_paths=(),
        network_hosts=(),
        mcp_server=None,
        mcp_tool=None,
        package_manager=None,
        package_name=None,
        script_name=None,
        raw_payload_redacted={"passthrough_arg_count": len(passthrough_args)},
    )


def _evaluation_with_action_envelope(
    evaluation: dict[str, Any],
    action_envelope: GuardActionEnvelope,
) -> dict[str, Any]:
    artifacts = evaluation.get("artifacts")
    if not isinstance(artifacts, list):
        return evaluation
    action_payload = action_envelope.to_dict()
    normalized_artifacts: list[object] = []
    changed = False
    for item in artifacts:
        if isinstance(item, dict) and "action_envelope_json" not in item:
            normalized_artifacts.append({**item, "action_envelope_json": action_payload})
            changed = True
        else:
            normalized_artifacts.append(item)
    if not changed:
        return evaluation
    return {**evaluation, "artifacts": normalized_artifacts}


def _evaluation_with_detector_registry(
    evaluation: dict[str, Any],
    action_envelope: GuardActionEnvelope,
    context: HarnessContext,
    config: GuardConfig,
) -> dict[str, Any]:
    if not config.runtime_detector_registry:
        return evaluation
    detector_context = DetectorContext(
        config=config,
        workspace=context.workspace_dir,
        prior_decisions={},
        threat_intel={},
        redaction_settings={},
    )
    result = _get_default_detector_registry().run(
        action_envelope,
        detector_context,
        timeout_ms=config.runtime_detector_timeout_ms,
        disabled_detector_ids=config.runtime_detector_disabled_ids,
    )
    trace_error = (
        _write_detector_debug_trace(config, action_envelope, result) if config.runtime_detector_debug_trace else None
    )
    if not result.signals and not result.telemetry:
        if trace_error is None:
            return evaluation
        return {**evaluation, "runtime_detector_trace_error": trace_error}
    next_evaluation = {
        **evaluation,
        "runtime_detector_signals_v2": [signal.to_dict() for signal in result.signals],
        "runtime_detector_telemetry": [item.to_dict() for item in result.telemetry],
    }
    base_action: str = "block" if evaluation.get("blocked") else "allow"
    composition = compose_action_from_signals(result.signals, base_action)  # type: ignore[arg-type]
    next_evaluation["runtime_detector_composition"] = {
        "action": composition.action,
        "reason": composition.reason,
        "downgraded": composition.downgraded,
        "upgraded": composition.upgraded,
    }
    if composition.action == "block" and not bool(evaluation.get("blocked")):
        next_evaluation["blocked"] = True
        next_evaluation["blocked_by_detector"] = composition.reason
    if trace_error is not None:
        next_evaluation["runtime_detector_trace_error"] = trace_error
    return next_evaluation


def _write_detector_debug_trace(
    config: GuardConfig,
    action_envelope: GuardActionEnvelope,
    result: DetectorRunResult,
) -> dict[str, object] | None:
    created_at = datetime.now(timezone.utc)
    action_payload = action_envelope.to_dict()
    trace_payload = {
        "schema_version": 1,
        "created_at": created_at.isoformat(),
        "action": _redact_detector_debug_payload(action_payload),
        "signals": [signal.to_dict() for signal in result.signals],
        "telemetry": [item.to_dict() for item in result.telemetry],
    }
    trace_dir = config.guard_home / "debug" / "detectors"
    action_digest = hashlib.sha256(
        json.dumps(action_payload, sort_keys=True, default=str).encode("utf-8"),
    ).hexdigest()[:12]
    trace_path = trace_dir / f"{created_at.strftime('%Y%m%dT%H%M%S%fZ')}-{action_digest}.json"
    try:
        trace_dir.mkdir(parents=True, exist_ok=True)
        trace_path.write_text(json.dumps(trace_payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except OSError as error:
        return {"error_type": type(error).__name__, "message": str(error)}
    return None


def _redact_detector_debug_payload(value: object) -> object:
    if isinstance(value, dict):
        redacted: dict[str, object] = {}
        for key, item in value.items():
            key_text = str(key)
            if "prompt" in key_text.lower():
                redacted[key_text] = "[redacted]"
            else:
                redacted[key_text] = _redact_detector_debug_payload(item)
        return redacted
    if isinstance(value, (tuple, list)):
        return [_redact_detector_debug_payload(item) for item in value]
    return value


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
    existing_classes = {request.request_class for request in requests}
    for request in detect_prompt_injection_requests(normalized_prompt):
        if request.request_class in existing_classes:
            continue
        requests.append(request)
        existing_classes.add(request.request_class)
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


def _policy_bundle_acknowledgement_payload(
    *,
    device_id: str,
    device_name: str,
    policy_bundle: dict[str, object],
    synced_at: str,
) -> dict[str, object]:
    return {
        "appliedAt": synced_at,
        "bundleHash": policy_bundle["bundleHash"],
        "bundleVersion": policy_bundle["bundleVersion"],
        "deviceId": device_id,
        "deviceName": device_name,
        "status": "synced",
    }


def _version_tuple(value: str) -> tuple[int, ...] | None:
    tokens = [token for token in re.split(r"[^0-9]+", value) if token]
    if not tokens:
        return None
    return tuple(int(token) for token in tokens)


def _daemon_version_supported(policy_bundle: dict[str, object]) -> bool:
    min_daemon_version = non_empty_string(policy_bundle.get("minDaemonVersion"))
    if min_daemon_version is None:
        return True
    current = _version_tuple(__version__)
    minimum = _version_tuple(min_daemon_version)
    if current is None or minimum is None:
        return True
    return current >= minimum


def _policy_bundle_is_version_downgrade(
    existing_bundle: dict[str, object] | None,
    next_bundle: dict[str, object],
) -> bool:
    if not isinstance(existing_bundle, dict) or not existing_bundle:
        return False
    existing_issued_at = non_empty_string(existing_bundle.get("issuedAt"))
    next_issued_at = non_empty_string(next_bundle.get("issuedAt"))
    if existing_issued_at is None or next_issued_at is None:
        return False
    try:
        return datetime.fromisoformat(next_issued_at) < datetime.fromisoformat(existing_issued_at)
    except (TypeError, ValueError):
        return False


def _policy_bundle_rule_matcher_families(rule: dict[str, object]) -> list[str]:
    explicit = rule.get("matcherFamilies")
    if isinstance(explicit, list):
        values = [
            family for family in explicit if isinstance(family, str) and family in POLICY_BUNDLE_RULE_MATCHER_FAMILIES
        ]
        return list(dict.fromkeys(values))

    derived: list[str] = []
    scope = rule.get("scope")
    if isinstance(scope, dict):
        if isinstance(scope.get("ecosystems"), list) and scope["ecosystems"]:
            derived.append("package-request")
        if non_empty_string(scope.get("mcp")) is not None or non_empty_string(scope.get("tool")) is not None:
            derived.append("mcp")
        if non_empty_string(scope.get("command")) is not None:
            derived.append("tool-action")
        if non_empty_string(scope.get("path")) is not None or non_empty_string(scope.get("secretType")) is not None:
            derived.append("file-read")
    artifact_type = non_empty_string(rule.get("artifactType"))
    if artifact_type == "package_request":
        derived.append("package-request")
    if artifact_type == "tool_action_request":
        derived.append("tool-action")
    if artifact_type == "file_read_request":
        derived.append("file-read")
    if artifact_type == "prompt_request":
        derived.append("prompt")
    return list(dict.fromkeys(family for family in derived if family in POLICY_BUNDLE_RULE_MATCHER_FAMILIES))


def _policy_bundle_rule_matches_local_scope(
    rule: dict[str, object],
    *,
    device_id: str,
    device_name: str,
) -> bool:
    scope = rule.get("scope")
    if not isinstance(scope, dict):
        return False
    devices = scope.get("devices")
    if isinstance(devices, list) and devices and device_id not in devices and device_name not in devices:
        return False
    environments = scope.get("environments")
    if (
        isinstance(environments, list)
        and environments
        and not any(isinstance(item, str) and item in POLICY_BUNDLE_DEFAULT_ENVIRONMENTS for item in environments)
    ):
        return False
    locations = scope.get("locations")
    return not (isinstance(locations, list) and locations)


def _policy_bundle_rule_harnesses(rule: dict[str, object]) -> list[str]:
    scope = rule.get("scope")
    if not isinstance(scope, dict):
        return ["*"]
    values: list[str] = []
    for key in ("harnesses", "agents"):
        current = scope.get(key)
        if isinstance(current, list):
            values.extend(item for item in current if isinstance(item, str) and item.strip())
    normalized = [value.strip().lower() for value in values]
    if not normalized:
        return ["*"]
    return ["*" if value == "custom" else value for value in dict.fromkeys(normalized)]


def _build_policy_bundle_decisions(
    policy_bundle: dict[str, object],
    *,
    device_id: str,
    device_name: str,
) -> list[PolicyDecision]:
    decisions: list[PolicyDecision] = []
    rules = policy_bundle.get("rules")
    if not isinstance(rules, list):
        return decisions
    for item in rules:
        if not isinstance(item, dict):
            continue
        if not _policy_bundle_rule_matches_local_scope(item, device_id=device_id, device_name=device_name):
            continue
        action = item.get("action")
        if action == "ignore" or action not in POLICY_BUNDLE_RULE_ACTIONS:
            continue
        matcher_families = _policy_bundle_rule_matcher_families(item)
        if not matcher_families:
            continue
        rule_id = non_empty_string(item.get("ruleId")) or "bundle-rule"
        reason = non_empty_string(item.get("reason")) or f"Matched Guard Cloud rule {rule_id}."
        for harness in _policy_bundle_rule_harnesses(item):
            for family in matcher_families:
                decisions.append(
                    PolicyDecision(
                        harness=harness,
                        scope="harness",
                        action=action,
                        artifact_id=f"family:{family}",
                        reason=reason,
                        owner=rule_id,
                        source="policy-bundle",
                        expires_at=non_empty_string(policy_bundle.get("expiresAt")),
                    )
                )
    return decisions


def _parse_policy_simulation_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    normalized = value.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(normalized)
    except ValueError:
        return None


def _receipt_policy_bundle_matcher_family(receipt: dict[str, object]) -> str | None:
    artifact_id = non_empty_string(receipt.get("artifact_id"))
    if artifact_id is None:
        return None
    for family in POLICY_BUNDLE_RULE_MATCHER_FAMILIES:
        if f":{family}:" in artifact_id:
            return family
    return None


def simulate_policy_bundle_receipts(
    store: GuardStore,
    policy_bundle: dict[str, object],
    *,
    limit: int = 50,
    now: str | None = None,
) -> dict[str, object]:
    receipts = store.list_receipts(limit=limit)
    device_id, device_name = _guard_device_metadata(store)
    decisions = _build_policy_bundle_decisions(policy_bundle, device_id=device_id, device_name=device_name)
    generated_at = now or _now()
    generated_at_dt = _parse_policy_simulation_timestamp(generated_at)
    latest_receipt_at: str | None = None
    oldest_receipt_at: str | None = None
    latest_dt: datetime | None = None
    oldest_dt: datetime | None = None
    matches: list[dict[str, object]] = []
    summary = {"allow": 0, "block": 0, "review": 0, "ignore": 0, "matched": 0, "unchanged": 0}
    for receipt in receipts:
        receipt_dt = _parse_policy_simulation_timestamp(receipt.get("timestamp"))
        if receipt_dt is not None and (latest_dt is None or receipt_dt > latest_dt):
            latest_dt = receipt_dt
            latest_receipt_at = str(receipt.get("timestamp"))
        if receipt_dt is not None and (oldest_dt is None or receipt_dt < oldest_dt):
            oldest_dt = receipt_dt
            oldest_receipt_at = str(receipt.get("timestamp"))
        family = _receipt_policy_bundle_matcher_family(receipt)
        if family is None:
            continue
        harness = non_empty_string(receipt.get("harness")) or "*"
        matched = next(
            (item for item in decisions if item.artifact_id == f"family:{family}" and item.harness in {harness, "*"}),
            None,
        )
        simulated_action = matched.action if matched is not None else str(receipt.get("policy_decision") or "review")
        if simulated_action not in {"allow", "block", "review", "ignore"}:
            simulated_action = "review"
        summary[simulated_action] = summary.get(simulated_action, 0) + 1
        if matched is not None:
            summary["matched"] += 1
        else:
            summary["unchanged"] += 1
        matches.append(
            {
                "receipt_id": receipt.get("receipt_id"),
                "artifact_id": receipt.get("artifact_id"),
                "harness": harness,
                "matcher_family": family,
                "observed_action": receipt.get("policy_decision"),
                "simulated_action": simulated_action,
                "matched_rule_id": matched.owner if matched is not None else None,
                "policy_version": non_empty_string(policy_bundle.get("bundleHash")),
                "timestamp": receipt.get("timestamp"),
            }
        )
    stale = False
    if generated_at_dt is not None and latest_dt is not None:
        stale = (generated_at_dt - latest_dt).total_seconds() > 24 * 60 * 60
    return {
        "generated_at": generated_at,
        "policy_bundle_version": non_empty_string(policy_bundle.get("bundleVersion")),
        "policy_version": non_empty_string(policy_bundle.get("bundleHash")),
        "receipt_count": len(receipts),
        "summary": summary,
        "matches": matches,
        "event_freshness": {
            "latest_receipt_at": latest_receipt_at,
            "oldest_receipt_at": oldest_receipt_at,
            "sampled_receipts": len(receipts),
            "stale": stale,
        },
    }


def sync_receipts(
    store: GuardStore,
    *,
    persist_sync_summary: bool = True,
    persist_connect_state: bool = True,
    auth_context: dict[str, object] | None = None,
) -> dict[str, object]:
    """Push local receipts to the configured sync endpoint."""

    resolved_auth_context = auth_context if auth_context is not None else _resolve_guard_sync_auth_context(store)
    sync_url = _normalized_receipts_sync_url(resolved_auth_context["sync_url"])
    prior_receipt_cursor = _receipt_sync_cursor_rowid(store)
    receipts = _receipt_sync_rows_for_upload(store, cursor_rowid=prior_receipt_cursor)
    inventory = store.list_inventory()
    payload: dict[str, object] = {}
    receipts_stored_total = 0
    advisories_payload: list[dict[str, object]] = []
    exceptions_payload: list[dict[str, object]] = []
    policy_payload: dict[str, object] | None = None
    policy_bundle_payload: dict[str, object] | None = None
    alert_preferences_payload: dict[str, object] | None = None
    team_policy_pack_payload: dict[str, object] | None = None
    remote_decisions: set[PolicyDecision] = set()
    device_id, device_name = _guard_device_metadata(store)
    local_guard_online_at = _now()
    sync_context = _receipt_sync_context(
        store=store,
        local_guard_online_at=local_guard_online_at,
        device_id=device_id,
        device_name=device_name,
    )
    latest_uploaded_rowid: int | None = None
    for receipt_batch in _iter_receipt_sync_batches(receipts):
        body = json.dumps(
            {
                "receipts": _cloud_sync_receipts_payload(
                    receipt_batch,
                    device_id=device_id,
                    device_name=device_name,
                ),
                "syncContext": sync_context,
            }
        ).encode("utf-8")
        request = _guard_sync_request(
            resolved_auth_context,
            request_url=sync_url,
            method="POST",
            data=body,
            extra_headers=None,
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
        batch_rowids = [item.get("receipt_rowid") for item in receipt_batch]
        for rowid in batch_rowids:
            if isinstance(rowid, int) and (latest_uploaded_rowid is None or rowid > latest_uploaded_rowid):
                latest_uploaded_rowid = rowid
        batch_synced_at = _sync_timestamp(payload)
        if latest_uploaded_rowid is not None:
            _persist_receipt_sync_cursor(
                store=store,
                latest_uploaded_rowid=latest_uploaded_rowid,
                synced_at=batch_synced_at,
            )
        batch_receipts_stored = payload.get("receiptsStored")
        if isinstance(batch_receipts_stored, int):
            receipts_stored_total += batch_receipts_stored
        advisories = payload.get("advisories")
        if isinstance(advisories, list):
            advisories_payload.extend(item for item in advisories if isinstance(item, dict))
        policy = payload.get("policy")
        if isinstance(policy, dict) and (policy or policy_payload is None):
            policy_payload = policy
        policy_bundle = payload.get("policyBundle")
        if isinstance(policy_bundle, dict) and (policy_bundle or policy_bundle_payload is None):
            policy_bundle_payload = policy_bundle
        alert_preferences = payload.get("alertPreferences")
        if isinstance(alert_preferences, dict) and (alert_preferences or alert_preferences_payload is None):
            alert_preferences_payload = alert_preferences
        team_policy_pack = payload.get("teamPolicyPack")
        if isinstance(team_policy_pack, dict) and (team_policy_pack or team_policy_pack_payload is None):
            team_policy_pack_payload = team_policy_pack
        exceptions = payload.get("exceptions")
        if isinstance(exceptions, list):
            exceptions_payload.extend(item for item in exceptions if isinstance(item, dict))
        remote_decisions.update(_build_remote_policy_decisions(payload))
    now = _sync_timestamp(payload)
    persisted_cursor_rowid = latest_uploaded_rowid if latest_uploaded_rowid is not None else prior_receipt_cursor
    _persist_receipt_sync_cursor(
        store=store,
        latest_uploaded_rowid=persisted_cursor_rowid,
        synced_at=now,
    )
    deduped_advisories = _dedupe_sync_payload_items(advisories_payload)
    deduped_exceptions = _dedupe_sync_payload_items(exceptions_payload)
    advisories_stored = 0
    if deduped_advisories:
        advisories_stored = store.cache_advisories(deduped_advisories, now)
    if policy_payload is not None:
        store.set_sync_payload("policy", policy_payload, now)
    else:
        store.set_sync_payload("policy", {}, now)
    if policy_bundle_payload is not None:
        validated_policy_bundle, policy_bundle_rejection_reason = _validated_policy_bundle_payload(
            policy_bundle_payload
        )
        existing_policy_bundle_payload = store.get_sync_payload("policy_bundle")
        existing_policy_bundle = (
            existing_policy_bundle_payload if isinstance(existing_policy_bundle_payload, dict) else None
        )
        if validated_policy_bundle is not None and not _daemon_version_supported(validated_policy_bundle):
            validated_policy_bundle = None
            policy_bundle_rejection_reason = "unsupported_daemon_version"
        if validated_policy_bundle is not None and _policy_bundle_is_version_downgrade(
            existing_policy_bundle, validated_policy_bundle
        ):
            validated_policy_bundle = None
            policy_bundle_rejection_reason = "bundle_version_downgrade"
        if validated_policy_bundle is not None:
            store.set_sync_payload("policy_bundle", validated_policy_bundle, now)
            store.set_sync_payload("policy_bundle_last_good", validated_policy_bundle, now)
            store.set_sync_payload(
                "policy_bundle_ack",
                _policy_bundle_acknowledgement_payload(
                    device_id=device_id,
                    device_name=device_name,
                    policy_bundle=validated_policy_bundle,
                    synced_at=now,
                ),
                now,
            )
            store.set_sync_payload("policy_bundle_last_error", {}, now)
            remote_decisions.update(
                _build_policy_bundle_decisions(
                    validated_policy_bundle,
                    device_id=device_id,
                    device_name=device_name,
                )
            )
        else:
            last_good_bundle_payload = store.get_sync_payload("policy_bundle_last_good")
            preserved_bundle_payload = (
                last_good_bundle_payload
                if isinstance(last_good_bundle_payload, dict) and last_good_bundle_payload
                else existing_policy_bundle
            )
            if isinstance(preserved_bundle_payload, dict) and preserved_bundle_payload:
                remote_decisions.update(
                    _build_policy_bundle_decisions(
                        preserved_bundle_payload,
                        device_id=device_id,
                        device_name=device_name,
                    )
                )
            store.set_sync_payload(
                "policy_bundle_last_error",
                {"reason": policy_bundle_rejection_reason or "invalid_policy_bundle"},
                now,
            )
            store.add_event(
                "policy_bundle/rejected",
                {"reason": policy_bundle_rejection_reason or "invalid_policy_bundle"},
                now,
            )
    else:
        existing_bundle_payload = store.get_sync_payload("policy_bundle")
        if isinstance(existing_bundle_payload, dict) and existing_bundle_payload:
            remote_decisions.update(
                _build_policy_bundle_decisions(
                    existing_bundle_payload,
                    device_id=device_id,
                    device_name=device_name,
                )
            )
    if not isinstance(store.get_sync_payload("policy_bundle_last_error"), dict):
        store.set_sync_payload("policy_bundle_last_error", {}, now)
    if alert_preferences_payload is not None:
        store.set_sync_payload("alert_preferences", alert_preferences_payload, now)
    else:
        store.set_sync_payload("alert_preferences", {}, now)
    if team_policy_pack_payload is not None:
        store.set_sync_payload("team_policy_pack", team_policy_pack_payload, now)
    else:
        store.set_sync_payload("team_policy_pack", {}, now)
    remote_policies_stored = len(remote_decisions)
    remote_policy_sync_blocked = False
    try:
        store.replace_remote_policies(list(remote_decisions), now)
    except ApprovalGateError as error:
        remote_policies_stored = 0
        remote_policy_sync_blocked = True
        store.add_event(
            "approval_gate/remote_policy_sync_blocked",
            {
                "error": error.code,
                "remote_policies_count": len(remote_decisions),
            },
            now,
        )
    _record_synced_alert_events(
        store=store,
        advisories=deduped_advisories,
        alert_preferences=alert_preferences_payload,
        exceptions=deduped_exceptions,
        now=now,
    )
    pain_signals_uploaded = sync_pain_signals(store, auth_context=resolved_auth_context)
    value_metrics = _build_value_metrics(store)
    weekly_digest = _build_weekly_firewall_digest(metrics=value_metrics, now=now)
    summary = {
        "synced_at": payload.get("syncedAt"),
        "receipts_stored": receipts_stored_total,
        "advisories_stored": advisories_stored,
        "exceptions_stored": len(deduped_exceptions),
        "remote_policies_stored": remote_policies_stored,
        "pain_signals_uploaded": pain_signals_uploaded,
        "receipts": len(receipts),
        "receipt_cursor_rowid": persisted_cursor_rowid,
        "receipt_cursor_backfill": bool(
            prior_receipt_cursor is not None
            and len(receipts) > 0
            and not any(
                isinstance(item.get("receipt_rowid"), int) and int(item.get("receipt_rowid")) > prior_receipt_cursor
                for item in receipts
            )
        ),
        "inventory": 0,
        "inventory_tracked": len(inventory),
        "value_metrics": value_metrics,
        "weekly_digest": weekly_digest,
    }
    if remote_policy_sync_blocked:
        summary["remote_policy_sync_blocked"] = True
    summary["guard_events_v1"] = sync_guard_events(store, auth_context=resolved_auth_context)
    if persist_sync_summary:
        store.set_sync_payload("sync_summary", summary, now)
    if persist_connect_state:
        store.record_latest_guard_connect_sync_success(sync_payload=summary, now=now)
    return summary


def _fetch_supply_chain_bundle_payload(request: urllib.request.Request) -> dict[str, object]:
    try:
        return _urlopen_json_with_timeout_retry(
            request=request,
            timeout_seconds=_SYNC_HTTP_TIMEOUT_SECONDS,
            retry_timeout_seconds=_SYNC_HTTP_RETRY_TIMEOUT_SECONDS,
        )
    except urllib.error.HTTPError as error:
        if error.code == 403:
            is_plan_restricted, message = _check_plan_restriction_403(error)
            if is_plan_restricted:
                raise GuardSyncNotAvailableError(message) from error
            raise RuntimeError(message) from error
        raise RuntimeError(_sync_http_error_message(error)) from error
    except OSError as error:
        raise RuntimeError(_sync_url_error_message(error)) from error


def _normalized_supply_chain_bundle_index_url(bundle_url: str) -> str:
    parsed = urllib.parse.urlsplit(bundle_url)
    return urllib.parse.urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path.rstrip("/") + "/index",
            parsed.query,
            "",
        )
    )


def _supply_chain_partition_bundle_url(bundle_url: str, *, ecosystem: str, partition: int) -> str:
    parsed = urllib.parse.urlsplit(bundle_url)
    query_pairs = [
        (key, value)
        for key, value in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        if key not in {"ecosystem", "partition"}
    ]
    query_pairs.extend((("ecosystem", ecosystem), ("partition", str(partition))))
    return urllib.parse.urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            urllib.parse.urlencode(query_pairs),
            "",
        )
    )


def _sync_supply_chain_bundle_incremental(
    *,
    bundle_url: str,
    cached_bundle_version: str | None,
    auth_context: dict[str, object],
    store: GuardStore,
    trusted_keys: tuple[object, ...],
    workspace_id: str,
) -> dict[str, object] | None:
    index_request = _guard_sync_request(
        auth_context,
        request_url=_normalized_supply_chain_bundle_index_url(bundle_url),
        method="GET",
        data=None,
        extra_headers={"Accept-Encoding": "identity"},
    )
    try:
        index_payload = _fetch_supply_chain_bundle_payload(index_request)
    except RuntimeError:
        return None
    if not isinstance(index_payload, dict):
        return None
    raw_partitions = index_payload.get("partitions")
    if not isinstance(raw_partitions, list) or len(raw_partitions) == 0:
        return None
    cached_partition_payload = store.get_sync_payload("supply_chain_bundle_partition_cache")
    cached_partitions = {}
    if isinstance(cached_partition_payload, dict):
        raw_cached_partitions = cached_partition_payload.get("partitions")
        if isinstance(raw_cached_partitions, dict):
            cached_partitions = raw_cached_partitions
    next_partition_cache: dict[str, object] = {}
    refreshed_partitions = 0
    for descriptor in raw_partitions:
        if not isinstance(descriptor, dict):
            continue
        ecosystem = descriptor.get("ecosystem")
        partition = descriptor.get("partition")
        payload_hash = descriptor.get("payloadHash")
        if not isinstance(ecosystem, str) or not isinstance(partition, int) or not isinstance(payload_hash, str):
            continue
        cache_key = f"{ecosystem}:{partition}"
        cached_partition = cached_partitions.get(cache_key)
        response = None
        if isinstance(cached_partition, dict) and cached_partition.get("payload_hash") == payload_hash:
            raw_cached_response = cached_partition.get("response")
            if isinstance(raw_cached_response, dict):
                try:
                    response = load_supply_chain_bundle_response(raw_cached_response)
                    verify_supply_chain_bundle_response(
                        response,
                        trusted_keys=trusted_keys or None,
                        cached_bundle_version=cached_bundle_version,
                    )
                except SupplyChainBundleError:
                    response = None
        if response is None:
            try:
                partition_request = _guard_sync_request(
                    auth_context,
                    request_url=_supply_chain_partition_bundle_url(
                        bundle_url, ecosystem=ecosystem, partition=partition
                    ),
                    method="GET",
                    data=None,
                    extra_headers={"Accept-Encoding": "identity"},
                )
                partition_payload = _fetch_supply_chain_bundle_payload(partition_request)
                response = load_supply_chain_bundle_response(partition_payload)
                verify_supply_chain_bundle_response(
                    response,
                    trusted_keys=trusted_keys or None,
                    cached_bundle_version=cached_bundle_version,
                )
            except (RuntimeError, SupplyChainBundleError):
                return None
            refreshed_partitions += 1
        next_partition_cache[cache_key] = {
            "payload_hash": payload_hash,
            "response": response.to_dict(),
        }
    if not next_partition_cache:
        return None
    bundle_version = index_payload.get("bundleVersion")
    resolved_bundle_version = bundle_version if isinstance(bundle_version, str) and bundle_version else None
    if resolved_bundle_version is None:
        resolved_bundle_version = cached_bundle_version or ""
    return {
        "cache_payload": {
            "bundle_version": resolved_bundle_version,
            "partitions": next_partition_cache,
            "workspace_id": workspace_id,
        },
        "refreshed_partitions": refreshed_partitions,
        "total_partitions": len(next_partition_cache),
    }


def sync_supply_chain_bundle(store: GuardStore) -> dict[str, object]:
    """Fetch, verify, and persist the active supply-chain bundle for the cloud workspace."""

    auth_context = _resolve_guard_sync_auth_context(store)
    workspace_id = store.get_cloud_workspace_id()
    if workspace_id is None:
        raise GuardSyncNotConfiguredError("Guard Cloud workspace is not connected.")
    bundle_url = _normalized_supply_chain_bundle_url(str(auth_context["sync_url"]), workspace_id)
    cached_bundle = store.get_cached_supply_chain_bundle(workspace_id)
    cached_bundle_version = None
    if isinstance(cached_bundle, dict):
        cached_payload = cached_bundle.get("bundle")
        if isinstance(cached_payload, dict):
            existing_version = cached_payload.get("bundleVersion")
            if isinstance(existing_version, str) and existing_version:
                cached_bundle_version = existing_version
    trusted_keys = load_supply_chain_verification_keys(store.get_sync_payload("supply_chain_bundle_keyring"))
    try:
        partition_sync: dict[str, object] | None = _sync_supply_chain_bundle_incremental(
            bundle_url=bundle_url,
            cached_bundle_version=cached_bundle_version,
            auth_context=auth_context,
            store=store,
            trusted_keys=trusted_keys,
            workspace_id=workspace_id,
        )
    except (RuntimeError, SupplyChainBundleError):
        partition_sync = None
    if (
        partition_sync is not None
        and partition_sync.get("refreshed_partitions") == 0
        and isinstance(cached_bundle, dict)
    ):
        try:
            response = load_supply_chain_bundle_response(cached_bundle)
            verify_supply_chain_bundle_response(
                response,
                trusted_keys=trusted_keys or None,
                cached_bundle_version=cached_bundle_version,
            )
        except SupplyChainBundleError:
            try:
                request = _guard_sync_request(
                    auth_context,
                    request_url=bundle_url,
                    method="GET",
                    data=None,
                    extra_headers={"Accept-Encoding": "identity"},
                )
                payload = _fetch_supply_chain_bundle_payload(request)
                response = load_supply_chain_bundle_response(payload)
                verify_supply_chain_bundle_response(
                    response,
                    trusted_keys=trusted_keys or None,
                    cached_bundle_version=cached_bundle_version,
                )
            except (RuntimeError, SupplyChainBundleError) as error:
                raise RuntimeError(f"Guard supply-chain bundle sync failed: {error}") from error
    else:
        request = _guard_sync_request(
            auth_context,
            request_url=bundle_url,
            method="GET",
            data=None,
            extra_headers={"Accept-Encoding": "identity"},
        )
        payload = _fetch_supply_chain_bundle_payload(request)
        try:
            response = load_supply_chain_bundle_response(payload)
            verify_supply_chain_bundle_response(
                response,
                trusted_keys=trusted_keys or None,
                cached_bundle_version=cached_bundle_version,
            )
        except SupplyChainBundleError as error:
            raise RuntimeError(f"Guard supply-chain bundle sync failed: {error}") from error
    synced_at = _now()
    store.cache_supply_chain_bundle(workspace_id, response.to_dict(), synced_at)
    store.set_sync_payload(
        "supply_chain_bundle_keyring",
        {
            "workspace_id": workspace_id,
            "keys": [item.to_dict() for item in response.verification_keys],
        },
        synced_at,
    )
    store.set_sync_payload(
        "supply_chain_bundle_entitlement",
        {
            "bundle_version": response.bundle.bundle_version,
            "key_id": response.bundle.key_id,
            "policy_hash": response.bundle.policy_hash,
            "tier": response.bundle.tier,
            "workspace_id": workspace_id,
        },
        synced_at,
    )
    if partition_sync is not None:
        store.set_sync_payload(
            "supply_chain_bundle_partition_cache",
            partition_sync["cache_payload"],  # type: ignore[arg-type]
            synced_at,
        )
    summary = {
        "advisory_count": len(response.bundle.advisories),
        "bundle_version": response.bundle.bundle_version,
        "ecosystem_support": list(ecosystem_support_matrix()),
        "feed_snapshot_hash": response.bundle.feed_snapshot_hash,
        "package_count": len(response.bundle.packages),
        "policy_hash": response.bundle.policy_hash,
        "status": "synced",
        "synced_at": synced_at,
        "tier": response.bundle.tier,
        "workspace_id": workspace_id,
    }
    if partition_sync is not None:
        summary["partition_sync"] = {
            "enabled": True,
            "refreshed": partition_sync["refreshed_partitions"],  # type: ignore[index]
            "total": partition_sync["total_partitions"],  # type: ignore[index]
        }
    store.set_sync_payload("supply_chain_bundle_summary", summary, synced_at)
    return summary


def sync_guard_events(
    store: GuardStore,
    *,
    auth_context: dict[str, object] | None = None,
) -> dict[str, object]:
    """Push pending GuardEventV1 envelopes to Guard Cloud."""

    resolved_auth_context = auth_context if auth_context is not None else _resolve_guard_sync_auth_context(store)
    sync_url = _guard_events_sync_url(resolved_auth_context["sync_url"])
    previous_summary = store.get_sync_payload("guard_events_v1_summary")
    total_events = 0
    total_accepted = 0
    synced_at = _now()
    while True:
        pending_events = store.list_guard_events_v1(uploaded=False, limit=200)
        if not pending_events:
            if (
                total_events == 0
                and isinstance(previous_summary, dict)
                and previous_summary.get("sync_reason") == "guard_events_endpoint_unavailable"
                and _guard_events_endpoint_unavailable_recently(store)
            ):
                return previous_summary
            break
        body = json.dumps({"events": [event["payload"] for event in pending_events]}).encode("utf-8")
        request = _guard_sync_request(
            resolved_auth_context,
            request_url=sync_url,
            method="POST",
            data=body,
            extra_headers=None,
        )
        try:
            payload = _urlopen_json_with_timeout_retry(
                request=request,
                timeout_seconds=_SYNC_HTTP_TIMEOUT_SECONDS,
                retry_timeout_seconds=_SYNC_HTTP_RETRY_TIMEOUT_SECONDS,
            )
        except urllib.error.HTTPError as error:
            if error.code == 404:
                skipped_count = _mark_all_guard_events_v1_uploaded(store, synced_at)
                summary = {
                    "synced_at": synced_at,
                    "events": total_events + skipped_count,
                    "accepted": total_accepted,
                    "skipped": skipped_count,
                    "sync_skipped": True,
                    "sync_reason": "guard_events_endpoint_unavailable",
                }
                store.set_sync_payload("guard_events_v1_summary", summary, synced_at)
                return summary
            if error.code == 403:
                is_plan, message = _check_plan_restriction_403(error)
                if is_plan:
                    raise GuardSyncNotAvailableError(message) from error
                _record_guard_events_sync_failure(
                    store,
                    total_events=total_events,
                    total_accepted=total_accepted,
                    pending_count=len(pending_events),
                    error_type=type(error).__name__,
                    message=message,
                )
                raise RuntimeError(message) from error
            message = _sync_http_error_message(error)
            _record_guard_events_sync_failure(
                store,
                total_events=total_events,
                total_accepted=total_accepted,
                pending_count=len(pending_events),
                error_type=type(error).__name__,
                message=message,
            )
            raise RuntimeError(_redact_sync_text(message)) from error
        except OSError as error:
            message = _sync_url_error_message(error)
            _record_guard_events_sync_failure(
                store,
                total_events=total_events,
                total_accepted=total_accepted,
                pending_count=len(pending_events),
                error_type=type(error).__name__,
                message=message,
            )
            raise RuntimeError(_redact_sync_text(message)) from error
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


def _mark_all_guard_events_v1_uploaded(store: GuardStore, uploaded_at: str) -> int:
    total_marked = 0
    while True:
        pending_events = store.list_guard_events_v1(uploaded=False, limit=200)
        if not pending_events:
            break
        event_ids = [str(event["event_id"]) for event in pending_events if isinstance(event.get("event_id"), str)]
        if not event_ids:
            break
        marked = store.mark_guard_events_v1_uploaded(event_ids, uploaded_at)
        total_marked += marked
        if marked == 0:
            break
    return total_marked


def _record_guard_events_sync_failure(
    store: GuardStore,
    *,
    total_events: int,
    total_accepted: int,
    pending_count: int,
    error_type: str,
    message: str,
) -> None:
    recorded_at = _now()
    next_retry_after = (datetime.now(timezone.utc) + timedelta(seconds=_SYNC_HTTP_RETRY_TIMEOUT_SECONDS)).isoformat()
    summary = {
        "synced_at": None,
        "status": "failed",
        "events": total_events,
        "accepted": total_accepted,
        "pending_events": pending_count,
        "error_type": error_type,
        "message": _redact_sync_text(message),
        "retry_after_seconds": _SYNC_HTTP_RETRY_TIMEOUT_SECONDS,
        "next_retry_after": next_retry_after,
    }
    store.set_sync_payload("guard_events_v1_summary", summary, recorded_at)


def _guard_events_endpoint_unavailable_recently(store: GuardStore) -> bool:
    summary = store.get_sync_payload("guard_events_v1_summary")
    if not isinstance(summary, dict):
        return False
    if summary.get("sync_reason") != "guard_events_endpoint_unavailable":
        return False
    synced_at = summary.get("synced_at")
    if not isinstance(synced_at, str):
        return True
    parsed = _parse_iso_timestamp(synced_at)
    if parsed is None:
        return True
    return datetime.now(timezone.utc) - parsed < timedelta(hours=_GUARD_EVENTS_ENDPOINT_UNAVAILABLE_RETRY_HOURS)


def sync_runtime_session(
    store: GuardStore,
    *,
    session: dict[str, object],
    auth_context: dict[str, object] | None = None,
) -> dict[str, object]:
    """Publish the active Guard runtime session so the dashboard can show the machine immediately."""

    resolved_auth_context = auth_context or _resolve_guard_sync_auth_context(store)
    sync_url = _normalized_runtime_sessions_sync_url(resolved_auth_context["sync_url"])
    session_payload = _cloud_runtime_session_payload(store, session)
    body = json.dumps({"session": session_payload}).encode("utf-8")
    request = _guard_sync_request(
        resolved_auth_context,
        request_url=sync_url,
        method="POST",
        data=body,
        extra_headers=None,
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
                "local_guard_online_at": recorded_at,
                "runtime_harness": session_payload["harness"],
                "runtime_surface": session_payload["surface"],
                "runtime_workspace": session_payload["workspace"],
                "runtime_device_id": session_payload["deviceId"],
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
        "local_guard_online_at": synced_at,
        "runtime_harness": session_payload["harness"],
        "runtime_surface": session_payload["surface"],
        "runtime_workspace": session_payload["workspace"],
        "runtime_device_id": session_payload["deviceId"],
    }
    store.set_sync_payload("runtime_session_summary", summary, synced_at)
    workspace_id = store.get_cloud_workspace_id()
    device_id = store.get_or_create_installation_id()
    if not _guard_events_endpoint_unavailable_recently(store):
        store.add_guard_event_v1(
            build_runtime_session_event(
                session_id=str(session_payload["sessionId"]),
                occurred_at=synced_at,
                payload=session_payload,
                workspace_id=workspace_id,
                device_id=device_id,
            )
        )
    return summary


def _local_guard_runtime_session() -> dict[str, object]:
    return {
        "harness": "hol-guard",
        "surface": "cli",
        "status": "active",
        "client_name": "hol-guard",
        "client_title": "HOL Guard CLI",
        "client_version": __version__,
        "workspace": "local-machine",
        "capabilities": ["approval-center", "guard-cloud-sync", "local-daemon"],
    }


def sync_local_guard_cloud_proof(
    store: GuardStore,
    *,
    auth_context: dict[str, object] | None = None,
) -> dict[str, object]:
    """Publish the local Guard runtime session before syncing receipts."""

    resolved_auth_context = auth_context if auth_context is not None else _resolve_guard_sync_auth_context(store)
    runtime_summary = sync_runtime_session(
        store,
        session=_local_guard_runtime_session(),
        auth_context=resolved_auth_context,
    )
    receipts_summary = sync_receipts(
        store,
        persist_sync_summary=False,
        persist_connect_state=False,
        auth_context=resolved_auth_context,
    )
    summary = dict(receipts_summary)
    summary.update(
        {
            "runtime_session_id": runtime_summary.get("runtime_session_id"),
            "runtime_session_synced_at": runtime_summary.get("runtime_session_synced_at"),
            "runtime_sessions_visible": runtime_summary.get("runtime_sessions_visible"),
            "local_guard_online_at": runtime_summary.get("local_guard_online_at")
            or receipts_summary.get("local_guard_online_at"),
            "runtime_harness": runtime_summary.get("runtime_harness"),
            "runtime_surface": runtime_summary.get("runtime_surface"),
            "runtime_workspace": runtime_summary.get("runtime_workspace"),
            "runtime_device_id": runtime_summary.get("runtime_device_id"),
            "runtime": runtime_summary,
            "receipts": dict(receipts_summary),
        }
    )
    recorded_at = str(summary.get("synced_at") or summary.get("runtime_session_synced_at") or _now())
    store.set_sync_payload("sync_summary", summary, recorded_at)
    store.record_latest_guard_connect_sync_success(sync_payload=summary, now=recorded_at)
    return summary


def sync_pain_signals(
    store: GuardStore,
    *,
    auth_context: dict[str, object] | None = None,
) -> int:
    try:
        resolved_auth_context = auth_context or _resolve_guard_sync_auth_context(store)
    except GuardSyncAuthorizationExpiredError:
        raise
    except GuardSyncNotConfiguredError:
        return 0
    normalized_sync_url = _normalized_receipts_sync_url(resolved_auth_context["sync_url"])
    cursor_payload = store.get_sync_payload("pain_signal_cursor")
    last_event_id = _last_uploaded_event_id(cursor_payload)
    uploaded_count = 0
    current_event_id = last_event_id
    warn_occurrences: dict[tuple[str, str], int] = {}
    while True:
        candidates = store.list_events_after(
            current_event_id,
            limit=500,
            event_names=tuple(sorted(_PAIN_SIGNAL_EVENTS)),
        )
        if not candidates:
            break
        last_processed_event_id = int(candidates[-1]["event_id"])
        signal_items: list[dict[str, object]] = []
        for item in candidates:
            event_name = _optional_string(item.get("event_name"))
            payload = item.get("payload")
            if event_name == "install_time_warn" and isinstance(payload, dict):
                warn_key = _warning_occurrence_key(payload)
                if warn_key is not None:
                    warn_occurrences[warn_key] = warn_occurrences.get(warn_key, 0) + 1
            pain_signal = _pain_signal_item(item, warn_occurrences=warn_occurrences)
            if pain_signal is not None:
                signal_items.append(pain_signal)
        if signal_items:
            request = _guard_sync_request(
                resolved_auth_context,
                request_url=_pain_signal_sync_url(normalized_sync_url),
                method="POST",
                data=json.dumps({"items": signal_items}).encode("utf-8"),
                extra_headers=None,
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


def _base64url_encode(data: bytes) -> str:
    return urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _encode_jwt_segment(payload: dict[str, object]) -> str:
    return _base64url_encode(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))


def _dpop_access_token_confirmation_claim(access_token: str) -> str:
    # RFC 9449 requires the DPoP `ath` claim to be the SHA-256 hash of the access token.
    # codeql[py/weak-sensitive-data-hashing]
    digest = hashes.Hash(hashes.SHA256())
    digest.update(access_token.encode("ascii"))
    return _base64url_encode(digest.finalize())


def _sign_guard_dpop_proof(
    *,
    request_url: str,
    method: str,
    dpop_key_material: GuardDpopKeyMaterial,
    access_token: str | None = None,
    nonce: str | None = None,
    now: datetime | None = None,
) -> str:
    issued_at = int((now or datetime.now(timezone.utc)).timestamp())
    header = {
        "alg": dpop_key_material.algorithm,
        "jwk": dpop_key_material.public_jwk,
        "typ": "dpop+jwt",
    }
    claims: dict[str, object] = {
        "htu": request_url,
        "htm": method.upper(),
        "iat": issued_at,
        "jti": str(uuid4()),
    }
    if isinstance(access_token, str) and access_token:
        claims["ath"] = _dpop_access_token_confirmation_claim(access_token)
    if isinstance(nonce, str):
        normalized_nonce = nonce.strip()
        if normalized_nonce:
            claims["nonce"] = normalized_nonce
    signing_input = f"{_encode_jwt_segment(header)}.{_encode_jwt_segment(claims)}".encode("ascii")
    private_key = serialization.load_pem_private_key(
        dpop_key_material.private_key_pem.encode("ascii"),
        password=None,
    )
    if not isinstance(private_key, ec.EllipticCurvePrivateKey) or not isinstance(private_key.curve, ec.SECP256R1):
        raise RuntimeError("Guard DPoP key must be a P-256 (SECP256R1) EC private key.")
    der_signature = private_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    r_value, s_value = decode_dss_signature(der_signature)
    jose_signature = _base64url_encode(r_value.to_bytes(32, byteorder="big") + s_value.to_bytes(32, byteorder="big"))
    return f"{signing_input.decode('ascii')}.{jose_signature}"


def _guard_http_header_value(response: object, header_name: str) -> str | None:
    headers = getattr(response, "headers", None)
    if headers is None:
        return None
    value = headers.get(header_name)
    if value is None:
        header_items = getattr(headers, "items", None)
        if callable(header_items):
            target_header = header_name.lower()
            for current_name, current_value in header_items():
                if isinstance(current_name, str) and current_name.lower() == target_header:
                    value = current_value
                    break
    if not isinstance(value, str):
        return None
    normalized_value = value.strip()
    return normalized_value or None


def _http_error_payload(error: urllib.error.HTTPError) -> object:
    try:
        raw_body = error.read()
    except OSError:
        raw_body = b""
    error.fp = io.BytesIO(raw_body)
    if not raw_body:
        return None
    try:
        return json.loads(raw_body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None


def _dpop_nonce_from_http_error(error: urllib.error.HTTPError, payload: object) -> str | None:
    if error.code not in {400, 401}:
        return None
    nonce = _guard_http_header_value(error, "DPoP-Nonce")
    if nonce is None:
        return None
    if isinstance(payload, dict):
        oauth_error = str(payload.get("error") or "").strip()
        if oauth_error and oauth_error not in {"use_dpop_nonce", "invalid_dpop_proof"}:
            return None
    return nonce


_GUARD_DPOP_REQUEST_CONTEXTS: dict[str, dict[str, object]] = {}
_GUARD_DPOP_REQUEST_CONTEXT_LIMIT = 1000


def _remember_guard_dpop_request_context(dpop_header: str, context: dict[str, object]) -> None:
    if len(_GUARD_DPOP_REQUEST_CONTEXTS) >= _GUARD_DPOP_REQUEST_CONTEXT_LIMIT:
        oldest_header = next(iter(_GUARD_DPOP_REQUEST_CONTEXTS), None)
        if isinstance(oldest_header, str):
            _GUARD_DPOP_REQUEST_CONTEXTS.pop(oldest_header, None)
    _GUARD_DPOP_REQUEST_CONTEXTS[dpop_header] = context


def _guard_sync_request(
    auth_context: dict[str, object],
    *,
    request_url: str,
    method: str,
    data: bytes | None = None,
    extra_headers: dict[str, str] | None = None,
    dpop_nonce: str | None = None,
) -> urllib.request.Request:
    headers = _guard_sync_headers(
        auth_context,
        request_url=request_url,
        method=method,
        extra_headers=extra_headers,
        dpop_nonce=dpop_nonce,
    )
    request = urllib.request.Request(
        request_url,
        data=data,
        method=method,
        headers=headers,
    )
    request._guard_dpop_retry_context = {
        "auth_context": auth_context,
        "request_url": request_url,
        "method": method,
        "extra_headers": None if extra_headers is None else dict(extra_headers),
        "dpop_nonce": dpop_nonce,
    }
    return request


def _oauth_refresh_error_message(error: urllib.error.HTTPError) -> str:
    try:
        raw_body = error.read().decode("utf-8")
    except OSError:
        raw_body = ""
    try:
        payload = json.loads(raw_body) if raw_body else None
    except json.JSONDecodeError:
        payload = None
    if isinstance(payload, dict):
        description = _optional_string(payload.get("error_description"))
        if description is not None:
            return description
        error_code = _optional_string(payload.get("error"))
        if error_code is not None:
            return error_code
    normalized_body = raw_body.strip()
    if normalized_body:
        return normalized_body
    return f"HTTP Error {error.code}: {error.reason}"


def _guard_oauth_reauthorization_message() -> str:
    return "Guard authorization expired. Run `hol-guard connect` to sign in again."


def _guard_sync_reconnect_message() -> str:
    return "Guard Cloud sync endpoint is not trusted. Run `hol-guard connect` to restore Cloud sync."


def _validate_guard_sync_url(sync_url: str, *, issuer: str | None = None) -> str:
    try:
        return validate_guard_sync_endpoint(sync_url, issuer=issuer)
    except ValueError as error:
        if issuer is not None:
            raise GuardSyncAuthorizationExpiredError(f"{_guard_oauth_reauthorization_message()} {error}") from error
        raise GuardSyncNotConfiguredError(f"{_guard_sync_reconnect_message()} {error}") from error


def _refresh_guard_oauth_access_token(
    *,
    token_endpoint: str,
    client_id: str,
    refresh_token: str,
    dpop_key_material: GuardDpopKeyMaterial,
) -> dict[str, object]:
    request_body = urllib.parse.urlencode(
        {
            "grant_type": "refresh_token",
            "client_id": client_id,
            "refresh_token": refresh_token,
        }
    ).encode("utf-8")
    dpop_nonce: str | None = None
    nonce_retry_count = 0
    while True:
        request = urllib.request.Request(
            token_endpoint,
            data=request_body,
            method="POST",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
                "User-Agent": _GUARD_SYNC_USER_AGENT,
                "DPoP": _sign_guard_dpop_proof(
                    request_url=token_endpoint,
                    method="POST",
                    dpop_key_material=dpop_key_material,
                    nonce=dpop_nonce,
                ),
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=_SYNC_HTTP_TIMEOUT_SECONDS) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as error:
            payload = _http_error_payload(error) if error.code in {400, 401} else None
            challenge_nonce = _dpop_nonce_from_http_error(error, payload)
            if challenge_nonce is not None and challenge_nonce != dpop_nonce and nonce_retry_count < 3:
                dpop_nonce = challenge_nonce
                nonce_retry_count += 1
                continue
            refresh_error_message = _oauth_refresh_error_message(error)
            if error.code in {400, 401, 403}:
                raise GuardSyncAuthorizationExpiredError(
                    f"{_guard_oauth_reauthorization_message()} {refresh_error_message}"
                ) from error
            raise RuntimeError(f"Guard OAuth token refresh failed: {refresh_error_message}") from error
        except OSError as error:
            raise RuntimeError(_sync_url_error_message(error)) from error
        if not isinstance(payload, dict):
            raise GuardSyncAuthorizationExpiredError(_guard_oauth_reauthorization_message())
        access_token = _optional_string(payload.get("access_token"))
        token_type = _optional_string(payload.get("token_type"))
        if access_token is None or token_type is None or token_type.lower() not in {"bearer", "dpop"}:
            raise GuardSyncAuthorizationExpiredError(_guard_oauth_reauthorization_message())
        return {
            "access_token": access_token,
            "package_firewall_entitlement": build_oauth_package_firewall_entitlement(
                payload,
                now=datetime.now(timezone.utc),
            ),
            "refresh_token": _optional_string(payload.get("refresh_token")) or refresh_token,
        }


def _oauth_sync_url_from_issuer(issuer: str) -> str:
    oauth_client = resolve_guard_oauth_client_config(issuer)
    return f"{oauth_client.issuer}/api/guard/receipts/sync"


def _oauth_dpop_key_material(credentials: dict[str, object]) -> GuardDpopKeyMaterial:
    dpop_private_key_pem = _optional_string(credentials.get("dpop_private_key_pem"))
    dpop_public_jwk = credentials.get("dpop_public_jwk")
    dpop_public_jwk_thumbprint = _optional_string(credentials.get("dpop_public_jwk_thumbprint"))
    if dpop_private_key_pem is None or not isinstance(dpop_public_jwk, dict) or dpop_public_jwk_thumbprint is None:
        raise GuardSyncAuthorizationExpiredError(_guard_oauth_reauthorization_message())
    return GuardDpopKeyMaterial(
        algorithm="ES256",
        private_key_pem=dpop_private_key_pem,
        public_jwk={str(key): str(value) for key, value in dpop_public_jwk.items()},
        public_jwk_thumbprint=dpop_public_jwk_thumbprint,
    )


def _persist_rotated_oauth_refresh_token(
    *,
    store: GuardStore,
    credentials: dict[str, object],
    package_firewall_entitlement: dict[str, object] | None = None,
    refresh_token: str,
) -> None:
    issuer = _optional_string(credentials.get("issuer"))
    client_id = _optional_string(credentials.get("client_id"))
    dpop_private_key_pem = _optional_string(credentials.get("dpop_private_key_pem"))
    dpop_public_jwk = credentials.get("dpop_public_jwk")
    dpop_public_jwk_thumbprint = _optional_string(credentials.get("dpop_public_jwk_thumbprint"))
    if (
        issuer is None
        or client_id is None
        or dpop_private_key_pem is None
        or not isinstance(dpop_public_jwk, dict)
        or dpop_public_jwk_thumbprint is None
    ):
        raise GuardSyncAuthorizationExpiredError(_guard_oauth_reauthorization_message())
    store.set_oauth_local_credentials(
        issuer=issuer,
        client_id=client_id,
        refresh_token=refresh_token,
        dpop_private_key_pem=dpop_private_key_pem,
        dpop_public_jwk={str(key): str(value) for key, value in dpop_public_jwk.items()},
        dpop_public_jwk_thumbprint=dpop_public_jwk_thumbprint,
        grant_id=_optional_string(credentials.get("grant_id")),
        machine_id=_optional_string(credentials.get("machine_id")),
        supply_chain_entitlement_expires_at=(
            _optional_string(package_firewall_entitlement.get("supply_chain_entitlement_expires_at"))
            if isinstance(package_firewall_entitlement, dict)
            else _optional_string(credentials.get("supply_chain_entitlement_expires_at"))
        ),
        supply_chain_firewall=(
            package_firewall_entitlement.get("supply_chain_firewall")
            if isinstance(package_firewall_entitlement, dict)
            and isinstance(package_firewall_entitlement.get("supply_chain_firewall"), bool)
            else (
                credentials.get("supply_chain_firewall")
                if isinstance(credentials.get("supply_chain_firewall"), bool)
                else None
            )
        ),
        supply_chain_plan_id=(
            _optional_string(package_firewall_entitlement.get("supply_chain_plan_id"))
            if isinstance(package_firewall_entitlement, dict)
            else _optional_string(credentials.get("supply_chain_plan_id"))
        ),
        workspace_id=_optional_string(credentials.get("workspace_id")),
        now=_now(),
    )


def _resolve_guard_sync_auth_context_from_oauth_credentials(
    store: GuardStore,
    oauth_credentials: dict[str, object],
    *,
    persist_recovered_secret: bool = False,
) -> dict[str, object]:
    issuer = _optional_string(oauth_credentials.get("issuer"))
    client_id = _optional_string(oauth_credentials.get("client_id"))
    refresh_token = _optional_string(oauth_credentials.get("refresh_token"))
    if issuer is None or client_id is None or refresh_token is None:
        raise GuardSyncAuthorizationExpiredError(_guard_oauth_reauthorization_message())
    dpop_key_material = _oauth_dpop_key_material(oauth_credentials)
    try:
        oauth_client = resolve_guard_oauth_client_config(issuer)
    except ValueError as error:
        raise GuardSyncAuthorizationExpiredError(f"{_guard_oauth_reauthorization_message()} {error}") from error
    refreshed = _refresh_guard_oauth_access_token(
        token_endpoint=oauth_client.token_endpoint,
        client_id=client_id,
        refresh_token=refresh_token,
        dpop_key_material=dpop_key_material,
    )
    rotated_refresh_token = str(refreshed["refresh_token"])
    package_firewall_entitlement = (
        refreshed["package_firewall_entitlement"]
        if isinstance(refreshed.get("package_firewall_entitlement"), dict)
        else None
    )
    if rotated_refresh_token != refresh_token or package_firewall_entitlement is not None or persist_recovered_secret:
        _persist_rotated_oauth_refresh_token(
            store=store,
            credentials=oauth_credentials,
            package_firewall_entitlement=package_firewall_entitlement,
            refresh_token=rotated_refresh_token,
        )
    sync_url = _validate_guard_sync_url(
        _oauth_sync_url_from_issuer(oauth_client.issuer),
        issuer=oauth_client.issuer,
    )
    return {
        "sync_url": sync_url,
        "access_token": str(refreshed["access_token"]),
        "dpop_key_material": dpop_key_material,
    }


def _resolve_guard_sync_auth_context(store: GuardStore) -> dict[str, object]:
    with _guard_sync_auth_lock(store):
        oauth_health = store.get_oauth_local_credential_health()
        oauth_credentials = store.get_oauth_local_credentials()
        if oauth_credentials is not None:
            return _resolve_guard_sync_auth_context_from_oauth_credentials(store, oauth_credentials)
        if bool(oauth_health.get("configured")):
            recoverable_credentials = store.get_recoverable_oauth_local_credentials()
            if recoverable_credentials is not None:
                return _resolve_guard_sync_auth_context_from_oauth_credentials(
                    store,
                    recoverable_credentials,
                    persist_recovered_secret=True,
                )
            raise GuardSyncAuthorizationExpiredError(_guard_oauth_reauthorization_message())
        credentials = store.get_sync_credentials()
        if credentials is None:
            raise GuardSyncNotConfiguredError("Guard is not logged in.")
        return {
            "sync_url": _validate_guard_sync_url(str(credentials["sync_url"])),
            "access_token": str(credentials["token"]),
            "dpop_key_material": None,
        }


def _guard_sync_headers(
    auth_context: dict[str, object],
    *,
    request_url: str,
    method: str,
    extra_headers: dict[str, str] | None = None,
    dpop_nonce: str | None = None,
) -> dict[str, str]:
    access_token = str(auth_context["access_token"])
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": _GUARD_SYNC_USER_AGENT,
    }
    dpop_key_material = auth_context.get("dpop_key_material")
    if isinstance(dpop_key_material, GuardDpopKeyMaterial):
        dpop_header = _sign_guard_dpop_proof(
            request_url=request_url,
            method=method,
            dpop_key_material=dpop_key_material,
            access_token=access_token,
            nonce=dpop_nonce,
        )
        headers["DPoP"] = dpop_header
        _remember_guard_dpop_request_context(
            dpop_header,
            {
                "auth_context": auth_context,
                "request_url": request_url,
                "method": method,
                "extra_headers": None if extra_headers is None else dict(extra_headers),
                "dpop_nonce": dpop_nonce,
            },
        )
    if isinstance(extra_headers, dict):
        headers.update(extra_headers)
    return headers


def _guard_sync_request_with_nonce(
    request: urllib.request.Request,
    dpop_nonce: str,
) -> urllib.request.Request | None:
    request_context = getattr(request, "_guard_dpop_retry_context", None)
    if not isinstance(request_context, dict):
        current_dpop = request.get_header("DPoP")
        if not isinstance(current_dpop, str):
            for header_name, header_value in request.header_items():
                if header_name.lower() == "dpop":
                    current_dpop = header_value
                    break
        if not isinstance(current_dpop, str):
            return None
        request_context = _GUARD_DPOP_REQUEST_CONTEXTS.get(current_dpop)
        if not isinstance(request_context, dict):
            return None
    auth_context = request_context.get("auth_context")
    request_url = request_context.get("request_url")
    method = request_context.get("method")
    extra_headers = request_context.get("extra_headers")
    current_dpop_nonce = request_context.get("dpop_nonce")
    if not isinstance(auth_context, dict) or not isinstance(request_url, str) or not isinstance(method, str):
        return None
    if extra_headers is not None and not isinstance(extra_headers, dict):
        return None
    if current_dpop_nonce == dpop_nonce:
        return None
    return _guard_sync_request(
        auth_context,
        request_url=request_url,
        method=method,
        data=request.data,
        extra_headers=None if extra_headers is None else {str(key): str(value) for key, value in extra_headers.items()},
        dpop_nonce=dpop_nonce,
    )


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


def _redact_sync_text(value: str) -> str:
    return redact_sensitive_text(value)


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
    current_request = request
    current_timeout_seconds = timeout_seconds
    retried_timeout = False
    nonce_retry_count = 0
    while True:
        try:
            with urllib.request.urlopen(current_request, timeout=current_timeout_seconds) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as error:
            error_payload = _http_error_payload(error) if error.code in {400, 401} else None
            dpop_nonce = _dpop_nonce_from_http_error(error, error_payload)
            retry_request = (
                None
                if dpop_nonce is None or nonce_retry_count >= 3
                else _guard_sync_request_with_nonce(current_request, dpop_nonce)
            )
            if retry_request is not None:
                nonce_retry_count += 1
                current_request = retry_request
                current_timeout_seconds = timeout_seconds
                retried_timeout = False
                continue
            raise
        except OSError as error:
            if not retried_timeout and _is_timeout_error(error):
                current_timeout_seconds = retry_timeout_seconds
                retried_timeout = True
                continue
            raise
        if not isinstance(payload, dict):
            raise RuntimeError("Guard Cloud sync returned an invalid response payload.")
        return payload


def _urlopen_with_timeout_retry(
    *,
    request: urllib.request.Request,
    timeout_seconds: int,
    retry_timeout_seconds: int,
) -> None:
    current_request = request
    current_timeout_seconds = timeout_seconds
    retried_timeout = False
    nonce_retry_count = 0
    while True:
        try:
            with urllib.request.urlopen(current_request, timeout=current_timeout_seconds):
                return
        except urllib.error.HTTPError as error:
            error_payload = _http_error_payload(error) if error.code in {400, 401} else None
            dpop_nonce = _dpop_nonce_from_http_error(error, error_payload)
            retry_request = (
                None
                if dpop_nonce is None or nonce_retry_count >= 3
                else _guard_sync_request_with_nonce(current_request, dpop_nonce)
            )
            if retry_request is not None:
                nonce_retry_count += 1
                current_request = retry_request
                current_timeout_seconds = timeout_seconds
                retried_timeout = False
                continue
            raise
        except OSError as error:
            if not retried_timeout and _is_timeout_error(error):
                current_timeout_seconds = retry_timeout_seconds
                retried_timeout = True
                continue
            raise


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


def _pain_signal_item(
    event: dict[str, object],
    *,
    warn_occurrences: dict[tuple[str, str], int] | None = None,
) -> dict[str, object] | None:
    event_name = _optional_string(event.get("event_name"))
    payload = event.get("payload")
    occurred_at = _optional_string(event.get("occurred_at"))
    if event_name is None or not isinstance(payload, dict) or occurred_at is None:
        return None
    artifact_id, artifact_name = _pain_signal_artifact_identity(event_name, payload)
    if artifact_id is None or artifact_name is None:
        return None
    if not _should_emit_pain_signal(
        event_name=event_name,
        payload=payload,
        warn_occurrences=warn_occurrences,
    ):
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


def _build_value_metrics(store: GuardStore) -> dict[str, dict[str, object]]:
    events = store.list_events(limit=5000)
    installs_stopped = 0
    scripts_prevented = 0
    tokens_protected = 0
    for event in events:
        event_name = _optional_string(event.get("event_name")) or ""
        payload = event.get("payload")
        if not isinstance(payload, dict):
            continue
        if event_name in {"install_time_block", "install_time_review"}:
            installs_stopped += 1
            install_kind = (_optional_string(payload.get("install_kind")) or "").lower()
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
            "source": "guard_events:install_time_block|install_time_review",
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
    installs_stopped = int(metrics["installs_stopped_before_execution"]["value"])
    scripts_prevented = int(metrics["scripts_prevented"]["value"])
    tokens_protected = int(metrics["tokens_protected"]["value"])
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
    artifact_id = _optional_string(payload.get("artifact_id"))
    artifact_name = _optional_string(payload.get("artifact_name"))
    if artifact_id is not None and artifact_name is not None:
        return (artifact_id, artifact_name)
    if event_name == "supply_chain_bundle_refresh_requested":
        fallback_id = artifact_id or "guard:supply-chain:feed"
        return (fallback_id, artifact_name or fallback_id)
    if event_name == "approval_gate/remote_policy_sync_blocked":
        return ("guard:policy:disable", "remote policy sync disabled")
    return (None, None)


def _warning_occurrence_key(payload: dict[str, object]) -> tuple[str, str] | None:
    artifact_id = _optional_string(payload.get("artifact_id"))
    harness = _optional_string(payload.get("harness")) or _optional_string(payload.get("executor"))
    if artifact_id is None or harness is None:
        return None
    return (harness, artifact_id)


def _should_emit_pain_signal(
    *,
    event_name: str,
    payload: dict[str, object],
    warn_occurrences: dict[tuple[str, str], int] | None,
) -> bool:
    if event_name in {"install_time_block", "install_time_review"}:
        return True
    if event_name == "install_time_warn":
        warn_key = _warning_occurrence_key(payload)
        if warn_key is None:
            return False
        if warn_occurrences is None:
            return False
        return warn_occurrences.get(warn_key, 0) >= 2
    if event_name == "changed_artifact_caught":
        policy_action = _optional_string(payload.get("policy_action"))
        return policy_action in {"block", "sandbox-required", "require-reapproval"}
    if event_name == "supply_chain_bundle_refresh_requested":
        reason = _optional_string(payload.get("reason"))
        return reason == "feed_stale"
    return event_name == "approval_gate/remote_policy_sync_blocked"


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
                "/registry/api/v1/guard/receipts/sync",
                parsed.query,
                "",
            )
        )
    return sync_url


def _normalized_runtime_sessions_sync_url(sync_url: str) -> str:
    normalized_receipts_url = _normalized_receipts_sync_url(sync_url)
    parsed = urllib.parse.urlsplit(normalized_receipts_url)
    if parsed.path.rstrip("/") == "/registry/api/v1/guard/receipts/sync":
        return urllib.parse.urlunsplit(
            (
                parsed.scheme,
                parsed.netloc,
                "/registry/api/v1/guard/runtime/sessions/sync",
                parsed.query,
                "",
            )
        )
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


def _normalized_supply_chain_bundle_url(sync_url: str, workspace_id: str) -> str:
    normalized_receipts_url = _normalized_receipts_sync_url(sync_url)
    parsed = urllib.parse.urlsplit(normalized_receipts_url)
    if parsed.path.rstrip("/") == "/registry/api/v1/guard/receipts/sync":
        next_path = "/registry/api/v1/guard/supply-chain/bundle"
    elif parsed.path.rstrip("/") == "/api/guard/receipts/sync":
        next_path = "/api/guard/supply-chain/bundle"
    elif parsed.path.rstrip("/") == "/guard/receipts/sync":
        next_path = "/guard/supply-chain/bundle"
    else:
        next_path = parsed.path.rstrip("/") + "/supply-chain/bundle"
    query_pairs = [
        (key, value)
        for key, value in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        if key != "workspaceId"
    ]
    query_pairs.append(("workspaceId", workspace_id))
    return urllib.parse.urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            next_path,
            urllib.parse.urlencode(query_pairs),
            "",
        )
    )


def _guard_events_sync_url(sync_url: str) -> str:
    parsed = urllib.parse.urlsplit(_normalized_receipts_sync_url(sync_url))
    if parsed.path.rstrip("/").endswith("/api/v1/guard/events"):
        return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), parsed.query, ""))
    path = parsed.path.rstrip("/")
    for suffix in (
        "/registry/api/v1/guard/receipts/sync",
        "/api/guard/receipts/sync",
        "/guard/receipts/sync",
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


def _cloud_sync_receipts_payload(
    receipts: list[dict[str, object]],
    *,
    device_id: str,
    device_name: str,
) -> list[dict[str, object]]:
    return [_cloud_sync_receipt_payload(receipt, device_id=device_id, device_name=device_name) for receipt in receipts]


def _dedupe_sync_payload_items(items: list[dict[str, object]]) -> list[dict[str, object]]:
    seen: set[str] = set()
    deduped: list[dict[str, object]] = []
    for item in items:
        fingerprint = json.dumps(item, sort_keys=True)
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        deduped.append(item)
    return deduped


def _iter_receipt_sync_batches(receipts: list[dict[str, object]]) -> tuple[list[dict[str, object]], ...]:
    if not receipts:
        return ([],)
    return tuple(
        receipts[index : index + _RECEIPT_SYNC_BATCH_SIZE]
        for index in range(0, len(receipts), _RECEIPT_SYNC_BATCH_SIZE)
    )


def _receipt_sync_cursor_rowid(store: GuardStore) -> int | None:
    payload = store.get_sync_payload("receipt_sync_cursor")
    if not isinstance(payload, dict):
        return None
    value = payload.get("last_rowid")
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, str):
        stripped = value.strip()
        if stripped.isdigit():
            return int(stripped)
    return None


def _receipt_sync_rows_for_upload(store: GuardStore, *, cursor_rowid: int | None) -> list[dict[str, object]]:
    if cursor_rowid is None:
        return store.list_receipts(limit=_RECEIPT_SYNC_CURSOR_PAGE_SIZE)
    latest_rowid = store.latest_receipt_rowid()
    if latest_rowid is None:
        return []
    if cursor_rowid > latest_rowid:
        backfill_after = max(latest_rowid - _RECEIPT_SYNC_CURSOR_BACKFILL_ROWS, 0)
        return store.list_receipts_since_rowid(after_rowid=backfill_after, limit=_RECEIPT_SYNC_CURSOR_PAGE_SIZE)
    return store.list_receipts_since_rowid(after_rowid=cursor_rowid, limit=_RECEIPT_SYNC_CURSOR_PAGE_SIZE)


def _receipt_sync_context(
    store: GuardStore,
    *,
    local_guard_online_at: str,
    device_id: str | None = None,
    device_name: str | None = None,
) -> dict[str, object]:
    resolved_device_id = device_id
    resolved_device_name = device_name
    if resolved_device_id is None or resolved_device_name is None:
        resolved_device_id, resolved_device_name = _guard_device_metadata(store)
    runtime_summary = store.get_sync_payload("runtime_session_summary")
    runtime_synced_at = (
        _optional_string(runtime_summary.get("runtime_session_synced_at"))
        if isinstance(runtime_summary, dict)
        else None
    )
    runtime_harness = (
        _optional_string(runtime_summary.get("runtime_harness")) if isinstance(runtime_summary, dict) else None
    )
    sync_health = "healthy" if runtime_synced_at is not None else "degraded"
    policy_bundle_ack = store.get_sync_payload("policy_bundle_ack")
    context: dict[str, object] = {
        "deviceId": resolved_device_id,
        "deviceName": resolved_device_name,
        "harness": runtime_harness or "hol-guard",
        "localGuardOnlineAt": local_guard_online_at,
        "syncHealth": sync_health,
    }
    if isinstance(policy_bundle_ack, dict) and policy_bundle_ack:
        context["policyBundleAcknowledgement"] = policy_bundle_ack
    if runtime_synced_at is not None:
        context["lastRuntimeSyncAt"] = runtime_synced_at
    return context


def _persist_receipt_sync_cursor(
    *,
    store: GuardStore,
    latest_uploaded_rowid: int | None,
    synced_at: str,
) -> None:
    if latest_uploaded_rowid is None:
        return
    payload = {
        "last_rowid": latest_uploaded_rowid,
        "synced_at": synced_at,
    }
    store.set_sync_payload("receipt_sync_cursor", payload, synced_at)


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
        capabilities = [
            _cloud_sync_sanitize_text(item, fallback="redacted-capability") for item in changed_capabilities
        ]
    elif capabilities_summary is not None:
        capabilities = [_cloud_sync_sanitize_text(capabilities_summary, fallback="redacted-capability")]
    else:
        capabilities = []
    summary_input = (
        _optional_string(receipt.get("provenance_summary"))
        or capabilities_summary
        or f"Guard recorded a {policy_decision} decision."
    )
    summary = _cloud_sync_sanitize_text(summary_input, fallback=f"Guard recorded a {policy_decision} decision.")
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
        or policy_decision in {"review", "require-reapproval", "sandbox-required"},
        "deviceId": device_id,
        "deviceName": device_name,
        "harness": _optional_string(receipt.get("harness")) or "unknown",
        "policyDecision": policy_decision,
        "recommendation": _cloud_sync_recommendation(policy_decision),
        "summary": summary,
    }
    publisher = _optional_string(receipt.get("publisher"))
    if publisher is not None:
        payload["publisher"] = publisher
    redacted_envelope = receipt.get("envelope_redacted_json")
    if isinstance(redacted_envelope, dict) and redacted_envelope:
        payload["envelopeRedacted"] = redacted_envelope
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
    package_manager_coverage = _cloud_package_manager_coverage(
        store,
        workspace=workspace,
        generated_at=updated_at,
    )
    local_identity = _cloud_local_identity_payload(observed_at=updated_at)
    return {
        "sessionId": session_id,
        "harness": _optional_string(session.get("harness")) or "hol-guard",
        "surface": _optional_string(session.get("surface")) or "cli",
        "status": _optional_string(session.get("status")) or "active",
        "clientName": _optional_string(session.get("client_name") or session.get("clientName")) or "hol-guard",
        "clientTitle": _optional_string(session.get("client_title") or session.get("clientTitle"))
        or f"HOL Guard on {device_name}",
        "clientVersion": _optional_string(session.get("client_version") or session.get("clientVersion")) or __version__,
        "deviceId": device_id,
        "deviceName": device_name,
        "localIdentity": local_identity,
        "localIdentitySource": _cloud_local_identity_source_payload(local_identity),
        "packageManagerCoverage": package_manager_coverage,
        "workspace": workspace,
        "capabilities": capabilities,
        "operations": [],
        "createdAt": created_at,
        "updatedAt": updated_at,
    }


def _cloud_local_identity_payload(*, observed_at: str) -> dict[str, object]:
    hostname = _safe_hostname()
    private_ip = _safe_private_ip()
    if private_ip is None:
        private_ip = _safe_private_ipv6()
    payload: dict[str, object] = {"lastSyncedAt": observed_at}
    if hostname is not None:
        payload["hostname"] = hostname
    if private_ip is not None:
        payload["ipAddress"] = private_ip
        payload["privateIpAddress"] = private_ip
    return payload


def _cloud_local_identity_source_payload(local_identity: dict[str, object]) -> dict[str, str]:
    source: dict[str, str] = {
        "daemonId": "local-guard",
        "daemonVersion": "local-guard",
        "daemonStatus": "local-guard",
        "relayState": "local-guard",
    }
    if "hostname" in local_identity:
        source["hostname"] = "local-guard"
    if "ipAddress" in local_identity:
        source["ipAddress"] = "local-guard"
    if "privateIpAddress" in local_identity:
        source["privateIpAddress"] = "local-guard"
    if "publicIpAddress" in local_identity:
        source["publicIpAddress"] = "local-guard"
    return source


def _safe_hostname() -> str | None:
    with suppress(OSError):
        hostname = socket.gethostname().strip()
        if hostname:
            return hostname[:255]
    return None


def _safe_private_ip() -> str | None:
    with suppress(OSError), socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect(("8.8.8.8", 80))
        address = sock.getsockname()[0]
        if isinstance(address, str) and address and not address.startswith("127."):
            return address[:128]
    with suppress(OSError):
        address = socket.gethostbyname(socket.gethostname())
        if address and not address.startswith("127."):
            return address[:128]
    return None


def _safe_private_ipv6() -> str | None:
    with suppress(OSError):
        addresses = socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET6)
        for entry in addresses:
            candidate = entry[4][0]
            if isinstance(candidate, str) and candidate and candidate != "::1":
                return candidate[:128]
    return None


def _cloud_sync_receipt_fingerprint(receipt: dict[str, object]) -> str:
    encoded_receipt = json.dumps(receipt, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded_receipt.encode("utf-8")).hexdigest()


def _cloud_package_manager_coverage(
    store: GuardStore,
    *,
    workspace: str,
    generated_at: str,
) -> dict[str, object]:
    coverage = package_shim_cloud_coverage(
        HarnessContext(
            home_dir=Path.home(),
            workspace_dir=Path(workspace),
            guard_home=store.guard_home,
        ),
        generated_at=generated_at,
    )
    summary = store.get_sync_payload("supply_chain_bundle_summary")
    synced_at = None
    next_refresh_at = None
    if isinstance(summary, dict):
        synced_at = _optional_string(summary.get("synced_at") or summary.get("syncedAt"))
        next_refresh_at = _optional_string(summary.get("next_refresh_at") or summary.get("nextRefreshAt"))
    reference_timestamp = _parse_iso_timestamp(generated_at) or datetime.now(timezone.utc)
    stale_status = "unknown"
    if synced_at is not None:
        stale_status = "fresh"
    next_refresh_timestamp = _parse_iso_timestamp(next_refresh_at) if next_refresh_at is not None else None
    if next_refresh_timestamp is None and synced_at is not None:
        next_refresh_timestamp = _parse_iso_timestamp(synced_at)
        if next_refresh_timestamp is not None:
            next_refresh_timestamp += timedelta(minutes=15)
            next_refresh_at = next_refresh_timestamp.isoformat()
    if next_refresh_timestamp is not None and next_refresh_timestamp <= reference_timestamp:
        stale_status = "stale"
    coverage["staleIntel"] = {
        "status": stale_status,
        "lastSyncedAt": synced_at,
        "nextRefreshAt": next_refresh_at,
    }
    return coverage


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


def _cloud_sync_sanitize_text(value: str, *, fallback: str) -> str:
    redacted = redact_sensitive_text(value).strip()
    if not redacted:
        return fallback
    if _looks_like_source_excerpt(redacted):
        return fallback
    if len(redacted) > 320:
        return f"{redacted[:317]}..."
    return redacted


def _looks_like_source_excerpt(value: str) -> bool:
    lowered = value.lower()
    suspicious_tokens = (
        "function ",
        "def ",
        "class ",
        "import ",
        "from ",
        " => ",
        "console.log(",
        "<script",
        "#!/bin/",
    )
    has_structured_code_shape = "\n" in value and ("{" in value or "}" in value or ";" in value)
    return has_structured_code_shape or any(token in lowered for token in suspicious_tokens)


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
