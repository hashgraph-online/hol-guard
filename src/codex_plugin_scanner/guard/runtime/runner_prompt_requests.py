"""Prompt requests.

Shared state and replaceable dependencies belong to the runner facade.
"""

from __future__ import annotations

from . import runner


def _write_detector_debug_trace(
    config: runner.GuardConfig,
    action_envelope: runner.GuardActionEnvelope,
    result: runner.DetectorRunResult,
) -> dict[str, object] | None:
    created_at = runner.datetime.now(runner.timezone.utc)
    action_payload = action_envelope.to_dict()
    trace_payload = {
        "schema_version": 1,
        "created_at": created_at.isoformat(),
        "action": runner._redact_detector_debug_payload(action_payload),
        "signals": [signal.to_dict() for signal in result.signals],
        "telemetry": [item.to_dict() for item in result.telemetry],
    }
    trace_dir = config.guard_home / "debug" / "detectors"
    action_digest = runner.hashlib.sha256(
        runner.json.dumps(action_payload, sort_keys=True, default=str).encode("utf-8"),
    ).hexdigest()[:12]
    trace_path = trace_dir / f"{created_at.strftime('%Y%m%dT%H%M%S%fZ')}-{action_digest}.json"
    try:
        trace_dir.mkdir(parents=True, exist_ok=True)
        trace_path.write_text(runner.json.dumps(trace_payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
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
                redacted[key_text] = runner._redact_detector_debug_payload(item)
        return redacted
    if isinstance(value, (tuple, list)):
        return [runner._redact_detector_debug_payload(item) for item in value]
    return value


def _guard_run_config_paths(
    *,
    detection: runner.HarnessDetection,
    context: runner.HarnessContext,
    passthrough_args: list[str],
) -> list[str]:
    if detection.config_paths:
        return list(detection.config_paths)
    prompt_text = " ".join(value.strip() for value in passthrough_args if value.strip())
    if prompt_text:
        return [str(runner._prompt_policy_path(detection, context))]
    return []


def _detection_with_prompt_artifacts(
    detection: runner.HarnessDetection,
    context: runner.HarnessContext,
    passthrough_args: list[str],
) -> runner.HarnessDetection:
    prompt_text = " ".join(value.strip() for value in passthrough_args if value.strip())
    prompt_requests = runner.extract_prompt_requests(prompt_text)
    if not prompt_requests:
        return detection
    prompt_artifacts = runner.prompt_requests_to_artifacts(
        detection=detection,
        context=context,
        requests=prompt_requests,
    )
    return runner.HarnessDetection(
        harness=detection.harness,
        installed=detection.installed,
        command_available=detection.command_available,
        config_paths=detection.config_paths,
        artifacts=(*detection.artifacts, *prompt_artifacts),
        warnings=detection.warnings,
    )


def extract_prompt_requests(prompt_text: str) -> list[runner.PromptRequest]:
    """Extract structured prompt intent requests from passthrough arguments."""

    normalized_prompt = " ".join(prompt_text.split())
    lowered = normalized_prompt.lower()
    if not lowered:
        return []
    requests: list[runner.PromptRequest] = []
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
            runner.PromptRequest(
                request_id=runner._prompt_request_id("secret_read", matched, lowered),
                request_class="secret_read",
                summary=summary,
                matched_text=matched,
                severity=8,
                confidence=0.9,
                remediation=(
                    runner.RemediationAction(
                        kind="approve_once", label="Approve once", detail="Allow a one-time access."
                    ),
                    runner.RemediationAction(
                        kind="rotate_exposed_secret",
                        label="Rotate secret",
                        detail="Rotate credentials if this read is unexpected.",
                    ),
                ),
            )
        )

    for pattern, label in runner._SECRET_REQUEST_PATTERNS:
        for match in pattern.finditer(normalized_prompt):
            if not runner._prompt_has_secret_read_intent(normalized_prompt, start=match.start(), end=match.end()):
                continue
            add_secret_request(label=label, matched=match.group(0).strip())
            break
    for hint, label in runner._SECRET_ABSOLUTE_HINTS:
        for start, end in runner._iter_hint_occurrences(lowered, hint):
            if runner._prompt_has_secret_read_intent(normalized_prompt, start=start, end=end):
                add_secret_request(label=label, matched=hint)
                break
    exfil_match = runner._first_match(runner._EXFIL_PROMPT_PATTERNS, normalized_prompt)
    if exfil_match is not None:
        matched_text = exfil_match.group(0).strip()
        requests.append(
            runner.PromptRequest(
                request_id=runner._prompt_request_id("exfil_intent", matched_text, lowered),
                request_class="exfil_intent",
                summary="Prompt includes exfiltration-oriented transfer intent.",
                matched_text=matched_text,
                severity=8,
                confidence=0.84,
                remediation=(
                    runner.RemediationAction(
                        kind="review_network_destination",
                        label="Review destination",
                        detail="Validate destination before data transfer.",
                    ),
                    runner.RemediationAction(
                        kind="defer_and_notify_team", label="Notify team", detail="Escalate for review."
                    ),
                ),
            )
        )
    destructive_match = runner._first_match(runner._DESTRUCTIVE_PROMPT_PATTERNS, normalized_prompt)
    if destructive_match is not None:
        matched_text = destructive_match.group(0).strip()
        requests.append(
            runner.PromptRequest(
                request_id=runner._prompt_request_id(
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
                    runner.RemediationAction(
                        kind="approve_once",
                        label="Approve once",
                        detail="Require explicit one-time approval.",
                    ),
                    runner.RemediationAction(
                        kind="open_investigation",
                        label="Open investigation",
                        detail="Track destructive intent.",
                    ),
                ),
            )
        )
    subprocess_match = runner._first_match(runner._SUBPROCESS_PROMPT_PATTERNS, normalized_prompt)
    if subprocess_match is not None:
        matched_text = subprocess_match.group(0).strip()
        requests.append(
            runner.PromptRequest(
                request_id=runner._prompt_request_id(
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
                    runner.RemediationAction(
                        kind="approve_once",
                        label="Approve once",
                        detail="Constrain this run to one approval.",
                    ),
                    runner.RemediationAction(
                        kind="run_in_sandbox",
                        label="Run in sandbox",
                        detail="Execute in isolated mode.",
                    ),
                ),
            )
        )
    if runner._GUARD_BYPASS_PROMPT_PATTERN.search(normalized_prompt):
        requests.append(
            runner.PromptRequest(
                request_id=runner._prompt_request_id("guard_bypass_intent", "guard-bypass", lowered),
                request_class="guard_bypass_intent",
                summary="Prompt includes Guard bypass or disable intent.",
                matched_text="guard-bypass",
                severity=10,
                confidence=0.93,
                remediation=(
                    runner.RemediationAction(
                        kind="block_and_remove",
                        label="Block",
                        detail="Do not allow bypass behavior.",
                    ),
                    runner.RemediationAction(
                        kind="open_investigation",
                        label="Investigate",
                        detail="Escalate bypass attempt.",
                    ),
                ),
            )
        )
    existing_classes = {request.request_class for request in requests}
    for request in runner.detect_prompt_injection_requests(normalized_prompt):
        if request.request_class in existing_classes:
            continue
        requests.append(request)
        existing_classes.add(request.request_class)
    deduped: dict[str, runner.PromptRequest] = {}
    for request in requests:
        deduped[request.request_id] = request
    return list(deduped.values())


def prompt_requests_to_artifacts(
    *,
    detection: runner.HarnessDetection,
    context: runner.HarnessContext,
    requests: list[runner.PromptRequest],
) -> list[runner.GuardArtifact]:
    """Convert typed prompt requests into pseudo-artifacts for policy evaluation."""

    config_path = str(runner._prompt_policy_path(detection, context))
    artifacts: list[runner.GuardArtifact] = []
    for request in requests:
        if request.request_class == "secret_read" and ".env" in request.matched_text.lower():
            artifact_id = f"{detection.harness}:session:prompt-env-read:{request.request_id[:24]}"
        else:
            artifact_id = f"{detection.harness}:session:prompt:{request.request_class}:{request.request_id[:24]}"
        artifacts.append(
            runner.GuardArtifact(
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


def should_force_reapproval(prompt_reqs: list[runner.PromptRequest], prior_policy: dict[str, object] | None) -> bool:
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
    fingerprint = runner.hashlib.sha256(f"{request_class}:{matched_text}:{normalized_prompt}".encode()).hexdigest()
    return fingerprint


def _prompt_policy_path(detection: runner.HarnessDetection, context: runner.HarnessContext) -> runner.Path:
    from ..adapters import get_adapter

    config_candidates = runner._prompt_config_candidates(detection, context)
    if context.workspace_dir is not None:
        for config_path in config_candidates:
            candidate = runner.Path(config_path)
            if candidate.is_relative_to(context.workspace_dir):
                return candidate
    if config_candidates:
        return runner.Path(config_candidates[0])
    return get_adapter(detection.harness).policy_path(context)


def _prompt_config_candidates(detection: runner.HarnessDetection, context: runner.HarnessContext) -> tuple[str, ...]:
    if detection.harness == "opencode":
        configured_path = runner.os.getenv("OPENCODE_CONFIG")
        configured_candidate = None
        if configured_path:
            candidate = runner.Path(configured_path).expanduser()
            if not candidate.is_absolute():
                if context.workspace_dir is not None:
                    candidate = context.workspace_dir / candidate
                else:
                    candidate = runner.Path.cwd() / candidate
            configured_candidate = str(candidate)
        return tuple(
            config_path
            for config_path in detection.config_paths
            if runner.Path(config_path).name in {"opencode.json", "opencode.jsonc"}
            or config_path == configured_candidate
        )
    return detection.config_paths
