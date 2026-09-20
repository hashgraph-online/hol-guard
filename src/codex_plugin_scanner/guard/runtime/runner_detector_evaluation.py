"""Detector evaluation.

Shared state and replaceable dependencies belong to the runner facade.
"""

from __future__ import annotations

from . import runner


def _guard_run_action_envelope(
    harness: str,
    context: runner.HarnessContext,
    passthrough_args: list[str],
) -> runner.GuardActionEnvelope:
    workspace = context.workspace_dir
    workspace_hash = None
    if workspace is not None:
        workspace_path = workspace.expanduser()
        with runner.suppress(OSError):
            workspace_path = workspace_path.resolve()
        workspace_hash = runner.hashlib.sha256(str(workspace_path).encode("utf-8")).hexdigest()
    return runner.GuardActionEnvelope(
        schema_version=1,
        action_id="",
        harness=harness,
        event_name="HarnessStart",
        action_type="harness_start",
        workspace=runner.redacted_workspace_label(workspace, home_dir=context.home_dir),
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
    evaluation: dict[str, runner.Any],
    action_envelope: runner.GuardActionEnvelope,
) -> dict[str, runner.Any]:
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
    evaluation: dict[str, runner.Any],
    action_envelope: runner.GuardActionEnvelope,
    context: runner.HarnessContext,
    config: runner.GuardConfig,
) -> dict[str, runner.Any]:
    if not config.runtime_detector_registry:
        return evaluation
    detector_context = runner.DetectorContext(
        config=config,
        workspace=context.workspace_dir,
        prior_decisions={},
        threat_intel={},
        redaction_settings={},
    )
    result = runner._get_default_detector_registry().run(
        action_envelope,
        detector_context,
        timeout_ms=config.runtime_detector_timeout_ms,
        disabled_detector_ids=config.runtime_detector_disabled_ids,
    )
    trace_error = (
        runner._write_detector_debug_trace(config, action_envelope, result)
        if config.runtime_detector_debug_trace
        else None
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
    # Compose detector authority independently from the base artifact result.
    # Otherwise an already-reviewable artifact makes every detector result
    # appear to be a block and prevents us from identifying a genuine terminal
    # detector block before entering the approval flow.
    composition = runner.compose_action_from_signals(result.signals, "allow")
    next_evaluation["runtime_detector_composition"] = {
        "action": composition.action,
        "reason": composition.reason,
        "downgraded": composition.downgraded,
        "upgraded": composition.upgraded,
    }
    if composition.action == "block":
        next_evaluation["blocked"] = True
        next_evaluation["blocked_by_detector"] = composition.reason
    if trace_error is not None:
        next_evaluation["runtime_detector_trace_error"] = trace_error
    return next_evaluation


def _artifact_with_authority_updates(
    item: runner.Mapping[str, object],
    *,
    reason: str | None,
    composition_updates: runner.Mapping[str, object],
    additional_signals: runner.Sequence[runner.RiskSignalV2] = (),
) -> dict[str, object]:
    """Apply runner trace changes without allowing serialized aliases to drift."""

    try:
        return runner.rebuild_artifact_authority(
            item,
            reason=reason,
            composition_updates=composition_updates,
            additional_signals=additional_signals,
        )
    except (TypeError, ValueError):
        # Preserve evidence for the final gate. The malformed decision remains
        # intentionally unmodified so evaluation_authority_error fails closed.
        return {**dict(item), "decision_contract_error": runner.AUTHORITATIVE_DECISION_INCONSISTENT}


def _runtime_detector_signals_from_evaluation(
    evaluation: runner.Mapping[str, object],
) -> tuple[runner.RiskSignalV2, ...]:
    raw_signals = evaluation.get("runtime_detector_signals_v2")
    if raw_signals is None:
        return ()
    if not isinstance(raw_signals, list):
        raise ValueError("runtime_detector_signals_v2 must be a list")
    signals: list[runner.RiskSignalV2] = []
    for raw_signal in raw_signals:
        if not isinstance(raw_signal, runner.Mapping):
            raise ValueError("runtime detector signal must be an object")
        signals.append(runner.RiskSignalV2.from_dict(raw_signal))
    return tuple(signals)


def _evaluation_with_recorded_detector_result(
    evaluation: dict[str, runner.Any],
    detector_evaluation: runner.Mapping[str, object],
) -> dict[str, runner.Any]:
    """Carry one pre-launch detector result across persistence without rerunning it."""

    next_evaluation = dict(evaluation)
    for key in runner._RUNTIME_DETECTOR_RESULT_KEYS:
        if key in detector_evaluation:
            next_evaluation[key] = detector_evaluation[key]
    blocked_by_detector = detector_evaluation.get("blocked_by_detector")
    if isinstance(blocked_by_detector, str) and blocked_by_detector:
        next_evaluation["blocked"] = True
        next_evaluation["blocked_by_detector"] = blocked_by_detector
    detector_action, detector_reason = runner._runtime_detector_authority(detector_evaluation)
    try:
        detector_signals = runner._runtime_detector_signals_from_evaluation(detector_evaluation)
    except (TypeError, ValueError):
        next_evaluation["decision_contract_error"] = runner.AUTHORITATIVE_DECISION_INCONSISTENT
        return next_evaluation
    evidence = runner._runtime_detector_nonterminal_evidence(detector_action, detector_reason)

    raw_artifacts = next_evaluation.get("artifacts")
    if not isinstance(raw_artifacts, list) or not raw_artifacts:
        if detector_action is not None:
            authority_reason = detector_reason or (
                str(evidence["reason"]) if evidence is not None else "runtime detector blocked this launch"
            )
            run_decision = runner.build_authoritative_decision(
                detector_action,
                reason=authority_reason,
                composition_trace={"runtime_detector_action": detector_action},
                signals=detector_signals,
                authority_finalized=detector_action != "review",
                source="runtime-detector-registry",
            )
            next_evaluation["run_authoritative_decision"] = run_decision.to_dict()
            next_evaluation["blocked"] = bool(next_evaluation.get("blocked")) or run_decision.enforcement.blocking
            if run_decision.enforcement.blocking:
                next_evaluation["blocked_by_detector"] = authority_reason
        return next_evaluation
    artifacts: list[object] = []
    for raw_item in raw_artifacts:
        if not isinstance(raw_item, runner.Mapping):
            artifacts.append(raw_item)
            continue
        item = dict(raw_item)
        raw_scanner_evidence = item.get("scanner_evidence")
        scanner_evidence: list[object] = (
            [
                dict(raw_evidence) if isinstance(raw_evidence, runner.Mapping) else raw_evidence
                for raw_evidence in raw_scanner_evidence
            ]
            if isinstance(raw_scanner_evidence, list)
            else []
        )
        if evidence is not None and not any(
            isinstance(raw_evidence, runner.Mapping)
            and raw_evidence.get("source") == evidence["source"]
            and raw_evidence.get("reason_code") == evidence["reason_code"]
            for raw_evidence in scanner_evidence
        ):
            scanner_evidence.append(evidence)
        item["scanner_evidence"] = scanner_evidence
        composition_updates: dict[str, object] = {}
        if detector_action is not None:
            composition_updates = {
                "runtime_detector_action": detector_action,
                "runtime_detector_reason": detector_reason
                or (str(evidence["reason"]) if evidence is not None else "runtime detector authority"),
            }
        item = runner._artifact_with_authority_updates(
            item,
            reason=(
                str(evidence["reason_code"])
                if evidence is not None and item.get("policy_action") == detector_action
                else None
            ),
            composition_updates=composition_updates,
            additional_signals=detector_signals,
        )
        artifacts.append(item)
    next_evaluation["artifacts"] = artifacts
    return next_evaluation


def _evaluation_with_preclaim_failure(
    evaluation: dict[str, runner.Any],
    *,
    affected_artifact_ids: set[str],
    reason_code: str,
    reason: str,
    claim_status: str,
    revalidation_status: str,
) -> dict[str, runner.Any]:
    """Record a terminal, auditable failure before approval authority is claimed."""

    evidence = {
        "source": "approval_reuse",
        "status": "rejected",
        "reason_code": reason_code,
        "reason": reason,
    }
    artifacts: list[object] = []
    for raw_item in evaluation.get("artifacts", []):
        if not isinstance(raw_item, runner.Mapping) or raw_item.get("artifact_id") not in affected_artifact_ids:
            artifacts.append(raw_item)
            continue
        item = dict(raw_item)
        raw_scanner_evidence = item.get("scanner_evidence")
        scanner_evidence: list[object] = (
            [
                dict(raw_evidence)
                for raw_evidence in raw_scanner_evidence
                if isinstance(raw_evidence, runner.Mapping) and raw_evidence.get("source") != "approval_reuse"
            ]
            if isinstance(raw_scanner_evidence, list)
            else []
        )
        scanner_evidence.append(evidence)
        item["scanner_evidence"] = scanner_evidence
        item["approval_reuse_status"] = "rejected"
        item["approval_reuse_reason_code"] = reason_code
        approval_reuse = item.get("approval_reuse")
        item["approval_reuse"] = {
            **(dict(approval_reuse) if isinstance(approval_reuse, runner.Mapping) else {}),
            "action": item.get("policy_action"),
            "status": "rejected",
            "reason_code": reason_code,
            "should_claim": False,
        }
        item = runner._artifact_with_authority_updates(
            item,
            reason=reason_code,
            composition_updates={
                "claim_revalidation": revalidation_status,
                "claim_revalidation_reason": reason_code,
            },
        )
        artifacts.append(item)
    return {
        **evaluation,
        "artifacts": artifacts,
        "blocked": True,
        "approval_claim": {
            "status": claim_status,
            "reason_code": reason_code,
            "artifact_ids": sorted(affected_artifact_ids),
        },
    }


def _evaluation_with_claim_context_failure(
    evaluation: dict[str, runner.Any],
    *,
    claimed_artifact_ids: set[str],
) -> dict[str, runner.Any]:
    """Make a changed post-claim authority terminal and auditable."""

    evidence = {
        "source": "approval_reuse",
        "status": "rejected",
        "reason_code": runner._APPROVAL_REUSE_CONTEXT_CHANGED_AFTER_CLAIM,
        "reason": "launch authority changed after the saved approval was claimed",
    }
    artifacts: list[object] = []
    for raw_item in evaluation.get("artifacts", []):
        if not isinstance(raw_item, runner.Mapping):
            artifacts.append(raw_item)
            continue
        item = dict(raw_item)
        raw_scanner_evidence = item.get("scanner_evidence")
        scanner_evidence: list[object] = (
            [
                dict(raw_evidence)
                for raw_evidence in raw_scanner_evidence
                if isinstance(raw_evidence, runner.Mapping) and raw_evidence.get("source") != "approval_reuse"
            ]
            if isinstance(raw_scanner_evidence, list)
            else []
        )
        scanner_evidence.append(evidence)
        item["scanner_evidence"] = scanner_evidence
        item["approval_reuse_status"] = "rejected"
        item["approval_reuse_reason_code"] = runner._APPROVAL_REUSE_CONTEXT_CHANGED_AFTER_CLAIM
        approval_reuse = item.get("approval_reuse")
        item["approval_reuse"] = {
            **(dict(approval_reuse) if isinstance(approval_reuse, runner.Mapping) else {}),
            "action": item.get("policy_action"),
            "status": "rejected",
            "reason_code": runner._APPROVAL_REUSE_CONTEXT_CHANGED_AFTER_CLAIM,
            "should_claim": False,
        }
        item = runner._artifact_with_authority_updates(
            item,
            reason=runner._APPROVAL_REUSE_CONTEXT_CHANGED_AFTER_CLAIM,
            composition_updates={
                "claim_revalidation": "changed",
                "claim_revalidation_reason": runner._APPROVAL_REUSE_CONTEXT_CHANGED_AFTER_CLAIM,
            },
        )
        artifacts.append(item)
    next_evaluation = {
        **evaluation,
        "artifacts": artifacts,
        "blocked": True,
        "approval_claim": {
            "status": "rejected",
            "reason_code": runner._APPROVAL_REUSE_CONTEXT_CHANGED_AFTER_CLAIM,
            "artifact_ids": sorted(claimed_artifact_ids),
        },
    }
    return next_evaluation
