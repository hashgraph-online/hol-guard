"""Explicitly benign request classification and artifact construction."""

from __future__ import annotations

from pathlib import Path

from ...models import GuardArtifact
from ...native_tool_action_identity import tool_action_request_artifact_id
from ...redaction import redact_text
from ..command_decision_adapter import effect_decision_to_dict
from ..command_evaluation import CompositeCommandEvaluation, evaluate_command
from ..command_extensions import risk_classes_for_command_action
from ..command_model import parse_shell_command
from ..effect_contract import UncertaintyKind
from ..effect_decision import DecisionFactorSource, DecisionReason, EffectDecision, FinalDisposition
from ..extension_control_contract import ExtensionControlLayer
from ..extension_control_runtime import ExtensionControlRuntimeSnapshot
from .constants_core import _PATH_KEYS, _PATH_LIST_KEYS
from .request_models import ToolActionRequestMatch, _normalize_tool_name, tool_action_risk_summary

# Artifact discovery can run before an authenticated native result exists, and
# the sensitive request still has to be preserved at a review floor. The
# resident cannot be asked for that floor: this branch exists precisely because
# the native side produced nothing. Running the Python evaluator here would be
# a second place a floor is decided, so the decision is pinned instead. It is
# exactly what the Rust evaluator returns for an empty request carrying
# `unsupported-input`, and `pinned_unavailable_evidence_floor` in `guard-command`
# fails if the two ever drift.
_UNSUPPORTED_INPUT_REASON = DecisionReason(
    source=DecisionFactorSource.POLICY,
    reason_code=f"uncertainty.{UncertaintyKind.UNSUPPORTED_INPUT.value}",
    action_floor="review",
    segment_ref=None,
    operation_ref=None,
)
_NATIVE_EVIDENCE_UNAVAILABLE_DECISION = EffectDecision(
    action="review",
    disposition=FinalDisposition.REVIEW,
    controlling_reasons=(_UNSUPPORTED_INPUT_REASON,),
    reasons=(_UNSUPPORTED_INPUT_REASON,),
    proof_routes=frozenset(),
)


def is_explicitly_benign_native_file_read_request(
    tool_name: object,
    arguments: object,
    *,
    cwd: Path | None = None,
    home_dir: Path | None = None,
) -> bool:
    """Recognize one existing, non-sensitive native ``Read`` target."""

    if _normalize_tool_name(tool_name) != "read" or not isinstance(arguments, dict):
        return False
    typed_arguments: dict[str, object] = {key: value for key, value in arguments.items() if isinstance(key, str)}
    if any(key in typed_arguments for key in _PATH_LIST_KEYS):
        return False
    candidates = [
        value.strip() for key in _PATH_KEYS if isinstance((value := typed_arguments.get(key)), str) and value.strip()
    ]
    if len(candidates) != 1:
        return False
    target = candidates[0]
    if not target or any(marker in target for marker in ("$", "`", "<", ">", "|", ";", "&", "\x00")):
        return False

    from ..source_paths import source_path_is_allowed

    decision = source_path_is_allowed(target, cwd=cwd, home_dir=home_dir)
    resolved = decision.resolved_path
    try:
        return decision.allowed and resolved is not None and resolved.is_file()
    except OSError:
        return False


def build_tool_action_request_artifact(
    harness: str,
    request: ToolActionRequestMatch,
    *,
    config_path: str,
    source_scope: str,
    extension_control_layers: tuple[ExtensionControlLayer, ...] | None = None,
    extension_control_snapshot: ExtensionControlRuntimeSnapshot | None = None,
    native_extension_evidence: object | None = None,
    native_evaluation: CompositeCommandEvaluation | None = None,
    extension_allow_hint: dict[str, object] | None = None,
) -> GuardArtifact:
    """Build a Guard artifact for a sensitive native tool action request."""

    policy_command = request.raw_command_text or request.command_text
    evidence_available = native_extension_evidence is not None and extension_control_snapshot is not None
    if evidence_available:
        evaluation = native_evaluation
        if evaluation is None:
            evaluation = evaluate_command(
                policy_command,
                canonical_command=request.canonical_command,
                compatibility_action_class=request.action_class,
                compatibility_reason=request.reason,
                extension_control_snapshot=extension_control_snapshot,
                native_extension_evidence=native_extension_evidence,
            )
        command = evaluation.command
        decision_plane = evaluation.decision_plane
        control_resolution = {
            "blocked": evaluation.control_resolution.blocked,
            "failures": [failure.code.value for failure in evaluation.control_resolution.failures],
            **(
                {
                    "explicitly_enabled_permission_ids": list(
                        evaluation.control_resolution.explicitly_enabled_permission_ids
                    )
                }
                if evaluation.control_resolution.explicitly_enabled_permission_ids
                else {}
            ),
        }
        command_rule_matches = [owned.to_dict() for owned in evaluation.matches]
        risk_classes = list(evaluation.risk_classes)
    else:
        # Artifact discovery can run before the authenticated resident result is
        # available. Preserve the sensitive request and an explicit review
        # floor without reconstructing matcher semantics or claiming controls
        # were evaluated.
        command = (
            request.canonical_command
            if request.raw_command_text is None and request.canonical_command is not None
            else parse_shell_command(policy_command)
        )
        decision_plane = _NATIVE_EVIDENCE_UNAVAILABLE_DECISION
        control_resolution = {"blocked": True, "failures": ["native-evidence-unavailable"]}
        command_rule_matches = []
        risk_classes = list(risk_classes_for_command_action(request.action_class))
    wrapper_chain = tuple(dict.fromkeys((*command.wrapper_chain, *request.wrapper_chain)))
    # The artifact id is the key a saved approval for this action is stored
    # under, so the resident derives it and this side never recomputes it.
    artifact_id = tool_action_request_artifact_id(harness, request, source_scope=source_scope)
    display_command_text = redact_text(request.command_text).text
    display_raw_command_text = (
        redact_text(request.raw_command_text).text if request.raw_command_text is not None else None
    )
    request_summary = f"Requested `{request.tool_name}` action `{display_command_text}` ({request.action_class})."
    if wrapper_chain:
        request_summary = (
            f"Requested `{request.tool_name}` action `{display_command_text}` via transparent wrappers "
            f"`{' -> '.join(wrapper_chain)}` ({request.action_class})."
        )
    risk_summary = tool_action_risk_summary(request)
    runtime_reason = request.reason
    if wrapper_chain:
        runtime_reason = (
            f"Guard normalized the transparent wrapper chain {' -> '.join(wrapper_chain)} "
            f"before evaluation. {request.reason}"
        )
    execution_context_metadata: dict[str, object] = {}
    if request.shell_execution_context_hash is not None:
        effective_cwds = list(request.shell_execution_effective_cwds)
        execution_context_metadata = {
            "shell_execution_context_hash": request.shell_execution_context_hash,
            "shell_execution_context_complete": request.shell_execution_context_reason_code is None,
            "shell_execution_context_reason_code": request.shell_execution_context_reason_code,
            "shell_execution_effective_cwds": effective_cwds,
            "effective_cwd": effective_cwds[-1] if effective_cwds else None,
        }
    return GuardArtifact(
        artifact_id=artifact_id,
        name=f"{request.tool_name} {request.action_class}",
        harness=harness,
        artifact_type="tool_action_request",
        source_scope=source_scope,
        config_path=config_path,
        command=policy_command,
        metadata={
            "tool_name": request.tool_name,
            "command_text": display_command_text,
            "action_class": request.action_class,
            "request_summary": request_summary,
            "runtime_request_signals": [risk_summary],
            "runtime_request_summary": risk_summary,
            "runtime_request_reason": runtime_reason,
            "raw_command_text": display_raw_command_text,
            "wrapper_chain": list(wrapper_chain),
            "command_security_identity": command.security_identity,
            "command_action_floor": decision_plane.action,
            "command_decision_plane": effect_decision_to_dict(decision_plane),
            "extension_control_resolution": control_resolution,
            "command_rule_matches": command_rule_matches,
            "risk_classes": risk_classes,
            "command_parse_confidence": command.confidence,
            "command_uncertainty_reason": command.uncertainty_reason,
            "native_extension_evidence": "bound" if evidence_available else "unavailable",
            "interpreter_executable_identities": [
                dict(identity) for identity in request.interpreter_executable_identities
            ],
            **execution_context_metadata,
            **(
                {"guard_default_action": request.guard_default_action}
                if request.guard_default_action is not None
                else {}
            ),
            **({"reason_code": request.reason_code} if request.reason_code is not None else {}),
            **(
                {"extension_allow_hint": extension_allow_hint}
                if evidence_available and extension_allow_hint is not None
                else {}
            ),
            **(
                {"script_read_identity_sha256": request.script_read_identity_sha256}
                if request.script_read_identity_sha256 is not None
                else {}
            ),
            **(
                {
                    "pytest_config_identity_sha256": request.pytest_config_identity_sha256,
                    "pytest_config_sources": list(request.pytest_config_sources),
                    "pytest_config_complete": not request.pytest_config_reason_codes,
                    "pytest_config_reason_codes": list(request.pytest_config_reason_codes),
                }
                if request.pytest_config_identity_sha256 is not None
                else {}
            ),
            **(
                {
                    "restricted_profile_version": request.restricted_profile_version,
                    "restricted_capabilities": {
                        "workspace": "read-write",
                        "private_temporary_directory": "read-write",
                        "host_home": "denied",
                        "host_secret_environment": "denied",
                        "network": "denied",
                        "outside_writes": "denied",
                        "process_execution": "approved-interpreter-runtime-only",
                    },
                }
                if request.restricted_profile_version is not None
                else {}
            ),
        },
    )


__all__ = [
    "build_tool_action_request_artifact",
    "is_explicitly_benign_native_file_read_request",
]
