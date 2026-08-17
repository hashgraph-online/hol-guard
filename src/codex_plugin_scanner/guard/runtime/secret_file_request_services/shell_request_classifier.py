"""Primary shell request risk classifier."""

from __future__ import annotations

from pathlib import Path

from ..command_evaluation import evaluate_command
from ..command_extension_interaction import classify_command_extension_interaction
from ..command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from ..command_model import CanonicalCommand, parse_shell_command
from ..direct_vitest import direct_local_typescript_execution_context, direct_local_vitest_execution_context
from ..extension_control_contract import ControlSurface
from ..extension_control_resolver import resolve_extension_controls
from ..extension_control_runtime import current_extension_control_snapshot
from ..github_capability_contract import github_capability_contract
from ..github_capability_interaction import github_capability_action_class, github_capability_requires_confirmation
from ..pytest_config import PytestConfigAssessment
from ..restricted_pytest import PYTEST_RESTRICTED_PROFILE_VERSION
from ..shell_execution_context import SHELL_CWD_WORKSPACE_ESCAPE, ShellExecutionContext, model_shell_execution_context
from .constants_core import _SHELL_TOOL_NAMES
from .docker_requests import _shell_execution_context_validation_reason, shell_execution_context_starts_with_literal_cd
from .encoded_payloads import _looks_destructive_shell_command
from .github_pr_body_safety import _gh_pr_create_uses_safe_static_body_file, _gh_pr_edit_uses_safe_static_body_file
from .github_shell_capabilities import classify_github_shell_capabilities
from .interpreter_identity import _python_interpreter_executable_identities
from .interpreter_trust import _pytest_config_assessment_for_command
from .pytest_target_detection import _shell_command_targets_pytest
from .request_models import ToolActionRequestMatch
from .shell_initial_risk import initial_shell_risk_match
from .shell_quote_parsing import _bounded_current_workspace_source_edit_execution_context, literal_cd_execution_context
from .source_edit_context import (
    _bounded_verified_source_edit_execution_context,
    low_risk_compound_developer_execution_context,
)


def _destructive_shell_tool_action_request(
    *,
    tool_name: str,
    normalized_tool_name: str,
    command_text: str,
    cwd: Path | None,
    home_dir: Path | None,
    canonical_command: CanonicalCommand | None = None,
    raw_command_text: str | None = None,
    execution_context: ShellExecutionContext | None = None,
    raw_execution_context: ShellExecutionContext | None = None,
) -> ToolActionRequestMatch | None:
    if normalized_tool_name not in _SHELL_TOOL_NAMES:
        return None
    canonical_command = canonical_command or parse_shell_command(command_text, cwd=cwd, home_dir=home_dir)
    execution_context = execution_context or model_shell_execution_context(
        command_text,
        cwd=cwd,
        workspace_root=cwd,
        home_dir=home_dir,
    )
    detection_command_text = command_text
    pytest_execution_requested = _shell_command_targets_pytest(detection_command_text)
    pytest_config_assessment = (
        _pytest_config_assessment_for_command(
            detection_command_text,
            cwd=cwd,
            execution_context=execution_context,
        )
        if pytest_execution_requested
        else PytestConfigAssessment((), True, False, (), None)
    )
    pytest_config_sources = tuple(result.source_path for result in pytest_config_assessment.results)
    interpreter_executable_identities = _python_interpreter_executable_identities(
        raw_command_text or detection_command_text,
        cwd=cwd,
        home_dir=home_dir,
        execution_context=(
            raw_execution_context
            if raw_command_text is not None and raw_command_text != detection_command_text
            else execution_context
        ),
    )
    extension_interaction = classify_command_extension_interaction(
        canonical_command,
        BUILT_IN_COMMAND_EXTENSION_REGISTRY,
    )
    initial_risk_handled, initial_risk = initial_shell_risk_match(
        tool_name=tool_name,
        normalized_tool_name=normalized_tool_name,
        command_text=command_text,
        detection_command_text=detection_command_text,
        raw_command_text=raw_command_text,
        cwd=cwd,
        home_dir=home_dir,
        canonical_command=canonical_command,
        extension_interaction=extension_interaction,
        interpreter_executable_identities=interpreter_executable_identities,
    )
    if initial_risk_handled:
        return initial_risk
    if not execution_context.complete and home_dir is not None:
        developer_execution_context = (
            direct_local_vitest_execution_context(
                detection_command_text,
                cwd=cwd,
                home_dir=home_dir,
            )
            or direct_local_typescript_execution_context(
                detection_command_text,
                cwd=cwd,
                home_dir=home_dir,
            )
            or literal_cd_execution_context(
                detection_command_text,
                home_dir=home_dir,
            )
            or low_risk_compound_developer_execution_context(detection_command_text, home_dir=home_dir)
        )
        raw_developer_execution_context = (
            direct_local_vitest_execution_context(
                raw_command_text,
                cwd=cwd,
                home_dir=home_dir,
            )
            or direct_local_typescript_execution_context(
                raw_command_text,
                cwd=cwd,
                home_dir=home_dir,
            )
            or literal_cd_execution_context(raw_command_text, home_dir=home_dir)
            or low_risk_compound_developer_execution_context(raw_command_text, home_dir=home_dir)
            if raw_command_text is not None and raw_command_text != detection_command_text
            else developer_execution_context
        )
        if developer_execution_context is not None and raw_developer_execution_context is not None:
            execution_context = developer_execution_context
            raw_execution_context = raw_developer_execution_context
            interpreter_executable_identities = _python_interpreter_executable_identities(
                raw_command_text or detection_command_text,
                cwd=home_dir,
                home_dir=home_dir,
                execution_context=(
                    raw_execution_context
                    if raw_command_text is not None and raw_command_text != detection_command_text
                    else execution_context
                ),
            )
    github_assessment = classify_github_shell_capabilities(
        raw_command_text or detection_command_text,
        home_dir=home_dir,
    )
    if execution_context.reason_code == SHELL_CWD_WORKSPACE_ESCAPE and home_dir is not None and cwd is None:
        home_risk_context = model_shell_execution_context(
            detection_command_text,
            cwd=home_dir,
            workspace_root=home_dir,
            home_dir=home_dir,
        )
        raw_home_risk_context = (
            model_shell_execution_context(
                raw_command_text,
                cwd=home_dir,
                workspace_root=home_dir,
                home_dir=home_dir,
            )
            if raw_command_text is not None and raw_command_text != detection_command_text
            else home_risk_context
        )
        home_context_is_destructive = (
            home_risk_context.complete
            and raw_home_risk_context.complete
            and shell_execution_context_starts_with_literal_cd(home_risk_context)
            and shell_execution_context_starts_with_literal_cd(raw_home_risk_context)
            and (
                _looks_destructive_shell_command(
                    detection_command_text,
                    cwd=home_dir,
                    home_dir=home_dir,
                    execution_context=home_risk_context,
                )
                or (
                    raw_command_text is not None
                    and raw_command_text != detection_command_text
                    and _looks_destructive_shell_command(
                        raw_command_text,
                        cwd=home_dir,
                        home_dir=home_dir,
                        execution_context=raw_home_risk_context,
                    )
                )
            )
        )
        if home_context_is_destructive:
            execution_context = home_risk_context
            raw_execution_context = raw_home_risk_context
            interpreter_executable_identities = _python_interpreter_executable_identities(
                raw_command_text or detection_command_text,
                cwd=home_dir,
                home_dir=home_dir,
                execution_context=(
                    raw_execution_context
                    if raw_command_text is not None and raw_command_text != detection_command_text
                    else execution_context
                ),
            )
    if (
        github_assessment is not None
        and not github_capability_requires_confirmation(github_assessment)
        and execution_context.reason_code == SHELL_CWD_WORKSPACE_ESCAPE
        and home_dir is not None
    ):
        home_execution_context = model_shell_execution_context(
            detection_command_text,
            cwd=cwd,
            workspace_root=home_dir,
            home_dir=home_dir,
        )
        raw_home_execution_context = (
            model_shell_execution_context(
                raw_command_text,
                cwd=cwd,
                workspace_root=home_dir,
                home_dir=home_dir,
            )
            if raw_command_text is not None and raw_command_text != detection_command_text
            else home_execution_context
        )
        if not home_execution_context.complete and cwd is None:
            fallback_home_execution_context = model_shell_execution_context(
                detection_command_text,
                cwd=home_dir,
                workspace_root=home_dir,
                home_dir=home_dir,
            )
            fallback_raw_home_execution_context = (
                model_shell_execution_context(
                    raw_command_text,
                    cwd=home_dir,
                    workspace_root=home_dir,
                    home_dir=home_dir,
                )
                if raw_command_text is not None and raw_command_text != detection_command_text
                else fallback_home_execution_context
            )
            if shell_execution_context_starts_with_literal_cd(
                fallback_home_execution_context
            ) and shell_execution_context_starts_with_literal_cd(fallback_raw_home_execution_context):
                home_execution_context = fallback_home_execution_context
                raw_home_execution_context = fallback_raw_home_execution_context
        if home_execution_context.complete and raw_home_execution_context.complete:
            execution_context = home_execution_context
            raw_execution_context = raw_home_execution_context
            interpreter_executable_identities = _python_interpreter_executable_identities(
                raw_command_text or detection_command_text,
                cwd=cwd,
                home_dir=home_dir,
                execution_context=(
                    raw_execution_context
                    if raw_command_text is not None and raw_command_text != detection_command_text
                    else execution_context
                ),
            )
    bounded_source_edit_context = (
        (
            _bounded_verified_source_edit_execution_context(detection_command_text, home_dir=home_dir)
            or _bounded_current_workspace_source_edit_execution_context(
                detection_command_text,
                cwd=cwd,
                home_dir=home_dir,
            )
        )
        if home_dir is not None
        else None
    )
    raw_bounded_source_edit_context = (
        (
            _bounded_verified_source_edit_execution_context(raw_command_text, home_dir=home_dir)
            or _bounded_current_workspace_source_edit_execution_context(
                raw_command_text,
                cwd=cwd,
                home_dir=home_dir,
            )
        )
        if home_dir is not None and raw_command_text is not None and raw_command_text != detection_command_text
        else bounded_source_edit_context
    )
    if bounded_source_edit_context is not None and raw_bounded_source_edit_context is not None:
        bounded_source_edit = True
        execution_context = bounded_source_edit_context
        raw_execution_context = raw_bounded_source_edit_context
    else:
        bounded_source_edit = False

    execution_context_reason = _shell_execution_context_validation_reason(execution_context)
    if execution_context.directory_change_present and execution_context_reason is not None:
        return ToolActionRequestMatch(
            tool_name=tool_name,
            normalized_tool_name=normalized_tool_name,
            command_text=command_text,
            action_class="unresolved shell execution context",
            reason=(
                "Guard could not prove the working directory for every shell segment and requires one "
                f"conservative decision before the user confirms execution ({execution_context_reason}). Use a "
                "literal, existing in-workspace directory with deterministic cd/pushd/popd control flow, or run the "
                "command from the intended directory."
            ),
            canonical_command=canonical_command,
            shell_execution_context_hash=execution_context.context_hash,
            shell_execution_context_reason_code=execution_context_reason,
            shell_execution_effective_cwds=tuple(str(path) for path in execution_context.effective_cwds),
            guard_default_action="sandbox-required" if pytest_execution_requested else None,
            reason_code="pytest_restricted_profile_required" if pytest_execution_requested else None,
            restricted_profile_version=PYTEST_RESTRICTED_PROFILE_VERSION if pytest_execution_requested else None,
            pytest_config_identity_sha256=pytest_config_assessment.identity_sha256,
            pytest_config_sources=pytest_config_sources,
            pytest_config_reason_codes=pytest_config_assessment.reason_codes,
            interpreter_executable_identities=interpreter_executable_identities,
        )
    detection_command_is_destructive = _looks_destructive_shell_command(
        detection_command_text,
        cwd=cwd,
        home_dir=home_dir,
        execution_context=execution_context,
    )
    raw_command_is_destructive = (
        raw_command_text is not None
        and raw_command_text != detection_command_text
        and _looks_destructive_shell_command(
            raw_command_text,
            cwd=cwd,
            home_dir=home_dir,
            execution_context=raw_execution_context,
        )
    )
    if (detection_command_is_destructive or raw_command_is_destructive) and not bounded_source_edit:
        matched_execution_context = raw_execution_context if raw_command_is_destructive else execution_context
        matched_execution_context = matched_execution_context or execution_context
        destructive_reason = (
            "Guard found execution-affecting pytest configuration or could not inspect the selected pytest "
            "configuration completely. Keep plugin/output/config overrides inside the restricted pytest profile; "
            "repair or remove malformed, missing, unreadable, oversized, or unsafe config inputs before retrying."
            if pytest_execution_requested and pytest_config_assessment.unsafe
            else (
                "Guard treats destructive shell writes and delete operations as sensitive because they can mutate "
                "the local machine before the user confirms the action."
            )
        )
        return ToolActionRequestMatch(
            tool_name=tool_name,
            normalized_tool_name=normalized_tool_name,
            command_text=command_text,
            action_class="destructive shell command",
            reason=destructive_reason,
            canonical_command=canonical_command,
            shell_execution_context_hash=(
                matched_execution_context.context_hash if matched_execution_context.directory_change_present else None
            ),
            shell_execution_context_reason_code=matched_execution_context.reason_code,
            shell_execution_effective_cwds=(
                tuple(str(path) for path in matched_execution_context.effective_cwds)
                if matched_execution_context.directory_change_present
                else ()
            ),
            guard_default_action="sandbox-required" if pytest_execution_requested else None,
            reason_code="pytest_restricted_profile_required" if pytest_execution_requested else None,
            restricted_profile_version=PYTEST_RESTRICTED_PROFILE_VERSION if pytest_execution_requested else None,
            pytest_config_identity_sha256=pytest_config_assessment.identity_sha256,
            pytest_config_sources=pytest_config_sources,
            pytest_config_reason_codes=pytest_config_assessment.reason_codes,
            interpreter_executable_identities=interpreter_executable_identities,
        )
    if pytest_execution_requested:
        return ToolActionRequestMatch(
            tool_name=tool_name,
            normalized_tool_name=normalized_tool_name,
            command_text=command_text,
            action_class="pytest repository-code execution",
            reason=(
                "pytest_restricted_profile_required: Pytest collection imports repository-controlled tests, "
                "conftest.py files, and plugins. Run the exact pytest argv through "
                "`hol-guard pytest-contained --workspace <workspace> -- ...`; Guard will not launch pytest when "
                "the required operating-system sandbox is unavailable."
            ),
            canonical_command=canonical_command,
            guard_default_action="sandbox-required",
            reason_code="pytest_restricted_profile_required",
            restricted_profile_version=PYTEST_RESTRICTED_PROFILE_VERSION,
            pytest_config_identity_sha256=pytest_config_assessment.identity_sha256,
            pytest_config_sources=pytest_config_sources,
            pytest_config_reason_codes=pytest_config_assessment.reason_codes,
            interpreter_executable_identities=interpreter_executable_identities,
        )
    safe_pr_create_body_file = _gh_pr_create_uses_safe_static_body_file(
        detection_command_text,
        cwd=cwd,
        home_dir=home_dir,
    ) and (
        raw_command_text is None
        or raw_command_text == detection_command_text
        or _gh_pr_create_uses_safe_static_body_file(
            raw_command_text,
            cwd=cwd,
            home_dir=home_dir,
        )
    )
    if safe_pr_create_body_file:
        snapshot = current_extension_control_snapshot()
        proposal_permission = BUILT_IN_COMMAND_EXTENSION_REGISTRY.permission_for_typed_capability("propose_remote")
        if snapshot is not None and proposal_permission is not None:
            proposal_contract = github_capability_contract("propose_remote")
            control_resolution = resolve_extension_controls(
                snapshot.layers,
                BUILT_IN_COMMAND_EXTENSION_REGISTRY,
                extension_ids=(proposal_permission.extension_id,),
                permission_ids=(proposal_permission.permission_id,),
                surface=ControlSurface.COMMAND_EVALUATION,
                authority_failure=snapshot.authority_failure,
            )
            if control_resolution.blocked:
                return ToolActionRequestMatch(
                    tool_name=tool_name,
                    normalized_tool_name=normalized_tool_name,
                    command_text=command_text,
                    action_class=proposal_contract.action_class or "GitHub pull-request proposal command",
                    reason="Guard extension controls block this GitHub capability.",
                    canonical_command=canonical_command,
                    interpreter_executable_identities=interpreter_executable_identities,
                )
        return None
    if _gh_pr_edit_uses_safe_static_body_file(
        detection_command_text,
        cwd=cwd,
        home_dir=home_dir,
    ) and (
        raw_command_text is None
        or raw_command_text == detection_command_text
        or _gh_pr_edit_uses_safe_static_body_file(
            raw_command_text,
            cwd=cwd,
            home_dir=home_dir,
        )
    ):
        return None
    if github_assessment is not None and github_capability_requires_confirmation(github_assessment):
        return ToolActionRequestMatch(
            tool_name=tool_name,
            normalized_tool_name=normalized_tool_name,
            command_text=command_text,
            action_class=github_capability_action_class(github_assessment),
            reason=(
                f"{github_assessment.detail} Guard requires confirmation because the operation is not a "
                "statically proven read-only composition."
            ),
            canonical_command=canonical_command,
            interpreter_executable_identities=interpreter_executable_identities,
        )
    controlled_action_class = (
        github_capability_contract(github_assessment.capability).action_class
        if github_assessment is not None and current_extension_control_snapshot() is not None
        else None
    )
    if github_assessment is not None and controlled_action_class is not None:
        action_class = controlled_action_class
        controlled_evaluation = evaluate_command(
            raw_command_text or detection_command_text,
            compatibility_action_class=action_class,
            compatibility_reason=github_assessment.detail,
            cwd=cwd,
            home_dir=home_dir,
        )
        if controlled_evaluation.control_resolution.blocked:
            return ToolActionRequestMatch(
                tool_name=tool_name,
                normalized_tool_name=normalized_tool_name,
                command_text=command_text,
                action_class=action_class,
                reason="Guard extension controls block this GitHub capability.",
                canonical_command=canonical_command,
                interpreter_executable_identities=interpreter_executable_identities,
            )
    if extension_interaction.fallback is not None:
        return ToolActionRequestMatch(
            tool_name=tool_name,
            normalized_tool_name=normalized_tool_name,
            command_text=command_text,
            action_class=extension_interaction.fallback.action_class,
            reason=extension_interaction.fallback.reason,
            canonical_command=canonical_command,
            interpreter_executable_identities=interpreter_executable_identities,
        )
    untrusted_interpreters = tuple(
        evidence
        for evidence in interpreter_executable_identities
        if evidence.get("trust") not in {"trusted_guard", "trusted_system"}
    )
    if untrusted_interpreters:
        trust_reasons = ", ".join(
            sorted({str(evidence.get("trust") or "unknown") for evidence in untrusted_interpreters})
        )
        return ToolActionRequestMatch(
            tool_name=tool_name,
            normalized_tool_name=normalized_tool_name,
            command_text=command_text,
            action_class="untrusted Python interpreter",
            reason=(
                "Guard requires review because the Python command resolves through an interpreter path that is "
                f"not an attested Guard or system runtime ({trust_reasons}). The decision is bound to the raw "
                "interpreter token, launch path, symlink chain, executable mode, file identity, and content hash."
            ),
            canonical_command=canonical_command,
            reason_code="interpreter_identity_untrusted",
            interpreter_executable_identities=interpreter_executable_identities,
        )
    return None


__all__ = [
    "_destructive_shell_tool_action_request",
]
