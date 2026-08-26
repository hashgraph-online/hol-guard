"""Explicitly benign request classification and artifact construction."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
from pathlib import Path

from ...models import GuardArtifact
from ..command_decision_adapter import effect_decision_to_dict
from ..command_evaluation import evaluate_command
from ..command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from ..direct_vitest import direct_local_typescript_execution_context, direct_local_vitest_execution_context
from ..extension_control_contract import ControlSurface, ExtensionControlLayer
from ..extension_control_resolver import resolve_extension_controls
from ..extension_control_runtime import current_extension_control_snapshot
from ..false_positive_rules import KNOWN_AGENT_DOC_SUFFIXES, target_is_known_skill_doc_path
from ..github_actions_read_workflow import is_nonexecuting_github_actions_read_workflow
from ..github_capability_contract import GitHubCommandAssessment
from ..github_capability_interaction import github_capability_requires_confirmation
from ..read_only_git_audit import is_read_only_git_ancestry_audit
from ..routine_setup_commands import is_safe_codex_memory_registry_search, is_safe_git_worktree_add
from ..shell_command_wrappers import normalize_transparent_shell_command
from ..shell_execution_context import model_shell_execution_context
from .agent_guidance_reads import is_benign_agent_guidance_read
from .constants_core import _SHELL_TOOL_NAMES
from .destructive_shell_detection import _shell_command_names_from_parts
from .developer_routines import (
    _looks_like_safe_cli_metadata_command,
    _looks_like_safe_compound_developer_inspection,
    _looks_like_safe_kubernetes_inventory_command,
    _safe_dependency_symlink_execution_context,
)
from .git_routines import (
    _looks_like_safe_git_branch_switch_command,
    _looks_like_safe_git_status_command,
    _looks_like_safe_standalone_git_routine,
)
from .github_pr_ephemeral_body import gh_pr_create_uses_safe_ephemeral_body
from .github_shell_capabilities import (
    _ShellTokenWithQuoteContext,
    classify_github_shell_capabilities,
    github_argument_token_has_untrusted_expansion,
)
from .interpreter_identity import _python_interpreter_executable_identities
from .interpreter_observers import (
    _looks_like_benign_interpreter_wait,
    _looks_like_benign_interpreter_wait_chain,
    _looks_like_read_only_interpreter_command,
    _looks_like_safe_read_only_lookup_command,
)
from .request_artifacts import _candidate_command_texts
from .request_models import ToolActionRequestMatch, _normalize_tool_name
from .routine_directory_creation import is_safe_routine_directory_creation
from .sensitive_read_pipeline import _runtime_read_root_texts
from .shell_quote_tokens import shell_token_segments, shell_tokens_preserving_quote_context
from .shell_static_safety import _path_text_is_within_root_text, _without_safe_inspection_redirections
from .shell_stdin_sources import (
    _cat_reads_local_file,
    _cat_stdout_payloads,
    _echo_stdout_payload,
    _printf_stdout_payloads,
)
from .shell_tokenization import _iter_shell_command_segments, _shell_segment_primary_command, _split_shell_parts


def is_explicitly_benign_tool_action_request(
    tool_name: object,
    arguments: object,
    *,
    cwd: Path | None = None,
    home_dir: Path | None = None,
) -> bool:
    normalized_tool_name = _normalize_tool_name(tool_name)
    if normalized_tool_name not in _SHELL_TOOL_NAMES:
        return False
    found_benign_candidate = False
    for command_text in _candidate_command_texts(arguments):
        raw_command_text = command_text
        interpreter_evidence = _python_interpreter_executable_identities(
            command_text,
            cwd=cwd,
            home_dir=home_dir,
        )
        if any(evidence.get("trust") not in {"trusted_guard", "trusted_system"} for evidence in interpreter_evidence):
            return False
        if normalized_tool_name in _SHELL_TOOL_NAMES:
            normalization = normalize_transparent_shell_command(command_text, cwd=cwd, home_dir=home_dir)
            command_text = normalization.normalized_command
            if normalization.wrapper_chain:
                raw_github_assessment = classify_github_shell_capabilities(raw_command_text, home_dir=home_dir)
                if raw_github_assessment is not None and github_capability_requires_confirmation(raw_github_assessment):
                    return False
                normalized_parts = _split_shell_parts(command_text)
                normalized_segments = _iter_shell_command_segments(normalized_parts)
                invokes_guard = any(
                    _shell_segment_primary_command(segment)[0] == "hol-guard" for segment in normalized_segments
                )
                if invokes_guard and command_text != raw_command_text:
                    return False
        stripped_command = command_text.strip()
        if not stripped_command:
            continue
        if is_nonexecuting_github_actions_read_workflow(stripped_command, cwd=cwd):
            found_benign_candidate = True
            continue
        if gh_pr_create_uses_safe_ephemeral_body(stripped_command):
            found_benign_candidate = True
            continue
        github_assessment = classify_github_shell_capabilities(stripped_command, home_dir=home_dir)
        if github_assessment is not None and github_capability_requires_confirmation(github_assessment):
            return False
        control_snapshot = current_extension_control_snapshot()
        if github_assessment is not None and control_snapshot is not None:
            permissions = tuple(
                permission
                for capability in github_assessment.capabilities
                if (permission := BUILT_IN_COMMAND_EXTENSION_REGISTRY.permission_for_typed_capability(capability))
                is not None
            )
            control_resolution = resolve_extension_controls(
                control_snapshot.layers,
                BUILT_IN_COMMAND_EXTENSION_REGISTRY,
                extension_ids=tuple(sorted({permission.extension_id for permission in permissions})),
                permission_ids=tuple(sorted({permission.permission_id for permission in permissions})),
                surface=ControlSurface.COMMAND_EVALUATION,
                authority_failure=control_snapshot.authority_failure,
            )
            if control_resolution.blocked:
                return False
        if _quote_aware_direct_github_read_is_safe(stripped_command, assessment=github_assessment):
            found_benign_candidate = True
            continue
        if home_dir is not None and is_benign_agent_guidance_read(stripped_command, cwd, home_dir):
            found_benign_candidate = True
            continue
        parts = _split_shell_parts(stripped_command)
        if not parts:
            return False
        parsed_command_names = list(_shell_command_names_from_parts(parts))
        if _looks_like_benign_interpreter_wait(stripped_command, parts, parsed_command_names):
            found_benign_candidate = True
            continue
        if _looks_like_benign_interpreter_wait_chain(stripped_command, parts):
            found_benign_candidate = True
            continue
        if _looks_like_read_only_interpreter_command(stripped_command, parts, parsed_command_names):
            found_benign_candidate = True
            continue
        if _looks_like_safe_read_only_lookup_command(
            stripped_command,
            parts,
            home_dir=home_dir,
        ):
            found_benign_candidate = True
            continue
        if _looks_like_safe_existence_probe(stripped_command, cwd=cwd, home_dir=home_dir):
            found_benign_candidate = True
            continue
        if is_safe_routine_directory_creation(stripped_command, cwd=cwd, home_dir=home_dir):
            found_benign_candidate = True
            continue
        if _looks_like_safe_cli_metadata_command(stripped_command, parts, cwd=cwd):
            found_benign_candidate = True
            continue
        if _looks_like_safe_git_branch_switch_command(stripped_command, parts, cwd=cwd):
            found_benign_candidate = True
            continue
        if _looks_like_safe_git_status_command(stripped_command, parts, cwd=cwd):
            found_benign_candidate = True
            continue
        if _looks_like_safe_standalone_git_routine(stripped_command, cwd=cwd, home_dir=home_dir):
            found_benign_candidate = True
            continue
        if home_dir is not None and is_safe_git_worktree_add(
            stripped_command,
            cwd=cwd,
            home_dir=home_dir,
        ):
            found_benign_candidate = True
            continue
        if home_dir is not None and is_safe_codex_memory_registry_search(
            stripped_command,
            cwd=cwd,
            home_dir=home_dir,
        ):
            found_benign_candidate = True
            continue
        if home_dir is not None and (
            direct_local_vitest_execution_context(
                stripped_command,
                cwd=cwd,
                home_dir=home_dir,
            )
            or direct_local_typescript_execution_context(
                stripped_command,
                cwd=cwd,
                home_dir=home_dir,
            )
        ):
            found_benign_candidate = True
            continue
        if (
            home_dir is not None
            and _safe_dependency_symlink_execution_context(
                stripped_command,
                cwd=cwd,
                home_dir=home_dir,
            )
            is not None
        ):
            found_benign_candidate = True
            continue
        if home_dir is not None and _looks_like_safe_compound_developer_inspection(
            stripped_command,
            cwd=cwd,
            home_dir=home_dir,
        ):
            found_benign_candidate = True
            continue
        if home_dir is not None and is_read_only_git_ancestry_audit(
            stripped_command,
            cwd=cwd,
            home_dir=home_dir,
        ):
            found_benign_candidate = True
            continue
        if _looks_like_safe_kubernetes_inventory_command(stripped_command, parts, cwd=cwd):
            found_benign_candidate = True
            continue
        return False
    return found_benign_candidate


def _is_bounded_agent_guidance_read_chain(
    command_text: str,
    *,
    cwd: Path | None,
    home_dir: Path,
) -> bool:
    if any(marker in command_text for marker in ("$(", "`", "<(", ">(")):
        return False
    context = model_shell_execution_context(
        command_text,
        cwd=cwd,
        workspace_root=cwd,
        home_dir=home_dir,
    )
    if not context.complete or not 1 <= len(context.segments) <= 8:
        return False
    for segment in context.segments:
        controls = (*segment.control_before, *segment.control_after)
        if any(operator != "&&" for operator in controls) or segment.directory_operation is not None:
            return False
        parts = list(segment.tokens)
        target = _bounded_sed_read_target(parts)
        if target is None:
            return False
        if _is_approved_agent_guidance_target(target, home_dir=home_dir):
            continue
        if _is_guard_safety_doc_target(target, home_dir=home_dir):
            continue
        return False
    return True


def _bounded_sed_read_target(parts: list[str]) -> str | None:
    if len(parts) != 4 or parts[:2] != ["sed", "-n"]:
        return None
    match = re.fullmatch(r"([1-9][0-9]{0,3}),([1-9][0-9]{0,3})p", parts[2])
    if match is None:
        return None
    start, end = map(int, match.groups())
    return parts[3] if start <= end and end - start + 1 <= 500 else None


def _is_approved_agent_guidance_target(target: str, *, home_dir: Path) -> bool:
    if not target_is_known_skill_doc_path(target, home_dir=home_dir):
        return False
    normalized = target.replace("\\", "/").rstrip("/")
    return normalized.endswith("/SKILL.md") or any(normalized.endswith(suffix) for suffix in KNOWN_AGENT_DOC_SUFFIXES)


def _is_guard_safety_doc_target(target: str, *, home_dir: Path) -> bool:
    expected = home_dir / ".hol-support" / "SAFETY.md"
    candidate = home_dir / target[2:] if target.startswith("~/") else Path(target)
    try:
        resolved_home = home_dir.resolve(strict=True)
        resolved_support = (home_dir / ".hol-support").resolve(strict=True)
        resolved_expected = expected.resolve(strict=True)
        return (
            candidate.absolute() == expected.absolute()
            and not home_dir.is_symlink()
            and not (home_dir / ".hol-support").is_symlink()
            and not expected.is_symlink()
            and resolved_support == resolved_home / ".hol-support"
            and resolved_expected == resolved_support / "SAFETY.md"
            and resolved_expected.is_file()
        )
    except (OSError, RuntimeError):
        return False


def _quote_aware_direct_github_read_is_safe(
    command_text: str,
    *,
    assessment: GitHubCommandAssessment | None,
) -> bool:
    if assessment is None:
        return False
    segments = shell_token_segments(shell_tokens_preserving_quote_context(command_text))
    if len(segments) != 1 or not segments[0] or segments[0][0].raw != "gh":
        return False
    segment = segments[0]
    plain_segment = [token.plain for token in segment]
    command_name, command_index = _shell_segment_primary_command(plain_segment)
    if command_name != "gh" or command_index != 0:
        return False
    if _without_safe_inspection_redirections(plain_segment[1:]) is None:
        return False
    return not any(github_argument_token_has_untrusted_expansion(token.raw) for token in segment[1:])


def _looks_like_safe_existence_probe(
    command_text: str,
    *,
    cwd: Path | None,
    home_dir: Path | None,
) -> bool:
    """Recognize a metadata-only local path existence check with literal output."""

    try:
        lexer = shlex.shlex(command_text, posix=True, punctuation_chars=";&|<>()")
        lexer.whitespace_split = True
        lexer.commenters = ""
        parts = list(lexer)
    except ValueError:
        return False
    if len(parts) != 9 or parts[:2] != ["test", "-e"]:
        return False
    if parts[3:] != ["&&", "echo", "exists", "||", "echo", "absent"]:
        return False
    target = parts[2]
    if any(marker in target for marker in ("$", "`", "*", "?", "[", "]", "{", "}")):
        return False
    try:
        candidate = Path(target).expanduser()
        if not candidate.is_absolute():
            if cwd is None:
                return False
            if ".." in candidate.parts:
                return False
            candidate = cwd / candidate
        resolved = candidate.resolve(strict=False)
        allowed_roots = tuple(root.resolve() for root in (cwd, home_dir) if root is not None)
    except (OSError, RuntimeError):
        return False
    return bool(allowed_roots) and any(resolved.is_relative_to(root) for root in allowed_roots)


def _skip_shell_wrapper_options(segment: list[_ShellTokenWithQuoteContext], index: int) -> int:
    while index < len(segment) and segment[index].plain.startswith("-"):
        index += 1
    return index


def _shell_stdout_payloads(
    segment: list[str],
    *,
    cwd: Path | None,
    home_dir: Path | None,
    allowed_roots: tuple[Path, ...] | None = None,
) -> tuple[tuple[str, Path | None], ...]:
    command_name, command_index = _shell_segment_primary_command(segment)
    if command_name is None or command_index is None:
        return ()
    segment_args = segment[command_index + 1 :]
    if command_name == "printf":
        payloads = _printf_stdout_payloads(segment_args)
        return tuple((payload, cwd) for payload in payloads)
    if command_name == "echo":
        payload = _echo_stdout_payload(segment_args)
        return ((payload, cwd),) if payload else ()
    if command_name == "cat":
        return _cat_stdout_payloads(segment_args, cwd=cwd, home_dir=home_dir, allowed_roots=allowed_roots)
    return ()


def _shell_stdout_uses_local_file(
    segment: list[str],
    *,
    cwd: Path | None,
    home_dir: Path | None,
) -> bool:
    command_name, command_index = _shell_segment_primary_command(segment)
    if command_name != "cat" or command_index is None:
        return False
    return _cat_reads_local_file(segment[command_index + 1 :], cwd=cwd, home_dir=home_dir)


def build_tool_action_request_artifact(
    harness: str,
    request: ToolActionRequestMatch,
    *,
    config_path: str,
    source_scope: str,
    extension_control_layers: tuple[ExtensionControlLayer, ...] | None = None,
) -> GuardArtifact:
    """Build a Guard artifact for a sensitive native tool action request."""

    policy_command = request.raw_command_text or request.command_text
    evaluation = evaluate_command(
        policy_command,
        canonical_command=(request.canonical_command if request.raw_command_text is None else None),
        compatibility_action_class=request.action_class,
        compatibility_reason=request.reason,
        extension_control_layers=extension_control_layers,
    )
    wrapper_chain = tuple(dict.fromkeys((*evaluation.command.wrapper_chain, *request.wrapper_chain)))
    fingerprint_payload = {
        "harness": harness,
        "tool_name": request.normalized_tool_name,
        "command_text": request.command_text,
        "action_class": request.action_class,
        "shell_execution_context_hash": request.shell_execution_context_hash,
        "interpreter_executable_identities": request.interpreter_executable_identities,
    }
    if request.restricted_profile_version is not None:
        fingerprint_payload["restricted_profile_version"] = request.restricted_profile_version
    if request.pytest_config_identity_sha256 is not None:
        fingerprint_payload["pytest_config_identity_sha256"] = request.pytest_config_identity_sha256
    fingerprint = hashlib.sha256(json.dumps(fingerprint_payload, sort_keys=True).encode("utf-8")).hexdigest()
    request_summary = f"Requested `{request.tool_name}` action `{request.command_text}` ({request.action_class})."
    if wrapper_chain:
        request_summary = (
            f"Requested `{request.tool_name}` action `{request.command_text}` via transparent wrappers "
            f"`{' -> '.join(wrapper_chain)}` ({request.action_class})."
        )
    risk_summary = f"Requests a sensitive native tool action: {request.action_class}."
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
        artifact_id=f"{harness}:{source_scope}:tool-action:{fingerprint}",
        name=f"{request.tool_name} {request.action_class}",
        harness=harness,
        artifact_type="tool_action_request",
        source_scope=source_scope,
        config_path=config_path,
        command=policy_command,
        metadata={
            "tool_name": request.tool_name,
            "command_text": request.command_text,
            "action_class": request.action_class,
            "request_summary": request_summary,
            "runtime_request_signals": [f"invokes a sensitive native tool action: {request.action_class}"],
            "runtime_request_summary": risk_summary,
            "runtime_request_reason": runtime_reason,
            "raw_command_text": request.raw_command_text,
            "wrapper_chain": list(wrapper_chain),
            "command_security_identity": evaluation.command.security_identity,
            "command_action_floor": evaluation.decision_plane.action,
            "command_decision_plane": effect_decision_to_dict(evaluation.decision_plane),
            "extension_control_resolution": {
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
            },
            "command_rule_matches": [owned.to_dict() for owned in evaluation.matches],
            "risk_classes": list(evaluation.risk_classes),
            "command_parse_confidence": evaluation.command.confidence,
            "command_uncertainty_reason": evaluation.command.uncertainty_reason,
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


def _path_is_within_roots(path: Path, roots: tuple[Path, ...]) -> bool:
    path_text = os.path.realpath(os.fspath(path))
    root_texts = _runtime_read_root_texts(roots)
    return any(_path_text_is_within_root_text(path_text, root_text) for root_text in root_texts)


__all__ = [
    "_path_is_within_roots",
    "_shell_stdout_payloads",
    "_shell_stdout_uses_local_file",
    "_skip_shell_wrapper_options",
    "build_tool_action_request_artifact",
    "is_explicitly_benign_tool_action_request",
]
