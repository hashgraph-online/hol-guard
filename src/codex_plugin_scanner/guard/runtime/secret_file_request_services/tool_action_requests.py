"""Native tool action request extraction."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path
from typing import cast

from ..command_model import CanonicalCommand
from ..compound_git_inspection import (
    canonical_home_git_c_path,
    is_low_risk_git_inspection_segment,
    is_low_risk_standalone_git_routine,
)
from ..git_execution_safety import git_status_args_are_read_only, git_status_has_execution_free_config
from ..kubernetes_commands import kubernetes_secret_read_source
from ..shell_command_wrappers import normalize_transparent_shell_command
from ..shell_execution_context import ShellExecutionContext, model_shell_execution_context
from .constants_core import _FILE_WRITE_TOOL_NAMES, _SHELL_TOOL_NAMES
from .docker_requests import (
    _docker_config_tool_action_request,
    _docker_sensitive_tool_action_request,
    _shell_execution_context_validation_reason,
)
from .pytest_config_safety import _shell_args_without_trailing_redirections
from .request_artifacts import _candidate_command_texts, _shell_normalized_tool_name
from .request_models import ToolActionRequestMatch, _normalize_tool_name
from .shell_request_classifier import _destructive_shell_tool_action_request
from .shell_static_safety import _shell_token_has_command_substitution
from .shell_tokenization import _shell_segment_primary_command

_GIT_GLOBAL_FLAG_OPTIONS = frozenset(
    {
        "--bare",
        "--literal-pathspecs",
        "--no-advice",
        "--no-lazy-fetch",
        "--no-optional-locks",
        "--no-pager",
        "--no-replace-objects",
        "--paginate",
        "-P",
        "-p",
    }
)
_GIT_GLOBAL_VALUE_OPTIONS = frozenset(
    {"--config-env", "--exec-path", "--git-dir", "--namespace", "--super-prefix", "--work-tree", "-C", "-c"}
)


def extract_sensitive_tool_action_request(
    tool_name: object,
    arguments: object,
    *,
    cwd: Path | None = None,
    home_dir: Path | None = None,
    canonical_command: CanonicalCommand | None = None,
) -> ToolActionRequestMatch | None:
    """Extract a sensitive native tool action from arguments."""

    normalized_tool_name = _normalize_tool_name(tool_name)
    command_arguments = arguments
    if normalized_tool_name not in _SHELL_TOOL_NAMES and isinstance(arguments, Mapping):
        typed_arguments = cast(Mapping[str, object], arguments)
        command_arguments = {
            key: value
            for key, value in typed_arguments.items()
            if key in {"command", "cmd", "shell_command", "shellCommand"}
        }
    command_texts = _candidate_command_texts(command_arguments)
    if normalized_tool_name in _FILE_WRITE_TOOL_NAMES:
        return None
    if normalized_tool_name is None and not command_texts:
        return None
    requested_tool_name = str(tool_name).strip() if isinstance(tool_name, str) and str(tool_name).strip() else "Shell"
    effective_tool_name = _shell_normalized_tool_name(
        normalized_tool_name=normalized_tool_name,
        arguments=arguments,
    )
    if effective_tool_name is None:
        return None
    for command_text in command_texts:
        raw_command_text = command_text
        candidate_canonical = (
            canonical_command
            if canonical_command is not None and canonical_command.raw_text == raw_command_text.strip()
            else None
        )
        wrapper_chain: tuple[str, ...] = ()
        normalized_command_text = command_text
        if effective_tool_name in _SHELL_TOOL_NAMES:
            normalized_command = normalize_transparent_shell_command(command_text, cwd=cwd, home_dir=home_dir)
            command_text = normalized_command.normalized_command
            normalized_command_text = command_text
            wrapper_chain = normalized_command.wrapper_chain
        git_fetch_request = _unverified_git_fetch_request(
            tool_name=requested_tool_name,
            normalized_tool_name=effective_tool_name,
            command_text=command_text,
            cwd=cwd,
            home_dir=home_dir,
        )
        if git_fetch_request is not None:
            return git_fetch_request
        docker_sensitive_request = _docker_sensitive_tool_action_request(
            tool_name=requested_tool_name,
            normalized_tool_name=effective_tool_name,
            command_text=command_text,
        )
        if docker_sensitive_request is not None:
            docker_sensitive_request = _request_with_shell_execution_context(
                docker_sensitive_request,
                command_text=command_text,
                cwd=cwd,
            )
            if wrapper_chain:
                docker_sensitive_request = _request_with_wrapper_context(
                    docker_sensitive_request,
                    raw_command_text=raw_command_text,
                    wrapper_chain=wrapper_chain,
                )
            return docker_sensitive_request
        if raw_command_text != command_text:
            docker_sensitive_request = _docker_sensitive_tool_action_request(
                tool_name=requested_tool_name,
                normalized_tool_name=effective_tool_name,
                command_text=raw_command_text,
            )
            if docker_sensitive_request is not None:
                docker_sensitive_request = _request_with_shell_execution_context(
                    docker_sensitive_request,
                    command_text=normalized_command_text,
                    cwd=cwd,
                )
                if wrapper_chain:
                    docker_sensitive_request = _request_with_wrapper_context(
                        replace(
                            docker_sensitive_request,
                            command_text=normalized_command_text,
                        ),
                        raw_command_text=raw_command_text,
                        wrapper_chain=wrapper_chain,
                    )
                return docker_sensitive_request
        docker_config_request = _docker_config_tool_action_request(
            tool_name=requested_tool_name,
            normalized_tool_name=effective_tool_name,
            command_text=command_text,
            cwd=cwd,
            home_dir=home_dir,
        )
        if docker_config_request is not None:
            docker_config_request = _request_with_shell_execution_context(
                docker_config_request,
                command_text=command_text,
                cwd=cwd,
            )
            if wrapper_chain:
                docker_config_request = _request_with_wrapper_context(
                    docker_config_request,
                    raw_command_text=raw_command_text,
                    wrapper_chain=wrapper_chain,
                )
            return docker_config_request
        kubernetes_secret_source = kubernetes_secret_read_source(command_text)
        if kubernetes_secret_source is not None:
            kubernetes_secret_request = ToolActionRequestMatch(
                tool_name=requested_tool_name,
                normalized_tool_name=effective_tool_name,
                command_text=command_text,
                action_class="Kubernetes secret read command",
                reason=(
                    f"Guard treats {kubernetes_secret_source} reads through Kubernetes CLIs as sensitive because "
                    "they can expose cluster credentials or application secrets before the user confirms the action."
                ),
            )
            kubernetes_secret_request = _request_with_shell_execution_context(
                kubernetes_secret_request,
                command_text=command_text,
                cwd=cwd,
            )
            if wrapper_chain:
                kubernetes_secret_request = _request_with_wrapper_context(
                    kubernetes_secret_request,
                    raw_command_text=raw_command_text,
                    wrapper_chain=wrapper_chain,
                )
            return kubernetes_secret_request
        destructive_execution_context = model_shell_execution_context(
            command_text,
            cwd=cwd,
            workspace_root=cwd,
            home_dir=home_dir,
        )
        raw_destructive_execution_context = (
            model_shell_execution_context(
                raw_command_text,
                cwd=cwd,
                workspace_root=cwd,
                home_dir=home_dir,
            )
            if raw_command_text != command_text
            else destructive_execution_context
        )
        destructive_shell_request = _destructive_shell_tool_action_request(
            tool_name=requested_tool_name,
            normalized_tool_name=effective_tool_name,
            command_text=command_text,
            cwd=cwd,
            home_dir=home_dir,
            canonical_command=(
                candidate_canonical
                if candidate_canonical is not None and candidate_canonical.normalized_text == command_text
                else None
            ),
            raw_command_text=raw_command_text,
            execution_context=destructive_execution_context,
            raw_execution_context=raw_destructive_execution_context,
        )
        if destructive_shell_request is not None:
            destructive_shell_request = _request_with_shell_execution_context(
                destructive_shell_request,
                command_text=command_text,
                cwd=cwd,
                context=destructive_execution_context,
            )
            if wrapper_chain:
                destructive_shell_request = _request_with_wrapper_context(
                    destructive_shell_request,
                    raw_command_text=raw_command_text,
                    wrapper_chain=wrapper_chain,
                )
            return destructive_shell_request
        if wrapper_chain:
            destructive_shell_request = _destructive_shell_tool_action_request(
                tool_name=requested_tool_name,
                normalized_tool_name=effective_tool_name,
                command_text=raw_command_text,
                cwd=cwd,
                home_dir=home_dir,
                canonical_command=candidate_canonical,
                raw_command_text=raw_command_text,
                execution_context=raw_destructive_execution_context,
                raw_execution_context=raw_destructive_execution_context,
            )
            if destructive_shell_request is not None:
                destructive_shell_request = _request_with_shell_execution_context(
                    destructive_shell_request,
                    command_text=normalized_command_text,
                    cwd=cwd,
                )
                destructive_shell_request = _request_with_wrapper_context(
                    replace(
                        destructive_shell_request,
                        command_text=normalized_command_text,
                    ),
                    raw_command_text=raw_command_text,
                    wrapper_chain=wrapper_chain,
                )
                return destructive_shell_request
    return None


def _unverified_git_fetch_request(
    *,
    tool_name: str,
    normalized_tool_name: str,
    command_text: str,
    cwd: Path | None,
    home_dir: Path | None,
) -> ToolActionRequestMatch | None:
    if "git" not in command_text or "fetch" not in command_text:
        return None
    parsing_cwd = cwd or home_dir or Path.cwd()
    context = model_shell_execution_context(
        command_text,
        cwd=parsing_cwd,
        workspace_root=parsing_cwd,
        home_dir=home_dir,
    )
    trusted_home = home_dir if canonical_home_git_c_path(command_text) is not None else None
    if not any(_segment_invokes_git_fetch(segment.tokens) for segment in context.segments):
        return None
    if cwd is not None and is_low_risk_standalone_git_routine(context, home_dir=trusted_home):
        return None
    if context.complete and all(
        not _segment_invokes_git_fetch(segment.tokens)
        or is_low_risk_git_inspection_segment(segment, home_dir=trusted_home)
        for segment in context.segments
    ):
        return None
    return ToolActionRequestMatch(
        tool_name=tool_name,
        normalized_tool_name=normalized_tool_name,
        command_text=command_text,
        action_class="unverified Git remote refresh",
        reason="Git fetch requires repository-bound remote and execution-configuration verification.",
    )


def _segment_invokes_git_fetch(tokens: tuple[str, ...]) -> bool:
    command_name, command_index = _shell_segment_primary_command(list(tokens))
    if command_name != "git" or command_index is None:
        return False
    args = tokens[command_index + 1 :]
    index = 0
    while index < len(args):
        token = args[index]
        option_name = token.partition("=")[0]
        if token in _GIT_GLOBAL_FLAG_OPTIONS:
            index += 1
            continue
        if option_name in _GIT_GLOBAL_VALUE_OPTIONS:
            if "=" in token:
                if not token.partition("=")[2]:
                    return False
                index += 1
                continue
            if index + 1 >= len(args):
                return False
            index += 2
            continue
        if token.startswith("-"):
            index += 1
            continue
        return token == "fetch"
    return False


def _safe_git_status_cd_target(command_name: str, args: list[str], *, cwd: Path) -> Path | None:
    if command_name != "cd":
        return None
    path_args = _shell_args_without_trailing_redirections(args)
    if path_args != args or len(path_args) != 1 or path_args[0] in {"-", "--"}:
        return None
    path_text = path_args[0]
    if _shell_token_has_command_substitution(path_text):
        return None
    try:
        candidate = Path(path_text).expanduser()
        if not candidate.is_absolute():
            candidate = cwd / candidate
        resolved = candidate.resolve()
    except (OSError, RuntimeError):
        return None
    return resolved if resolved.is_dir() else None


def _git_status_has_execution_free_config(
    cwd: Path | None,
    *,
    git_binary: Path | None = None,
) -> bool:
    try:
        execution_cwd = (cwd or Path.cwd()).resolve()
    except (OSError, RuntimeError):
        return False
    return git_status_has_execution_free_config(execution_cwd, git_binary=git_binary)


def _git_status_args_are_read_only(args: list[str]) -> bool:
    return git_status_args_are_read_only(args)


def _request_with_wrapper_context(
    request: ToolActionRequestMatch,
    *,
    raw_command_text: str,
    wrapper_chain: tuple[str, ...],
) -> ToolActionRequestMatch:
    return ToolActionRequestMatch(
        tool_name=request.tool_name,
        normalized_tool_name=request.normalized_tool_name,
        command_text=request.command_text,
        action_class=request.action_class,
        reason=request.reason,
        raw_command_text=raw_command_text,
        wrapper_chain=wrapper_chain,
        canonical_command=request.canonical_command,
        shell_execution_context_hash=request.shell_execution_context_hash,
        shell_execution_context_reason_code=request.shell_execution_context_reason_code,
        shell_execution_effective_cwds=request.shell_execution_effective_cwds,
        guard_default_action=request.guard_default_action,
        reason_code=request.reason_code,
        restricted_profile_version=request.restricted_profile_version,
        pytest_config_identity_sha256=request.pytest_config_identity_sha256,
        pytest_config_sources=request.pytest_config_sources,
        pytest_config_reason_codes=request.pytest_config_reason_codes,
        interpreter_executable_identities=request.interpreter_executable_identities,
    )


def _request_with_shell_execution_context(
    request: ToolActionRequestMatch,
    *,
    command_text: str,
    cwd: Path | None,
    context: ShellExecutionContext | None = None,
) -> ToolActionRequestMatch:
    context = context or model_shell_execution_context(command_text, cwd=cwd, workspace_root=cwd)
    if not context.directory_change_present:
        return request
    reason_code = _shell_execution_context_validation_reason(context)
    return replace(
        request,
        shell_execution_context_hash=context.context_hash,
        shell_execution_context_reason_code=reason_code,
        shell_execution_effective_cwds=tuple(str(path) for path in context.effective_cwds),
    )


__all__ = [
    "_git_status_args_are_read_only",
    "_git_status_has_execution_free_config",
    "_request_with_shell_execution_context",
    "_request_with_wrapper_context",
    "_safe_git_status_cd_target",
    "extract_sensitive_tool_action_request",
]
