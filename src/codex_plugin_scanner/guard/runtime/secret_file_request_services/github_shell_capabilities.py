"""Public carriers delegated to the existing native shell kernels."""

from __future__ import annotations

from pathlib import Path

from ...native_shell_request_authority import shell_request_authority
from ..github_capability_contract import GitHubCommandAssessment
from .shell_quote_tokens import ShellTokenWithQuoteContext as _ShellTokenWithQuoteContext


def classify_github_shell_capabilities(command_text: str, *, home_dir: Path | None) -> GitHubCommandAssessment | None:
    value = shell_request_authority("classify_github_shell_capabilities", locals())
    return (
        None
        if value is None
        else GitHubCommandAssessment(
            value["capability"], value["reason_code"], value["detail"], tuple(value["capabilities"])
        )
    )


def _github_environment_requires_review(assignments: tuple[tuple[str, str], ...]) -> bool:
    return shell_request_authority("_github_environment_requires_review", locals())


def _persistent_github_environment_requires_review(parts: list[str]) -> bool:
    return shell_request_authority("_persistent_github_environment_requires_review", locals())


def _github_shell_has_dynamic_arguments(command_text: str) -> bool:
    return shell_request_authority("_github_shell_has_dynamic_arguments", locals())


def github_argument_token_has_untrusted_expansion(token: str) -> bool:
    return shell_request_authority("github_argument_token_has_untrusted_expansion", locals())


def _shell_token_has_expansion(token: str) -> bool:
    return shell_request_authority("_shell_token_has_expansion", locals())


def _github_script_requires_review(script: str) -> bool:
    return shell_request_authority("_github_script_requires_review", locals())


def _github_environment_name(name: str) -> bool:
    return shell_request_authority("_github_environment_name", locals())


def _shell_segment_is_command_builtin_lookup(segment: list[str]) -> bool:
    return shell_request_authority("_shell_segment_is_command_builtin_lookup", locals())


def _github_pipeline_companion_is_read_only(segment: list[str], *, home_dir: Path | None, command_text: str) -> bool:
    return shell_request_authority("_github_pipeline_companion_is_read_only", locals())


def _command_builtin_options_are_lookup_only(segment: list[_ShellTokenWithQuoteContext], index: int) -> bool:
    return shell_request_authority("_command_builtin_options_are_lookup_only", locals())


def _shell_command_substitution_payloads(command_text: str) -> tuple[str, ...]:
    return tuple(shell_request_authority("_shell_command_substitution_payloads", locals()))


def _read_command_substitution(command_text: str, start_index: int) -> tuple[str, int]:
    return tuple(shell_request_authority("_read_command_substitution", locals()))


def _read_backtick_command_substitution(command_text: str, start_index: int) -> tuple[str, int]:
    return tuple(shell_request_authority("_read_backtick_command_substitution", locals()))


def _iter_shell_pipelines(parts: list[str]) -> list[list[list[str]]]:
    return shell_request_authority("_iter_shell_pipelines", locals())


def _env_split_string_payloads(parts: list[str]) -> tuple[str, ...]:
    return tuple(shell_request_authority("_env_split_string_payloads", locals()))


def _shell_segment_env_index(segment: list[str]) -> int | None:
    return shell_request_authority("_shell_segment_env_index", locals())


def _shell_command_scripts(parts: list[str]) -> tuple[str, ...]:
    return tuple(shell_request_authority("_shell_command_scripts", locals()))


__all__ = [
    "_ShellTokenWithQuoteContext",
    "_command_builtin_options_are_lookup_only",
    "_env_split_string_payloads",
    "_github_pipeline_companion_is_read_only",
    "_iter_shell_pipelines",
    "_read_backtick_command_substitution",
    "_read_command_substitution",
    "_shell_command_scripts",
    "_shell_command_substitution_payloads",
    "_shell_segment_env_index",
    "_shell_segment_is_command_builtin_lookup",
    "classify_github_shell_capabilities",
]
