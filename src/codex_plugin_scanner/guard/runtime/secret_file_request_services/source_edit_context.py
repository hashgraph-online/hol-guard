"""Public developer inspection carriers and bound native authority adapters."""

from __future__ import annotations

from pathlib import Path

from ...native_developer_inspection_authority import developer_inspection_authority
from ..shell_execution_context import ShellExecutionContext


def low_risk_compound_developer_execution_context(
    command_text: str, *, cwd: Path | None = None, home_dir: Path
) -> ShellExecutionContext | None:
    return developer_inspection_authority("low_risk_compound_developer_execution_context", locals())


def _bounded_verified_source_edit_execution_context(
    command_text: str, *, home_dir: Path
) -> ShellExecutionContext | None:
    return developer_inspection_authority("_bounded_verified_source_edit_execution_context", locals())


def _bounded_in_place_sed_target(args: list[str], *, cwd: Path, workspace_root: Path) -> str | None:
    return developer_inspection_authority("_bounded_in_place_sed_target", locals())


def _literal_sed_script_is_safe(script: str) -> bool:
    return developer_inspection_authority("_literal_sed_script_is_safe", locals())


def _split_literal_sed_commands(script: str) -> tuple[str, ...]:
    return developer_inspection_authority("_split_literal_sed_commands", locals())


def _bounded_edit_workspace_is_safe(workspace_root: Path, *, home_dir: Path) -> bool:
    return developer_inspection_authority("_bounded_edit_workspace_is_safe", locals())


def _literal_sed_substitution_is_safe(script: str) -> bool:
    return developer_inspection_authority("_literal_sed_substitution_is_safe", locals())


def _sed_pattern_is_literal(pattern: str, *, delimiter: str) -> bool:
    return developer_inspection_authority("_sed_pattern_is_literal", locals())


def _sed_replacement_is_literal(replacement: str, *, delimiter: str) -> bool:
    return developer_inspection_authority("_sed_replacement_is_literal", locals())


def _same_workspace_file(left: str, right: str, *, cwd: Path) -> bool:
    return developer_inspection_authority("_same_workspace_file", locals())


__all__ = [
    "_bounded_edit_workspace_is_safe",
    "_bounded_in_place_sed_target",
    "_bounded_verified_source_edit_execution_context",
    "_literal_sed_script_is_safe",
    "_literal_sed_substitution_is_safe",
    "_same_workspace_file",
    "_sed_pattern_is_literal",
    "_sed_replacement_is_literal",
    "_split_literal_sed_commands",
    "low_risk_compound_developer_execution_context",
]
