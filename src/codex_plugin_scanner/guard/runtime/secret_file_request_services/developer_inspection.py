"""Public developer inspection carriers and bound native authority adapters."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from ...native_developer_inspection_authority import developer_inspection_authority
from ..shell_execution_context import ShellExecutionContext


class DeveloperShellEffect(str, Enum):
    """Effects that may participate in a silently verified inspection chain."""

    DIRECTORY = "directory"
    LOCAL_READ = "local-read"
    REMOTE_READ = "remote-read"
    STREAM_FILTER = "stream-filter"
    STATIC_OUTPUT = "static-output"
    SYNTAX_CHECK = "syntax-check"


@dataclass(frozen=True, slots=True)
class DeveloperShellSegmentEffect:
    index: int
    command_name: str
    effect: DeveloperShellEffect


@dataclass(frozen=True)
class DeveloperShellEffectGraph:
    """Complete, ordered proof that every shell segment is a bounded observer."""

    __slots__ = ("_native_observation", "context", "segments")
    context: ShellExecutionContext
    segments: tuple[DeveloperShellSegmentEffect, ...]

    def __getstate__(self) -> list[object]:
        return [self.context, self.segments]

    def __setstate__(self, state: list[object]) -> None:
        object.__setattr__(self, "context", state[0])
        object.__setattr__(self, "segments", state[1])

    @property
    def has_observation(self) -> bool:
        observation = getattr(self, "_native_observation", None)
        if observation is not None:
            return observation
        return developer_inspection_authority(
            "_graph_has_observation", {"context": self.context, "segments": self.segments}
        )


def _low_risk_compound_developer_execution_context(
    command_text: str, *, cwd: Path | None = None, home_dir: Path
) -> ShellExecutionContext | None:
    return developer_inspection_authority("_low_risk_compound_developer_execution_context", locals())


def _compound_developer_effect_graph(
    command_text: str, *, cwd: Path | None = None, home_dir: Path
) -> DeveloperShellEffectGraph | None:
    return developer_inspection_authority("_compound_developer_effect_graph", locals())


def _known_context_effect_graph(
    context: ShellExecutionContext, observation_effect: DeveloperShellEffect
) -> DeveloperShellEffectGraph:
    return developer_inspection_authority("_known_context_effect_graph", locals())


def _read_only_lookup_primary_segment_is_safe(command: str, args: list[str], *, home_dir: Path | None) -> bool:
    return developer_inspection_authority("_read_only_lookup_primary_segment_is_safe", locals())


def _read_only_lookup_date_args_are_safe(args: list[str]) -> bool:
    return developer_inspection_authority("_read_only_lookup_date_args_are_safe", locals())


def _read_only_lookup_plain_targets_are_safe(
    args: list[str], *, allow_dirs: bool, home_dir: Path | None = None
) -> bool:
    return developer_inspection_authority("_read_only_lookup_plain_targets_are_safe", locals())


def _read_only_lookup_search_args_are_safe(command: str, args: list[str], *, home_dir: Path | None = None) -> bool:
    return developer_inspection_authority("_read_only_lookup_search_args_are_safe", locals())


def _read_only_lookup_search_uses_file_input(command: str, args: list[str]) -> bool:
    return developer_inspection_authority("_read_only_lookup_search_uses_file_input", locals())


def _ripgrep_config_is_disabled(args: list[str]) -> bool:
    return developer_inspection_authority("_ripgrep_config_is_disabled", locals())


def _read_only_lookup_fd_args_are_safe(args: list[str], *, home_dir: Path | None = None) -> bool:
    return developer_inspection_authority("_read_only_lookup_fd_args_are_safe", locals())


def _fd_exec_sed_read_only_args_are_safe(args: list[str], *, home_dir: Path | None = None) -> bool:
    return developer_inspection_authority("_fd_exec_sed_read_only_args_are_safe", locals())


def _read_only_lookup_find_args_are_safe(args: list[str], *, home_dir: Path | None = None) -> bool:
    return developer_inspection_authority("_read_only_lookup_find_args_are_safe", locals())


def _find_args_use_write_or_unsafe_exec_action(args: list[str]) -> bool:
    return developer_inspection_authority("_find_args_use_write_or_unsafe_exec_action", locals())


def _find_exec_sed_args_are_read_only(args: list[str]) -> bool:
    return developer_inspection_authority("_find_exec_sed_args_are_read_only", locals())


def _find_exec_ls_args_are_read_only(args: list[str]) -> bool:
    return developer_inspection_authority("_find_exec_ls_args_are_read_only", locals())


def _static_shell_segment_is_safe(args: list[str]) -> bool:
    return developer_inspection_authority("_static_shell_segment_is_safe", locals())


def _static_shell_arg_is_safe(arg: str) -> bool:
    return developer_inspection_authority("_static_shell_arg_is_safe", locals())


def _is_read_only_observer_interpreter_command(command_name: str) -> bool:
    return developer_inspection_authority("_is_read_only_observer_interpreter_command", locals())


__all__ = [
    "DeveloperShellEffect",
    "DeveloperShellEffectGraph",
    "DeveloperShellSegmentEffect",
    "_compound_developer_effect_graph",
    "_fd_exec_sed_read_only_args_are_safe",
    "_find_args_use_write_or_unsafe_exec_action",
    "_find_exec_sed_args_are_read_only",
    "_is_read_only_observer_interpreter_command",
    "_low_risk_compound_developer_execution_context",
    "_read_only_lookup_date_args_are_safe",
    "_read_only_lookup_fd_args_are_safe",
    "_read_only_lookup_find_args_are_safe",
    "_read_only_lookup_plain_targets_are_safe",
    "_read_only_lookup_primary_segment_is_safe",
    "_read_only_lookup_search_args_are_safe",
    "_static_shell_arg_is_safe",
    "_static_shell_segment_is_safe",
]
