"""Safe Kubernetes and developer workflow recognition."""

from __future__ import annotations

from pathlib import Path

from ..compound_git_inspection import is_low_risk_git_inspection_segment
from ..git_execution_safety import trusted_git_binary_for_cwd
from ..kubernetes_commands import kubernetes_read_only_inventory_args
from ..shell_command_wrappers import is_trusted_absolute_command_path
from ..shell_execution_context import ShellExecutionContext, ShellExecutionSegment, model_shell_execution_context
from .constants_core import _READ_ONLY_LOOKUP_COMMANDS, _READ_ONLY_LOOKUP_FILTERS, _SAFE_STATIC_SHELL_COMMANDS
from .developer_inspection import (
    DeveloperShellEffect,
    _compound_developer_effect_graph,
    _is_read_only_observer_interpreter_command,
)
from .docker_requests import (
    _shell_execution_context_validation_reason,
    _which_for_execution_cwd,
)
from .git_routines import _git_log_has_execution_free_config, _read_only_git_invocation
from .shell_static_safety import (
    _leading_literal_cd_workspace_root,
    _safe_cli_metadata_segment_is_safe,
    _without_safe_inspection_redirections,
)
from .shell_tokenization import _iter_shell_command_segments, _shell_segment_primary_command
from .tool_action_requests import _git_status_has_execution_free_config, _safe_git_status_cd_target


def _looks_like_safe_kubernetes_inventory_command(
    command_text: str,
    parts: list[str],
    *,
    cwd: Path | None,
) -> bool:
    if any(marker in command_text for marker in ("$(", "`", "<(", ">(")):
        return False
    segments = _iter_shell_command_segments(parts)
    if not segments:
        return False
    try:
        effective_cwd = (cwd or Path.cwd()).resolve()
    except OSError:
        return False
    saw_inventory = False
    for segment in segments:
        command_name, command_index = _shell_segment_primary_command(segment)
        if command_name is None or command_index != 0:
            return False
        args = _without_safe_inspection_redirections(segment[command_index + 1 :])
        if args is None:
            return False
        next_cwd = _safe_git_status_cd_target(command_name, args, cwd=effective_cwd)
        if next_cwd is not None:
            effective_cwd = next_cwd
            continue
        executable = segment[command_index]
        if "/" in executable or "\\" in executable:
            return False
        if not kubernetes_read_only_inventory_args(command_name, args):
            return False
        saw_inventory = True
    return saw_inventory


def _looks_like_safe_compound_developer_inspection(
    command_text: str,
    *,
    cwd: Path | None,
    home_dir: Path,
) -> bool:
    """Auto-relax only a command with a complete bounded-observer effect graph."""

    graph = _compound_developer_effect_graph(command_text, cwd=cwd, home_dir=home_dir)
    if graph is None or not graph.context.complete:
        return False
    silently_verified_effects = {
        DeveloperShellEffect.DIRECTORY,
        DeveloperShellEffect.LOCAL_READ,
        DeveloperShellEffect.REMOTE_READ,
        DeveloperShellEffect.STREAM_FILTER,
        DeveloperShellEffect.STATIC_OUTPUT,
        DeveloperShellEffect.SYNTAX_CHECK,
    }
    if any(segment.effect not in silently_verified_effects for segment in graph.segments):
        return False
    effects_by_index = {segment.index: segment.effect for segment in graph.segments}
    for index, segment in enumerate(graph.context.segments):
        command_name, command_index = _shell_segment_primary_command(list(segment.tokens))
        if command_index is None:
            return False
        args = _without_safe_inspection_redirections(list(segment.tokens[command_index + 1 :]))
        if args is not None and _safe_cli_metadata_segment_is_safe(
            command_name or "",
            args,
            cwd=segment.effective_cwd or home_dir,
        ):
            continue
        if command_name != "git":
            effect = effects_by_index.get(index)
            if effect is DeveloperShellEffect.DIRECTORY and segment.directory_operation is not None:
                continue
            if effect is DeveloperShellEffect.REMOTE_READ and command_name == "gh":
                continue
            if effect is DeveloperShellEffect.LOCAL_READ and (
                command_name in _READ_ONLY_LOOKUP_COMMANDS
                or command_name == "wc"
                or _is_read_only_observer_interpreter_command(command_name or "")
            ):
                continue
            if effect is DeveloperShellEffect.STREAM_FILTER and command_name in {
                *_READ_ONLY_LOOKUP_FILTERS,
                "sort",
            }:
                continue
            if effect is DeveloperShellEffect.STATIC_OUTPUT and command_name in _SAFE_STATIC_SHELL_COMMANDS:
                continue
            if effect is DeveloperShellEffect.SYNTAX_CHECK:
                continue
            return False
        if args is None or not _git_segment_is_silently_verified(
            segment,
            args,
            cwd=segment.effective_cwd or home_dir,
        ):
            return False
    return True


def _git_segment_is_silently_verified(
    segment: ShellExecutionSegment,
    args: list[str],
    *,
    cwd: Path,
) -> bool:
    invocation = _read_only_git_invocation(args, cwd=cwd)
    git_binary = trusted_git_binary_for_cwd(cwd)
    if invocation is None or git_binary is None:
        return False
    operation, git_cwd = invocation
    if operation == "status":
        return _git_status_has_execution_free_config(git_cwd, git_binary=git_binary)
    if operation == "log":
        return _git_log_has_execution_free_config(git_cwd, git_binary=git_binary)
    if operation in {"blame", "branch", "show", "worktree"}:
        return is_low_risk_git_inspection_segment(segment)
    return operation in {"ls-files", "rev-parse"}


def _looks_like_safe_cli_metadata_command(command_text: str, parts: list[str], *, cwd: Path | None) -> bool:
    if any(marker in command_text for marker in ("$(", "`", "<(", ">(", ";", "&", "|", "<", ">")):
        return False
    segments = _iter_shell_command_segments(parts)
    if len(segments) != 1:
        return False
    command_name, command_index = _shell_segment_primary_command(segments[0])
    if command_name is None or command_index != 0:
        return False
    executable = segments[0][0]
    if "/" in executable or "\\" in executable:
        return False
    return _safe_cli_metadata_segment_is_safe(command_name, segments[0][1:], cwd=cwd or Path.cwd())


def _safe_dependency_symlink_execution_context(
    command_text: str,
    *,
    cwd: Path | None,
    home_dir: Path,
) -> ShellExecutionContext | None:
    """Recognize one non-overwriting workspace dependency link."""

    initial_root = cwd or home_dir
    context = model_shell_execution_context(
        command_text,
        cwd=initial_root,
        workspace_root=initial_root,
        home_dir=home_dir,
    )
    workspace_root = _leading_literal_cd_workspace_root(context, home_dir=home_dir)
    if workspace_root is not None and workspace_root != initial_root.resolve():
        context = model_shell_execution_context(
            command_text,
            cwd=workspace_root,
            workspace_root=workspace_root,
            home_dir=home_dir,
        )
    if _shell_execution_context_validation_reason(context) is not None or len(context.segments) not in {2, 3}:
        return None
    directory, link, *marker_segments = context.segments
    if directory.directory_operation != "cd" or directory.control_before or link.control_before != ("&&",):
        return None
    link_name, link_index = _shell_segment_primary_command(list(link.tokens))
    if link_name != "ln" or link_index is None:
        return None
    link_args = _without_safe_inspection_redirections(list(link.tokens[link_index + 1 :]))
    if link_args is None or link_args[:1] != ["-s"] or len(link_args) != 3:
        return None
    if marker_segments:
        marker = marker_segments[0]
        marker_name, marker_index = _shell_segment_primary_command(list(marker.tokens))
        if (
            marker.control_before not in {(";",), ("&&",)}
            or marker_name != "echo"
            or marker_index is None
            or _without_safe_inspection_redirections(list(marker.tokens[marker_index + 1 :])) != ["linked"]
        ):
            return None
    source_text, destination_text = link_args[1:]
    if any(marker in source_text for marker in ("$", "`", "\x00")) or any(
        marker in destination_text for marker in ("$", "`", "\x00")
    ):
        return None
    if destination_text not in {".", "node_modules", "./node_modules"}:
        return None
    source = Path(source_text).expanduser()
    if not source.is_absolute():
        source = (link.effective_cwd or workspace_root or initial_root) / source
    destination_root = link.effective_cwd
    if destination_root is None:
        return None
    try:
        resolved_home = home_dir.resolve(strict=True)
        resolved_workspace = (workspace_root or initial_root).resolve(strict=True)
        resolved_source = source.resolve(strict=True)
        destination = (
            destination_root / resolved_source.name if destination_text == "." else destination_root / destination_text
        )
        ln_path = _which_for_execution_cwd("ln", cwd=destination_root)
        if ln_path is None:
            return None
        resolved_ln = Path(ln_path).resolve(strict=True)
        _ = resolved_source.relative_to(resolved_home)
        resolved_destination_parent = destination.parent.resolve(strict=True)
        _ = resolved_destination_parent.relative_to(resolved_workspace)
    except (OSError, RuntimeError, ValueError):
        return None
    if (
        not is_trusted_absolute_command_path(
            resolved_ln,
            cwd=resolved_workspace,
            home_dir=home_dir,
        )
        or not any((resolved_workspace / marker).exists() for marker in (".git", "package.json", "pyproject.toml"))
        or resolved_source.name != "node_modules"
        or source.is_symlink()
        or not resolved_source.is_dir()
        or not (resolved_source.parent / "package.json").is_file()
        or destination.exists()
        or destination.is_symlink()
        or resolved_destination_parent != resolved_workspace
    ):
        return None
    return context


__all__ = [
    "_looks_like_safe_cli_metadata_command",
    "_looks_like_safe_compound_developer_inspection",
    "_looks_like_safe_kubernetes_inventory_command",
    "_safe_dependency_symlink_execution_context",
]
