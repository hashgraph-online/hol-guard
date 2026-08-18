"""Bounded source edit context validation."""

from __future__ import annotations

import os
import re
from dataclasses import replace
from pathlib import Path

from ..git_index_inspection import index_inspection_execution_context
from ..shell_execution_context import ShellExecutionContext, model_shell_execution_context
from .developer_inspection import (
    _low_risk_compound_developer_execution_context,
    _read_only_lookup_primary_segment_is_safe,
    _static_shell_segment_is_safe,
)
from .docker_requests import _shell_execution_context_validation_reason, shell_execution_context_starts_with_literal_cd
from .local_read_operands import _search_concrete_file_operand_tokens
from .read_only_filters import _read_only_lookup_target_is_safe
from .shell_static_safety import _leading_literal_cd_workspace_root, _without_safe_inspection_redirections
from .shell_tokenization import _shell_segment_primary_command


def low_risk_compound_developer_execution_context(
    command_text: str,
    *,
    cwd: Path | None = None,
    home_dir: Path,
) -> ShellExecutionContext | None:
    """Model a deterministic whole-command developer inspection from the user's home."""

    delayed = re.fullmatch(r"\s*sleep\s+([1-9]\d{0,3})\s*&&\s*(.+)", command_text, re.DOTALL)
    if delayed is not None and int(delayed.group(1)) <= 3600:
        recovered = _low_risk_compound_developer_execution_context(
            delayed.group(2),
            cwd=cwd,
            home_dir=home_dir,
        )
        return replace(recovered, command_text=command_text) if recovered is not None else None

    return (
        _low_risk_compound_developer_execution_context(
            command_text,
            cwd=cwd,
            home_dir=home_dir,
        )
        or index_inspection_execution_context(command_text, cwd=cwd, home_dir=home_dir)
        or _bounded_verified_source_edit_execution_context(command_text, home_dir=home_dir)
    )


def _bounded_verified_source_edit_execution_context(
    command_text: str,
    *,
    home_dir: Path,
) -> ShellExecutionContext | None:
    """Recognize one literal source substitution followed by same-file verification."""

    if any(marker in command_text for marker in ("$(", "`", "<(", ">(")):
        return None
    modeled_command = command_text.replace("\\\r\n", " ").replace("\\\n", " ")
    context = model_shell_execution_context(
        modeled_command,
        cwd=home_dir,
        workspace_root=home_dir,
        home_dir=home_dir,
    )
    workspace_root = _leading_literal_cd_workspace_root(context, home_dir=home_dir)
    if workspace_root is None or workspace_root == home_dir.resolve():
        return None
    if not _bounded_edit_workspace_is_safe(workspace_root, home_dir=home_dir):
        return None
    context = model_shell_execution_context(
        modeled_command,
        cwd=workspace_root,
        workspace_root=workspace_root,
        home_dir=home_dir,
    )
    if not shell_execution_context_starts_with_literal_cd(context):
        return None
    if _shell_execution_context_validation_reason(context) is not None:
        return None
    if len(context.segments) not in {3, 4}:
        return None

    edit = context.segments[1]
    edit_name, edit_index = _shell_segment_primary_command(list(edit.tokens))
    if edit_name != "sed" or edit_index is None or edit.control_before != ("&&",):
        return None
    edit_args = _without_safe_inspection_redirections(list(edit.tokens[edit_index + 1 :]))
    if edit_args is None:
        return None
    target = _bounded_in_place_sed_target(
        edit_args,
        cwd=edit.effective_cwd or workspace_root,
        workspace_root=workspace_root,
    )
    if target is None:
        return None

    verification_segments = context.segments[2:]
    if len(verification_segments) == 2:
        label = verification_segments[0]
        label_name, label_index = _shell_segment_primary_command(list(label.tokens))
        if label_name != "echo" or label_index is None or label.control_before not in {("&&",), ("\n",)}:
            return None
        label_args = _without_safe_inspection_redirections(list(label.tokens[label_index + 1 :]))
        if label_args is None or not _static_shell_segment_is_safe(label_args):
            return None

    verification = verification_segments[-1]
    verification_name, verification_index = _shell_segment_primary_command(list(verification.tokens))
    if verification_name not in {"grep", "egrep", "fgrep"} or verification_index is None:
        return None
    if verification.control_before not in {("&&",), ("\n",)}:
        return None
    verification_args = _without_safe_inspection_redirections(list(verification.tokens[verification_index + 1 :]))
    if verification_args is None or not _read_only_lookup_primary_segment_is_safe(
        verification_name,
        verification_args,
        home_dir=verification.effective_cwd or workspace_root,
    ):
        return None
    verification_targets = _search_concrete_file_operand_tokens(verification_name, verification_args)
    if len(verification_targets) != 1:
        return None
    if not _same_workspace_file(target, verification_targets[0], cwd=workspace_root):
        return None
    return replace(context, command_text=command_text)


def _bounded_in_place_sed_target(
    args: list[str],
    *,
    cwd: Path,
    workspace_root: Path,
) -> str | None:
    if len(args) < 4 or args[:2] != ["-i", ""]:
        return None
    scripts: list[str] = []
    index = 2
    if args[index] == "-e":
        while index < len(args) and args[index] == "-e":
            if index + 1 >= len(args):
                return None
            scripts.append(args[index + 1])
            index += 2
    else:
        scripts.append(args[index])
        index += 1
    targets = args[index:]
    if not 1 <= len(scripts) <= 16 or len(targets) != 1:
        return None
    if any(not _literal_sed_script_is_safe(script) for script in scripts):
        return None
    target = targets[0]
    if target.startswith("-") or not _read_only_lookup_target_is_safe(target, allow_dirs=False, home_dir=cwd):
        return None
    try:
        candidate = cwd / target
        lexical = Path(os.path.abspath(os.fspath(candidate)))
        resolved = candidate.resolve(strict=True)
        _ = resolved.relative_to(workspace_root.resolve(strict=True))
    except (OSError, RuntimeError, ValueError):
        return None
    return target if resolved == lexical and resolved.is_file() else None


def _literal_sed_script_is_safe(script: str) -> bool:
    commands = _split_literal_sed_commands(script)
    return 1 <= len(commands) <= 16 and all(_literal_sed_substitution_is_safe(command) for command in commands)


def _split_literal_sed_commands(script: str) -> tuple[str, ...]:
    commands: list[str] = []
    index = 0
    while index < len(script):
        while index < len(script) and script[index].isspace():
            index += 1
        start = index
        if index + 1 >= len(script) or script[index] != "s":
            return ()
        delimiter = script[index + 1]
        if delimiter.isalnum() or delimiter.isspace() or delimiter == "\\":
            return ()
        index += 2
        terminated_fields = 0
        escaped = False
        while index < len(script) and terminated_fields < 2:
            character = script[index]
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == delimiter:
                terminated_fields += 1
            index += 1
        if escaped or terminated_fields != 2:
            return ()
        while index < len(script) and script[index] != ";":
            index += 1
        command = script[start:index].strip()
        if not command:
            return ()
        commands.append(command)
        if len(commands) > 16:
            return ()
        if index < len(script):
            index += 1
    return tuple(commands)


def _bounded_edit_workspace_is_safe(workspace_root: Path, *, home_dir: Path) -> bool:
    try:
        relative = workspace_root.relative_to(home_dir.resolve(strict=True))
    except (OSError, RuntimeError, ValueError):
        return False
    if not relative.parts or relative.parts[0].startswith("."):
        return False
    return any(
        (workspace_root / marker).exists()
        for marker in (".git", "package.json", "pyproject.toml", "Cargo.toml", "go.mod")
    )


def _literal_sed_substitution_is_safe(script: str) -> bool:
    if len(script) > 4096 or len(script) < 5 or script[0] != "s":
        return False
    delimiter = script[1]
    if delimiter.isalnum() or delimiter.isspace() or delimiter == "\\":
        return False
    fields: list[str] = []
    current: list[str] = []
    escaped = False
    for character in script[2:]:
        if escaped:
            current.extend(("\\", character))
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == delimiter and len(fields) < 2:
            fields.append("".join(current))
            current = []
        else:
            current.append(character)
    if escaped or len(fields) != 2:
        return False
    flags = "".join(current)
    pattern, replacement = fields
    return (
        bool(pattern)
        and flags in {"", "g"}
        and _sed_pattern_is_literal(pattern, delimiter=delimiter)
        and _sed_replacement_is_literal(replacement, delimiter=delimiter)
    )


def _sed_pattern_is_literal(pattern: str, *, delimiter: str) -> bool:
    regex_metacharacters = frozenset(".^$*+?[]()|")
    escaped = False
    for character in pattern:
        if escaped:
            if character not in regex_metacharacters | {delimiter, "\\"}:
                return False
            escaped = False
        elif character == "\\":
            escaped = True
        elif character in regex_metacharacters:
            return False
    return not escaped


def _sed_replacement_is_literal(replacement: str, *, delimiter: str) -> bool:
    escaped = False
    for character in replacement:
        if escaped:
            if character not in {delimiter, "\\", "&", "$"}:
                return False
            escaped = False
        elif character == "\\":
            escaped = True
        elif character in {"&", "\n", "$"}:
            return False
    return not escaped


def _same_workspace_file(left: str, right: str, *, cwd: Path) -> bool:
    try:
        return (cwd / left).resolve(strict=True) == (cwd / right).resolve(strict=True)
    except (OSError, RuntimeError):
        return False


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
