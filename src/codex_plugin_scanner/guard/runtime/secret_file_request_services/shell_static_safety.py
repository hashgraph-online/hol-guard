"""Static shell path, script, and interpreter safety checks."""

from __future__ import annotations

import ast
import os
from dataclasses import dataclass
from pathlib import Path

from ..shell_execution_context import ShellExecutionContext


def _leading_literal_cd_workspace_root(
    context: ShellExecutionContext,
    *,
    home_dir: Path,
) -> Path | None:
    """Resolve a literal leading cd as the bounded root for an inspection chain."""

    if not context.segments:
        return None
    first = context.segments[0]
    if first.control_before or first.directory_operation != "cd" or len(first.tokens) != 2:
        return None
    if first.tokens[0].strip("\"'").casefold() != "cd":
        return None
    operand = first.tokens[1].strip()
    if (
        not operand
        or _shell_token_has_command_substitution(operand)
        or any(marker in operand for marker in ("$", "`", "\x00"))
    ):
        return None
    if operand == "~":
        candidate = home_dir
    elif operand.startswith("~/"):
        candidate = home_dir / operand[2:]
    elif operand.startswith("~"):
        return None
    else:
        candidate = Path(operand)
        if not candidate.is_absolute():
            candidate = home_dir / candidate
    try:
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError):
        return None
    return resolved if resolved.is_dir() else None


def _without_safe_inspection_redirections(args: list[str]) -> list[str] | None:
    filtered: list[str] = []
    index = 0
    while index < len(args):
        token = args[index]
        if token in {"2>&1", "2>/dev/null"}:
            index += 1
            continue
        if token == "2>" and index + 1 < len(args) and args[index + 1] == "/dev/null":
            index += 2
            continue
        if any(marker in token for marker in (">", "<")) and not any(character.isspace() for character in token):
            return None
        filtered.append(token)
        index += 1
    return filtered


def _shell_token_escapes_root(token: str, *, cwd: Path, root: Path) -> bool:
    stripped = token.strip().strip("'\"")
    if not stripped:
        return False
    candidate = Path(stripped)
    if stripped.startswith("~/"):
        candidate = root / stripped[2:]
    elif stripped.startswith("~"):
        return True
    elif candidate.anchor and not candidate.is_absolute():
        # Windows rooted paths and drive-relative paths depend on ambient
        # drive state. They cannot establish containment inside this root.
        return True
    elif not candidate.is_absolute():
        if ".." not in candidate.parts:
            return False
        candidate = cwd / candidate
    return not _path_text_is_within_root(os.fspath(candidate), root)


def _path_text_is_within_root(path_text: str, root: Path) -> bool:
    return _path_text_is_within_root_text(path_text, os.path.realpath(os.fspath(root)))


def _path_text_is_within_root_text(path_text: str, root_text: str) -> bool:
    normalized_path_text = os.path.normcase(path_text)
    normalized_root_text = os.path.normcase(root_text)
    try:
        return os.path.commonpath((normalized_path_text, normalized_root_text)) == normalized_root_text
    except ValueError:
        return False


def _shell_token_has_command_substitution(token: str) -> bool:
    if "$(" in token or "`" in token:
        return True
    return any(character in token for character in ("$", "<", ">", "|", "&", ";", "\n"))


def _script_has_aliased_risky_import(script_text: str) -> bool:
    risky_roots = {"os", "pathlib", "shutil", "subprocess"}
    try:
        parsed_script = ast.parse(script_text)
    except (SyntaxError, ValueError):
        return False
    for node in ast.walk(parsed_script):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname is None:
                    continue
                module_name = alias.name.split(".", 1)[0]
                if module_name in risky_roots:
                    return True
            continue
        if not isinstance(node, ast.ImportFrom) or node.module is None:
            continue
        module_name = node.module.split(".", 1)[0]
        if module_name not in risky_roots:
            continue
        if any(alias.asname is not None for alias in node.names):
            return True
    return False


@dataclass(frozen=True, slots=True)
class _InterpreterFlagPayload:
    script_text: str
    tokens_consumed: int


def _interpreter_flag_payload(parts: list[str], index: int) -> _InterpreterFlagPayload | None:
    normalized_token = parts[index].strip().lstrip("(").rstrip(")")
    if not normalized_token.startswith("-"):
        return None
    if normalized_token.startswith("--"):
        for long_flag in ("--command", "--eval", "--execute"):
            if normalized_token == long_flag:
                if index + 1 >= len(parts):
                    return None
                next_script = parts[index + 1].strip()
                if not next_script:
                    return None
                return _InterpreterFlagPayload(script_text=next_script, tokens_consumed=2)
            if normalized_token.startswith(f"{long_flag}="):
                attached_script = normalized_token.split("=", 1)[1].strip()
                if not attached_script:
                    return None
                return _InterpreterFlagPayload(script_text=attached_script, tokens_consumed=1)
        return None
    flag_text = normalized_token[1:]
    for flag_index, flag_name in enumerate(flag_text):
        if flag_name not in {"c", "e"}:
            continue
        attached_script = flag_text[flag_index + 1 :].strip()
        if attached_script:
            return _InterpreterFlagPayload(script_text=attached_script, tokens_consumed=1)
        if index + 1 >= len(parts):
            return None
        next_script = parts[index + 1].strip()
        if not next_script:
            return None
        return _InterpreterFlagPayload(script_text=next_script, tokens_consumed=2)
    return None


__all__ = [
    "_InterpreterFlagPayload",
    "_interpreter_flag_payload",
    "_leading_literal_cd_workspace_root",
    "_path_text_is_within_root",
    "_path_text_is_within_root_text",
    "_script_has_aliased_risky_import",
    "_shell_token_escapes_root",
    "_shell_token_has_command_substitution",
    "_without_safe_inspection_redirections",
]
