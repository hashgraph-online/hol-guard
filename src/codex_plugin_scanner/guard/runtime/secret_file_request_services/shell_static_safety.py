"""Static shell path, script, and interpreter safety checks."""

from __future__ import annotations

import ast
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path

from ..git_execution_safety import git_binary_path_is_trusted
from ..shell_execution_context import ShellExecutionContext
from .constants_core import _SHELL_COMMAND_STRING_INTERPRETERS, _UNMODELED_INLINE_INTERPRETER_COMMANDS
from .constants_patterns import _READ_ONLY_INTERPRETER_MUTATION_PATTERNS
from .docker_requests import _which_for_execution_cwd
from .request_artifacts import _normalized_shell_command_name
from .shell_tokenization import _iter_shell_command_segments, _shell_segment_primary_command


def _safe_cli_metadata_segment_is_safe(command_name: str, args: list[str], *, cwd: Path) -> bool:
    if command_name == "git" and args in (["--version"], ["version"]):
        git_path = _which_for_execution_cwd("git", cwd=cwd)
        if git_path is None:
            return False
        try:
            return git_binary_path_is_trusted(Path(git_path).resolve(), cwd=cwd.resolve())
        except (OSError, RuntimeError):
            return False
    if command_name != "hol-guard" or args not in (["--version"], ["status"]):
        return False
    executable = _which_for_execution_cwd("hol-guard", cwd=cwd)
    if executable is None:
        return False
    try:
        actual = Path(executable).resolve(strict=True)
    except (OSError, RuntimeError):
        return False
    bin_name = "Scripts" if os.name == "nt" else "bin"
    roots = [Path(sys.prefix)]
    site_packages = next(
        (parent for parent in Path(__file__).resolve().parents if parent.name == "site-packages"), None
    )
    if site_packages is not None:
        roots.append(site_packages.parent.parent if os.name == "nt" else site_packages.parent.parent.parent)
    managed_candidates: set[Path] = set()
    for root in roots:
        try:
            managed_candidates.add((root / bin_name / "hol-guard").resolve(strict=True))
        except (OSError, RuntimeError):
            continue
    return actual in managed_candidates


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


def _shell_syntax_check_segment_is_safe(command_name: str, args: list[str]) -> bool:
    if command_name not in _SHELL_COMMAND_STRING_INTERPRETERS or len(args) != 2 or args[0] != "-n":
        return False
    target = Path(args[1].strip("'\""))
    return target.suffix == ".sh" and all(
        part not in {"", ".", ".."} and not part.startswith(".") for part in target.parts if part != target.anchor
    )


def _shell_token_escapes_root(token: str, *, cwd: Path, root: Path) -> bool:
    stripped = token.strip().strip("'\"")
    if not stripped:
        return False
    candidate = Path(stripped)
    if stripped.startswith("~/"):
        candidate = root / stripped[2:]
    elif stripped.startswith("~"):
        return True
    elif not candidate.is_absolute():
        if ".." not in candidate.parts:
            return False
        candidate = cwd / candidate
    return not _path_text_is_within_root(os.fspath(candidate), root)


def _github_jq_filter_args_are_safe(args: list[str]) -> bool:
    normalized_args = _collapse_single_quoted_shell_argument(args)
    if normalized_args is None:
        return False
    boolean_options = {
        "--ascii-output",
        "--compact-output",
        "--exit-status",
        "--join-output",
        "--monochrome-output",
        "--raw-input",
        "--raw-output",
        "--slurp",
        "--sort-keys",
        "-C",
        "-M",
        "-R",
        "-S",
        "-a",
        "-c",
        "-e",
        "-j",
        "-r",
        "-s",
    }
    value_options = {"--arg": 2, "--argjson": 2}
    index = 0
    while index < len(normalized_args):
        token = normalized_args[index]
        if token in {"2>&1", "1>&2"}:
            index += 1
            continue
        if token in boolean_options:
            index += 1
            continue
        if token in value_options:
            index += 1 + value_options[token]
            if index > len(normalized_args):
                return False
            continue
        if token.startswith("-"):
            return False
        return index == len(normalized_args) - 1 and _github_jq_program_is_safe(token)
    return False


_JQ_EXTERNAL_INPUT = re.compile(r"\$ENV\b|(?<![A-Za-z0-9_$\.])(env|import|include)(?![A-Za-z0-9_])")


def _github_jq_program_is_safe(program: str) -> bool:
    """Reject jq programs that can read process or module data outside stdin."""

    normalized = program[1:-1] if len(program) >= 2 and program.startswith("'") and program.endswith("'") else program
    sanitized = _strip_jq_strings_and_comments(normalized)
    for match in _JQ_EXTERNAL_INPUT.finditer(sanitized):
        if match.group(0).startswith("$"):
            return False
        previous = _previous_nonspace(sanitized, match.start())
        following = _next_nonspace(sanitized, match.end())
        if previous == "." or following == ":" or (previous in {"{", ","} and following in {",", "}"}):
            if match.group(1) == "env" and following in {",", "}"}:
                return False
            continue
        return False
    return True


def _previous_nonspace(value: str, end: int) -> str:
    return next((value[index] for index in range(end - 1, -1, -1) if not value[index].isspace()), "")


def _next_nonspace(value: str, start: int) -> str:
    return next((value[index] for index in range(start, len(value)) if not value[index].isspace()), "")


def _strip_jq_strings_and_comments(program: str) -> str:
    """Mask jq strings and comments while preserving token boundaries."""

    output: list[str] = []
    in_string = False
    in_comment = False
    escaped = False
    for character in program:
        if in_comment:
            in_comment = character != "\n"
            output.append("\n" if character == "\n" else " ")
            continue
        if in_string:
            output.append(" ")
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
            output.append(" ")
        elif character == "#":
            in_comment = True
            output.append(" ")
        else:
            output.append(character)
    return "".join(output)


def _collapse_single_quoted_shell_argument(args: list[str]) -> list[str] | None:
    """Rejoin one shell-tokenized single-quoted argument without widening operands."""

    normalized: list[str] = []
    index = 0
    while index < len(args):
        token = args[index]
        if not token.startswith("'"):
            normalized.append(token)
            index += 1
            continue
        if len(token) > 1 and token.endswith("'"):
            if "'" in token[1:-1]:
                return None
            normalized.append(token)
            index += 1
            continue
        parts = [token]
        index += 1
        while index < len(args) and not args[index].endswith("'"):
            if "'" in args[index]:
                return None
            parts.append(args[index])
            index += 1
        if index >= len(args) or "'" in args[index][:-1]:
            return None
        parts.append(args[index])
        normalized.append(" ".join(parts))
        index += 1
    return normalized


def _path_text_is_within_root(path_text: str, root: Path) -> bool:
    return _path_text_is_within_root_text(path_text, os.path.realpath(os.fspath(root)))


def _path_text_is_within_root_text(path_text: str, root_text: str) -> bool:
    normalized_path_text = os.path.normcase(path_text)
    normalized_root_text = os.path.normcase(root_text)
    try:
        return os.path.commonpath((normalized_path_text, normalized_root_text)) == normalized_root_text
    except ValueError:
        return False


def _script_interpreter_texts(parts: list[str]) -> tuple[str, ...]:
    scripts: list[str] = []
    for segment in _iter_shell_command_segments(parts):
        command_name, command_index = _shell_segment_primary_command(segment)
        if command_name is None or command_index is None:
            continue
        if command_name not in _SHELL_COMMAND_STRING_INTERPRETERS and not _is_script_interpreter_command(command_name):
            continue
        index = command_index + 1
        while index < len(segment):
            flag_payload = _interpreter_flag_payload(segment, index)
            if flag_payload is not None:
                scripts.append(flag_payload.script_text)
                break
            index += 1
    return tuple(scripts)


def _shell_token_has_command_substitution(token: str) -> bool:
    if "$(" in token or "`" in token:
        return True
    return any(character in token for character in ("$", "<", ">", "|", "&", ";", "\n"))


def _is_script_interpreter_command(command_name: str) -> bool:
    return _is_python_interpreter_command(command_name) or command_name in _UNMODELED_INLINE_INTERPRETER_COMMANDS


def _is_python_interpreter_command(command_name: str) -> bool:
    normalized_name = _normalized_shell_command_name(command_name)
    return re.fullmatch(r"pythonw?(?:\d+(?:\.\d+)*)?(?:\.exe)?", normalized_name) is not None


def _script_is_benign_wait(script_text: str) -> bool:
    normalized_script = script_text.strip()
    if not normalized_script:
        return False
    return bool(
        re.fullmatch(r"sleep\s+\d+(?:\.\d+)?", normalized_script)
        or re.fullmatch(r"(?:import\s+time\s*;\s*)?time\.sleep\(\s*\d+(?:\.\d+)?\s*\)", normalized_script)
    )


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


def _script_is_read_only_observer(script_text: str) -> bool:
    normalized_script = script_text.strip()
    if not normalized_script:
        return False
    if _script_is_benign_wait(normalized_script):
        return True
    if _script_has_aliased_risky_import(normalized_script):
        return False
    return not any(pattern.search(normalized_script) for pattern in _READ_ONLY_INTERPRETER_MUTATION_PATTERNS)


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
    "_github_jq_filter_args_are_safe",
    "_interpreter_flag_payload",
    "_is_python_interpreter_command",
    "_is_script_interpreter_command",
    "_leading_literal_cd_workspace_root",
    "_path_text_is_within_root",
    "_path_text_is_within_root_text",
    "_safe_cli_metadata_segment_is_safe",
    "_script_has_aliased_risky_import",
    "_script_interpreter_texts",
    "_script_is_benign_wait",
    "_script_is_read_only_observer",
    "_shell_syntax_check_segment_is_safe",
    "_shell_token_escapes_root",
    "_shell_token_has_command_substitution",
    "_without_safe_inspection_redirections",
]
