"""Read-only command filter validation."""

from __future__ import annotations

import os
import re
from pathlib import Path

from ..false_positive_rules import (
    SOURCE_INSPECTION_BENIGN_DOTFILES,
    SOURCE_INSPECTION_EXTENSIONS,
    SOURCE_INSPECTION_PARTS,
    SOURCE_INSPECTION_SENSITIVE_PARTS,
    target_is_known_skill_doc_path,
)
from ..sed_scripts import sed_script_is_bounded_print


def _read_only_lookup_filter_segment_is_safe(
    command: str,
    args: list[str],
    *,
    home_dir: Path | None = None,
    require_explicit_rg_no_config: bool = False,
) -> bool:
    if command == "cat":
        return not args or all(arg == "-" or (arg.startswith("-") and ">" not in arg) for arg in args)
    if command == "sed":
        return _read_only_lookup_sed_args_are_safe(args, require_target=False)
    if command in {"head", "tail"}:
        return _read_only_lookup_head_tail_args_are_safe(args, require_target=False)
    if command in {"grep", "egrep", "fgrep"}:
        return _read_only_lookup_filter_grep_args_are_safe(args, home_dir=home_dir)
    if command == "rg":
        return (
            not require_explicit_rg_no_config or "--no-config" in args
        ) and _read_only_lookup_filter_rg_args_are_safe(args)
    return False


def _github_output_filter_segment_is_safe(
    command: str,
    args: list[str],
    *,
    home_dir: Path | None = None,
    command_text: str | None = None,
) -> bool:
    """Require explicit config isolation for filters over remote output."""
    require_no_config = command == "rg" and not _ripgrep_configuration_is_absent(command_text)
    return _read_only_lookup_filter_segment_is_safe(
        command, args, home_dir=home_dir, require_explicit_rg_no_config=require_no_config
    )


def _ripgrep_configuration_is_absent(command_text: str | None) -> bool:
    if os.environ.get("RIPGREP_CONFIG_PATH") or command_text is None:
        return False
    return re.search(r"(?:^|[\s;&|])(?:export\s+)?RIPGREP_CONFIG_PATH\s*=", command_text) is None


def _read_only_lookup_may_be_primary(
    known_command: bool,
    control_before: tuple[str, ...],
    safe_pipe_filter: bool,
) -> bool:
    """Keep pipe filters on the stricter stdin-filter validation path."""
    return known_command and (control_before != ("|",) or safe_pipe_filter)


def _read_only_lookup_sed_args_are_safe(
    args: list[str],
    *,
    require_target: bool,
    home_dir: Path | None = None,
) -> bool:
    scripts: list[str] = []
    targets: list[str] = []
    saw_print_suppression = False
    skip_script = False
    after_options = False
    for arg in args:
        if skip_script:
            skip_script = False
            scripts.append(arg)
            continue
        if after_options:
            targets.append(arg)
            continue
        if arg == "--":
            after_options = True
            continue
        if arg in {"-i", "--in-place"} or arg.startswith(("-i", "--in-place=")):
            return False
        if arg in {"-n", "--quiet", "--silent"}:
            saw_print_suppression = True
            continue
        if arg in {"-e", "--expression"}:
            skip_script = True
            continue
        if arg.startswith("-e") and len(arg) > 2:
            scripts.append(arg[2:])
            continue
        if arg.startswith("--expression="):
            scripts.append(arg.split("=", 1)[1])
            continue
        if arg.startswith("-"):
            return False
        if not scripts:
            scripts.append(arg)
        else:
            targets.append(arg)
    if skip_script or not scripts or not saw_print_suppression:
        return False
    if not all(_read_only_lookup_sed_script_is_print_only(script) for script in scripts):
        return False
    if require_target:
        return bool(targets) and all(
            _read_only_lookup_target_is_safe(target, allow_dirs=False, home_dir=home_dir) for target in targets
        )
    return not targets


def _read_only_lookup_sed_script_is_print_only(script: str) -> bool:
    return sed_script_is_bounded_print(script)


def _read_only_lookup_head_tail_args_are_safe(
    args: list[str],
    *,
    require_target: bool,
    home_dir: Path | None = None,
) -> bool:
    targets: list[str] = []
    skip_count = False
    after_options = False
    for arg in args:
        if skip_count:
            skip_count = False
            if not re.fullmatch(r"\d{1,6}", arg.strip()):
                return False
            continue
        if after_options:
            targets.append(arg)
            continue
        if arg == "--":
            after_options = True
            continue
        if arg in {"-n", "--lines", "-c", "--bytes"}:
            skip_count = True
            continue
        if arg.startswith("--lines=") or arg.startswith("--bytes="):
            if not re.fullmatch(r"\d{1,6}", arg.split("=", 1)[1].strip()):
                return False
            continue
        if re.fullmatch(r"-\d{1,6}", arg):
            continue
        if arg.startswith("-"):
            return False
        targets.append(arg)
    if skip_count:
        return False
    if require_target:
        return bool(targets) and all(
            _read_only_lookup_target_is_safe(target, allow_dirs=False, home_dir=home_dir) for target in targets
        )
    return not targets


_GREP_PATTERN_OPTIONS = frozenset({"-e", "--regexp"})

_GREP_PATTERN_FILE_OPTIONS = frozenset({"-f", "--file"})

_GREP_FILTER_FILE_OPTIONS = frozenset({"--exclude-from"})

_GREP_SKIP_NEXT_OPTIONS = frozenset(
    {
        "-A",
        "-B",
        "-C",
        "-m",
        "--after-context",
        "--before-context",
        "--context",
        "--max-count",
    }
)


def _read_only_lookup_filter_grep_args_are_safe(
    args: list[str],
    *,
    home_dir: Path | None = None,
) -> bool:
    """Validate grep arguments in a filter (pipe) segment.

    In a filter segment grep reads stdin and writes matching lines to stdout.
    The first positional argument is the pattern (any string, including URIs).
    Subsequent positional arguments are file operands that grep opens as files.
    ``-f FILE`` reads patterns from a file, so it must also be validated.
    ``-e PATTERN`` provides a pattern and is safe to skip.
    """
    if not args:
        return False
    saw_pattern = False
    after_options = False
    skip_next_is_pattern = False
    skip_next_is_file = False
    skip_next_file_sets_pattern = False
    skip_next_is_value = False
    for arg in args:
        if skip_next_is_pattern:
            skip_next_is_pattern = False
            saw_pattern = True
            continue
        if skip_next_is_file:
            skip_next_is_file = False
            if not _read_only_lookup_target_is_safe(arg, allow_dirs=False, home_dir=home_dir):
                return False
            if skip_next_file_sets_pattern:
                saw_pattern = True
            continue
        if skip_next_is_value:
            skip_next_is_value = False
            continue
        if _read_only_lookup_arg_is_redirection(arg):
            return False
        if after_options:
            if not saw_pattern:
                saw_pattern = True
                continue
            if not _read_only_lookup_target_is_safe(arg, allow_dirs=False, home_dir=home_dir):
                return False
            continue
        if arg == "--":
            after_options = True
            continue
        if arg in _GREP_PATTERN_OPTIONS:
            skip_next_is_pattern = True
            saw_pattern = True
            continue
        if arg in _GREP_PATTERN_FILE_OPTIONS:
            skip_next_is_file = True
            skip_next_file_sets_pattern = True
            continue
        if arg in _GREP_FILTER_FILE_OPTIONS:
            skip_next_is_file = True
            skip_next_file_sets_pattern = False
            continue
        if arg in _GREP_SKIP_NEXT_OPTIONS:
            skip_next_is_value = True
            continue
        if arg.startswith("--"):
            # Long options: --file=VALUE, --regexp=VALUE, --fixed-strings, etc.
            if "=" in arg:
                key, _, value = arg.partition("=")
                if key in _GREP_PATTERN_FILE_OPTIONS:
                    if not _read_only_lookup_target_is_safe(value, allow_dirs=False, home_dir=home_dir):
                        return False
                    saw_pattern = True
                elif key in _GREP_FILTER_FILE_OPTIONS:
                    if not _read_only_lookup_target_is_safe(value, allow_dirs=False, home_dir=home_dir):
                        return False
                elif key in _GREP_PATTERN_OPTIONS:
                    saw_pattern = True
            # Long options without = are already handled above by exact match.
            continue
        if arg.startswith("-") and arg != "-":
            # Combined short options: check for -f or -e in the cluster.
            body = arg[1:]
            # Handle -fFILE (file operand attached) and -ePATTERN (pattern attached).
            for i, ch in enumerate(body):
                if ch == "f":
                    file_arg = body[i + 1 :]
                    if file_arg:
                        if not _read_only_lookup_target_is_safe(file_arg, allow_dirs=False, home_dir=home_dir):
                            return False
                        saw_pattern = True
                    else:
                        skip_next_is_file = True
                        skip_next_file_sets_pattern = True
                    break
                elif ch == "e":
                    saw_pattern = True
                    break
            continue
        # Positional argument: first one is the pattern, rest are file operands.
        if not saw_pattern:
            saw_pattern = True
        else:
            if not _read_only_lookup_target_is_safe(arg, allow_dirs=False, home_dir=home_dir):
                return False
    return not (skip_next_is_pattern or skip_next_is_file or skip_next_is_value)


_RG_FILTER_BOOLEAN_OPTIONS = frozenset(
    {
        "--case-sensitive",
        "--fixed-strings",
        "--ignore-case",
        "--invert-match",
        "--line-number",
        "--no-config",
        "--only-matching",
        "--quiet",
        "--smart-case",
        "--word-regexp",
        "--line-regexp",
    }
)
_RG_FILTER_BOOLEAN_SHORT_OPTIONS = frozenset("FiInNoqSsvwx")
_RG_FILTER_PATTERN_OPTIONS = frozenset({"-e", "--regexp"})


def _read_only_lookup_filter_rg_args_are_safe(args: list[str]) -> bool:
    """Accept ripgrep only as a bounded stdin filter with one inline pattern."""

    if not args:
        return False
    saw_pattern = False
    expect_pattern = False
    after_options = False
    saw_no_config = False
    for arg in args:
        if _read_only_lookup_arg_is_redirection(arg):
            return False
        if "`" in arg or re.search(r"\$(?:[A-Za-z_][A-Za-z0-9_]*|[0-9@*#?!_-]|\{|\()", arg):
            return False
        if expect_pattern:
            expect_pattern = False
            if not arg:
                return False
            saw_pattern = True
            continue
        if after_options:
            if saw_pattern:
                return False
            saw_pattern = bool(arg)
            continue
        if arg == "--":
            after_options = True
            continue
        if arg == "--no-config":
            if saw_no_config:
                return False
            saw_no_config = True
            continue
        if arg in _RG_FILTER_PATTERN_OPTIONS:
            if saw_pattern:
                return False
            expect_pattern = True
            continue
        if arg.startswith("--regexp="):
            if saw_pattern or not arg.partition("=")[2]:
                return False
            saw_pattern = True
            continue
        if arg in _RG_FILTER_BOOLEAN_OPTIONS:
            continue
        if arg.startswith("-") and arg != "-":
            if not arg.startswith("--") and set(arg[1:]) <= _RG_FILTER_BOOLEAN_SHORT_OPTIONS:
                continue
            return False
        if saw_pattern:
            return False
        saw_pattern = bool(arg)
    config_is_disabled = saw_no_config or not os.environ.get("RIPGREP_CONFIG_PATH", "").strip()
    return saw_pattern and config_is_disabled and not expect_pattern


def _read_only_lookup_arg_is_redirection(arg: str) -> bool:
    if arg in {">", ">>", ">|", "1>", "1>>", "1>|", "2>", "2>>", "2>|", "<", "0<"}:
        return True
    return _split_attached_redirection_token(arg) is not None


def _read_only_lookup_target_is_safe(target: str, *, allow_dirs: bool, home_dir: Path | None = None) -> bool:
    stripped = target.strip().strip("'\"")
    if stripped in {"", "."}:
        return allow_dirs
    if stripped == "-":
        return False
    if any(marker in stripped for marker in ("$", "`", "<", ">", "|", ";", "&")):
        return False
    normalized = stripped.replace("\\", "/")
    parts = [part for part in Path(normalized).parts if part not in {"", "/", "."}]
    lowered_parts = [part.lower() for part in parts]
    if not parts:
        return allow_dirs
    if ".." in parts or any(marker in stripped for marker in ("*", "?", "[", "]", "{", "}")):
        return False
    if any(part in SOURCE_INSPECTION_SENSITIVE_PARTS for part in lowered_parts):
        return False
    if target_is_known_skill_doc_path(stripped, home_dir=home_dir):
        return True
    hidden_parts = [part for part in lowered_parts if part.startswith(".")]
    if hidden_parts and not all(part in SOURCE_INSPECTION_BENIGN_DOTFILES for part in hidden_parts):
        return False
    if any(part in SOURCE_INSPECTION_PARTS for part in lowered_parts):
        return True
    if Path(normalized).suffix.lower() in SOURCE_INSPECTION_EXTENSIONS:
        return True
    return allow_dirs


def _split_attached_redirection_token(token: str) -> tuple[str, str, str, str] | None:
    for index, character in enumerate(token):
        if character != ">":
            continue
        op = _attached_redirection_operator(token, index)
        prefix = token[:index]
        if any(character.isspace() or character in {"<", ">"} for character in prefix):
            continue
        target = token[index + len(op) :]
        fd = ""
        if prefix and prefix[-1] in {"0", "1", "2"}:
            fd = prefix[-1]
            prefix = prefix[:-1]
        return prefix, fd, op, target
    return None


def _attached_redirection_operator(token: str, index: int) -> str:
    next_character = token[index + 1 : index + 2]
    if next_character == "|":
        return ">|"
    if next_character == ">":
        return ">>"
    return ">"


__all__ = [
    "_GREP_FILTER_FILE_OPTIONS",
    "_GREP_PATTERN_FILE_OPTIONS",
    "_GREP_PATTERN_OPTIONS",
    "_GREP_SKIP_NEXT_OPTIONS",
    "_attached_redirection_operator",
    "_github_output_filter_segment_is_safe",
    "_read_only_lookup_arg_is_redirection",
    "_read_only_lookup_filter_grep_args_are_safe",
    "_read_only_lookup_filter_rg_args_are_safe",
    "_read_only_lookup_filter_segment_is_safe",
    "_read_only_lookup_head_tail_args_are_safe",
    "_read_only_lookup_sed_args_are_safe",
    "_read_only_lookup_sed_script_is_print_only",
    "_read_only_lookup_target_is_safe",
    "_split_attached_redirection_token",
]
