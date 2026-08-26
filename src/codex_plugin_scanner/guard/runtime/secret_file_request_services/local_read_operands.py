"""Local read operand extraction and containment checks."""

from __future__ import annotations

import fnmatch
import os
import re
from pathlib import Path

from ..false_positive_rules import SOURCE_INSPECTION_BENIGN_DOTFILES, SOURCE_INSPECTION_SENSITIVE_PARTS
from .read_only_filters import _read_only_lookup_target_is_safe

_RG_SHORT_OPTIONS_WITH_VALUE = frozenset("ABCEdefgjmMrTt")
_RG_LONG_OPTIONS_WITH_VALUE = frozenset(
    {
        "--after-context",
        "--before-context",
        "--context",
        "--encoding",
        "--file",
        "--glob",
        "--iglob",
        "--max-columns",
        "--max-count",
        "--max-depth",
        "--max-filesize",
        "--regexp",
        "--replace",
        "--threads",
        "--type",
        "--type-not",
    }
)


def _ripgrep_args_expand_hidden_files(args: list[str]) -> bool:
    expect_value = False
    for arg in args:
        if expect_value:
            expect_value = False
            continue
        if arg == "--":
            break
        if arg in {"--hidden", "--unrestricted"}:
            return True
        if arg.startswith("--"):
            expect_value = "=" not in arg and arg in _RG_LONG_OPTIONS_WITH_VALUE
            continue
        if not arg.startswith("-") or arg == "-":
            continue
        cluster = arg[1:]
        for index, option in enumerate(cluster):
            if option in {"u", "."}:
                return True
            if option in _RG_SHORT_OPTIONS_WITH_VALUE:
                expect_value = index == len(cluster) - 1
                break
    return False


def _shell_segment_file_operand_tokens(segment: list[str]) -> tuple[str, ...]:
    if not segment:
        return ()
    command_name = Path(segment[0]).name.lower()
    args = segment[1:]
    if command_name == "cat":
        return _cat_file_operand_tokens(args)
    if command_name in {"head", "tail"}:
        return _plain_file_operand_tokens(args)
    if command_name == "sed":
        return _sed_file_operand_tokens(args)
    if command_name in {"grep", "egrep", "fgrep", "rg"}:
        return _search_file_operand_tokens(command_name, args)
    return ()


def _local_read_operands_resolve_safely(
    command_name: str,
    args: list[str],
    *,
    cwd: Path,
    root: Path,
) -> bool:
    """Reject local read operands redirected through symlink path components."""

    allow_dirs = command_name in {"grep", "egrep", "fgrep", "rg"}
    try:
        resolved_root = root.resolve(strict=True)
    except (OSError, RuntimeError):
        return False
    if command_name == "rg" and _ripgrep_args_expand_hidden_files(args):
        return False
    operand_roles = (
        _search_file_operand_roles(command_name, args)
        if command_name in {"grep", "egrep", "fgrep", "rg"}
        else tuple((operand, False) for operand in _shell_segment_file_operand_tokens([command_name, *args]))
    )
    for operand, is_search_glob in operand_roles:
        stripped = operand.strip().strip("'\"")
        if not stripped or stripped == "-":
            continue
        if is_search_glob:
            if not _search_glob_pattern_is_safe(stripped, root=root):
                return False
            continue
        has_glob_metacharacter = any(character in stripped for character in "*?[")
        candidate = Path(stripped)
        if not candidate.is_absolute():
            candidate = cwd / candidate
        if has_glob_metacharacter:
            if not _bounded_local_read_glob_is_safe(
                candidate,
                root=root,
                allow_dirs=allow_dirs,
            ):
                return False
            continue
        try:
            lexical = Path(os.path.abspath(os.fspath(candidate)))
            resolved = candidate.resolve(strict=True)
            relative = resolved.relative_to(resolved_root)
        except FileNotFoundError:
            continue
        except (OSError, RuntimeError, ValueError):
            return False
        safe_git_pointer = command_name == "cat" and relative.as_posix() == ".git"
        if resolved != lexical or (
            not safe_git_pointer
            and not _read_only_lookup_target_is_safe(
                relative.as_posix(),
                allow_dirs=allow_dirs and resolved.is_dir(),
                home_dir=root,
            )
        ):
            return False
    return True


def _bounded_local_read_glob_is_safe(
    candidate: Path,
    *,
    root: Path,
    allow_dirs: bool,
) -> bool:
    """Accept bounded read globs only when every shell-visible match is safe."""

    try:
        root_resolved = root.resolve(strict=True)
        lexical_candidate = Path(os.path.abspath(os.fspath(candidate)))
        relative_pattern = lexical_candidate.relative_to(root_resolved)
    except (OSError, RuntimeError, ValueError):
        return False
    if "**" in relative_pattern.parts:
        return False
    matches = [root_resolved]
    literal_fallback = False
    try:
        entries_seen = 0
        for pattern in relative_pattern.parts:
            next_matches: list[Path] = []
            has_glob = any(character in pattern for character in "*?[")
            for parent in matches:
                if not has_glob:
                    child = parent / pattern
                    if child.exists():
                        next_matches.append(child)
                    continue
                for child in parent.iterdir():
                    entries_seen += 1
                    if entries_seen > 4096:
                        return False
                    if child.name.startswith(".") and not pattern.startswith("."):
                        continue
                    # Audit a cross-platform superset so case-insensitive filesystems cannot widen the read.
                    if fnmatch.fnmatchcase(child.name.casefold(), pattern.casefold()):
                        next_matches.append(child)
            matches = next_matches
            if len(matches) > 128:
                return False
            if not matches:
                break
    except (OSError, RuntimeError, ValueError):
        return False
    if not matches and lexical_candidate.exists():
        matches.append(lexical_candidate)
        literal_fallback = True
    for match in matches:
        if match.name.startswith("-"):
            return False
        try:
            if match.is_symlink():
                return False
            lexical = Path(os.path.abspath(os.fspath(match)))
            resolved = match.resolve(strict=True)
            relative = resolved.relative_to(root_resolved)
        except (FileNotFoundError, OSError, RuntimeError, ValueError):
            return False
        lookup_target = relative.as_posix()
        if literal_fallback:
            lookup_target = lookup_target.replace("[", "").replace("]", "")
        if (
            resolved != lexical
            or not lookup_target
            or not _read_only_lookup_target_is_safe(
                lookup_target,
                allow_dirs=allow_dirs and resolved.is_dir(),
                home_dir=root,
            )
        ):
            return False
    return True


def _cat_file_operand_tokens(args: list[str]) -> tuple[str, ...]:
    operands: list[str] = []
    after_options = False
    for arg in args:
        if after_options:
            operands.append(arg)
            continue
        if arg == "--":
            after_options = True
            continue
        if arg == "-":
            continue
        if arg.startswith("-"):
            continue
        operands.append(arg)
    return tuple(operands)


def _plain_file_operand_tokens(args: list[str]) -> tuple[str, ...]:
    operands: list[str] = []
    skip_next = False
    after_options = False
    for arg in args:
        if skip_next:
            skip_next = False
            continue
        if after_options:
            operands.append(arg)
            continue
        if arg == "--":
            after_options = True
            continue
        if arg in {"-n", "--lines", "-c", "--bytes"}:
            skip_next = True
            continue
        if arg.startswith("--lines=") or arg.startswith("--bytes=") or re.fullmatch(r"-\d{1,6}", arg):
            continue
        if arg.startswith("-"):
            continue
        operands.append(arg)
    return tuple(operands)


def _sed_file_operand_tokens(args: list[str]) -> tuple[str, ...]:
    operands: list[str] = []
    scripts_seen = 0
    skip_script = False
    after_options = False
    for arg in args:
        if skip_script:
            skip_script = False
            scripts_seen += 1
            continue
        if after_options:
            operands.append(arg)
            continue
        if arg == "--":
            after_options = True
            continue
        if arg in {"-n", "--quiet", "--silent"}:
            continue
        if arg in {"-e", "--expression"}:
            skip_script = True
            continue
        if arg.startswith("-e") and len(arg) > 2:
            scripts_seen += 1
            continue
        if arg.startswith("--expression="):
            scripts_seen += 1
            continue
        if arg.startswith("-"):
            continue
        if scripts_seen == 0:
            scripts_seen += 1
            continue
        operands.append(arg)
    return tuple(operands)


def _search_file_operand_tokens(command_name: str, args: list[str]) -> tuple[str, ...]:
    return tuple(operand for operand, _is_search_glob in _search_file_operand_roles(command_name, args))


def _search_concrete_file_operand_tokens(command_name: str, args: list[str]) -> tuple[str, ...]:
    return tuple(
        operand for operand, is_search_glob in _search_file_operand_roles(command_name, args) if not is_search_glob
    )


def search_operands_are_safe(command_name: str, args: list[str], *, root: Path | None) -> bool:
    """Validate search globs, lexical targets, and resolved local operands together."""

    roles = _search_file_operand_roles(command_name, args)
    if not all(
        _search_glob_pattern_is_safe(operand, root=root)
        if is_search_glob
        else _read_only_lookup_target_is_safe(operand, allow_dirs=True, home_dir=root)
        for operand, is_search_glob in roles
    ):
        return False
    if root is None:
        return True
    return _local_read_operands_resolve_safely(command_name, args, cwd=root, root=root)


def _search_file_operand_roles(command_name: str, args: list[str]) -> tuple[tuple[str, bool], ...]:
    operands: list[tuple[str, bool]] = []
    pattern_seen = _search_command_has_no_pattern(command_name, args)
    skip_next = False
    skip_next_is_operand = False
    after_options = False
    for arg in args:
        if skip_next:
            if skip_next_is_operand:
                operands.append((arg, True))
            skip_next = False
            skip_next_is_operand = False
            continue
        if after_options:
            operands.append((arg, False))
            continue
        if arg == "--":
            after_options = True
            continue
        if arg in {
            "-A",
            "-B",
            "-C",
            "-e",
            "-f",
            "-g",
            "-m",
            "-t",
            "--after-context",
            "--before-context",
            "--context",
            "--exclude",
            "--exclude-dir",
            "--file",
            "--glob",
            "--iglob",
            "--include",
            "--max-count",
            "--max-depth",
            "--max-filesize",
            "--regexp",
            "--type",
            "--type-not",
        }:
            skip_next = True
            skip_next_is_operand = (command_name in {"grep", "egrep", "fgrep"} and arg == "--include") or (
                command_name == "rg" and arg in {"-g", "--glob", "--iglob"}
            )
            if arg in {"-e", "--regexp", "-f", "--file"}:
                pattern_seen = True
            continue
        search_value_flags = (
            "--after-context",
            "--before-context",
            "--context",
            "--exclude",
            "--exclude-dir",
            "--file",
            "--glob",
            "--iglob",
            "--include",
            "--max-count",
            "--max-depth",
            "--max-filesize",
            "--regexp",
            "--type",
            "--type-not",
        )
        if any(arg.startswith(f"{flag}=") for flag in search_value_flags):
            if command_name in {"grep", "egrep", "fgrep"} and arg.startswith("--include="):
                operands.append((arg.split("=", 1)[1], True))
                continue
            if command_name == "rg" and any(arg.startswith(f"{flag}=") for flag in ("--glob", "--iglob")):
                operands.append((arg.split("=", 1)[1], True))
                continue
            if arg.startswith(("--regexp=", "--file=")):
                pattern_seen = True
            continue
        option_value_prefixes = ("-A", "-B", "-C", "-m")
        if any(arg.startswith(prefix) and len(arg) > len(prefix) for prefix in option_value_prefixes):
            continue
        if command_name == "rg" and arg.startswith("-g") and len(arg) > 2:
            operands.append((arg[2:], True))
            continue
        if arg.startswith("-e") and len(arg) > 2:
            pattern_seen = True
            continue
        if arg.startswith("-"):
            continue
        if not pattern_seen:
            pattern_seen = True
            continue
        operands.append((arg, False))
    return tuple(operands)


def _search_command_has_no_pattern(command_name: str, args: list[str]) -> bool:
    return command_name == "rg" and "--files" in args


def _search_glob_pattern_is_safe(pattern: str, *, root: Path | None) -> bool:
    is_exclusion = pattern.startswith("!")
    effective_pattern = pattern[1:] if is_exclusion else pattern
    if (
        not effective_pattern
        or len(effective_pattern) > 4096
        or "\n" in effective_pattern
        or "\x00" in effective_pattern
        or any(token in effective_pattern for token in ("**", "{", "}", "!"))
        or Path(effective_pattern).is_absolute()
        or any(component in {"", ".", ".."} for component in Path(effective_pattern).parts)
    ):
        return False
    if is_exclusion:
        return True
    components = Path(effective_pattern).parts
    for component in components:
        folded = component.casefold()
        if folded.startswith(".") and folded not in SOURCE_INSPECTION_BENIGN_DOTFILES:
            return False
        for sensitive in SOURCE_INSPECTION_SENSITIVE_PARTS:
            sensitive_folded = sensitive.casefold()
            if fnmatch.fnmatchcase(sensitive_folded, folded) or fnmatch.fnmatchcase(
                f"{sensitive_folded}.guard-sensitive-probe", folded
            ):
                return False
    return True


__all__ = [
    "_bounded_local_read_glob_is_safe",
    "_cat_file_operand_tokens",
    "_local_read_operands_resolve_safely",
    "_plain_file_operand_tokens",
    "_ripgrep_args_expand_hidden_files",
    "_search_concrete_file_operand_tokens",
    "_search_file_operand_tokens",
    "_sed_file_operand_tokens",
    "_shell_segment_file_operand_tokens",
    "search_operands_are_safe",
]
