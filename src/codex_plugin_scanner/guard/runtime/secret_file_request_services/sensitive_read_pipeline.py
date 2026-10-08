"""Sensitive local-read pipeline and runtime path checks."""

from __future__ import annotations

import os
import stat
from pathlib import Path

from ..home_path_text import expand_home, normalize_path
from .constants_core import _FIND_EXEC_ACTION_FLAGS, _FIND_EXEC_TERMINATOR_TOKENS
from .constants_patterns import (
    _CURL_AT_FILE_FLAGS_WITH_VALUE,
    _CURL_DIRECT_FILE_FLAGS_WITH_VALUE,
    _CURL_FORM_FLAGS_WITH_VALUE,
    _SHELL_NETWORK_SINK_COMMANDS,
    _WGET_UPLOAD_FLAGS_WITH_VALUE,
)
from .github_pr_body_safety import _shell_segment_reads_sensitive_path
from .shell_static_safety import _path_text_is_within_root_text
from .shell_tokenization import _shell_segment_primary_command


def _shell_pipeline_reads_sensitive_path_to_network(
    parts: list[str],
    *,
    cwd: Path | None,
    home_dir: Path | None,
) -> bool:
    secret_in_pipeline = False
    segment: list[str] = []
    for token in [*parts, ";"]:
        if token == ";" and _find_segment_expects_exec_terminator(segment):
            segment.append(token)
            continue
        if token in {"|", "|&"}:
            if _shell_segment_network_sink_receives_pipeline(segment) and secret_in_pipeline:
                return True
            if _shell_segment_reads_sensitive_path(segment, cwd=cwd, home_dir=home_dir):
                secret_in_pipeline = True
            segment = []
            continue
        if token in {"&&", "||", ";", "&"}:
            if _shell_segment_network_sink_receives_pipeline(segment) and secret_in_pipeline:
                return True
            secret_in_pipeline = False
            segment = []
            continue
        segment.append(token)
    return False


def _find_segment_expects_exec_terminator(segment: list[str]) -> bool:
    command_name, command_index = _shell_segment_primary_command(segment)
    if command_name != "find" or command_index is None:
        return False
    args = segment[command_index + 1 :]
    index = 0
    while index < len(args):
        if args[index] not in _FIND_EXEC_ACTION_FLAGS:
            index += 1
            continue
        index += 1
        while index < len(args) and args[index] not in _FIND_EXEC_TERMINATOR_TOKENS:
            index += 1
        if index >= len(args):
            return True
        index += 1
    return False


def _shell_segment_network_sink_receives_pipeline(segment: list[str]) -> bool:
    command_name, command_index = _shell_segment_primary_command(segment)
    if command_name not in _SHELL_NETWORK_SINK_COMMANDS or command_index is None:
        return False
    args = segment[command_index + 1 :]
    if command_name == "curl":
        return _curl_segment_consumes_stdin(args)
    if command_name == "wget":
        return _wget_segment_consumes_stdin(args)
    if command_name == "ssh":
        return _ssh_segment_consumes_stdin(args)
    return command_name in {"nc", "ncat", "netcat"}


def _ssh_segment_consumes_stdin(args: list[str]) -> bool:
    if not args:
        return False
    skip_next = False
    flags_with_values = frozenset(
        {
            "-b",
            "-c",
            "-D",
            "-E",
            "-e",
            "-F",
            "-I",
            "-i",
            "-J",
            "-L",
            "-l",
            "-m",
            "-O",
            "-o",
            "-p",
            "-R",
            "-S",
            "-W",
            "-w",
        }
    )
    for arg in args:
        if skip_next:
            skip_next = False
            continue
        if arg == "--":
            break
        if arg in flags_with_values:
            skip_next = True
            continue
        if any(arg.startswith(flag) and len(arg) > len(flag) for flag in flags_with_values):
            continue
        if arg in {"-n", "-f", "-G", "-N", "-Q", "-V"}:
            return False
        if any(arg.startswith(flag) and len(arg) > 2 for flag in ("-G", "-N", "-Q")):
            return False
        if arg.startswith("-") and not arg.startswith("--"):
            cluster_flags = arg[1:]
            for index, flag in enumerate(cluster_flags):
                if flag in {"n", "f", "N"}:
                    return False
                if f"-{flag}" in flags_with_values:
                    if index == len(cluster_flags) - 1:
                        break
                    break
    return True


def _curl_segment_consumes_stdin(args: list[str]) -> bool:
    for index, arg in enumerate(args):
        if arg in _CURL_DIRECT_FILE_FLAGS_WITH_VALUE:
            if index + 1 < len(args) and args[index + 1].strip("'\"") == "-":
                return True
            continue
        if any(arg.startswith(f"{flag}=") for flag in _CURL_DIRECT_FILE_FLAGS_WITH_VALUE):
            if arg.split("=", 1)[1].strip("'\"") == "-":
                return True
            continue
        if arg.startswith("-T") and len(arg) > 2:
            if arg[2:].strip("'\"") == "-":
                return True
            continue
        if arg in _CURL_AT_FILE_FLAGS_WITH_VALUE or arg in _CURL_FORM_FLAGS_WITH_VALUE:
            if index + 1 < len(args) and _curl_value_consumes_stdin(args[index + 1]):
                return True
            continue
        if any(arg.startswith(f"{flag}=") for flag in _CURL_AT_FILE_FLAGS_WITH_VALUE | _CURL_FORM_FLAGS_WITH_VALUE):
            if _curl_value_consumes_stdin(arg.split("=", 1)[1]):
                return True
            continue
        if arg.startswith("-d") and len(arg) > 2:
            if _curl_value_consumes_stdin(arg[2:]):
                return True
            continue
        if arg.startswith("-F") and len(arg) > 2:
            if _curl_value_consumes_stdin(arg[2:]):
                return True
            continue
    return False


def _curl_value_consumes_stdin(value: str) -> bool:
    stripped = value.strip("'\"")
    return stripped == "@-" or stripped.endswith("=@-")


def _wget_segment_consumes_stdin(args: list[str]) -> bool:
    for index, arg in enumerate(args):
        if arg in _WGET_UPLOAD_FLAGS_WITH_VALUE:
            if index + 1 < len(args) and args[index + 1].strip("'\"") == "-":
                return True
            continue
        if (
            any(arg.startswith(f"{flag}=") for flag in _WGET_UPLOAD_FLAGS_WITH_VALUE)
            and arg.split("=", 1)[1].strip("'\"") == "-"
        ):
            return True
    return False


def _strip_cli_value(value: str) -> str:
    return value.strip().strip("'").strip('"')


def _runtime_read_roots(cwd: Path | None, home_dir: Path | None) -> tuple[Path, ...]:
    roots: list[Path] = []
    for candidate in (cwd, home_dir or Path.home()):
        if candidate is None:
            continue
        try:
            resolved_candidate = candidate.resolve(strict=False)
        except OSError:
            continue
        if resolved_candidate not in roots:
            roots.append(resolved_candidate)
    return tuple(roots)


def _runtime_read_root_texts(roots: tuple[Path, ...]) -> tuple[str, ...]:
    return tuple(os.path.realpath(os.fspath(root)) for root in roots)


def _runtime_relative_parts(path_text: str, root_text: str) -> tuple[str, ...] | None:
    try:
        relative_text = os.path.relpath(path_text, root_text)
    except ValueError:
        return None
    if relative_text in {"", "."}:
        return None
    parts = Path(relative_text).parts
    if not parts or any(_runtime_relative_part_is_unsafe(part) for part in parts):
        return None
    return parts


def _runtime_relative_part_is_unsafe(part: str) -> bool:
    if part in {"", ".", ".."}:
        return True
    separators = (os.sep, os.altsep) if os.altsep else (os.sep,)
    return any(separator in part for separator in separators)


def _runtime_entry_name_matches(
    entry_name: str,
    requested_name: str,
    *,
    entry_path: str,
    requested_path: str,
) -> bool:
    if entry_name == requested_name or os.path.normcase(entry_name) == os.path.normcase(requested_name):
        return True
    if entry_name.casefold() != requested_name.casefold():
        return False
    try:
        return os.path.samefile(entry_path, requested_path)
    except OSError:
        return False


def _runtime_entry_for_name(directory_text: str, requested_name: str) -> os.DirEntry[str] | None:
    requested_path = os.path.join(directory_text, requested_name)
    try:
        with os.scandir(directory_text) as entries:
            return next(
                (
                    entry
                    for entry in entries
                    if _runtime_entry_name_matches(
                        entry.name,
                        requested_name,
                        entry_path=entry.path,
                        requested_path=requested_path,
                    )
                ),
                None,
            )
    except OSError:
        return None


def _runtime_file_entry_under_root(path_text: str, root_text: str) -> os.DirEntry[str] | None:
    relative_parts = _runtime_relative_parts(path_text, root_text)
    if relative_parts is None:
        return None
    current_dir_text = root_text
    for directory_name in relative_parts[:-1]:
        directory_entry = _runtime_entry_for_name(current_dir_text, directory_name)
        if directory_entry is None:
            return None
        try:
            directory_stat = directory_entry.stat(follow_symlinks=False)
        except OSError:
            return None
        if not stat.S_ISDIR(directory_stat.st_mode):
            return None
        current_dir_text = os.path.realpath(directory_entry.path)
        if not _path_text_is_within_root_text(current_dir_text, root_text):
            return None
    return _runtime_entry_for_name(current_dir_text, relative_parts[-1])


def _resolved_runtime_path(
    value: str,
    *,
    cwd: Path | None,
    home_dir: Path | None,
    allowed_roots: tuple[Path, ...] | None = None,
) -> Path | None:
    stripped_value = _strip_cli_value(value)
    if not stripped_value:
        return None
    expanded_value = expand_home(stripped_value, home_dir)
    normalized_path = Path(normalize_path(expanded_value, cwd))
    read_roots = allowed_roots or _runtime_read_roots(cwd, home_dir)
    if not read_roots:
        return None
    path_text = os.path.realpath(os.fspath(normalized_path))
    root_texts = _runtime_read_root_texts(read_roots)
    if not any(_path_text_is_within_root_text(path_text, root_text) for root_text in root_texts):
        return None
    return Path(path_text)


__all__ = [
    "_curl_segment_consumes_stdin",
    "_curl_value_consumes_stdin",
    "_find_segment_expects_exec_terminator",
    "_resolved_runtime_path",
    "_runtime_entry_for_name",
    "_runtime_entry_name_matches",
    "_runtime_file_entry_under_root",
    "_runtime_read_root_texts",
    "_runtime_read_roots",
    "_runtime_relative_part_is_unsafe",
    "_runtime_relative_parts",
    "_shell_pipeline_reads_sensitive_path_to_network",
    "_shell_segment_network_sink_receives_pipeline",
    "_ssh_segment_consumes_stdin",
    "_strip_cli_value",
    "_wget_segment_consumes_stdin",
]
