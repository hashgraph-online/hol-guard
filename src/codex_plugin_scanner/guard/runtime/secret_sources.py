"""Secret source extraction helpers for Guard runtime detectors."""

from __future__ import annotations

import re
from collections.abc import Sequence
from pathlib import Path

from codex_plugin_scanner.guard.runtime.data_flow import (
    extract_command_substitutions,
    extract_input_redirects,
    extract_url_ranges,
)
from codex_plugin_scanner.guard.runtime.secret_sensitivity import SecretPathMatch, classify_secret_path
from codex_plugin_scanner.guard.runtime.shell_commands import (
    command_execution_segments,
    command_tokens_after_env_assignments,
)

_SECRET_PATH_TOKEN_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_.-])"
    r"(?P<path>"
    r"\.env(?:\.[A-Za-z0-9_-]+)?|\.npmrc|\.pypirc|\.netrc|\.git-credentials|"
    r"(?:~?/)?\.aws/credentials|(?:~?/)?\.ssh/id_(?:rsa|ed25519|ecdsa)|"
    r"wallet\.key|private-key\.pem|terraform\.tfvars"
    r")"
    r"(?![A-Za-z0-9_.-])",
    re.IGNORECASE,
)
_SECRET_READ_COMMANDS = frozenset(
    {
        "awk",
        "base64",
        "cat",
        "cut",
        "grep",
        "head",
        "jq",
        "less",
        "more",
        "openssl",
        "rg",
        "sed",
        "tail",
        "xxd",
        "yq",
    }
)


def secret_path_matches_in_command(
    command: str, *, workspace: Path | None, extra_paths: Sequence[str] = ()
) -> tuple[SecretPathMatch, ...]:
    candidates = list(extract_input_redirects(command))
    candidates.extend(_secret_read_command_paths(command))
    candidates.extend(
        path
        for substitution in extract_command_substitutions(command)
        for path in _substitution_secret_paths(substitution)
    )
    candidates.extend(extra_paths)
    return _secret_path_matches(tuple(candidates), workspace=workspace)


def strip_shell_token(value: str) -> str:
    stripped = value.strip().strip(",")
    if len(stripped) >= 2 and stripped[0] == stripped[-1] and stripped[0] in {"'", '"'}:
        return stripped[1:-1]
    return stripped


def _secret_read_command_paths(command: str) -> tuple[str, ...]:
    paths: list[str] = []
    url_ranges = extract_url_ranges(command)
    for segment in command_execution_segments(command):
        tokens = command_tokens_after_env_assignments(segment)
        if not tokens or tokens[0].lower() not in _SECRET_READ_COMMANDS:
            continue
        paths.extend(
            strip_shell_token(match.group("path"))
            for match in _SECRET_PATH_TOKEN_PATTERN.finditer(segment)
            if not any(start <= match.start("path") < end for start, end in url_ranges)
        )
    return tuple(paths)


def _substitution_secret_paths(command: str) -> tuple[str, ...]:
    paths = list(extract_input_redirects(command))
    paths.extend(_secret_read_command_paths(command))
    return tuple(paths)


def _secret_path_matches(paths: Sequence[str], *, workspace: Path | None) -> tuple[SecretPathMatch, ...]:
    matches: list[SecretPathMatch] = []
    for path in paths:
        match = classify_secret_path(path, cwd=workspace)
        if match is not None:
            matches.append(match)
    return tuple(matches)
