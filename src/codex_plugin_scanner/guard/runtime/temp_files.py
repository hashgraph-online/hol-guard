"""Temp-file shell helpers for Guard runtime detectors."""

from __future__ import annotations

import re

from codex_plugin_scanner.guard.runtime.data_flow import extract_command_segments
from codex_plugin_scanner.guard.runtime.shell_commands import command_tokens_after_env_assignments, shell_tokens

_TEMP_SECRET_WRITE_PATTERN = re.compile(r"(?is)(?:>\s*(?P<redirect>/tmp/[^\s;&|]+)|tee\b(?P<tee>[^\r\n;&|]+))")


def temp_write_targets(segment: str) -> tuple[str, ...]:
    targets: list[str] = []
    for match in _TEMP_SECRET_WRITE_PATTERN.finditer(segment):
        redirect = match.group("redirect")
        if redirect:
            targets.append(_strip_shell_token(redirect))
        tee_body = match.group("tee")
        if tee_body:
            targets.extend(_tee_targets(tee_body))
    return tuple(target for target in targets if target.startswith("/tmp/"))


def chmod_temp_targets(command: str) -> tuple[tuple[str, str], ...]:
    targets: list[tuple[str, str]] = []
    for segment in extract_command_segments(command):
        tokens = command_tokens_after_env_assignments(segment)
        if len(tokens) < 3 or tokens[0].lower() != "chmod":
            continue
        mode_index = _chmod_mode_index(tokens)
        if mode_index is None:
            continue
        targets.extend((_strip_shell_token(path), tokens[mode_index]) for path in tokens[mode_index + 1 :])
    return tuple(targets)


def _tee_targets(body: str) -> tuple[str, ...]:
    return tuple(_strip_shell_token(token) for token in shell_tokens(body) if not token.startswith("-"))


def _chmod_mode_index(tokens: tuple[str, ...]) -> int | None:
    index = 1
    while index < len(tokens) and tokens[index].startswith("-"):
        index += 1
    if index < len(tokens):
        return index
    return None


def _strip_shell_token(value: str) -> str:
    stripped = value.strip().strip(",")
    if len(stripped) >= 2 and stripped[0] == stripped[-1] and stripped[0] in {"'", '"'}:
        return stripped[1:-1]
    return stripped
