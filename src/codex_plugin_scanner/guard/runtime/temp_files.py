"""Temp-file shell helpers for Guard runtime detectors."""

from __future__ import annotations

import re

from codex_plugin_scanner.guard.runtime.data_flow import extract_command_segments
from codex_plugin_scanner.guard.runtime.shell_commands import segment_executes_command, shell_tokens

_TEMP_SECRET_WRITE_PATTERN = re.compile(r"(?is)(?:>\s*(?P<redirect>/tmp/[^\s;&|]+)|tee\b(?P<tee>[^\r\n;&|]+))")
_CHMOD_TEMP_PATTERN = re.compile(r"(?is)chmod\s+(?P<mode>[0-7]{3,4}|[A-Za-z,+=-]+)\s+(?P<path>/tmp/[^\s;&|]+)")


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
        if not segment_executes_command(segment, {"chmod"}):
            continue
        targets.extend(
            (_strip_shell_token(match.group("path")), match.group("mode"))
            for match in _CHMOD_TEMP_PATTERN.finditer(segment)
        )
    return tuple(targets)


def _tee_targets(body: str) -> tuple[str, ...]:
    return tuple(_strip_shell_token(token) for token in shell_tokens(body) if not token.startswith("-"))


def _strip_shell_token(value: str) -> str:
    stripped = value.strip().strip(",")
    if len(stripped) >= 2 and stripped[0] == stripped[-1] and stripped[0] in {"'", '"'}:
        return stripped[1:-1]
    return stripped
