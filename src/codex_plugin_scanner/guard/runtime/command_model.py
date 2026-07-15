"""Canonical, side-effect-free command model shared by Guard extensions."""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from .data_flow import extract_command_segments, extract_pipes
from .shell_command_wrappers import (
    SHELL_COMMAND_NORMALIZE_MAX_BYTES,
    normalize_transparent_shell_command,
)

CommandDialect = Literal["posix", "powershell", "cmd", "argv", "unknown"]
CommandTransport = Literal["shell_string", "argv", "embedded_script"]
ParseConfidence = Literal["exact", "fallback", "uncertain"]

MAX_COMMAND_BYTES = 32_768
MAX_COMMAND_SEGMENTS = 128
MAX_COMMAND_TOKENS = 2_048

_ENV_ASSIGNMENT_PATTERN = re.compile(r"^(?P<name>[A-Za-z_][A-Za-z0-9_]*)=.*$", re.DOTALL)
_SUDO_OPTIONS_WITH_VALUES = frozenset({"-C", "-D", "-g", "-h", "-p", "-R", "-r", "-T", "-t", "-u"})
_SUDO_LONG_OPTIONS_WITH_VALUES = frozenset(
    {"--chdir", "--chroot", "--close-from", "--group", "--host", "--prompt", "--role", "--type", "--user"}
)


@dataclass(frozen=True, slots=True)
class CommandSegment:
    """One executable segment from a normalized command string."""

    text: str
    tokens: tuple[str, ...]
    executable: str | None
    arguments: tuple[str, ...]
    environment_names: tuple[str, ...]
    wrapper_chain: tuple[str, ...]
    path_overridden: bool
    pipeline_index: int
    start: int
    end: int

    def to_dict(self) -> dict[str, object]:
        return {
            "text": self.text,
            "tokens": list(self.tokens),
            "executable": self.executable,
            "arguments": list(self.arguments),
            "environment_names": list(self.environment_names),
            "wrapper_chain": list(self.wrapper_chain),
            "path_overridden": self.path_overridden,
            "pipeline_index": self.pipeline_index,
            "span": {"source": "normalized", "start": self.start, "end": self.end},
        }


@dataclass(frozen=True, slots=True)
class CanonicalCommand:
    """Normalized command representation that never executes shell input."""

    raw_text: str
    normalized_text: str
    dialect: CommandDialect
    transport: CommandTransport
    extraction_provenance: str
    wrapper_chain: tuple[str, ...]
    segments: tuple[CommandSegment, ...]
    confidence: ParseConfidence
    uncertainty_reason: str | None = None

    @property
    def path_overridden(self) -> bool:
        return any(segment.path_overridden for segment in self.segments)

    def to_dict(self) -> dict[str, object]:
        return {
            "normalized_text": self.normalized_text,
            "dialect": self.dialect,
            "transport": self.transport,
            "extraction_provenance": self.extraction_provenance,
            "wrapper_chain": list(self.wrapper_chain),
            "segments": [segment.to_dict() for segment in self.segments],
            "confidence": self.confidence,
            "uncertainty_reason": self.uncertainty_reason,
            "path_overridden": self.path_overridden,
        }


def parse_shell_command(
    command: str,
    *,
    cwd: Path | None = None,
    home_dir: Path | None = None,
    dialect: CommandDialect = "posix",
    transport: CommandTransport = "shell_string",
    extraction_provenance: str = "guard-shell",
) -> CanonicalCommand:
    """Parse one command without expansion, execution, or persistent state."""

    raw_text = command.strip()
    if not raw_text:
        raise ValueError("Command text cannot be empty")
    if dialect != "posix" or transport != "shell_string":
        return CanonicalCommand(
            raw_text=raw_text,
            normalized_text=raw_text,
            dialect=dialect,
            transport=transport,
            extraction_provenance=extraction_provenance,
            wrapper_chain=(),
            segments=(),
            confidence="uncertain",
            uncertainty_reason=f"unsupported_{dialect}_{transport}",
        )
    if len(raw_text) > MAX_COMMAND_BYTES:
        return CanonicalCommand(
            raw_text=raw_text,
            normalized_text=raw_text,
            dialect=dialect,
            transport=transport,
            extraction_provenance=extraction_provenance,
            wrapper_chain=(),
            segments=(),
            confidence="uncertain",
            uncertainty_reason="command_byte_limit_exceeded",
        )
    command_bytes = len(raw_text.encode("utf-8"))
    if command_bytes > MAX_COMMAND_BYTES:
        return CanonicalCommand(
            raw_text=raw_text,
            normalized_text=raw_text,
            dialect=dialect,
            transport=transport,
            extraction_provenance=extraction_provenance,
            wrapper_chain=(),
            segments=(),
            confidence="uncertain",
            uncertainty_reason="command_byte_limit_exceeded",
        )

    normalization = normalize_transparent_shell_command(raw_text, cwd=cwd, home_dir=home_dir)
    normalized_text = normalization.normalized_command
    confidence: ParseConfidence = "exact"
    uncertainty_reason: str | None = None
    if command_bytes > SHELL_COMMAND_NORMALIZE_MAX_BYTES:
        confidence = "uncertain"
        uncertainty_reason = "wrapper_normalization_limit_exceeded"

    segment_texts = _execution_segment_texts(normalized_text)
    if len(segment_texts) > MAX_COMMAND_SEGMENTS:
        return CanonicalCommand(
            raw_text=raw_text,
            normalized_text=normalized_text,
            dialect=dialect,
            transport=transport,
            extraction_provenance=extraction_provenance,
            wrapper_chain=normalization.wrapper_chain,
            segments=(),
            confidence="uncertain",
            uncertainty_reason="command_segment_limit_exceeded",
        )

    segments: list[CommandSegment] = []
    segment_wrappers: list[str] = []
    cursor = 0
    total_tokens = 0
    for pipeline_index, segment_text in segment_texts:
        tokens, exact = _shell_tokens(segment_text)
        total_tokens += len(tokens)
        if total_tokens > MAX_COMMAND_TOKENS:
            return CanonicalCommand(
                raw_text=raw_text,
                normalized_text=normalized_text,
                dialect=dialect,
                transport=transport,
                extraction_provenance=extraction_provenance,
                wrapper_chain=normalization.wrapper_chain,
                segments=tuple(segments),
                confidence="uncertain",
                uncertainty_reason="command_token_limit_exceeded",
            )
        if not exact and confidence == "exact":
            confidence = "fallback"
            uncertainty_reason = "malformed_shell_quoting"
        environment_names, executable_index, wrappers = _leading_environment(tokens)
        for wrapper in wrappers:
            if wrapper not in segment_wrappers:
                segment_wrappers.append(wrapper)
        executable = tokens[executable_index] if executable_index < len(tokens) else None
        arguments = tokens[executable_index + 1 :] if executable is not None else ()
        start = normalized_text.find(segment_text, cursor)
        if start < 0:
            start = normalized_text.find(segment_text)
        if start < 0:
            start = min(cursor, len(normalized_text))
        end = min(start + len(segment_text), len(normalized_text))
        cursor = end
        segments.append(
            CommandSegment(
                text=segment_text,
                tokens=tokens,
                executable=executable,
                arguments=arguments,
                environment_names=environment_names,
                wrapper_chain=wrappers,
                path_overridden="PATH" in environment_names,
                pipeline_index=pipeline_index,
                start=start,
                end=end,
            )
        )

    return CanonicalCommand(
        raw_text=raw_text,
        normalized_text=normalized_text,
        dialect=dialect,
        transport=transport,
        extraction_provenance=extraction_provenance,
        wrapper_chain=(*normalization.wrapper_chain, *segment_wrappers),
        segments=tuple(segments),
        confidence=confidence,
        uncertainty_reason=uncertainty_reason,
    )


def _execution_segment_texts(command: str) -> tuple[tuple[int, str], ...]:
    segments: list[tuple[int, str]] = []
    for command_segment in extract_command_segments(command):
        pipes = extract_pipes(command_segment)
        if not pipes:
            stripped = command_segment.strip()
            if stripped:
                segments.append((0, stripped))
            continue
        pipe_parts = [pipes[0].left, *(pipe.right for pipe in pipes)]
        segments.extend((index, part.strip()) for index, part in enumerate(pipe_parts) if part.strip())
    return tuple(segments)


def _shell_tokens(command: str) -> tuple[tuple[str, ...], bool]:
    try:
        return tuple(shlex.split(command, posix=True, comments=False)), True
    except ValueError:
        return tuple(command.split()), False


def _leading_environment(tokens: tuple[str, ...]) -> tuple[tuple[str, ...], int, tuple[str, ...]]:
    names: list[str] = []
    wrappers: list[str] = []
    index = 0
    while index < len(tokens):
        match = _ENV_ASSIGNMENT_PATTERN.fullmatch(tokens[index])
        while match is not None:
            names.append(match.group("name"))
            index += 1
            if index >= len(tokens):
                return tuple(names), index, tuple(wrappers)
            match = _ENV_ASSIGNMENT_PATTERN.fullmatch(tokens[index])
        executable = tokens[index].replace("\\", "/").rsplit("/", 1)[-1].lower()
        if executable == "env":
            wrappers.append("env")
            index = _after_env_options(tokens, index + 1)
            continue
        if executable == "sudo":
            wrappers.append("sudo")
            index = _after_sudo_options(tokens, index + 1)
            continue
        break
    return tuple(names), index, tuple(wrappers)


def _after_env_options(tokens: tuple[str, ...], index: int) -> int:
    while index < len(tokens):
        token = tokens[index]
        if token == "--":
            return index + 1
        if token in {"-u", "-C", "--unset", "--chdir"}:
            index = min(index + 2, len(tokens))
            continue
        if token in {"-i", "-0", "--ignore-environment", "--null"} or token.startswith(("--unset=", "--chdir=")):
            index += 1
            continue
        if _ENV_ASSIGNMENT_PATTERN.fullmatch(token) is not None:
            return index
        return index
    return index


def _after_sudo_options(tokens: tuple[str, ...], index: int) -> int:
    while index < len(tokens):
        token = tokens[index]
        if token == "--":
            return index + 1
        option_name = token.split("=", 1)[0]
        if option_name in _SUDO_OPTIONS_WITH_VALUES or option_name in _SUDO_LONG_OPTIONS_WITH_VALUES:
            index += 1 if "=" in token else 2
            continue
        if token.startswith("-"):
            index += 1
            continue
        if _ENV_ASSIGNMENT_PATTERN.fullmatch(token) is not None:
            return index
        return index
    return index
