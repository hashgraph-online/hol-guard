"""Canonical, side-effect-free command model shared by Guard extensions."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from .command_structure import (
    CommandRedirect,
    EmbeddedCommand,
    build_command_security_identity,
    extract_command_redirects,
)
from .command_tokens import executable_name, leading_environment, shell_tokens
from .data_flow import (
    ShellHeredoc,
    extract_command_segments,
    extract_command_substitution_spans,
    extract_expanded_heredoc_substitution_spans,
    extract_heredocs,
    extract_pipes,
    mask_heredoc_bodies,
)
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

_SHELL_SCRIPT_EXECUTABLES = frozenset({"ash", "bash", "dash", "sh", "zsh"})


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
    execution_context: str
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
            "execution_context": self.execution_context,
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
    redirects: tuple[CommandRedirect, ...]
    embedded_commands: tuple[EmbeddedCommand, ...]
    confidence: ParseConfidence
    uncertainty_reason: str | None = None

    @property
    def path_overridden(self) -> bool:
        return any(segment.path_overridden for segment in self.segments)

    @property
    def security_identity(self) -> str:
        """Return a versioned identity over the complete executable structure."""

        return build_command_security_identity(
            normalized_text=self.normalized_text,
            dialect=self.dialect,
            transport=self.transport,
            wrapper_chain=self.wrapper_chain,
            segments=self.segments,
            redirects=self.redirects,
            embedded_commands=self.embedded_commands,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "normalized_text": self.normalized_text,
            "dialect": self.dialect,
            "transport": self.transport,
            "extraction_provenance": self.extraction_provenance,
            "wrapper_chain": list(self.wrapper_chain),
            "segments": [segment.to_dict() for segment in self.segments],
            "redirects": [redirect.to_dict() for redirect in self.redirects],
            "embedded_commands": [embedded.to_dict() for embedded in self.embedded_commands],
            "security_identity": self.security_identity,
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
            redirects=(),
            embedded_commands=(),
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
            redirects=(),
            embedded_commands=(),
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
            redirects=(),
            embedded_commands=(),
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

    heredocs = extract_heredocs(normalized_text)
    segment_texts = _execution_segment_texts(mask_heredoc_bodies(normalized_text, heredocs))
    if len(segment_texts) > MAX_COMMAND_SEGMENTS:
        return CanonicalCommand(
            raw_text=raw_text,
            normalized_text=normalized_text,
            dialect=dialect,
            transport=transport,
            extraction_provenance=extraction_provenance,
            wrapper_chain=normalization.wrapper_chain,
            segments=(),
            redirects=(),
            embedded_commands=(),
            confidence="uncertain",
            uncertainty_reason="command_segment_limit_exceeded",
        )

    segments: list[CommandSegment] = []
    segment_wrappers: list[str] = []
    cursor = 0
    total_tokens = 0
    for execution_context, pipeline_index, segment_text, source_offset in segment_texts:
        tokens, exact = shell_tokens(segment_text)
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
                redirects=(),
                embedded_commands=(),
                confidence="uncertain",
                uncertainty_reason="command_token_limit_exceeded",
            )
        if not exact and confidence == "exact":
            confidence = "fallback"
            uncertainty_reason = "malformed_shell_quoting"
        environment_names, executable_index, wrappers = leading_environment(tokens)
        for wrapper in wrappers:
            if wrapper not in segment_wrappers:
                segment_wrappers.append(wrapper)
        executable = tokens[executable_index] if executable_index < len(tokens) else None
        arguments = tokens[executable_index + 1 :] if executable is not None else ()
        start = normalized_text.find(segment_text, max(cursor, source_offset))
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
                execution_context=execution_context,
                pipeline_index=pipeline_index,
                start=start,
                end=end,
            )
        )

    embedded_commands, embedded_segments = _embedded_execution(
        normalized_text,
        heredocs=heredocs,
        top_level_segments=tuple(segments),
    )
    segments.extend(embedded_segments)
    if len(segments) > MAX_COMMAND_SEGMENTS or sum(len(segment.tokens) for segment in segments) > MAX_COMMAND_TOKENS:
        confidence = "uncertain"
        uncertainty_reason = "embedded_command_limit_exceeded"
    return CanonicalCommand(
        raw_text=raw_text,
        normalized_text=normalized_text,
        dialect=dialect,
        transport=transport,
        extraction_provenance=extraction_provenance,
        wrapper_chain=(*normalization.wrapper_chain, *segment_wrappers),
        segments=tuple(segments),
        redirects=extract_command_redirects(mask_heredoc_bodies(normalized_text, heredocs), heredocs),
        embedded_commands=embedded_commands,
        confidence=confidence,
        uncertainty_reason=uncertainty_reason,
    )


def _execution_segment_texts(command: str, *, context_prefix: str = "top") -> tuple[tuple[str, int, str, int], ...]:
    segments: list[tuple[str, int, str, int]] = []
    cursor = 0
    for group_index, command_segment in enumerate(extract_command_segments(command)):
        source_offset = command.find(command_segment, cursor)
        if source_offset < 0:
            source_offset = cursor
        cursor = source_offset + len(command_segment)
        execution_context = f"{context_prefix}:{group_index}"
        pipes = extract_pipes(command_segment)
        if not pipes:
            stripped = command_segment.strip()
            if stripped:
                segments.append((execution_context, 0, stripped, source_offset))
            continue
        pipe_parts = [pipes[0].left, *(pipe.right for pipe in pipes)]
        part_cursor = source_offset
        for index, part in enumerate(pipe_parts):
            stripped = part.strip()
            if not stripped:
                continue
            part_offset = command.find(stripped, part_cursor)
            if part_offset < 0:
                part_offset = part_cursor
            segments.append((execution_context, index, stripped, part_offset))
            part_cursor = part_offset + len(stripped)
    return tuple(segments)


def _embedded_execution(
    command: str,
    *,
    heredocs: tuple[ShellHeredoc, ...],
    top_level_segments: tuple[CommandSegment, ...],
) -> tuple[tuple[EmbeddedCommand, ...], tuple[CommandSegment, ...]]:
    embedded: list[EmbeddedCommand] = []
    segments: list[CommandSegment] = []
    _append_substitution_execution(
        command,
        source_offset=0,
        context_prefix="substitution",
        excluded_ranges=tuple((heredoc.body_start, heredoc.end) for heredoc in heredocs),
        embedded=embedded,
        segments=segments,
        depth=0,
    )

    for index, heredoc in enumerate(heredocs):
        owner = next(
            (segment for segment in top_level_segments if segment.start <= heredoc.operator_start <= segment.end),
            None,
        )
        executable = executable_name(owner.executable) if owner is not None else None
        if executable not in _SHELL_SCRIPT_EXECUTABLES:
            if not heredoc.quoted:
                _append_substitution_execution(
                    heredoc.body,
                    source_offset=heredoc.body_start,
                    context_prefix=f"heredoc:{index}:substitution",
                    excluded_ranges=(),
                    embedded=embedded,
                    segments=segments,
                    depth=0,
                    expanded_heredoc=True,
                )
            continue
        context = f"heredoc:{index}"
        embedded.append(
            EmbeddedCommand(
                kind="heredoc",
                text=heredoc.body,
                execution_context=context,
                start=heredoc.body_start,
                end=heredoc.body_end,
            )
        )
        segments.extend(
            _segments_for_embedded(
                heredoc.body,
                execution_context=context,
                source_offset=heredoc.body_start,
            )
        )
        _append_substitution_execution(
            heredoc.body,
            source_offset=heredoc.body_start,
            context_prefix=f"{context}:substitution",
            excluded_ranges=(),
            embedded=embedded,
            segments=segments,
            depth=0,
        )
    return tuple(embedded), tuple(segments)


def _append_substitution_execution(
    command: str,
    *,
    source_offset: int,
    context_prefix: str,
    excluded_ranges: tuple[tuple[int, int], ...],
    embedded: list[EmbeddedCommand],
    segments: list[CommandSegment],
    depth: int,
    expanded_heredoc: bool = False,
) -> None:
    if depth >= 4:
        return
    extractor = extract_expanded_heredoc_substitution_spans if expanded_heredoc else extract_command_substitution_spans
    for index, substitution in enumerate(extractor(command)):
        absolute_start = source_offset + substitution.body_start
        if any(start <= absolute_start < end for start, end in excluded_ranges):
            continue
        context = f"{context_prefix}:{index}"
        embedded.append(
            EmbeddedCommand(
                kind="substitution",
                text=substitution.body,
                execution_context=context,
                start=absolute_start,
                end=source_offset + substitution.body_end,
            )
        )
        segments.extend(
            _segments_for_embedded(
                substitution.body,
                execution_context=context,
                source_offset=absolute_start,
            )
        )
        _append_substitution_execution(
            substitution.body,
            source_offset=absolute_start,
            context_prefix=f"{context}:nested",
            excluded_ranges=(),
            embedded=embedded,
            segments=segments,
            depth=depth + 1,
        )


def _segments_for_embedded(
    command: str,
    *,
    execution_context: str,
    source_offset: int,
) -> tuple[CommandSegment, ...]:
    results: list[CommandSegment] = []
    for context, pipeline_index, segment_text, local_offset in _execution_segment_texts(
        command,
        context_prefix=execution_context,
    ):
        tokens, _exact = shell_tokens(segment_text)
        environment_names, executable_index, wrappers = leading_environment(tokens)
        executable = tokens[executable_index] if executable_index < len(tokens) else None
        arguments = tokens[executable_index + 1 :] if executable is not None else ()
        start = source_offset + local_offset
        results.append(
            CommandSegment(
                text=segment_text,
                tokens=tokens,
                executable=executable,
                arguments=arguments,
                environment_names=environment_names,
                wrapper_chain=wrappers,
                path_overridden="PATH" in environment_names,
                execution_context=context,
                pipeline_index=pipeline_index,
                start=start,
                end=start + len(segment_text),
            )
        )
    return tuple(results)
