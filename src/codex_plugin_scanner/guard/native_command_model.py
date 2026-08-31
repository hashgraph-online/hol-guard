"""Shadow-only Python bridge to the native command model.

This module compares the native parser through the same version-matched resident
runtime used by the PostToolUse path. Command PreToolUse authority lives in the
Rust runtime and native_pretool transport.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .native_resident_client import native_resident_client_request
from .native_runtime import _isolated_environment, _native_error, native_runtime_status
from .native_runtime_resilience import (
    native_record_overload,
    native_record_resident_failure,
    native_record_resident_success,
)
from .runtime.command_evaluation import evaluate_command
from .runtime.command_model import CanonicalCommand, CommandSegment
from .runtime.command_shadow_evaluation import CommandShadowCohort, CommandShadowProposal

_MAX_REQUEST_BYTES = 64 * 1024
_MAX_SEGMENTS = 128
_MAX_TOKENS = 2_048
_PARSER_PROFILE = "posix-simple-v1"
_REQUIRED_FEATURE = "pre-tool-command-model-shadow-v1"
_RESIDENT_FEATURE = "resident-command-model-shadow-v1"
_RESIDENT_PROTOCOL_FEATURE = "resident-protocol-v2"
_NATIVE_SHADOW_PROPOSAL_VERSION = "guard.command-shadow-proposal.rust-parser.v1"


def _plain_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _assignment_name(token: str) -> str | None:
    name, separator, _value = token.partition("=")
    if not separator or not name:
        return None
    first = name[0]
    if first != "_" and not (first.isascii() and first.isalpha()):
        return None
    if not all(character == "_" or (character.isascii() and character.isalnum()) for character in name[1:]):
        return None
    return name


def _decode_command_model(
    payload: object,
    *,
    command: str,
    dialect: str,
    transport: str,
    extraction_provenance: str,
) -> dict[str, Any] | None:
    """Validate and bind one native response to the request that produced it."""
    if not isinstance(payload, dict):
        return None
    normalized_text = payload.get("normalized_text")
    wrapper_chain = payload.get("wrapper_chain")
    segments = payload.get("segments")
    confidence = payload.get("confidence")
    uncertainty_reason = payload.get("uncertainty_reason")
    path_overridden = payload.get("path_overridden")
    if (
        not isinstance(normalized_text, str)
        or not normalized_text
        or normalized_text != command.strip()
        or payload.get("dialect") != dialect
        or payload.get("transport") != transport
        or payload.get("extraction_provenance") != extraction_provenance
        or wrapper_chain != []
        or not isinstance(segments, list)
        or len(segments) > _MAX_SEGMENTS
        or confidence not in {"exact", "uncertain"}
        or not isinstance(path_overridden, bool)
        or payload.get("parser_profile") != _PARSER_PROFILE
    ):
        return None

    if confidence == "uncertain":
        if segments or not isinstance(uncertainty_reason, str) or not uncertainty_reason.strip() or path_overridden:
            return None
        return payload
    if uncertainty_reason is not None or not segments:
        return None

    total_tokens = 0
    aggregate_path_override = False
    previous_end = 0
    previous_group = -1
    previous_pipeline = -1
    for index, segment in enumerate(segments):
        if not isinstance(segment, dict):
            return None
        text = segment.get("text")
        tokens = segment.get("tokens")
        arguments = segment.get("arguments")
        environment_names = segment.get("environment_names")
        segment_wrappers = segment.get("wrapper_chain")
        executable = segment.get("executable")
        segment_path_overridden = segment.get("path_overridden")
        execution_context = segment.get("execution_context")
        raw_pipeline_index = segment.get("pipeline_index")
        span = segment.get("span")
        if (
            not isinstance(text, str)
            or not text
            or text.strip() != text
            or not isinstance(tokens, list)
            or not tokens
            or not all(isinstance(value, str) for value in tokens)
            or not isinstance(arguments, list)
            or not all(isinstance(value, str) for value in arguments)
            or not isinstance(environment_names, list)
            or not all(isinstance(value, str) for value in environment_names)
            or segment_wrappers != []
            or (executable is not None and not isinstance(executable, str))
            or not isinstance(segment_path_overridden, bool)
            or not isinstance(execution_context, str)
            or not execution_context.startswith("top:")
            or not execution_context.removeprefix("top:").isdigit()
            or not isinstance(raw_pipeline_index, int)
            or isinstance(raw_pipeline_index, bool)
            or raw_pipeline_index < 0
            or not isinstance(span, dict)
            or span.get("source") != "normalized"
        ):
            return None

        raw_start = span.get("start")
        raw_end = span.get("end")
        if (
            not isinstance(raw_start, int)
            or isinstance(raw_start, bool)
            or not isinstance(raw_end, int)
            or isinstance(raw_end, bool)
        ):
            return None
        pipeline_index = raw_pipeline_index
        start = raw_start
        end = raw_end
        group_index = int(execution_context.removeprefix("top:"))
        if (
            start < previous_end
            or start < 0
            or end <= start
            or end > len(normalized_text)
            or normalized_text[start:end] != text
        ):
            return None
        if index == 0:
            if group_index != 0 or pipeline_index != 0:
                return None
        elif group_index == previous_group:
            if pipeline_index != previous_pipeline + 1:
                return None
        elif group_index == previous_group + 1:
            if pipeline_index != 0:
                return None
        else:
            return None

        executable_index = 0
        expected_environment_names: list[str] = []
        while executable_index < len(tokens):
            name = _assignment_name(tokens[executable_index])
            if name is None:
                break
            expected_environment_names.append(name)
            executable_index += 1
        expected_executable = tokens[executable_index] if executable_index < len(tokens) else None
        expected_arguments = tokens[executable_index + 1 :] if expected_executable is not None else []
        expected_path_override = "PATH" in expected_environment_names
        if (
            environment_names != expected_environment_names
            or executable != expected_executable
            or arguments != expected_arguments
            or segment_path_overridden != expected_path_override
        ):
            return None

        total_tokens += len(tokens)
        if total_tokens > _MAX_TOKENS:
            return None
        aggregate_path_override = aggregate_path_override or segment_path_overridden
        previous_end = end
        previous_group = group_index
        previous_pipeline = pipeline_index

    if path_overridden != aggregate_path_override:
        return None
    return payload


def _request_payload(
    command: str,
    *,
    dialect: str,
    transport: str,
    extraction_provenance: str,
) -> tuple[dict[str, str], bytes] | None:
    request = {
        "command": command,
        "dialect": dialect,
        "transport": transport,
        "extraction_provenance": extraction_provenance,
    }
    encoded = json.dumps(request, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if len(encoded) > _MAX_REQUEST_BYTES:
        return None
    return request, encoded


def review_command_model_native(
    command: str,
    *,
    guard_home: Path,
    dialect: str = "posix",
    transport: str = "shell_string",
    extraction_provenance: str = "guard-shell",
    timeout_seconds: float = 0.25,
) -> dict[str, Any] | None:
    """Return native command-model evidence in explicit shadow/force modes only."""
    status = native_runtime_status()
    if (
        status.mode not in {"shadow", "force"}
        or not status.available
        or not status.compatible
        or status.identity is None
        or status.capabilities is None
        or _REQUIRED_FEATURE not in status.capabilities.features
        or timeout_seconds <= 0
    ):
        return None
    prepared = _request_payload(
        command,
        dialect=dialect,
        transport=transport,
        extraction_provenance=extraction_provenance,
    )
    if prepared is None:
        return None
    request, _request_bytes = prepared
    timeout_seconds = min(timeout_seconds, 1.0)
    environment = _isolated_environment()
    decoder_arguments = {
        "command": command,
        "dialect": dialect,
        "transport": transport,
        "extraction_provenance": extraction_provenance,
    }

    if {_RESIDENT_FEATURE, _RESIDENT_PROTOCOL_FEATURE} <= set(status.capabilities.features):
        resident_envelope = json.dumps(
            {"operation": "command_model", "request": request},
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        resident_output = native_resident_client_request(
            executable=status.identity.path,
            guard_home=guard_home,
            environment=environment,
            payload=resident_envelope,
            timeout_seconds=timeout_seconds,
        )
        if resident_output is not None:
            try:
                resident_payload = json.loads(resident_output)
            except (UnicodeDecodeError, json.JSONDecodeError):
                resident_payload = None
            if _native_error(resident_payload) == "native_overloaded":
                native_record_overload(status.identity.sha256, guard_home)
                return None
            decoded = _decode_command_model(resident_payload, **decoder_arguments)
            if decoded is not None:
                native_record_resident_success(status.identity.sha256, guard_home)
                return decoded
        native_record_resident_failure(
            status.identity.sha256,
            guard_home,
            reason="native_command_resident_unavailable",
        )

    return None


def _canonical_command_from_native(
    command: str,
    payload: dict[str, Any],
) -> CanonicalCommand | None:
    """Convert only request-bound exact native evidence into the Python type."""
    validated = _decode_command_model(
        payload,
        command=command,
        dialect="posix",
        transport="shell_string",
        extraction_provenance="guard-shell",
    )
    if validated is None or validated.get("confidence") != "exact":
        return None

    normalized_text = validated.get("normalized_text")
    raw_segments = validated.get("segments")
    if not isinstance(normalized_text, str) or not isinstance(raw_segments, list):
        return None

    segments: list[CommandSegment] = []
    for raw_segment in raw_segments:
        if not isinstance(raw_segment, dict):
            return None
        text = raw_segment.get("text")
        tokens = raw_segment.get("tokens")
        executable = raw_segment.get("executable")
        arguments = raw_segment.get("arguments")
        environment_names = raw_segment.get("environment_names")
        path_overridden = raw_segment.get("path_overridden")
        execution_context = raw_segment.get("execution_context")
        raw_pipeline_index = raw_segment.get("pipeline_index")
        span = raw_segment.get("span")
        if (
            not isinstance(text, str)
            or not isinstance(tokens, list)
            or not all(isinstance(value, str) for value in tokens)
            or (executable is not None and not isinstance(executable, str))
            or not isinstance(arguments, list)
            or not all(isinstance(value, str) for value in arguments)
            or not isinstance(environment_names, list)
            or not all(isinstance(value, str) for value in environment_names)
            or not isinstance(path_overridden, bool)
            or not isinstance(execution_context, str)
            or not isinstance(raw_pipeline_index, int)
            or isinstance(raw_pipeline_index, bool)
            or raw_pipeline_index < 0
            or not isinstance(span, dict)
        ):
            return None
        raw_start = span.get("start")
        raw_end = span.get("end")
        if (
            not isinstance(raw_start, int)
            or isinstance(raw_start, bool)
            or not isinstance(raw_end, int)
            or isinstance(raw_end, bool)
        ):
            return None
        pipeline_index = raw_pipeline_index
        segments.append(
            CommandSegment(
                text=text,
                tokens=tuple(tokens),
                executable=executable,
                arguments=tuple(arguments),
                environment_names=tuple(environment_names),
                wrapper_chain=(),
                path_overridden=path_overridden,
                execution_context=execution_context,
                pipeline_index=pipeline_index,
                start=raw_start,
                end=raw_end,
            )
        )

    canonical = CanonicalCommand(
        raw_text=command.strip(),
        normalized_text=normalized_text,
        dialect="posix",
        transport="shell_string",
        extraction_provenance="guard-shell",
        wrapper_chain=(),
        segments=tuple(segments),
        redirects=(),
        embedded_commands=(),
        confidence="exact",
        uncertainty_reason=None,
    )
    if validated.get("path_overridden") is not canonical.path_overridden:
        return None
    return canonical


def native_command_shadow_proposal(
    command: str,
    *,
    guard_home: Path,
    cwd: Path | None,
    home_dir: Path | None,
    compatibility_action_class: str | None = None,
    compatibility_reason: str | None = None,
) -> CommandShadowProposal | None:
    """Build a privacy-safe shadow proposal from a Rust parse and Python rules."""
    payload = review_command_model_native(command, guard_home=guard_home)
    if payload is None:
        return None
    canonical = _canonical_command_from_native(command, payload)
    if canonical is None:
        return None
    evaluation = evaluate_command(
        command,
        canonical_command=canonical,
        compatibility_action_class=compatibility_action_class,
        compatibility_reason=compatibility_reason,
        cwd=cwd,
        home_dir=home_dir,
    )
    return CommandShadowProposal(
        decision=evaluation.decision_plane,
        cohorts=frozenset({CommandShadowCohort.BASELINE}),
        version=_NATIVE_SHADOW_PROPOSAL_VERSION,
    )


__all__ = [
    "native_command_shadow_proposal",
    "review_command_model_native",
]
