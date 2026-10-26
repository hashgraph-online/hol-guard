"""Canonical, side-effect-free command model shared by Guard extensions."""

from __future__ import annotations

from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any, Literal

from ..native_rich_command_model import request, string_tuple
from .command_structure import CommandRedirect, EmbeddedCommand, build_command_security_identity

CommandDialect = Literal["posix", "powershell", "cmd", "argv", "unknown"]
CommandTransport = Literal["shell_string", "argv", "embedded_script"]
ParseConfidence = Literal["exact", "fallback", "uncertain"]

MAX_COMMAND_BYTES = 32_768
MAX_COMMAND_SEGMENTS = 128
MAX_COMMAND_TOKENS = 2_048


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
        value: dict[str, object] = {
            item.name: list(value) if isinstance(value := getattr(self, item.name), tuple) else value
            for item in fields(self)
            if item.name not in {"start", "end"}
        }
        value["span"] = {"source": "normalized", "start": self.start, "end": self.end}
        return value


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
    _bound_identity: tuple[object, str] | None = field(default=None, repr=False, compare=False)

    @property
    def path_overridden(self) -> bool:
        return any(segment.path_overridden for segment in self.segments)

    @property
    def security_identity(self) -> str:
        """Return a versioned identity over the complete executable structure."""

        material = self._identity_material()
        if self._bound_identity is not None and self._bound_identity[0] == material:
            return self._bound_identity[1]
        identity = build_command_security_identity(
            normalized_text=self.normalized_text,
            dialect=self.dialect,
            transport=self.transport,
            wrapper_chain=self.wrapper_chain,
            segments=self.segments,
            redirects=self.redirects,
            embedded_commands=self.embedded_commands,
        )
        object.__setattr__(self, "_bound_identity", (material, identity))
        return identity

    def _identity_material(self) -> object:
        return tuple(getattr(self, item.name) for item in fields(self) if item.compare)

    def to_dict(self) -> dict[str, object]:
        return {
            **{
                item.name: list(value) if isinstance(value := getattr(self, item.name), tuple) else value
                for item in fields(self)
                if item.compare and item.name not in {"raw_text", "segments", "redirects", "embedded_commands"}
            },
            "segments": [segment.to_dict() for segment in self.segments],
            "redirects": [redirect.to_dict() for redirect in self.redirects],
            "embedded_commands": [embedded.to_dict() for embedded in self.embedded_commands],
            "security_identity": self.security_identity,
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
    normalize_wrappers: bool = True,
) -> CanonicalCommand:
    """Parse through the resident; native unavailability has no semantic fallback."""
    value = request(
        "parse",
        {
            "command": command,
            "cwd": str(cwd) if cwd is not None else None,
            "home_dir": str(home_dir) if home_dir is not None else None,
            "dialect": dialect,
            "transport": transport,
            "extraction_provenance": extraction_provenance,
            "normalize_wrappers": normalize_wrappers,
        },
    )
    return _canonical_from_wire(value)


def _canonical_from_wire(value: dict[str, Any]) -> CanonicalCommand:
    """Present a validated native model without deriving command semantics."""
    identity = value["security_identity"]
    value = {item.name: value[item.name] for item in fields(CanonicalCommand) if item.compare and item.name in value}
    segments = []
    for raw_segment in value["segments"]:
        segment = {
            item.name: raw_segment[item.name] for item in fields(CommandSegment) if item.name not in {"start", "end"}
        }
        span = raw_segment["span"]
        segment.update(start=span["start"], end=span["end"])
        for name in ("tokens", "arguments", "environment_names", "wrapper_chain"):
            segment[name] = string_tuple(segment[name])
        segments.append(CommandSegment(**segment))
    redirects = tuple(
        CommandRedirect(r["operator"], r["target"], r["span"]["start"], r["span"]["end"]) for r in value["redirects"]
    )
    embedded = tuple(
        EmbeddedCommand(e["kind"], e["text"], e["execution_context"], e["span"]["start"], e["span"]["end"])
        for e in value["embedded_commands"]
    )
    value.update(segments=tuple(segments), redirects=redirects, embedded_commands=embedded)
    value["wrapper_chain"] = string_tuple(value["wrapper_chain"])
    model = CanonicalCommand(**value)
    object.__setattr__(model, "_bound_identity", (model._identity_material(), identity))
    return model
