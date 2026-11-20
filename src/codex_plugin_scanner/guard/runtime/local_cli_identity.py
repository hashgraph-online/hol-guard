"""Identify CLIs that are not already a built-in command extension."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from ..native_local_cli_identity import native_local_cli_recognition, native_unlisted_cli_identities
from .command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY, CommandSafetyExtensionRegistry
from .command_model import CanonicalCommand, CommandSegment
from .custom_extension_suggestion import NATIVE_UNAVAILABLE_MESSAGE

LocalCliKind = Literal["executable", "script"]

REGISTRY_PACKAGE_PATH_CLASS = "registry-package"
_CLI_ID_PATTERN = re.compile(r"^local-cli\.[a-z0-9]+(?:-[a-z0-9]+){0,8}$")


@dataclass(frozen=True, slots=True)
class UnlistedCliIdentity:
    """Stable identity for one unlisted CLI. Public payloads stay path-redacted."""

    cli_id: str
    name: str
    kind: LocalCliKind
    identity_hash: str
    example_label: str
    interpreter_name: str | None = None
    source_path: str | None = None
    # Stored observation class; derived from ``source_path`` when unset.
    path_class: str | None = None
    # Package runner (``npx``) that launched the CLI, if any.
    runner: str | None = None
    # Verified launch material the native runtime derived this identity from.
    # The grant decision re-derives the identity from it, so it is never part
    # of equality, hashing, or the public payload.
    identity_source: Mapping[str, object] | None = field(default=None, compare=False, repr=False)

    @property
    def is_registry_package(self) -> bool:
        """Runner fetches without a proven local bin never carry a persistent allow."""

        return self.runner is not None and self.path_class == REGISTRY_PACKAGE_PATH_CLASS

    def to_dict(self) -> dict[str, object]:
        return {
            "cli_id": self.cli_id,
            "name": self.name,
            "kind": self.kind,
            "identity_hash": self.identity_hash,
            "example_label": self.example_label,
            "interpreter_name": self.interpreter_name,
        }


def catalog_owned_executables(
    registry: CommandSafetyExtensionRegistry = BUILT_IN_COMMAND_EXTENSION_REGISTRY,
) -> frozenset[str]:
    """Return lowercase executable names already owned by built-in extensions."""

    return registry.owned_executables


def identify_unlisted_cli(command_text: str, *, cwd: Path, home_dir: Path | None) -> UnlistedCliIdentity | None:
    """Return an unlisted CLI identity when the command is a single safe invocation."""

    identities = _native_identities(command_text, cwd=cwd, home_dir=home_dir, compound=False)
    return identities[0] if identities else None


def identify_unlisted_cli_identities(
    command_text: str, *, cwd: Path, home_dir: Path | None
) -> tuple[UnlistedCliIdentity, ...]:
    """Return unlisted CLI identities from a single invocation or compound shell."""

    return _native_identities(command_text, cwd=cwd, home_dir=home_dir, compound=True)


def _native_identities(
    command_text: str, *, cwd: Path, home_dir: Path | None, compound: bool
) -> tuple[UnlistedCliIdentity, ...]:
    records = native_unlisted_cli_identities(command_text, cwd=cwd, home_dir=home_dir, compound=compound)
    return tuple(_identity(record) for record in records)


def _identity(record: dict[str, Any]) -> UnlistedCliIdentity:
    return UnlistedCliIdentity(
        cli_id=record["cli_id"],
        name=record["name"],
        kind=record["kind"],
        identity_hash=record["identity_hash"],
        example_label=record["example_label"],
        interpreter_name=record["interpreter_name"],
        source_path=record["source_path"],
        path_class=record["path_class"],
        runner=record["runner"],
        identity_source=record["identity_source"],
    )


def unlisted_cli_invocation_is_safe(command: CanonicalCommand) -> bool:
    """Return whether the command is a single top-level invocation without wrappers."""

    if command.confidence != "exact":
        return False
    if command.redirects or command.embedded_commands or command.path_overridden:
        return False
    if command.wrapper_chain:
        return False
    if len(command.segments) != 1:
        return False
    segment = command.segments[0]
    return _safe_primary_segment(segment)


def is_local_cli_id(value: str) -> bool:
    return _CLI_ID_PATTERN.fullmatch(value) is not None


def recognize_operator_cli(
    command_text: str, *, cwd: Path, home_dir: Path
) -> tuple[UnlistedCliIdentity | None, str, str]:
    """Identify a pasted command or file path. Returns (identity, error_code, message).

    The native runtime owns recognition. When it cannot answer, the operator
    is told so instead of being shown a guessed refusal.
    """

    answer = native_local_cli_recognition(command_text, cwd=cwd, home_dir=home_dir)
    if answer is None:
        return None, "native_unavailable", NATIVE_UNAVAILABLE_MESSAGE
    identity = answer["identity"]
    return (None if identity is None else _identity(identity)), answer["error_code"], answer["message"]


def _safe_primary_segment(segment: CommandSegment) -> bool:
    return (
        segment.execution_context == "top:0"
        and segment.pipeline_index == 0
        and not segment.environment_names
        and not segment.wrapper_chain
        and not segment.path_overridden
        and segment.executable is not None
    )


def local_cli_recognition_candidates(
    command_text: str, *, cwd: Path, home_dir: Path, guard_home: Path | None = None
) -> tuple[str, ...]:
    """Return pasted-command variants Guard can bind to a single file, or none while the runtime cannot answer."""

    answer = native_local_cli_recognition(
        command_text, cwd=cwd, home_dir=home_dir, answer="candidates", guard_home=guard_home
    )
    return () if answer is None else tuple(answer["candidates"])
