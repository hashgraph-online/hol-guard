"""Immutable discovery values and checked replay of normalized snapshots."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Literal, cast

from .errors import BuilderError
from .io import digest, list_value, object_value
from .schemas import ADAPTERS, DISCOVERY_SCHEMA, MAX_MCP_TOOLS, MAX_OPERATIONS, validate_document
from .validation import (
    COMMAND_TOKEN_PATTERN,
    LAUNCHERS,
    OPTION_PATTERN,
    TOOL_PATTERN,
    https_reference,
    normalized_tool_name,
    package_identity,
    slug,
    text,
    token,
)

Kind = Literal["cli", "mcp"]


@dataclass(frozen=True, slots=True)
class Metadata:
    kind: Kind
    slug: str
    name: str
    publisher_id: str
    publisher_name: str
    homepage: str
    upstream_version: str = "unspecified"
    executable: str = ""
    launcher: str = ""
    package: str = ""

    @property
    def contribution_id(self) -> str:
        return f"{'command' if self.kind == 'cli' else 'mcp'}.{self.slug}"

    @property
    def catalog_id(self) -> str:
        return f"command.{'mcp-' if self.kind == 'mcp' else ''}{self.slug}"

    @property
    def module_leaf(self) -> str:
        return f"command_{self.slug.replace('-', '_')}_extensions"

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "slug": self.slug,
            "name": self.name,
            "publisher": {"id": self.publisher_id, "displayName": self.publisher_name},
            "homepage": self.homepage,
            "upstreamVersion": self.upstream_version,
            "executable": self.executable,
            "launcher": self.launcher,
            "package": self.package,
        }


def validate_metadata(metadata: Metadata) -> Metadata:
    slug(metadata.slug)
    text(metadata.name)
    text(metadata.publisher_name)
    token(metadata.publisher_id, pattern=r"[A-Za-z0-9][A-Za-z0-9._-]*", maximum=128)
    https_reference(metadata.homepage)
    text(metadata.upstream_version, maximum=64)
    if metadata.kind == "cli":
        token(metadata.executable)
        if metadata.slug.startswith("mcp-") or metadata.launcher or metadata.package:
            raise BuilderError(
                "invalid_metadata", "CLI metadata cannot use the reserved MCP namespace or launcher fields."
            )
    elif metadata.kind == "mcp":
        if metadata.executable or metadata.launcher not in LAUNCHERS:
            raise BuilderError("invalid_metadata", "MCP metadata requires an allowed launcher and no executable field.")
        package_identity(metadata.package, metadata.launcher)
    else:
        raise BuilderError("invalid_metadata", "Unsupported extension kind.")
    return metadata


def _metadata_from_dict(value: object) -> Metadata:
    row = object_value(value)
    publisher = object_value(row["publisher"])
    return validate_metadata(
        Metadata(
            kind=cast(Kind, row["kind"]),
            slug=cast(str, row["slug"]),
            name=cast(str, row["name"]),
            publisher_id=cast(str, publisher["id"]),
            publisher_name=cast(str, publisher["displayName"]),
            homepage=cast(str, row["homepage"]),
            upstream_version=cast(str, row["upstreamVersion"]),
            executable=cast(str, row["executable"]),
            launcher=cast(str, row["launcher"]),
            package=cast(str, row["package"]),
        )
    )


@dataclass(frozen=True, slots=True)
class Operation:
    operation_id: str
    path: tuple[str, ...]
    name: str
    flags: tuple[str, ...]
    options_with_values: tuple[str, ...]
    evidence_sha256: str
    hints: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.operation_id,
            "path": list(self.path),
            "name": self.name,
            "flags": list(self.flags),
            "optionsWithValues": list(self.options_with_values),
            "evidenceSha256": self.evidence_sha256,
            "hints": list(self.hints),
        }


def operation_id(kind: Kind, path: tuple[str, ...], name: str) -> str:
    identity = {"kind": kind, "path": list(path), "name": name}
    return f"{'op' if kind == 'cli' else 'tool'}-{digest(identity)[:16]}"


def make_operation(
    kind: Kind,
    *,
    path: tuple[str, ...] = (),
    name: str = "",
    flags: tuple[str, ...] = (),
    options_with_values: tuple[str, ...] = (),
    evidence: object,
    hints: tuple[str, ...] = (),
) -> Operation:
    if len(path) > 8 or len(flags) + len(options_with_values) > 128:
        raise BuilderError("operation_limit", "Operation grammar exceeds the documented size limit.")
    for part in path:
        token(part, pattern=COMMAND_TOKEN_PATTERN)
    for option in (*flags, *options_with_values):
        token(option, pattern=OPTION_PATTERN)
    if set(flags) & set(options_with_values):
        raise BuilderError("option_arity", "An option has conflicting flag and value-taking arity.")
    if kind == "mcp":
        token(name, pattern=TOOL_PATTERN, maximum=128)
        if normalized_tool_name(name) == "other" or path or flags or options_with_values:
            raise BuilderError("mcp_identity", "MCP tools cannot use the reserved fallback or CLI grammar fields.")
    elif name:
        raise BuilderError("cli_identity", "CLI operations must use structured paths rather than MCP tool names.")
    return Operation(
        operation_id(kind, path, name),
        path,
        name,
        tuple(sorted(set(flags))),
        tuple(sorted(set(options_with_values))),
        digest(evidence),
        tuple(sorted(set(hints))),
    )


@dataclass(frozen=True, slots=True)
class Discovery:
    metadata: Metadata
    adapter: str
    source_sha256: str
    operations: tuple[Operation, ...]
    limitations: tuple[str, ...]
    binding: str = ""

    def to_dict(self, *, include_digest: bool = True) -> dict[str, object]:
        result: dict[str, object] = {
            "schemaVersion": DISCOVERY_SCHEMA,
            "metadata": self.metadata.to_dict(),
            "adapter": self.adapter,
            "sourceSha256": self.source_sha256,
            "operations": [row.to_dict() for row in self.operations],
            "limitations": list(self.limitations),
        }
        if include_digest:
            result["digest"] = self.binding
        return result


def make_discovery(
    metadata: Metadata,
    adapter: str,
    source_sha256: str,
    operations: tuple[Operation, ...],
    limitations: tuple[str, ...],
) -> Discovery:
    validate_metadata(metadata)
    maximum = MAX_MCP_TOOLS if metadata.kind == "mcp" else MAX_OPERATIONS
    if not 1 <= len(operations) <= maximum:
        raise BuilderError("operation_limit", "Inventory is empty or exceeds the contribution operation limit.")
    if adapter not in ADAPTERS or (metadata.kind == "mcp") != (adapter == "mcp"):
        raise BuilderError("adapter_kind", "Source adapter does not match the extension kind.")
    identities = [
        tuple(part.lower() for part in row.path) if metadata.kind == "cli" else normalized_tool_name(row.name)
        for row in operations
    ]
    if len(set(identities)) != len(identities) or len({row.operation_id for row in operations}) != len(operations):
        raise BuilderError("duplicate_operation", "Inventory contains duplicate or runtime-colliding operations.")
    discovery = Discovery(
        metadata,
        adapter,
        source_sha256,
        tuple(sorted(operations, key=lambda row: (row.path, row.name))),
        tuple(sorted(set(limitations))),
    )
    discovery = replace(discovery, binding=digest(discovery.to_dict(include_digest=False)))
    validate_document(discovery.to_dict(), "discovery")
    return discovery


def load_discovery(value: object) -> Discovery:
    payload = validate_document(value, "discovery")
    metadata = _metadata_from_dict(payload["metadata"])
    operations: list[Operation] = []
    for value_row in list_value(payload["operations"]):
        row = object_value(value_row)
        checked = make_operation(
            metadata.kind,
            path=tuple(cast(list[str], row["path"])),
            name=cast(str, row["name"]),
            flags=tuple(cast(list[str], row["flags"])),
            options_with_values=tuple(cast(list[str], row["optionsWithValues"])),
            evidence=None,
        )
        if checked.operation_id != row["id"]:
            raise BuilderError("operation_identity", "Snapshot operation identity does not match its invocation.")
        operations.append(
            replace(
                checked,
                evidence_sha256=cast(str, row["evidenceSha256"]),
                hints=tuple(cast(list[str], row["hints"])),
            )
        )
    discovery = make_discovery(
        metadata,
        cast(str, payload["adapter"]),
        cast(str, payload["sourceSha256"]),
        tuple(operations),
        tuple(cast(list[str], payload["limitations"])),
    )
    if discovery.binding != payload["digest"]:
        raise BuilderError("discovery_digest", "Snapshot content does not match its binding digest.")
    return discovery
