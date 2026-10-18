"""Validated scalar header shared by activation and publisher transactions."""

from __future__ import annotations

from typing import Any, TypedDict


class ActivationHeader(TypedDict):
    authority_schema_version: int
    purpose: str
    schema: str
    revision: int
    previous_digest: str | None
    program_digest: str
    catalog_digest: str
    trust_digest: str
    engine: str
    source_sha: str
    publication_id: str
    root_digest: str
    authority_epoch: int
    revocation_epoch: int
    issued_at: int
    expires_at: int
    selection: dict[str, Any]
    selected_count: int
    registry: dict[str, Any]
    registry_count: int
    executables: dict[str, Any] | None
    executable_count: int
    distribution: dict[str, Any]
