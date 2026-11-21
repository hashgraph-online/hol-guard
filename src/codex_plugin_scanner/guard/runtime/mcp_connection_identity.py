"""Configured connection identity, separate from provider/server identity."""

from __future__ import annotations

import json
from dataclasses import dataclass
from hashlib import sha256


@dataclass(frozen=True, slots=True)
class McpConnectionIdentity:
    host: str
    source_scope: str
    configuration_hash: str
    server_identity_hash: str
    identity_hash: str


def build_mcp_connection_identity(
    *,
    host: str,
    source_scope: str,
    config_path: str,
    server_name: str,
    server_identity_hash: str,
) -> McpConnectionIdentity:
    """Bind a configured connection without publishing a private config path.

    This identity establishes the host/configuration boundary, not a verified
    provider account. Account resolution must be bound separately before a
    provider action can receive a grant.
    """

    configuration_hash = sha256(config_path.encode("utf-8")).hexdigest()
    payload = {
        "version": 1,
        "host": host,
        "source_scope": source_scope,
        "configuration_hash": configuration_hash,
        "server_name": server_name,
        "server_identity_hash": server_identity_hash,
    }
    digest = sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    return McpConnectionIdentity(host, source_scope, configuration_hash, server_identity_hash, digest)
