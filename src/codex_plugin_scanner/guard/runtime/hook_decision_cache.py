"""Exact source-read decision cache wrapper around existing scanner_cache.

This module provides typed access to the existing ``scanner_cache`` SQLite
table for source-read fast-path decisions. The cache key includes:

- content hash, stat metadata, scanner version
- config/policy fingerprint, source classifier version
- harness, event, realpath, workspace

Cache payloads never contain raw file content — only decision metadata
and digests. A stale cache entry (changed content, policy, config, or
scanner version) simply results in a cache miss.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..config import GuardConfig
    from ..store import GuardStore

SOURCE_CACHE_SCANNER_NAME = "hook-source-read"
SOURCE_CACHE_VERSION = "source-read-fast-v1"


@dataclass(frozen=True, slots=True)
class SourceReadCacheMaterial:
    """All fields that must match for a source-read cache hit.

    Changing any of these invalidates the cache. This includes content
    hash, file stat identity, scanner/policy/config versions, and
    workspace/harness/event identity.
    """

    kind: str
    harness: str
    event_name: str
    workspace_hash: str | None
    realpath: str
    stat_dev: int | None
    stat_ino: int | None
    stat_size: int
    stat_mtime_ns: int
    content_sha256: str
    output_sha256: str
    scanner_version: str
    source_classifier_version: str
    policy_fingerprint: str
    config_fingerprint: str


def hook_config_fingerprint(config: GuardConfig) -> str:
    """Return a stable hash of the config fields that affect allow/block.

    Includes mode, security level, default action, risk actions, harness
    risk actions, and approval surface policy. Never includes raw paths
    or user-specific data beyond what changes allow/block behavior.
    """
    material = {
        "mode": config.mode,
        "security_level": config.security_level,
        "default_action": config.default_action,
        "unknown_publisher_action": config.unknown_publisher_action,
        "changed_hash_action": config.changed_hash_action,
        "new_network_domain_action": config.new_network_domain_action,
        "subprocess_action": config.subprocess_action,
        "risk_actions": dict(sorted((config.risk_actions or {}).items())),
        "harness_risk_actions": {
            harness: dict(sorted(actions.items()))
            for harness, actions in sorted((config.harness_risk_actions or {}).items())
        },
        "approval_surface_policy": config.approval_surface_policy,
    }
    return hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


class HookDecisionCache:
    """Typed wrapper around ``scanner_cache`` for hook source-read decisions."""

    def __init__(self, store: GuardStore):
        self.store = store

    def source_target_id(self, material: SourceReadCacheMaterial) -> str:
        """Return a stable target ID for a source-read cache entry."""
        workspace = material.workspace_hash or ""
        raw = f"{material.harness}\0{workspace}\0{material.realpath}"
        return "source-read:" + hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def source_input_hash(self, material: SourceReadCacheMaterial) -> str:
        """Return a stable input content hash for a source-read cache entry.

        This hash covers every field in the material — content hash, stat
        identity, scanner/policy/config versions, etc. Any change in any
        field produces a different hash, ensuring cache invalidation.
        """
        return hashlib.sha256(
            json.dumps(asdict(material), sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()

    def get_source_read(self, material: SourceReadCacheMaterial) -> dict[str, object] | None:
        """Return cached source-read decision payload, or None on miss.

        Returns None if no cache entry exists for the exact material. The
        payload never contains raw file content.
        """
        return self.store.get_scanner_cache(
            scanner_name=SOURCE_CACHE_SCANNER_NAME,
            target_id=self.source_target_id(material),
            input_content_hash=self.source_input_hash(material),
            scanner_version=SOURCE_CACHE_VERSION,
        )

    def save_source_read(
        self,
        material: SourceReadCacheMaterial,
        payload: dict[str, object],
        *,
        now: str,
    ) -> None:
        """Save a source-read decision to cache.

        The payload must not contain raw file content. It should contain
        only decision metadata: decision, reason_code, digests, scanner
        version, and timestamps.
        """
        self.store.save_scanner_cache(
            scanner_name=SOURCE_CACHE_SCANNER_NAME,
            target_id=self.source_target_id(material),
            input_content_hash=self.source_input_hash(material),
            scanner_version=SOURCE_CACHE_VERSION,
            payload=payload,
            now=now,
        )


__all__ = [
    "HookDecisionCache",
    "SOURCE_CACHE_SCANNER_NAME",
    "SOURCE_CACHE_VERSION",
    "SourceReadCacheMaterial",
    "hook_config_fingerprint",
]
