"""Value models and bounded decoders for the native runtime bridge.

Native artifact selection, processes, caches, and policy authority remain
in the runtime bridge.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, cast

from .runtime.hook_review_types import HookReviewResponse

NativeMode = Literal["off", "shadow", "auto", "force"]

_INTEGRITY_FAILURE_REASONS = frozenset(
    {
        "native_manifest_invalid",
        "native_manifest_missing",
        "native_manifest_runtime_mismatch",
        "native_manifest_version_mismatch",
        "native_manifest_protocol_mismatch",
        "native_manifest_rule_mismatch",
        "native_manifest_build_mismatch",
    }
)

# Public API names re-exported by the native_runtime bridge, which owns runtime I/O.
_NATIVE_RUNTIME_EXPORTS = [
    "NativeRuntimeCapabilities",
    "NativeRuntimeHealthSnapshot",
    "NativeRuntimeIdentity",
    "NativeRuntimeManifest",
    "NativeRuntimeStatus",
    "native_mode",
    "native_output_sha256",
    "native_runtime_health",
    "native_runtime_status",
    "parity_signature",
    "review_post_tool_native",
]


def _resolve_native_mode(raw_value: str | None, default: NativeMode) -> NativeMode:
    if raw_value is None:
        return default
    value = raw_value.strip().lower()
    if value not in {"off", "shadow", "auto", "force"}:
        return default
    return cast(NativeMode, value)


@dataclass(frozen=True, slots=True)
class NativeRuntimeIdentity:
    path: Path
    size: int
    mtime_ns: int
    sha256: str


@dataclass(frozen=True, slots=True)
class NativeRuntimeCapabilities:
    protocol_version: int
    runtime_version: str
    rule_digest: str
    build_sha: str
    target: str
    features: tuple[str, ...]
    program_digest: str = ""
    catalog_digest: str = ""
    trust_digest: str = ""


@dataclass(frozen=True, slots=True)
class NativeRuntimeManifest:
    schema: str
    protocol_version: int
    package_version: str
    target: str
    platform_tag: str
    source_sha: str
    rule_digest: str
    runtime_sha256: str
    runtime_size: int


@dataclass(frozen=True, slots=True)
class NativeRuntimeStatus:
    mode: NativeMode
    available: bool
    compatible: bool
    reason: str
    identity: NativeRuntimeIdentity | None = None
    capabilities: NativeRuntimeCapabilities | None = None
    # The manifest is already validated against the bundled artifact and
    # runtime capabilities.  Exposing that same object lets bounded reports
    # carry provenance without creating a second trust path.
    manifest: NativeRuntimeManifest | None = None


def _identity_key(status: NativeRuntimeStatus) -> str:
    return status.identity.sha256 if status.identity is not None else "0" * 64


def _is_lower_hex(value: str, length: int) -> bool:
    return len(value) == length and all(character in "0123456789abcdef" for character in value)


def decode_runtime_manifest(
    payload: object,
    *,
    schema: str,
    protocol_version: int,
    hex_validator: Callable[[str, int], bool],
) -> NativeRuntimeManifest | None:
    if not isinstance(payload, dict):
        return None
    manifest_schema = payload.get("schema")
    manifest_protocol_version = payload.get("protocol_version")
    package_version = payload.get("package_version")
    target = payload.get("target")
    platform_tag = payload.get("platform_tag")
    source_sha = payload.get("source_sha")
    rule_digest = payload.get("rule_digest")
    runtime_sha256 = payload.get("runtime_sha256")
    runtime_size = payload.get("runtime_size")
    if (
        not isinstance(manifest_schema, str)
        or not isinstance(manifest_protocol_version, int)
        or manifest_schema != schema
        or manifest_protocol_version != protocol_version
        or not isinstance(package_version, str)
        or not package_version.strip()
        or not isinstance(target, str)
        or not target.strip()
        or not isinstance(platform_tag, str)
        or not platform_tag.strip()
        or not isinstance(source_sha, str)
        or not hex_validator(source_sha, 40)
        or not isinstance(rule_digest, str)
        or not hex_validator(rule_digest, 64)
        or not isinstance(runtime_sha256, str)
        or not hex_validator(runtime_sha256, 64)
        or not isinstance(runtime_size, int)
        or isinstance(runtime_size, bool)
        or runtime_size <= 0
    ):
        return None
    return NativeRuntimeManifest(
        schema=manifest_schema,
        protocol_version=manifest_protocol_version,
        package_version=package_version,
        target=target,
        platform_tag=platform_tag,
        source_sha=source_sha,
        rule_digest=rule_digest,
        runtime_sha256=runtime_sha256,
        runtime_size=runtime_size,
    )


def _advertised_digest(value: object) -> str:
    if isinstance(value, str) and _is_lower_hex(value, 64):
        return value
    return ""


def _decode_capabilities(payload: object) -> NativeRuntimeCapabilities | None:
    if not isinstance(payload, dict):
        return None
    protocol_version = payload.get("protocol_version")
    runtime_version = payload.get("runtime_version")
    rule_digest = payload.get("rule_digest")
    build_sha = payload.get("build_sha")
    target = payload.get("target")
    features = payload.get("features")
    if (
        not isinstance(protocol_version, int)
        or not isinstance(runtime_version, str)
        or not isinstance(rule_digest, str)
        or not isinstance(build_sha, str)
        or not isinstance(target, str)
        or not isinstance(features, list)
        or not all(isinstance(feature, str) for feature in features)
    ):
        return None
    return NativeRuntimeCapabilities(
        protocol_version=protocol_version,
        runtime_version=runtime_version,
        rule_digest=rule_digest,
        build_sha=build_sha,
        target=target,
        features=tuple(features),
        program_digest=_advertised_digest(payload.get("program_digest")),
        catalog_digest=_advertised_digest(payload.get("catalog_digest")),
        trust_digest=_advertised_digest(payload.get("trust_digest")),
    )


def _python_package_version() -> str | None:
    try:
        return importlib.metadata.version("hol-guard")
    except importlib.metadata.PackageNotFoundError:
        return None


def parity_signature(response: HookReviewResponse) -> tuple[object, ...]:
    excerpt_hash = native_output_sha256(response.reviewed_excerpt) if response.reviewed_excerpt is not None else None
    return (
        response.decision,
        response.model_output_action,
        response.reason_code,
        response.notice,
        response.policy_action,
        response.observed_policy_action,
        response.reviewed_output_sha256,
        excerpt_hash,
    )


def native_output_sha256(text: str) -> str:
    """Hash bounded native-hook output for recording and parity evidence."""

    return hashlib.sha256(text.encode("utf-8")).hexdigest()
