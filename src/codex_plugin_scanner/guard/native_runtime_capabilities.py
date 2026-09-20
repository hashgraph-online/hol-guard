"""Decode executable capabilities without inferring unsupported policy authority."""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class NativeRuntimeCapabilities:
    protocol_version: int
    runtime_version: str
    rule_digest: str
    build_sha: str
    target: str
    features: tuple[str, ...]
    extension_catalog_digest: str | None = None


def decode_native_runtime_capabilities(payload: object) -> NativeRuntimeCapabilities | None:
    if not isinstance(payload, dict):
        return None
    protocol_version = payload.get("protocol_version")
    runtime_version = payload.get("runtime_version")
    rule_digest = payload.get("rule_digest")
    build_sha = payload.get("build_sha")
    target = payload.get("target")
    features = payload.get("features")
    catalog_digest = payload.get("extension_catalog_digest")
    if (
        not isinstance(protocol_version, int)
        or (
            catalog_digest is not None
            and (not isinstance(catalog_digest, str) or re.fullmatch(r"[0-9a-f]{64}", catalog_digest) is None)
        )
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
        extension_catalog_digest=catalog_digest,
    )
