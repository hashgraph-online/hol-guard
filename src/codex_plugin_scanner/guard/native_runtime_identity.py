"""Privacy-safe identity projection for native Guard requests."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping

_POLICY_SCHEMA_VERSION = 1


def _digest(label: str, *parts: str) -> str:
    digest = hashlib.sha256()
    digest.update(label.encode("ascii"))
    for part in parts:
        digest.update(b"\x00")
        digest.update(part.encode("utf-8", errors="strict"))
    return digest.hexdigest()


def _payload_size_bytes(payload: Mapping[str, object]) -> int:
    encoded = json.dumps(
        payload,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return len(encoded)


def native_request_identity(
    *,
    binary_sha256: str,
    runtime_version: str,
    build_sha: str,
    rule_digest: str,
    payload: Mapping[str, object],
    source_ref_external_allowed: bool,
    payload_kind: str,
    source_scope: str,
) -> dict[str, object]:
    """Return versioned identities without raw hook material or local paths."""

    strict_config_digest = _digest(
        "hol-guard-native-strict-config-v1",
        "protocol:1",
        "operation:post_tool_review",
        "python_control_plane_authoritative:true",
    )
    never_allow_digest = _digest(
        "hol-guard-native-never-allow-v1",
        "native_subset:no_dynamic_allow_overrides",
    )
    source_policy_digest = _digest(
        "hol-guard-native-source-policy-v1",
        f"external:{str(source_ref_external_allowed).lower()}",
        f"payload_kind:{payload_kind}",
        f"source_scope:{source_scope}",
    )
    generation_material = _digest(
        "hol-guard-native-policy-generation-v1",
        rule_digest,
        strict_config_digest,
        never_allow_digest,
        source_policy_digest,
    )
    generation = int.from_bytes(bytes.fromhex(generation_material[:16]), "big") or 1
    return {
        "operation": "post_tool_review",
        "payload_size_bytes": _payload_size_bytes(payload),
        "runtime_identity": {
            "binary_sha256": binary_sha256,
            "runtime_version": runtime_version,
            "build_sha": build_sha,
            "rule_digest": rule_digest,
        },
        "policy_snapshot": {
            "schema_version": _POLICY_SCHEMA_VERSION,
            "generation": generation,
            "rule_set_digest": rule_digest,
            "strict_config_digest": strict_config_digest,
            "never_allow_digest": never_allow_digest,
            "source_policy_digest": source_policy_digest,
        },
    }


__all__ = ["native_request_identity"]
