"""Record the retired inventory item-metadata classification parity cases.

The Rust port in `rust/crates/guard-command/src/inventory_item_metadata.rs`
owns this grammar outright now; `inventory_item_metadata_reference` beside this
script keeps the CPython it replaced, and nothing under `src/` computes any of
it. The port reproduces: item kind, content-hash
canonicalization, the strict skill-directory reuse check, capability and risk
classification, and the bounded inspection roots. This script records what the
Python actually returns for each case so the port is pinned to behaviour rather
than to a reading of the source.

Run it from the repository root on the interpreter the project targets:

    uv run --python 3.12 --no-project python \
        scripts/ci/generate_inventory_item_metadata_parity.py

The cases below deliberately include values that are neither `true` nor `false`
(`"no"`, `0`, `[]`, `[0]`), because the Python tests capability and risk
evidence with `bool(...)` and a port that reads a JSON boolean would drop an
item's risk level to `info`.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import inventory_item_metadata_reference as reference  # noqa: E402

from codex_plugin_scanner.guard.skill_directory_identity_contract import (  # noqa: E402
    validated_complete_skill_directory_hash,
)

SCHEMA = "guard.skill-directory-identity.v1"
DIGEST = "a" * 64
OTHER_DIGEST = "b" * 64

ARTIFACT_TYPES = [
    "skill",
    "skill_file",
    "mcp_server",
    "mcp_tool",
    "channel",
    "gateway_config",
    "config",
    "agent",
    "hook",
    "instruction",
    "overlay",
    "command",
    "extension",
    "plugin",
    "plugin-file",
    "repository",
    "container_image",
    "policy",
    "secret_reference",
    "network_endpoint",
    "guard_launcher_shim",
    "package",
    "daemon_plugin",
    "model_provider",
    "prompt_pack",
    "mcp-server",
    "Skill",
    "",
    "unknown_future_category",
]

CANONICAL_HASHES = [
    DIGEST,
    DIGEST.upper(),
    f"sha256:{DIGEST}",
    f"SHA256:{DIGEST.upper()}",
    "a" * 63,
    "a" * 65,
    "g" * 64,
    "",
    "  " + DIGEST,
]


def _identity(**overrides: object) -> dict[str, object]:
    identity: dict[str, object] = {
        "schemaVersion": SCHEMA,
        "status": "complete",
        "reusable": True,
        "contentHash": f"sha256:{DIGEST}",
        "entryCount": 3,
        "totalBytes": 0,
    }
    identity.update(overrides)
    return identity


def _complete(**identity_overrides: object) -> dict[str, object]:
    return {
        "skillDirectoryIdentity": _identity(**identity_overrides),
        "directory_hash": f"sha256:{DIGEST}",
        "versionInfo": {"hashBasis": "skill-directory-v1", "contentHash": f"sha256:{DIGEST}"},
    }


def _without(metadata: dict[str, object], key: str) -> dict[str, object]:
    trimmed = dict(metadata)
    trimmed.pop(key, None)
    return trimmed


IDENTITY_CASES: list[dict[str, object]] = [
    _complete(),
    _complete(contentHash=DIGEST),
    _complete(contentHash=f"SHA256:{DIGEST.upper()}"),
    _complete(status="incomplete"),
    _complete(reusable=False),
    _complete(reusable=1),
    _complete(schemaVersion="guard.skill-directory-identity.v2"),
    _complete(reason="max_entries_exceeded"),
    _complete(reuseNonce="nonce"),
    _complete(incompleteStateHash=f"sha256:{OTHER_DIGEST}"),
    _complete(entryCount=0),
    _complete(entryCount=True),
    _complete(entryCount="3"),
    # CPython's `int` has no width, so these stay valid counts there.
    _complete(entryCount=2**70),
    _complete(totalBytes=2**70),
    _complete(entryCount=1.0),
    _complete(totalBytes=-1),
    _complete(totalBytes=False),
    _complete(contentHash=f"sha256:{OTHER_DIGEST}"),
    {**_complete(), "directory_hash": f"sha256:{OTHER_DIGEST}"},
    {**_complete(), "versionInfo": {"hashBasis": "file-v1", "contentHash": f"sha256:{DIGEST}"}},
    {**_complete(), "versionInfo": {"hashBasis": "skill-directory-v1", "contentHash": f"sha256:{OTHER_DIGEST}"}},
    {**_complete(), "versionInfo": "skill-directory-v1"},
    _without(_complete(), "versionInfo"),
    _without(_complete(), "directory_hash"),
    {"directory_hash": f"sha256:{DIGEST}"},
    {},
    {"skillDirectoryIdentity": "complete", "directory_hash": f"sha256:{DIGEST}"},
]

RESOLVE_CASES: list[tuple[dict[str, object], str]] = [
    ({"content_hash": DIGEST}, "semantic"),
    ({"content_hash": DIGEST.upper()}, "semantic"),
    ({"content_hash": ""}, "semantic"),
    ({"content_hash": None, "directory_hash": DIGEST}, "semantic"),
    ({"content_hash": 7, "directory_hash": f"sha256:{DIGEST}"}, "semantic"),
    ({"directory_hash": "not-a-digest"}, "semantic"),
    ({"versionInfo": {"contentHash": DIGEST}}, "semantic"),
    ({"versionInfo": {"contentHash": ""}}, "semantic"),
    ({"versionInfo": {"contentHash": 7}}, "semantic"),
    ({"versionInfo": [{"contentHash": DIGEST}]}, "semantic"),
    ({"content_hash": DIGEST, "directory_hash": OTHER_DIGEST}, "semantic"),
    ({}, "semantic:fallback"),
]

CAPABILITY_METADATA: list[dict[str, object]] = [
    {},
    {"transport": "stdio"},
    {"transport": "http"},
    {"envConfigurationPresent": True},
    {"envConfigurationPresent": False},
    {"envConfigurationPresent": "no"},
    {"envConfigurationPresent": ""},
    {"envConfigurationPresent": 0},
    {"envConfigurationPresent": 1},
    {"envConfigurationPresent": []},
    {"envConfigurationPresent": [0]},
    {"envConfigurationPresent": {}},
    {"envConfigurationPresent": {"a": 1}},
    {"envConfigurationPresent": None},
    {"has_auth_headers": True},
    {"has_auth_headers": "false"},
    {"has_auth_headers": 0.0},
    {"has_auth_headers": [0]},
    {"transport": "stdio", "has_auth_headers": True},
    {"endpointHostClass": "remote_public"},
    {"endpointHostClass": "loopback"},
    {"endpointHostClass": "remote_public", "has_auth_headers": True},
    {"endpointHostClass": "remote_public", "envConfigurationPresent": 0},
]

CAPABILITY_TYPES = [
    "instruction",
    "overlay",
    "command",
    "mcp_server",
    "channel",
    "skill",
    "skill_file",
    "plugin",
]

EVIDENCE_CASES: list[tuple[dict[str, object], object]] = [
    ({}, f"sha256:{DIGEST}"),
    ({}, None),
    ({"primaryContentHash": f"sha256:{OTHER_DIGEST}"}, None),
    ({"primaryContentHash": f"sha256:{OTHER_DIGEST}"}, f"sha256:{DIGEST}"),
    (
        {
            "contentEvidence": {"contentHash": f"sha256:{DIGEST}"},
            "documentedCapabilities": ["reads_files"],
        },
        f"sha256:{DIGEST}",
    ),
    (
        {
            "contentEvidence": {"contentHash": f"sha256:{OTHER_DIGEST}"},
            "documentedCapabilities": ["reads_files"],
        },
        f"sha256:{DIGEST}",
    ),
    (
        {"contentEvidence": {"byteLength": 12}, "documentedCapabilities": ["reads_files"]},
        f"sha256:{DIGEST}",
    ),
    ({"contentEvidence": {"byteLength": 12}, "documentedCapabilities": ["reads_files"]}, None),
    (
        {
            "contentEvidence": {"contentHash": f"sha256:{DIGEST}"},
            "documentedCapabilities": ["reads_files"],
        },
        None,
    ),
    (
        {"contentEvidence": "sha256", "documentedCapabilities": ["reads_files"]},
        f"sha256:{DIGEST}",
    ),
    ({"documentedCapabilities": ["reads_files"]}, f"sha256:{DIGEST}"),
    ({"contentEvidence": {"contentHash": DIGEST}}, f"sha256:{DIGEST}"),
]


def main() -> None:
    document = {
        "note": (
            "Generated by scripts/ci/generate_inventory_item_metadata_parity.py. "
            "Each entry records what the retired CPython in "
            "scripts/ci/inventory_item_metadata_reference.py returned, so the Rust port "
            "is pinned to observed behaviour."
        ),
        "python_version": ".".join(str(part) for part in sys.version_info[:3]),
        "item_kind": [{"artifact_type": value, "kind": reference.item_kind(value)} for value in ARTIFACT_TYPES],
        "canonical_content_hash": [
            {"value": value, "canonical": reference.canonical_inventory_content_hash(value)}
            for value in CANONICAL_HASHES
        ],
        "resolve_content_hash": [
            {
                "metadata": metadata,
                "semantic_text": semantic,
                "resolved": reference.resolve_item_content_hash(metadata, semantic),
            }
            for metadata, semantic in RESOLVE_CASES
        ],
        "validated_directory_hash": [
            {
                "metadata": metadata,
                "validated": validated_complete_skill_directory_hash(metadata),
                "sanitized": reference.discard_unverified_skill_directory_hash(metadata),
            }
            for metadata in IDENTITY_CASES
        ],
        "capabilities": [
            {
                "artifact_type": artifact_type,
                "metadata": metadata,
                "capabilities": list(reference.capabilities_for_artifact(artifact_type, metadata)),
                "risk_level": reference.risk_level(metadata),
            }
            for artifact_type in CAPABILITY_TYPES
            for metadata in CAPABILITY_METADATA
        ],
        "skill_document_evidence": [
            {
                "metadata": metadata,
                "primary_content_hash": primary,
                "bound": reference.bind_skill_document_evidence(metadata, primary_content_hash=primary),
            }
            for metadata, primary in EVIDENCE_CASES
        ],
    }
    target = REPO_ROOT / "rust/crates/guard-command/testdata/inventory_item_metadata_parity.json"
    target.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {target}")


if __name__ == "__main__":
    main()
