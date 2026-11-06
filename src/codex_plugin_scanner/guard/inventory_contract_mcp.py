"""MCP tool attestation metadata."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from pathlib import Path

from ..version import __version__


def _apply_tool_trust_attestation_metadata(
    metadata: dict[str, object],
    *,
    harness: str,
    item_id: str,
    content_hash: str,
    config_path_hash: str,
    repository_id: str,
    trust_attestation_context: Mapping[str, object] | None,
) -> dict[str, object]:
    """Attach tool-level trust metadata only when compatible attestation evidence exists."""
    from .runtime.trust_attestation import (
        GuardTrustAttestationSigningConfig,
        apply_trust_attestation_metadata,
    )

    if not isinstance(trust_attestation_context, Mapping):
        return apply_trust_attestation_metadata(
            metadata,
            agent_id=f"{harness}:local",
            item_id=item_id,
            item_kind="mcp_tool",
            content_hash=content_hash,
            adapter_id=harness,
            adapter_version=__version__,
            config_path_hash=config_path_hash,
            repository_id=repository_id,
        )

    raw_signing_config = trust_attestation_context.get("signingConfig")
    signing_config = raw_signing_config if isinstance(raw_signing_config, GuardTrustAttestationSigningConfig) else None
    raw_sequence = trust_attestation_context.get("sequence")
    sequence = raw_sequence if isinstance(raw_sequence, int) else None

    return apply_trust_attestation_metadata(
        metadata,
        agent_id=f"{harness}:local",
        analyzer_id=_optional_context_string(trust_attestation_context, "analyzerId"),
        analyzer_spec_version=_optional_context_string(trust_attestation_context, "analyzerSpecVersion"),
        analyzer_version=_optional_context_string(trust_attestation_context, "analyzerVersion"),
        item_id=item_id,
        item_kind="mcp_tool",
        content_hash=content_hash,
        challenge_id=_optional_context_string(trust_attestation_context, "challengeId"),
        expires_at=_optional_context_string(trust_attestation_context, "expiresAt"),
        installation_id=_optional_context_string(trust_attestation_context, "installationId"),
        nonce=_optional_context_string(trust_attestation_context, "nonce"),
        policy_version=_optional_context_string(trust_attestation_context, "policyVersion"),
        sequence=sequence,
        upload_id=_optional_context_string(trust_attestation_context, "uploadId"),
        workspace_id=_optional_context_string(trust_attestation_context, "workspaceId"),
        device_id=_optional_context_string(trust_attestation_context, "deviceId"),
        adapter_id=harness,
        adapter_version=__version__,
        config_path_hash=config_path_hash,
        repository_id=repository_id,
        signing_config=signing_config,
    )


def _attestation_path_hash(value: object, *, fallback: str) -> str:
    """Hash an attestation path without exporting the private absolute path."""
    raw = value if isinstance(value, str) and value else f"artifact:{fallback}"
    try:
        normalized = str(Path(raw).expanduser().resolve(strict=False))
    except (OSError, RuntimeError, ValueError):
        normalized = raw
    return f"sha256:{hashlib.sha256(normalized.encode('utf-8')).hexdigest()}"


def _attestation_repository_id(*, home_dir: Path, workspace_dir: Path | None) -> str:
    """Resolve repository identity from the available artifact metadata."""
    root = workspace_dir if workspace_dir is not None else home_dir
    try:
        normalized = str(root.expanduser().resolve(strict=False))
    except (OSError, RuntimeError, ValueError):
        normalized = str(root)
    return f"sha256:{hashlib.sha256(normalized.encode('utf-8')).hexdigest()}"


def _optional_context_string(context: Mapping[str, object], key: str) -> str | None:
    """Read a nonempty optional string from an untrusted metadata context."""
    value = context.get(key)
    return value if isinstance(value, str) and value else None
