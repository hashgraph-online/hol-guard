"""Raw artifact fields for local native requests, before resident redaction."""

from __future__ import annotations

from .models import GuardArtifact


def artifact_native_fields(artifact: GuardArtifact) -> dict[str, object]:
    """Keep hash inputs unredacted and exclude runtime-private metadata.

    The resident applies the artifact's redaction before hashing. Using
    ``to_dict()`` here would redact twice and change saved approval keys.
    """

    return {
        "artifact_id": artifact.artifact_id,
        "name": artifact.name,
        "harness": artifact.harness,
        "artifact_type": artifact.artifact_type,
        "source_scope": artifact.source_scope,
        "config_path": artifact.config_path,
        "command": artifact.command,
        "args": list(artifact.args),
        "url": artifact.url,
        "transport": artifact.transport,
        "publisher": artifact.publisher,
        "metadata": dict(artifact.metadata),
    }
