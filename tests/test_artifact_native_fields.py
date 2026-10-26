"""Native request builders preserve the same raw artifact contract."""

from __future__ import annotations

from collections.abc import Callable

import pytest

from codex_plugin_scanner.guard.aibom_detection import _artifact_wire
from codex_plugin_scanner.guard.artifact_native_fields import artifact_native_fields
from codex_plugin_scanner.guard.models import GuardArtifact
from codex_plugin_scanner.guard.native_artifact_content_hash import artifact_content_hash_fields
from codex_plugin_scanner.guard.native_mcp_sensitive_read import _artifact_fields


@pytest.mark.parametrize(
    "builder",
    [artifact_native_fields, _artifact_wire, artifact_content_hash_fields, _artifact_fields],
    ids=["shared", "discovery", "content-hash", "sensitive-read"],
)
def test_native_fields_preserve_raw_values_and_exclude_private_metadata(
    builder: Callable[[GuardArtifact], dict[str, object]],
) -> None:
    artifact = GuardArtifact(
        artifact_id="mcp:example",
        name="example",
        harness="codex",
        artifact_type="mcp_server",
        source_scope="workspace",
        config_path="/workspace/mcp.json",
        command="npx",
        args=("--token=secret",),
        url="https://example.test/mcp?token=secret",
        transport="stdio",
        publisher="example",
        metadata={"token": "secret", "env": {"TOKEN": "secret"}},
        runtime_private_metadata={"archive_url": "https://example.test/private"},
    )

    fields = builder(artifact)
    assert fields == {
        "artifact_id": "mcp:example",
        "name": "example",
        "harness": "codex",
        "artifact_type": "mcp_server",
        "source_scope": "workspace",
        "config_path": "/workspace/mcp.json",
        "command": "npx",
        "args": ["--token=secret"],
        "url": "https://example.test/mcp?token=secret",
        "transport": "stdio",
        "publisher": "example",
        "metadata": {"token": "secret", "env": {"TOKEN": "secret"}},
    }
    assert fields["args"] is not artifact.args
    assert fields["metadata"] is not artifact.metadata
    assert fields["metadata"]["env"] is artifact.metadata["env"]


def test_native_fields_keep_nulls_and_empty_collections() -> None:
    fields = artifact_native_fields(GuardArtifact("id", "name", "codex", "mcp_server", "workspace", ""))
    assert fields["command"] is None
    assert fields["url"] is None
    assert fields["transport"] is None
    assert fields["publisher"] is None
    assert fields["args"] == []
    assert fields["metadata"] == {}
