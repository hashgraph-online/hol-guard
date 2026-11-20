"""Cline artifacts the native inventory hands back keep their private MCP arguments."""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.aibom_detection import NativeAibomError, _artifact_from_wire


def _wire(artifact_id: str, artifact_type: str, **fields: object) -> dict[str, object]:
    return {
        "artifact_id": artifact_id,
        "name": artifact_id,
        "harness": "cline",
        "artifact_type": artifact_type,
        "source_scope": "global",
        "config_path": "/config",
        "command": None,
        "args": [],
        "url": None,
        "transport": None,
        "publisher": None,
        "metadata": {},
        **fields,
    }


def test_native_mcp_artifact_keeps_its_private_arguments_and_environment() -> None:
    wire = _wire(
        "cline:global:server",
        "mcp_server",
        args=["--token=*****"],
        runtime_private_metadata={"mcp_args": ["--token=abc"], "mcp_env": {"TOKEN": "secret"}},
    )

    artifact = _artifact_from_wire(wire)

    assert artifact.args == ("--token=*****",)
    assert artifact.runtime_private_metadata == {"mcp_args": ("--token=abc",), "mcp_env": {"TOKEN": "secret"}}
    assert "secret" not in repr(artifact) and "secret" not in str(artifact.to_dict())
    assert _artifact_from_wire(_wire("cline:host:cli", "harness_host")).runtime_private_metadata == {}


@pytest.mark.parametrize(
    "private",
    [
        [],
        "private",
        {},
        {"mcp_args": []},
        {"mcp_env": {}},
        {"mcp_args": "--x", "mcp_env": {}},
        {"mcp_args": [1], "mcp_env": {}},
        {"mcp_args": [], "mcp_env": []},
        {"mcp_args": [], "mcp_env": {"KEY": 1}},
        {"mcp_args": [], "mcp_env": {}, "extra": 1},
    ],
)
def test_malformed_private_metadata_is_refused(private: object) -> None:
    with pytest.raises(NativeAibomError, match="native_runner_authority_result_invalid"):
        _artifact_from_wire(_wire("cline:global:server", "mcp_server", runtime_private_metadata=private))
