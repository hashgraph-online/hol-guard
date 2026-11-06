"""Configured MCP environment identity regressions across primary adapters."""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest import mock

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.claude_code import ClaudeCodeHarnessAdapter
from codex_plugin_scanner.guard.adapters.codex import CodexHarnessAdapter
from codex_plugin_scanner.guard.adapters.cursor import CursorHarnessAdapter
from codex_plugin_scanner.guard.adapters.grok import GrokHarnessAdapter
from codex_plugin_scanner.guard.adapters.hermes import HermesHarnessAdapter
from codex_plugin_scanner.guard.adapters.mcp_servers import managed_stdio_servers
from codex_plugin_scanner.guard.adapters.zcode import ZCodeHarnessAdapter
from codex_plugin_scanner.guard.consumer import artifact_hash


def _context(tmp_path: Path) -> HarnessContext:
    return HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=None,
        guard_home=tmp_path / "guard-home",
    )


def _detect_server(
    adapter_name: str,
    *,
    context: HarnessContext,
    configured_value: str,
):
    if adapter_name == "claude-code":
        config_path = context.home_dir / ".claude" / "settings.json"
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "environment-proof": {
                            "command": "node",
                            "args": ["server.js"],
                            "env": {"MODE": configured_value},
                        }
                    }
                }
            ),
            encoding="utf-8",
        )
        detection = ClaudeCodeHarnessAdapter().detect(context)
    elif adapter_name == "codex":
        config_path = context.home_dir / ".codex" / "config.toml"
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(
            "\n".join(
                (
                    "[mcp_servers.environment-proof]",
                    'command = "node"',
                    'args = ["server.js"]',
                    f"env = {{ MODE = {json.dumps(configured_value)} }}",
                    "",
                )
            ),
            encoding="utf-8",
        )
        detection = CodexHarnessAdapter().detect(context)
    else:
        config_path = context.home_dir / ".cursor" / "mcp.json"
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "environment-proof": {
                            "command": "node",
                            "args": ["server.js"],
                            "env": {"MODE": configured_value},
                        }
                    }
                }
            ),
            encoding="utf-8",
        )
        detection = CursorHarnessAdapter().detect(context)
    artifact = next(item for item in detection.artifacts if item.artifact_type == "mcp_server")
    return detection, artifact


@pytest.mark.parametrize("adapter_name", ("claude-code", "codex", "cursor"))
def test_mcp_adapter_binds_configured_env_values_without_serializing_them(
    tmp_path: Path,
    adapter_name: str,
) -> None:
    context = _context(tmp_path)
    first_secret = f"{adapter_name}-configured-value-one"
    second_secret = f"{adapter_name}-configured-value-two"
    first_detection, first = _detect_server(
        adapter_name,
        context=context,
        configured_value=first_secret,
    )
    _second_detection, second = _detect_server(
        adapter_name,
        context=context,
        configured_value=second_secret,
    )

    first_env_hash = first.metadata["env_values_hash"]
    second_env_hash = second.metadata["env_values_hash"]
    assert isinstance(first_env_hash, str)
    assert len(first_env_hash) == 64
    assert isinstance(second_env_hash, str)
    assert first_env_hash != second_env_hash
    assert artifact_hash(first) != artifact_hash(second)

    serialized = json.dumps(first.to_dict(), sort_keys=True)
    assert first_secret not in serialized
    assert first_env_hash in serialized

    managed = managed_stdio_servers(first_detection)
    assert len(managed) == 1
    assert managed[0].env == {"MODE": first_secret}
    assert managed[0].identity is not None
    assert managed[0].identity.env_values_hash == first_env_hash


def _secondary_mcp_artifact(
    adapter_name: str,
    *,
    root: Path,
    field: str,
    configured_items: tuple[tuple[str, str], ...],
):
    server: dict[str, object] = {
        "args": ["server.js"],
        field: dict(configured_items),
    }
    if field == "headers":
        server["url"] = "https://example.invalid/mcp"
    else:
        server["command"] = "node"

    if adapter_name == "grok":
        grok_config = root / "home" / ".grok" / "config.toml"
        grok_config.parent.mkdir(parents=True, exist_ok=True)
        grok_config.write_text(
            "\n".join(
                (
                    '[mcp_servers."value-proof"]',
                    *(f"{key} = {json.dumps(value)}" for key, value in server.items() if key != field),
                    f"{field} = {{ "
                    + ", ".join(f"{json.dumps(key)} = {json.dumps(value)}" for key, value in configured_items)
                    + " }",
                    "",
                )
            ),
            encoding="utf-8",
        )
        with mock.patch.dict(os.environ):
            os.environ.pop("GROK_HOME", None)
            detection = GrokHarnessAdapter().detect(
                HarnessContext(home_dir=root / "home", workspace_dir=None, guard_home=root / "guard-home")
            )
        return next(item for item in detection.artifacts if item.artifact_type == "mcp_server")
    if adapter_name == "hermes":
        hermes_config = root / "home" / ".hermes" / "mcp_servers.json"
        hermes_config.parent.mkdir(parents=True, exist_ok=True)
        hermes_config.write_text(json.dumps({"value-proof": server}), encoding="utf-8")
        with mock.patch.dict(os.environ):
            os.environ.pop("HERMES_HOME", None)
            os.environ.pop("HERMES_HOST_HOME", None)
            detection = HermesHarnessAdapter().detect(
                HarnessContext(home_dir=root / "home", workspace_dir=None, guard_home=root / "guard-home")
            )
        return next(item for item in detection.artifacts if item.artifact_type == "mcp_server")

    config_path = root / "home" / ".zcode" / "cli" / "config.json"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(json.dumps({"mcp": {"servers": {"value-proof": server}}}), encoding="utf-8")
    detection = ZCodeHarnessAdapter().detect(
        HarnessContext(home_dir=root / "home", workspace_dir=None, guard_home=root / "guard-home")
    )
    return next(item for item in detection.artifacts if item.artifact_type == "mcp_server")


def _claude_header_artifact(
    *,
    context: HarnessContext,
    configured_items: tuple[tuple[str, str], ...],
):
    config_path = context.home_dir / ".claude" / "settings.json"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "header-proof": {
                        "url": "https://example.invalid/mcp",
                        "headers": dict(configured_items),
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    detection = ClaudeCodeHarnessAdapter().detect(context)
    return next(item for item in detection.artifacts if item.artifact_type == "mcp_server")


@pytest.mark.parametrize("adapter_name", ("grok", "hermes", "zcode"))
@pytest.mark.parametrize(
    ("field", "digest_key", "configured_items", "changed_items"),
    (
        (
            "env",
            "env_values_hash",
            (("MODE", "configured-secret-one"), ("REGION", "us-east")),
            (("MODE", "configured-secret-two"), ("REGION", "us-east")),
        ),
        (
            "headers",
            "header_values_hash",
            (("Authorization", "Bearer configured-secret-one"), ("X-Tenant", "alpha")),
            (("Authorization", "Bearer configured-secret-two"), ("X-Tenant", "alpha")),
        ),
    ),
)
def test_secondary_mcp_adapters_bind_secret_values_without_exposing_them(
    tmp_path: Path,
    adapter_name: str,
    field: str,
    digest_key: str,
    configured_items: tuple[tuple[str, str], ...],
    changed_items: tuple[tuple[str, str], ...],
) -> None:
    first = _secondary_mcp_artifact(
        adapter_name,
        root=tmp_path.resolve(),
        field=field,
        configured_items=configured_items,
    )
    reordered = _secondary_mcp_artifact(
        adapter_name,
        root=tmp_path.resolve(),
        field=field,
        configured_items=tuple(reversed(configured_items)),
    )
    changed = _secondary_mcp_artifact(
        adapter_name,
        root=tmp_path.resolve(),
        field=field,
        configured_items=changed_items,
    )

    first_digest = first.metadata[digest_key]
    assert isinstance(first_digest, str)
    assert len(first_digest) == 64
    assert reordered.metadata[digest_key] == first_digest
    assert changed.metadata[digest_key] != first_digest
    assert artifact_hash(reordered) == artifact_hash(first)
    assert artifact_hash(changed) != artifact_hash(first)

    raw_metadata = json.dumps(first.metadata, sort_keys=True)
    serialized = json.dumps(first.to_dict(), sort_keys=True)
    for _key, secret_value in configured_items:
        assert secret_value not in raw_metadata
        assert secret_value not in serialized
    assert first_digest in serialized


@pytest.mark.parametrize(
    ("adapter_name", "field", "key", "keys_field", "digest_key", "first_value", "second_value"),
    (
        (
            "claude-code",
            "headers",
            "Authorization",
            "headers_keys",
            "header_values_hash",
            "Bearer p44-first",
            "Bearer p44-second",
        ),
        (
            "hermes",
            "env",
            "MODE",
            "env_keys",
            "env_values_hash",
            "p44_env_first",
            "p44_env_second",
        ),
    ),
)
def test_mcp_adapters_canonicalize_padded_duplicate_configured_keys(
    tmp_path: Path,
    adapter_name: str,
    field: str,
    key: str,
    keys_field: str,
    digest_key: str,
    first_value: str,
    second_value: str,
) -> None:
    context = _context(tmp_path)

    def artifact(configured_items: tuple[tuple[str, str], ...]):
        if adapter_name == "claude-code":
            return _claude_header_artifact(context=context, configured_items=configured_items)
        return _secondary_mcp_artifact(
            adapter_name,
            root=tmp_path.resolve(),
            field=field,
            configured_items=configured_items,
        )

    padded_items = ((f"  {key}  ", first_value), (key, first_value), ("   ", "p44_blank_value"))
    padded = artifact(padded_items)
    reordered = artifact(tuple(reversed(padded_items)))
    canonical = artifact(((key, first_value),))
    changed = artifact(((f"  {key}  ", second_value), (key, second_value)))

    assert padded.metadata[keys_field] == [key]
    assert reordered.metadata[keys_field] == [key]
    assert padded.metadata[digest_key] == reordered.metadata[digest_key]
    assert padded.metadata[digest_key] == canonical.metadata[digest_key]
    assert padded.metadata["content_hash"] == canonical.metadata["content_hash"]
    assert artifact_hash(padded) == artifact_hash(reordered)
    assert artifact_hash(padded) == artifact_hash(canonical)
    assert changed.metadata[digest_key] != padded.metadata[digest_key]
    assert changed.metadata["content_hash"] != padded.metadata["content_hash"]
    assert artifact_hash(changed) != artifact_hash(padded)

    raw_metadata = json.dumps(padded.metadata, sort_keys=True)
    serialized = json.dumps(padded.to_dict(), sort_keys=True)
    for raw_value in (first_value, second_value, "p44_blank_value"):
        assert raw_value not in raw_metadata
        assert raw_value not in serialized
