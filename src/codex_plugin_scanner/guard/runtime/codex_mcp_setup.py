"""Version-bound MCP setup and rollback using the supported Codex config API."""

from __future__ import annotations

import json
import os
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass

from .codex_config_rpc import CodexConfigRpc

_NAME = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}\Z")


@dataclass(frozen=True)
class CodexMcpSetupReceipt:
    name: str
    file_path: str
    version: str
    entry_json: str
    previous_version: str | None = None


def _layers(payload: dict[str, object]) -> tuple[dict[str, object], list[dict[str, object]]]:
    layers = payload.get("layers")
    if isinstance(layers, list) and not layers:
        raise ValueError("codex_config_no_layers")
    if not isinstance(layers, list) or len(layers) > 32:
        raise ValueError("codex_config_layers_unavailable")
    checked: list[dict[str, object]] = []
    users: list[dict[str, object]] = []
    for layer in layers:
        if not isinstance(layer, dict) or not isinstance(layer.get("config"), dict):
            raise ValueError("codex_config_invalid_layer")
        config = layer["config"]
        servers = config.get("mcp_servers", {})
        if not isinstance(servers, dict):
            raise ValueError("codex_config_invalid_servers")
        checked.append(layer)
        source = layer.get("name")
        if isinstance(source, dict) and source.get("type") == "user" and source.get("profile") is None:
            users.append(layer)
    if not users:
        raise ValueError("codex_config_no_user_layer")
    if len(users) != 1:
        raise ValueError("codex_config_multiple_user_layers")
    user = users[0]
    source = user["name"]
    assert isinstance(source, dict)
    version, path = user.get("version"), source.get("file")
    if not isinstance(version, str) or not 1 <= len(version) <= 256:
        raise ValueError("codex_config_invalid_user_version")
    if not isinstance(path, str) or not os.path.isabs(path):
        raise ValueError("codex_config_invalid_user_path")
    if user.get("disabledReason") is not None:
        raise ValueError("codex_config_user_layer_disabled")
    return user, checked


def _entry(layer: Mapping[str, object], name: str) -> object:
    config = layer["config"]
    assert isinstance(config, dict)
    servers = config.get("mcp_servers", {})
    assert isinstance(servers, dict)
    return servers.get(name)


def _contains(layer: Mapping[str, object], name: str) -> bool:
    config = layer["config"]
    assert isinstance(config, dict)
    servers = config.get("mcp_servers", {})
    assert isinstance(servers, dict)
    return name in servers


def _write(rpc: CodexConfigRpc, receipt: CodexMcpSetupReceipt, value: Mapping[str, object] | None) -> str:
    try:
        response = rpc.request(
            "config/batchWrite",
            {
                "filePath": receipt.file_path,
                "expectedVersion": receipt.version,
                "reloadUserConfig": False,
                "edits": [{"keyPath": f"mcp_servers.{receipt.name}", "value": value, "mergeStrategy": "replace"}],
            },
        )
    except (ValueError, OSError) as error:
        if str(error) in {"codex_config_changed", "codex_config_readonly"}:
            raise
        raise ValueError("codex_setup_outcome_uncertain") from error
    version = response.get("version")
    if (
        response.get("status") != "ok"
        or response.get("filePath") != receipt.file_path
        or not isinstance(version, str)
        or not 1 <= len(version) <= 256
        or response.get("overriddenMetadata") is not None
    ):
        raise ValueError("codex_setup_outcome_uncertain")
    return version


def _rollback(rpc: CodexConfigRpc, receipt: CodexMcpSetupReceipt) -> str:
    user, layers = _layers(rpc.request("config/read", {"includeLayers": True}))
    source = user["name"]
    assert isinstance(source, dict)
    if (
        source["file"] != receipt.file_path
        or user["version"] != receipt.version
        or _entry(user, receipt.name) != json.loads(receipt.entry_json)
        or any(_contains(layer, receipt.name) for layer in layers if layer is not user)
    ):
        raise ValueError("codex_config_changed")
    version = _write(rpc, receipt, None)
    after, layers = _layers(rpc.request("config/read", {"includeLayers": True}))
    if after["version"] != version or any(_contains(layer, receipt.name) for layer in layers):
        raise ValueError("codex_setup_outcome_uncertain")
    return version


def install_reviewed_codex_mcp(
    executable: str,
    name: str,
    entry: dict[str, object],
    *,
    on_installed: Callable[[CodexMcpSetupReceipt], None] | None = None,
    on_version_chain: Callable[[str, list[tuple[str, str]]], None] | None = None,
) -> str:
    if not _NAME.fullmatch(name):
        raise ValueError("invalid_codex_setup_selection")
    encoded_entry = json.dumps(entry, sort_keys=True, separators=(",", ":"), allow_nan=False)
    with CodexConfigRpc(executable) as rpc:
        user, layers = _layers(rpc.request("config/read", {"includeLayers": True}))
        if any(_contains(layer, name) for layer in layers):
            raise ValueError("codex_connection_already_exists")
        source = user["name"]
        assert isinstance(source, dict)
        before = CodexMcpSetupReceipt(name, str(source["file"]), str(user["version"]), encoded_entry)
        version = _write(rpc, before, entry)
        installed = CodexMcpSetupReceipt(name, before.file_path, version, encoded_entry, before.version)
        try:
            verified, layers = _layers(rpc.request("config/read", {"includeLayers": True}))
            if (
                verified["version"] != version
                or verified["name"] != user["name"]
                or _entry(verified, name) != entry
                or any(_contains(layer, name) for layer in layers if layer is not verified)
            ):
                raise ValueError("codex_setup_outcome_uncertain")
            if on_installed is not None:
                on_installed(installed)
        except (ValueError, OSError) as error:
            try:
                removed_version = _rollback(rpc, installed)
                if on_version_chain is not None:
                    on_version_chain(
                        before.file_path, [(before.version, installed.version), (installed.version, removed_version)]
                    )
            except (ValueError, OSError):
                raise ValueError("codex_setup_outcome_uncertain") from error
            raise ValueError("codex_setup_rolled_back") from error
    return name


def rollback_reviewed_codex_mcp(executable: str, receipt: CodexMcpSetupReceipt) -> str:
    if not _NAME.fullmatch(receipt.name):
        raise ValueError("invalid_codex_setup_selection")
    with CodexConfigRpc(executable) as rpc:
        return _rollback(rpc, receipt)
