"""Load MCP server contribution payloads for tests.

Guard reads MCP server metadata from its compiled native program; nothing in
the runtime loads contribution payloads. Tests still walk the authored,
packaged and installed-bundle copies to check them against each other.
"""

from __future__ import annotations

import json
from importlib import resources
from pathlib import Path

from codex_plugin_scanner.guard.runtime.extension_contribution import frozen_package_data
from codex_plugin_scanner.guard.runtime.mcp_server_contribution import (
    _frozen_runtime,
    contributions_dir,
    direct_mcp_command_name,
    normalized_remote_mcp_url,
    normalized_remote_server_name,
    remote_mcp_endpoint_identity,
    validate_mcp_contribution,
)


def load_mcp_contribution_payloads(root: Path | None = None) -> tuple[dict[str, object], ...]:
    if root is not None:
        return _load_from_directory(root)
    from codex_plugin_scanner.guard.catalog_delivery.installed_bundle import compatibility_payloads

    bundled = compatibility_payloads("mcp")
    if bundled is not None:
        return bundled
    packaged = _load_packaged_payloads()
    if packaged:
        return packaged
    return _load_from_directory(contributions_dir())


def validate_mcp_contribution_file(path: Path) -> dict[str, object]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path.name} must contain an object")
    validate_mcp_contribution(payload, filename=path.name)
    return payload


def _load_from_directory(directory: Path) -> tuple[dict[str, object], ...]:
    if not directory.is_dir():
        return ()
    files = sorted(directory.glob("mcp.*.json"))
    return _finalize_payloads(tuple(validate_mcp_contribution_file(path) for path in files))


def _load_packaged_payloads() -> tuple[dict[str, object], ...]:
    try:
        root = resources.files("codex_plugin_scanner.guard.contracts.data.mcp_servers") / "contributions"
        names = [item for item in root.iterdir() if item.name.startswith("mcp.") and item.name.endswith(".json")]
    except (FileNotFoundError, ModuleNotFoundError, OSError, AttributeError):
        frozen = frozen_package_data("mcp_servers", "contributions")
        if frozen is None or not frozen.is_dir():
            if _frozen_runtime():
                raise FileNotFoundError("frozen Guard is missing packaged MCP server contributions") from None
            return ()
        names = [item for item in frozen.iterdir() if item.name.startswith("mcp.") and item.name.endswith(".json")]
    if not names:
        if _frozen_runtime():
            raise FileNotFoundError("frozen Guard is missing packaged MCP server contributions")
        return ()
    payloads: list[dict[str, object]] = []
    for item in sorted(names, key=lambda entry: entry.name):
        payload = json.loads(item.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError(f"{item.name} must contain an object")
        validate_mcp_contribution(payload, filename=item.name)
        payloads.append(payload)
    return _finalize_payloads(tuple(payloads))


def _finalize_payloads(payloads: tuple[dict[str, object], ...]) -> tuple[dict[str, object], ...]:
    packages: dict[str, str] = {}
    commands: dict[str, str] = {}
    remote_urls: dict[str, str] = {}
    remote_names: dict[str, str] = {}
    ids: set[str] = set()
    for payload in payloads:
        mcp_id = payload.get("id")
        if not isinstance(mcp_id, str):
            raise ValueError("MCP contribution is missing id")
        if mcp_id in ids:
            raise ValueError(f"duplicate MCP contribution id {mcp_id}")
        ids.add(mcp_id)
        launch = payload.get("launch")
        if not isinstance(launch, dict):
            raise ValueError(f"{mcp_id} is missing launch metadata")
        if launch.get("kind") == "package-launcher":
            package = launch.get("package")
            if not isinstance(package, str) or not package.strip():
                raise ValueError(f"{mcp_id} is missing a launch package")
            key = package.strip().lower()
            previous = packages.get(key)
            if previous is not None:
                raise ValueError(f"duplicate MCP launch package {package} for {previous} and {mcp_id}")
            packages[key] = mcp_id
            continue
        if launch.get("kind") == "direct-command":
            command = launch.get("command")
            if not isinstance(command, str) or direct_mcp_command_name(command) != command:
                raise ValueError(f"{mcp_id} has invalid direct command")
            previous = commands.get(command)
            if previous is not None:
                raise ValueError(f"duplicate MCP direct command {command} for {previous} and {mcp_id}")
            commands[command] = mcp_id
            continue
        if launch.get("kind") != "remote-http":
            raise ValueError(f"{mcp_id} has unsupported launch metadata")
        remote_url = normalized_remote_mcp_url(launch.get("url"))
        if remote_url is None:
            raise ValueError(f"{mcp_id} is missing a valid remote URL")
        remote_endpoint = remote_mcp_endpoint_identity(remote_url)
        if remote_endpoint is None:
            raise ValueError(f"{mcp_id} is missing a valid remote endpoint")
        previous_url = remote_urls.get(remote_endpoint)
        if previous_url is not None:
            raise ValueError(f"duplicate MCP remote endpoint {remote_endpoint} for {previous_url} and {mcp_id}")
        remote_urls[remote_endpoint] = mcp_id
        server_names = launch.get("serverNames")
        if not isinstance(server_names, list):
            raise ValueError(f"{mcp_id} is missing remote server names")
        for raw_name in server_names:
            server_name = normalized_remote_server_name(raw_name)
            if server_name is None:
                raise ValueError(f"{mcp_id} has invalid remote server name")
            previous_name = remote_names.get(server_name)
            if previous_name is not None:
                raise ValueError(f"duplicate MCP remote server name {raw_name} for {previous_name} and {mcp_id}")
            remote_names[server_name] = mcp_id
    return payloads
