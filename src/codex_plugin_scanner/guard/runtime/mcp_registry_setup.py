"""Reviewed Codex remote MCP setup through the installed host CLI."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
from collections.abc import Mapping
from urllib.parse import urlsplit

from .mcp_registry import search_mcp_registry

_NAME = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}\Z")


def _registry_query(registry_name: str) -> str:
    # Search is a bounded substring lookup; exact full-name matching happens below.
    return registry_name if len(registry_name) <= 80 else registry_name[-80:]


def reviewed_codex_setup_candidate(payload: dict[str, object]) -> dict[str, str]:
    registry_name, version, endpoint, setup_name = (
        payload.get("registry_name"),
        payload.get("version"),
        payload.get("endpoint"),
        payload.get("setup_name"),
    )
    if (
        not isinstance(registry_name, str)
        or not 1 <= len(registry_name) <= 256
        or not isinstance(version, str)
        or not 1 <= len(version) <= 80
        or not isinstance(endpoint, str)
        or len(endpoint) > 2048
        or not isinstance(setup_name, str)
        or not _NAME.fullmatch(setup_name)
    ):
        raise ValueError("invalid_codex_setup_selection")
    parsed = urlsplit(endpoint)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.fragment
        or parsed.query
    ):
        raise ValueError("invalid_codex_setup_endpoint")
    query = _registry_query(registry_name)
    search = search_mcp_registry(query)
    results = search.get("results")
    if not isinstance(results, list):
        raise ValueError("registry_setup_listing_changed")
    matching = [
        entry
        for entry in results
        if entry["name"] == registry_name
        and entry["version"] == version
        and entry["status"] == "active"
        and any(
            remote["url"] == endpoint and remote["transport"] == "streamable-http"
            for remote in entry["remote_endpoints"]
        )
    ]
    if len(matching) != 1:
        raise ValueError("registry_setup_listing_changed")
    digest = hashlib.sha256(
        json.dumps(
            ["codex", registry_name, version, endpoint, setup_name],
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode()
    ).hexdigest()
    return {
        "host": "codex",
        "kind": "remote",
        "registry_name": registry_name,
        "version": version,
        "endpoint": endpoint,
        "setup_name": setup_name,
        "selection_digest": digest,
        "account_binding": "unverified",
    }


def install_codex_remote_mcp(candidate: Mapping[str, object]) -> str:
    executable = shutil.which("codex")
    if executable is None:
        raise ValueError("codex_host_unavailable")
    name, endpoint = candidate.get("setup_name"), candidate.get("endpoint")
    if not isinstance(name, str) or not isinstance(endpoint, str):
        raise ValueError("invalid_codex_setup_selection")
    try:
        existing = subprocess.run(
            [executable, "mcp", "get", "--json", name],
            capture_output=True,
            timeout=8,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError("codex_host_unavailable") from error
    if existing.returncode == 0:
        raise ValueError("codex_connection_already_exists")
    # CLI failure for any other reason is not evidence that the name is free.
    missing = f"No MCP server named '{name}' found.".encode()
    if existing.returncode != 1 or missing not in existing.stderr[:1000]:
        raise ValueError("codex_host_unavailable")
    try:
        added = subprocess.run(
            [executable, "mcp", "add", name, "--url", endpoint],
            capture_output=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError("codex_setup_outcome_uncertain") from error
    if added.returncode != 0:
        raise ValueError("codex_setup_outcome_uncertain")
    try:
        verified = subprocess.run(
            [executable, "mcp", "get", "--json", name],
            capture_output=True,
            timeout=8,
            check=False,
        )
        response = json.loads(verified.stdout[:32_769]) if len(verified.stdout) <= 32_768 else None
    except (OSError, subprocess.TimeoutExpired, ValueError, UnicodeError) as error:
        raise ValueError("codex_setup_outcome_uncertain") from error
    if not isinstance(response, dict):
        raise ValueError("codex_setup_outcome_uncertain")
    transport = response.get("transport")
    observed_url = response.get("url") or (transport.get("url") if isinstance(transport, dict) else None)
    if verified.returncode != 0 or observed_url != endpoint:
        raise ValueError("codex_setup_outcome_uncertain")
    return name


def reviewed_codex_package_candidate(payload: dict[str, object]) -> dict[str, object]:
    """Bind a local stdio recipe to a fresh registry listing and runtime path."""
    registry_name = payload.get("registry_name")
    version = payload.get("version")
    identifier = payload.get("package_identifier")
    package_version = payload.get("package_version")
    setup_name = payload.get("setup_name")
    if (
        not isinstance(registry_name, str)
        or not 1 <= len(registry_name) <= 256
        or not isinstance(version, str)
        or not 1 <= len(version) <= 80
        or not isinstance(identifier, str)
        or not isinstance(package_version, str)
        or not isinstance(setup_name, str)
        or not _NAME.fullmatch(setup_name)
    ):
        raise ValueError("invalid_codex_package_selection")
    query = _registry_query(registry_name)
    results = search_mcp_registry(query).get("results")
    if not isinstance(results, list):
        raise ValueError("registry_setup_listing_changed")
    matches = [
        option
        for entry in results
        if isinstance(entry, dict)
        and entry.get("name") == registry_name
        and entry.get("version") == version
        and entry.get("status") == "active"
        and isinstance(entry.get("package_options"), list)
        for option in entry["package_options"]
        if isinstance(option, dict)
        and option.get("identifier") == identifier
        and option.get("version") == package_version
    ]
    if len(matches) != 1:
        raise ValueError("registry_setup_listing_changed")
    option = matches[0]
    command_name, arguments = option["command"], option["arguments"]
    if (
        not isinstance(command_name, str)
        or not isinstance(arguments, list)
        or not all(isinstance(value, str) for value in arguments)
    ):
        raise ValueError("registry_setup_listing_changed")
    command = shutil.which(command_name)
    if command is None or not os.path.isabs(command):
        raise ValueError("package_runtime_unavailable")
    digest = hashlib.sha256(
        json.dumps(
            ["codex-package", registry_name, version, identifier, package_version, setup_name, command, arguments],
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode()
    ).hexdigest()
    return {
        "host": "codex",
        "kind": "package",
        "registry_name": registry_name,
        "version": version,
        "package_identifier": identifier,
        "package_version": package_version,
        "registry_type": option["registry_type"],
        "setup_name": setup_name,
        "command": command,
        "arguments": arguments,
        "selection_digest": digest,
        "account_binding": "unverified",
        "verified_package": False,
    }


def install_codex_package_mcp(candidate: Mapping[str, object]) -> str:
    """Configure a reviewed pinned recipe in Codex; Codex owns first launch."""
    executable = shutil.which("codex")
    if executable is None:
        raise ValueError("codex_host_unavailable")
    name, command, arguments = candidate["setup_name"], candidate["command"], candidate["arguments"]
    if (
        not isinstance(name, str)
        or not isinstance(command, str)
        or not os.path.isabs(command)
        or not isinstance(arguments, list)
        or not all(isinstance(argument, str) for argument in arguments)
    ):
        raise ValueError("invalid_codex_package_selection")
    try:
        existing = subprocess.run(
            [executable, "mcp", "get", "--json", name], capture_output=True, timeout=8, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError("codex_host_unavailable") from error
    if existing.returncode == 0:
        raise ValueError("codex_connection_already_exists")
    if existing.returncode != 1 or f"No MCP server named '{name}' found.".encode() not in existing.stderr[:1000]:
        raise ValueError("codex_host_unavailable")
    try:
        added = subprocess.run(
            [executable, "mcp", "add", name, "--", command, *arguments],
            capture_output=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError("codex_setup_outcome_uncertain") from error
    if added.returncode != 0:
        raise ValueError("codex_setup_outcome_uncertain")
    try:
        verified = subprocess.run(
            [executable, "mcp", "get", "--json", name], capture_output=True, timeout=8, check=False
        )
        response = json.loads(verified.stdout[:32_769]) if len(verified.stdout) <= 32_768 else None
    except (OSError, subprocess.TimeoutExpired, ValueError, UnicodeError) as error:
        raise ValueError("codex_setup_outcome_uncertain") from error
    if not isinstance(response, dict) or verified.returncode != 0:
        raise ValueError("codex_setup_outcome_uncertain")
    transport = response.get("transport")
    observed = transport if isinstance(transport, dict) else response
    if observed.get("command") != command or observed.get("args") != arguments:
        raise ValueError("codex_setup_outcome_uncertain")
    return name
