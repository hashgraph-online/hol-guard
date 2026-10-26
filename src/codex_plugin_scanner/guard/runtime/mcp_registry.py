"""Bounded read-only search of the official public MCP server registry."""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request

from ..mdm.network import managed_urlopen
from ..strict_json_pairs import unique_json_object

_ENDPOINT = "https://registry.modelcontextprotocol.io/v0.1/servers"
_MAX_BYTES = 512_000
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,255}\Z")
_PIN = re.compile(r"[0-9][A-Za-z0-9._+-]{0,79}\Z")
_NPM = re.compile(r"(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*\Z")
_PYPI = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")


def reviewed_stdio_package_options(packages: object) -> list[dict[str, object]]:
    """Expose only pinned, literal registry launch recipes that Codex can own."""
    if not isinstance(packages, list):
        return []
    options: list[dict[str, object]] = []
    for package in packages[:8]:
        if not isinstance(package, dict):
            continue
        registry_type, identifier, version = (package.get(key) for key in ("registryType", "identifier", "version"))
        transport = package.get("transport")
        raw_arguments = package.get("packageArguments", [])
        if (
            not isinstance(identifier, str)
            or not isinstance(version, str)
            or not _PIN.fullmatch(version)
            or not isinstance(transport, dict)
            or transport.get("type") != "stdio"
            or not isinstance(raw_arguments, list)
            or len(raw_arguments) > 16
            # Empty declarations are inert; any populated environment or runtime arguments
            # need a separate reviewed setup flow before this recipe can be offered.
            or package.get("environmentVariables")
            or package.get("runtimeArguments")
        ):
            continue
        if registry_type == "npm" and package.get("runtimeHint") == "npx":
            if package.get("registryBaseUrl") not in (None, "https://registry.npmjs.org") or not _NPM.fullmatch(
                identifier
            ):
                continue
            command, prefix = "npx", ["-y", f"{identifier}@{version}"]
        elif registry_type == "pypi" and package.get("runtimeHint") == "uvx":
            if package.get("registryBaseUrl") not in (None, "https://pypi.org") or not _PYPI.fullmatch(identifier):
                continue
            command, prefix = "uvx", [f"{identifier}@{version}"]
        else:
            continue
        arguments: list[str] = []
        for argument in raw_arguments:
            value = (
                argument.get("value") if isinstance(argument, dict) and argument.get("type") == "positional" else None
            )
            if (
                not isinstance(value, str)
                or not 1 <= len(value) <= 160
                or any(ord(char) < 32 for char in value)
                or "${" in value
            ):
                break
            arguments.append(value)
        else:
            option: dict[str, object] = {
                "registry_type": registry_type,
                "identifier": identifier,
                "version": version,
                "command": command,
                "arguments": prefix + arguments,
                "transport": "stdio",
                "verified_package": False,
            }
            if option not in options:
                options.append(option)
    return options


def search_mcp_registry(query: str) -> dict[str, object]:
    if not isinstance(query, str) or not 2 <= len(query.strip()) <= 80 or any(ord(char) < 32 for char in query):
        raise ValueError("invalid_registry_search")
    url = _ENDPOINT + "?" + urllib.parse.urlencode({"search": query.strip(), "version": "latest", "limit": 20})
    try:
        with managed_urlopen(
            urllib.request.Request(url, headers={"Accept": "application/json"}),
            timeout=5,
            allow_redirects=False,
        ) as response:
            content_type = next(
                (value for key, value in response.headers.items() if key.lower() == "content-type"),
                "",
            )
            if response.status != 200 or content_type.split(";", 1)[0].strip().lower() != "application/json":
                raise ValueError("registry_unavailable")
            raw = response.read(_MAX_BYTES + 1)
    except (OSError, urllib.error.URLError, ValueError) as error:
        raise ValueError("registry_unavailable") from error
    if len(raw) > _MAX_BYTES:
        raise ValueError("registry_response_too_large")
    try:
        payload = json.loads(raw, object_pairs_hook=_unique_object, parse_constant=_invalid_constant)
    except (UnicodeError, ValueError, RecursionError) as error:
        raise ValueError("registry_response_invalid") from error
    servers = payload.get("servers") if isinstance(payload, dict) else None
    metadata = payload.get("metadata") if isinstance(payload, dict) else None
    if not isinstance(servers, list) or len(servers) > 20 or not isinstance(metadata, dict):
        raise ValueError("registry_response_invalid")
    results: list[dict[str, object]] = []
    for entry in servers:
        server = entry.get("server") if isinstance(entry, dict) else None
        registry_meta = entry.get("_meta") if isinstance(entry, dict) else None
        official = (
            registry_meta.get("io.modelcontextprotocol.registry/official") if isinstance(registry_meta, dict) else None
        )
        if not isinstance(server, dict) or not isinstance(official, dict):
            raise ValueError("registry_response_invalid")
        name, version, title, description = (server.get(key) for key in ("name", "version", "title", "description"))
        if not isinstance(name, str) or not _NAME.fullmatch(name) or not isinstance(version, str) or len(version) > 80:
            raise ValueError("registry_response_invalid")
        if not isinstance(title, str):
            title = name
        if not isinstance(description, str):
            description = ""
        remotes = server.get("remotes", [])
        packages = server.get("packages", [])
        if not isinstance(remotes, list) or not isinstance(packages, list):
            raise ValueError("registry_response_invalid")
        endpoints: list[dict[str, str]] = []
        for remote in remotes[:8]:
            if not isinstance(remote, dict):
                continue
            uri, transport = remote.get("url"), remote.get("type")
            if (
                isinstance(uri, str)
                and len(uri) <= 2048
                and uri.startswith("https://")
                and isinstance(transport, str)
                and transport in {"streamable-http", "sse"}
            ):
                endpoints.append({"url": uri, "transport": transport})
        results.append(
            {
                "name": name,
                "version": version,
                "title": title[:120],
                "description": description[:500],
                "status": official.get("status") if official.get("status") in {"active", "deprecated"} else "unknown",
                "remote_endpoints": endpoints,
                "package_count": min(len(packages), 100),
                "package_options": reviewed_stdio_package_options(packages),
                "provenance": "official-mcp-registry",
                "verified_package": False,
                "configured": False,
                "installed": False,
            }
        )
    return {
        "results": results,
        "source": "official-mcp-registry",
        "coverage": "search-page",
        "count": len(results),
        "more_available": isinstance(metadata.get("nextCursor"), str),
    }


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    return unique_json_object(pairs)


def _invalid_constant(_value: str) -> object:
    raise ValueError("nonfinite number")
