"""Shared fixtures and MCP-metadata cases for the AIBOM parity vector recorder."""

from __future__ import annotations

from collections.abc import Mapping

from codex_plugin_scanner.guard import aibom_detection as old

SKILL = "---\nname: {name}\n---\n{name} instructions.\n"
MARKETPLACE = ".agents/plugins/marketplace.json"
HOME = "home"
WORK = "work"
USER_HOME = "uhome"


def file(path: str, text: str = "content\n", mode: int = 0o644) -> dict:
    return {"path": path, "text": text, "mode": mode}


def link(path: str, target: str) -> dict:
    return {"path": path, "target": target}


def skill(base: str, name: str, *extra: dict) -> list[dict]:
    return [file(f"{base}/{name}/SKILL.md", SKILL.format(name=name)), *extra]


def mcp_case(name: str, metadata: dict, *, command=None, args=(), url=None, transport=None, env=None, headers=None):
    enriched = old.enrich_mcp_server_metadata(
        dict(metadata),
        command=command,
        args=tuple(args),
        url=url,
        transport=transport,
        configured_environment=env,
        configured_headers=headers,
    )
    owned = ("env_keys", "headers_keys", "env_values_hash", "header_values_hash", "content_hash", "versionInfo")
    raw_env = env if env is not None else metadata.get("env")
    raw_headers = headers if headers is not None else metadata.get("headers")
    return {
        "name": name,
        "kind": "mcp_metadata",
        "args": {
            "command": command,
            "args": list(args),
            "url": url,
            "transport": transport,
            "env_keys": string_list(metadata.get("env_keys")),
            "headers_keys": string_list(metadata.get("headers_keys")),
            "env": pairs(raw_env),
            "headers": pairs(raw_headers),
            "env_values_hash": string_or_none(metadata.get("env_values_hash")),
            "header_values_hash": string_or_none(metadata.get("header_values_hash")),
            "label": str(metadata.get("name", "mcp")),
        },
        "expected": {key: enriched[key] for key in owned},
    }


def string_list(value: object) -> list[str]:
    return [item for item in value if isinstance(item, str)] if isinstance(value, (list, tuple)) else []


def string_or_none(value: object) -> str | None:
    return value if isinstance(value, str) else None


def pairs(value: object) -> list[list[str]] | None:
    if not isinstance(value, Mapping):
        return None
    return [[key, item] for key, item in value.items() if isinstance(key, str) and isinstance(item, str)]


def mcp_cases() -> list[dict]:
    return [
        mcp_case("mcp_minimal", {}, command="npx", args=("-y", "server"), transport="stdio"),
        mcp_case("mcp_labelled", {"name": "docs"}, url="https://example.invalid/mcp", transport="http"),
        mcp_case("mcp_label_non_string", {"name": 5}, command="x"),
        mcp_case("mcp_label_none", {"name": None}, command="x"),
        mcp_case(
            "mcp_env_keys_are_stripped_deduped_sorted",
            {"env_keys": [" B ", "A", "A", "", "   ", 7, None, "C"]},
            command="x",
        ),
        mcp_case(
            "mcp_env_values_derive_keys_and_hash",
            {},
            command="x",
            env={"B": "2", "A": "1", " C ": "3", "": "empty", 9: "num", "D": 4},
        ),
        mcp_case(
            "mcp_env_duplicate_stripped_key_last_wins",
            {},
            command="x",
            env={"A": "first", " A": "second"},
        ),
        mcp_case(
            "mcp_metadata_env_used_when_configured_is_absent",
            {"env": {"TOKEN": "value"}, "name": "from-metadata"},
            command="x",
        ),
        mcp_case(
            "mcp_configured_env_overrides_metadata_env",
            {"env": {"TOKEN": "metadata"}},
            command="x",
            env={"TOKEN": "configured"},
        ),
        mcp_case(
            "mcp_prefilled_hashes_are_stripped_and_kept",
            {"env_values_hash": "  sha256:abc  ", "header_values_hash": "\theader-hash\n"},
            command="x",
            env={"A": "1"},
            headers={"H": "v"},
        ),
        mcp_case(
            "mcp_blank_and_non_string_hashes_are_recomputed",
            {"env_values_hash": "   ", "header_values_hash": 12},
            command="x",
            env={"A": "1"},
            headers={"H": "v"},
        ),
        mcp_case(
            "mcp_headers_keys_and_values",
            {"headers_keys": ["X-B", " X-A ", "X-A"]},
            url="https://example.invalid/mcp",
            transport="sse",
            headers={"Authorization": "Bearer placeholder", "X-A": "1"},
        ),
        mcp_case(
            "mcp_unicode_and_empty_values",
            {"name": "ünï"},
            command="câ",
            args=("--flag", "", "ü"),
            env={"É": "ü", "E": ""},
        ),
        mcp_case("mcp_explicit_empty_env_mapping", {"env": {"A": "1"}}, command="x", env={}),
        mcp_case("mcp_non_mapping_env_is_empty", {"env": ["A=1"]}, command="x"),
    ]
