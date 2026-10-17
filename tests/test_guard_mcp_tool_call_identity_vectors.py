"""Python oracle for the native ``mcp_tool_call_identity`` vectors.

``tests/fixtures/mcp_tool_call_identity/parity_vectors.json`` records, for each
recipe, the artifact and approval hash the Python builders produce and the
equivalent resident request. The Rust op replays the same request and must
return the same artifact, private metadata and hash. Risk categories come from
the native approval-hash builder both paths already share, so the fixture does
not record them separately. Set
``HOL_GUARD_RECORD_VECTORS=1`` to re-record the fixture from the Python path.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.mcp_tool_calls import (
    _tool_call_configuration,
    build_tool_call_artifact,
    build_tool_call_hash,
)
from codex_plugin_scanner.guard.native_context import bind_context_digest_home
from codex_plugin_scanner.guard.runtime.approval_context import current_extension_control_binding_digest
from codex_plugin_scanner.guard.runtime.mcp_protection import build_mcp_server_identity
from codex_plugin_scanner.guard.store_mcp_catalog import tool_definition_authority_hash

_FIXTURE = Path(__file__).parent / "fixtures" / "mcp_tool_call_identity" / "parity_vectors.json"
_WORKSPACE = "/work/space"
_SCHEMA = {
    "type": "object",
    "properties": {"path": {"type": "string"}, "limit": {"type": "number", "default": 1.5}},
    "required": ["path"],
}
_PROVIDER_HASH = "a" * 64
_COMMON = {
    "harness": "codex",
    "server_name": "workspace-tools",
    "source_scope": "project",
    "config_path": "/work/space/.codex/config.toml",
    "transport": "stdio",
}


def _identity(command: str, args: tuple[str, ...], env: dict[str, str] | None = None):
    return build_mcp_server_identity(
        config_path=_COMMON["config_path"], command=command, args=args, transport="stdio", env=env or {}, env_keys=()
    )


def _recipes() -> dict[str, dict[str, object]]:
    entry = {
        "name": "read_file",
        "description": "  Read a file  ",
        "inputSchema": _SCHEMA,
        "outputSchema": {"type": "object"},
        "annotations": {"readOnlyHint": True},
    }
    fingerprint = {
        "command": "node",
        "configured_env_values_hash": "b" * 64,
        "transport": "stdio",
        "resolved_executable": {"path": "/usr/bin/node", "sha256": "c" * 64},
        "tool_catalog_state": "complete",
        "tool_catalog_fingerprint": "d" * 64,
    }
    base = {"tool_name": "read_file", "arguments": {"path": "a.txt"}, "catalog": entry, "config": {"mode": "prompt"}}
    return {
        "minimal_digest_row": {**base, "catalog": None, "config": None, "workspace": None},
        "catalog_token": {**base, "fingerprint": fingerprint, "identity": _identity("node", ("server.js",))},
        "server_id": {**base, "server_id": "server-123", "fingerprint": fingerprint},
        "url_command_identity": {
            **base,
            "identity": _identity("https://user:secret@example.com/mcp?token=x", ()),
        },
        "package_launcher_identity": {
            **base,
            "identity": _identity("npx", ("--yes", "@scope/server@1.2.3"), {"TOKEN": "x", "MODE": "y"}),
            "config": {"mode": "enforce", "default_action": "allow", "security_level": "strict"},
        },
        "composio_provider_hash": {
            **base,
            "tool_name": "mcp__codex_apps__composio__composio_multi_execute_tool",
            "catalog": None,
            "provider_hash": _PROVIDER_HASH,
        },
        # A discovery wrapper cannot carry a provider action, so the runtime
        # leaves the provider hash out of its artifact even when one is passed.
        "composio_discovery_provider_hash": {
            **base,
            "tool_name": "mcp__codex_apps__composio__composio_search_tools",
            "catalog": None,
            "provider_hash": _PROVIDER_HASH,
        },
        "catalog_named_definition": {
            **base,
            "keep_name": True,
            "catalog": {"name": "read_file", "inputSchema": _SCHEMA, "annotations": {"readOnlyHint": True}},
        },
        "catalog_other_named_definition": {
            **base,
            "keep_name": True,
            "catalog": {"name": "other", "inputSchema": _SCHEMA},
        },
        "catalog_without_input_schema": {**base, "catalog": {"name": "read_file", "description": "x"}},
        "catalog_snake_schema": {
            **base,
            "catalog": {"name": "read_file", "input_schema": {"type": "object"}, "description": ""},
        },
        "catalog_null_input_schema": {**base, "catalog": {"name": "read_file", "inputSchema": None}},
        "catalog_unicode": {
            **base,
            "tool_name": "lire_fichier",
            "catalog": {"name": "lire", "description": "Lis le fichier éè ☃", "inputSchema": {"x": "é"}},
            "arguments": {"chemin": "été.txt"},
        },
        "explicit_source": {**base, "explicit": {"schema": _SCHEMA, "description": "  Explicit  "}, "catalog": None},
        "explicit_empty_description": {**base, "explicit": {"schema": None, "description": "   "}, "catalog": None},
        "arguments_json_string": {**base, "arguments": '{"path": "b.txt"}'},
        "arguments_list": {**base, "arguments": ["a", 1, None]},
        "arguments_none": {**base, "arguments": None},
        "arguments_nested_float": {**base, "arguments": {"limit": 2.0, "ratio": 1e-7, "big": 12345678901234567890}},
        "browser_volatile_arguments": {
            **base,
            "tool_name": "browser_navigate",
            "arguments": {"url": "https://example.com", "timestamp": 1, "requestId": "r"},
            "catalog": {"name": "browser_navigate", "inputSchema": {"type": "object"}},
        },
        "risky_shell": {
            **base,
            "tool_name": "shell_exec",
            "arguments": {"command": "rm -rf /tmp/x"},
            "catalog": {"name": "shell_exec", "inputSchema": {"type": "object"}, "description": "Run a shell command"},
        },
        "config_sandbox_and_managed": {
            **base,
            "config": {
                "mode": "enforce",
                "sandbox_analysis": "on",
                "managed_policy_hash": "e" * 64,
                "managed_policy_status": "applied",
                "managed_locked_settings": ["mode"],
                "artifact_actions": {"codex:runtime:project:workspace-tools:read_file": "block"},
            },
        },
        "no_workspace_with_config": {**base, "workspace": None},
        "build_only_without_hash": {**base, "build_only": True},
        "invalid_provider_hash": {**base, "provider_hash": "XYZ", "expect_error": "provider_hash_invalid"},
    }


def _build_python(recipe: dict[str, object]):
    entry = recipe["catalog"] if "explicit" not in recipe else None
    tool_name = recipe["tool_name"]
    kwargs: dict[str, object] = {
        **_COMMON,
        "tool_name": tool_name,
        "server_id": recipe.get("server_id"),
        "server_fingerprint": recipe.get("fingerprint"),
        "server_identity": recipe.get("identity"),
        "provider_catalog_hash": recipe.get("provider_hash"),
    }
    if "explicit" in recipe:
        explicit = recipe["explicit"]
        kwargs["tool_schema"] = explicit["schema"]  # type: ignore[index]
        kwargs["tool_description"] = explicit["description"]  # type: ignore[index]
        return build_tool_call_artifact(**kwargs)  # type: ignore[arg-type]
    definition = entry or {}
    description = definition.get("description")
    kwargs["tool_schema"] = definition.get("inputSchema", definition.get("input_schema"))
    kwargs["tool_description"] = description if isinstance(description, str) else None
    keep_name = bool(recipe.get("keep_name"))
    kwargs["tool_definition"] = {key: value for key, value in definition.items() if keep_name or key != "name"}
    artifact = build_tool_call_artifact(**kwargs)  # type: ignore[arg-type]
    if entry is not None:
        from dataclasses import replace

        artifact = replace(
            artifact,
            runtime_private_metadata={
                **artifact.runtime_private_metadata,
                "mcp_tool_authority_hash": tool_definition_authority_hash({"name": tool_name, **entry}),
            },
        )
    return artifact


def _config(recipe: dict[str, object], home: Path) -> tuple[GuardConfig | None, dict[str, object] | None]:
    raw = recipe.get("config")
    if raw is None:
        return None, None
    values = {key: value for key, value in raw.items() if key not in {"managed_policy_hash", "managed_policy_status"}}  # type: ignore[union-attr]
    if "managed_locked_settings" in values:
        values["managed_locked_settings"] = tuple(values["managed_locked_settings"])
    managed = {key: raw[key] for key in ("managed_policy_hash", "managed_policy_status") if key in raw}  # type: ignore[index]
    config = GuardConfig(guard_home=home, workspace=Path(_WORKSPACE), **values, **managed)
    wire = {
        **_tool_call_configuration(config),
        "managed_policy_hash": config.managed_policy_hash,
        "managed_policy_status": config.managed_policy_status,
        "sandbox_analysis": config.sandbox_analysis,
    }
    return config, json.loads(json.dumps(wire))


def _identity_wire(identity) -> dict[str, object] | None:
    if identity is None:
        return None
    return {
        "config_path": identity.config_path,
        "command": identity.command,
        "args_hash": identity.args_hash,
        "package_name": identity.package_name,
        "package_version": identity.package_version,
        "package_source": identity.package_source,
        "transport": identity.transport,
        "env_keys": list(identity.env_keys),
        "env_values_hash": identity.env_values_hash,
        "identity_hash": identity.identity_hash,
    }


def _artifact_wire(artifact) -> dict[str, object]:
    return {
        "artifact_id": artifact.artifact_id,
        "name": artifact.name,
        "harness": artifact.harness,
        "source_scope": artifact.source_scope,
        "config_path": artifact.config_path,
        "command": artifact.command,
        "transport": artifact.transport,
        "publisher": artifact.publisher,
        "metadata": json.loads(json.dumps(dict(artifact.metadata))),
    }


def _request(recipe: dict[str, object], wire_config: dict[str, object] | None, extension: str | None):
    if "explicit" in recipe:
        explicit = recipe["explicit"]
        tool = {"kind": "explicit", "schema": explicit["schema"], "description": explicit["description"]}  # type: ignore[index]
    else:
        catalog = recipe["catalog"]
        if isinstance(catalog, dict) and not recipe.get("keep_name"):
            catalog = {key: value for key, value in catalog.items() if key != "name"}
        tool = {"kind": "catalog", "entry": catalog}
    build = {
        **_COMMON,
        "tool_name": recipe["tool_name"],
        "server_id": recipe.get("server_id"),
        "server_fingerprint": recipe.get("fingerprint"),
        "server_identity": _identity_wire(recipe.get("identity")),
        "provider_catalog_hash": recipe.get("provider_hash"),
        "tool": tool,
    }
    workspace = recipe.get("workspace", _WORKSPACE)
    return {
        "build": build,
        "artifact": None,
        "hash": None
        if recipe.get("build_only")
        else {
            "arguments": recipe["arguments"],
            "config": wire_config,
            "workspace": workspace,
            "extension_control_digest": extension,
        },
    }


def _record(recipe: dict[str, object], home: Path) -> dict[str, object]:
    config, wire_config = _config(recipe, home)
    extension = current_extension_control_binding_digest() if config is not None else None
    request = _request(recipe, wire_config, extension)
    if recipe.get("expect_error"):
        with pytest.raises(ValueError, match="invalid provider catalog authority hash"):
            _build_python(recipe)
        return {"request": request, "error": "native_mcp_tool_call_identity_provider_hash_invalid"}
    artifact = _build_python(recipe)
    workspace = recipe.get("workspace", _WORKSPACE)
    artifact_hash = (
        None
        if recipe.get("build_only")
        else build_tool_call_hash(artifact, recipe["arguments"], workspace=workspace, config=config)  # type: ignore[arg-type]
    )
    return {
        "request": request,
        "expected": {
            "artifact": _artifact_wire(artifact),
            "runtime_private_metadata": json.loads(json.dumps(dict(artifact.runtime_private_metadata))),
            "artifact_hash": artifact_hash,
        },
    }


def _hash_only_vector(vectors: dict[str, dict[str, object]], home: Path) -> dict[str, object]:
    """Hash an artifact built earlier under a different config (the post-claim refresh)."""
    source = vectors["catalog_token"]["request"]  # type: ignore[index]
    artifact = _build_python(_recipes()["catalog_token"])
    config, wire_config = _config({"config": {"mode": "enforce", "security_level": "strict"}}, home)
    extension = current_extension_control_binding_digest()
    arguments = source["hash"]["arguments"]  # type: ignore[index]
    return {
        "request": {
            "build": None,
            "artifact": _artifact_wire(artifact),
            "hash": {
                "arguments": arguments,
                "config": wire_config,
                "workspace": _WORKSPACE,
                "extension_control_digest": extension,
            },
        },
        "expected": {
            "artifact": _artifact_wire(artifact),
            "runtime_private_metadata": {},
            "artifact_hash": build_tool_call_hash(artifact, arguments, workspace=_WORKSPACE, config=config),
        },
    }


def test_python_builders_match_recorded_vectors(native_context_digest: Path) -> None:
    home = native_context_digest
    bind_context_digest_home(home)
    recorded = {name: _record(recipe, home) for name, recipe in _recipes().items()}
    recorded["hash_only_refresh"] = _hash_only_vector(recorded, home)  # type: ignore[arg-type]
    if os.environ.get("HOL_GUARD_RECORD_VECTORS") == "1":
        _FIXTURE.write_text(json.dumps({"vectors": recorded}, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    assert json.loads(_FIXTURE.read_text(encoding="utf-8"))["vectors"] == json.loads(json.dumps(recorded))


def test_oversized_request_error_is_reported_with_its_code(monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard import native_mcp_tool_call_identity as identity

    def refuse(**kwargs: object) -> dict[str, object]:
        return {
            "schema": identity._RESULT_SCHEMA,
            "request_id": kwargs["request"]["request_id"],  # type: ignore[index]
            "request_sha256": "",
            "status": "error",
            "code": "native_mcp_tool_call_identity_request_too_large",
        }

    monkeypatch.setattr(identity, "_resident_request", refuse)
    monkeypatch.setattr(identity, "_resolve_digest_home", lambda _home: Path("/nonexistent"))
    with pytest.raises(ValueError, match="request_too_large"):
        identity.native_tool_call_identity(build={"harness": "codex"})
