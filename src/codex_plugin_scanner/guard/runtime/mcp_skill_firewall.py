"""Portal-aligned MCP/skill firewall metadata for Guard artifacts and receipts."""

from __future__ import annotations

import importlib
import re
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ..models import GuardArtifact
from .approval_context import build_configured_environment_hash
from .mcp_protection import (
    McpServerIdentity,
    McpToolIdentity,
    _command_name,
    _stable_digest,
    build_mcp_server_identity,
    build_mcp_tool_identity,
)

if TYPE_CHECKING:
    from .actions import GuardActionEnvelope


def _skill_protection_module():
    return importlib.import_module(".skill_protection", __package__)


_PACKAGE_MANAGER_PATTERN = re.compile(
    r"\b(npm|pnpm|yarn|bun|pip|uv|cargo|gem|brew)\b",
    re.IGNORECASE,
)
_SENSITIVE_CLASS_PATTERN = re.compile(
    r"(secret|token|credential|password|api[_-]?key|pii|phi|payment)",
    re.IGNORECASE,
)


def _publisher_stable_id(source: str | None) -> str | None:
    normalized = (source or "").strip().lower()
    if not normalized:
        return None
    return f"publisher:{_stable_digest(normalized)}"


def _dependency_hash(package_name: str | None, package_version: str | None) -> str | None:
    if not package_name:
        return None
    return _stable_digest(
        {
            "ecosystem": None,
            "packageName": package_name.strip(),
            "version": (package_version or "").strip() or None,
        }
    )


def _command_hash(command: str, args: tuple[str, ...]) -> str:
    return _stable_digest({"args": list(args), "command": _command_name(command)})


def _transport_hash(transport: str) -> str:
    return _stable_digest(transport.strip().lower() or "unknown")


def portal_mcp_server_identity(
    identity: McpServerIdentity,
    *,
    config_path: str,
    args: tuple[str, ...] = (),
    publisher: str | None = None,
    install_source: str | None = None,
) -> dict[str, object]:
    publisher_source = publisher or install_source or identity.package_name
    return {
        "argsHash": identity.args_hash,
        "command": identity.command,
        "commandHash": _command_hash(identity.command, args),
        "configPath": config_path,
        "dependencyHash": _dependency_hash(identity.package_name, identity.package_version),
        "envKeys": list(identity.env_keys),
        "envValuesHash": identity.env_values_hash,
        "identityHash": identity.identity_hash,
        "packageName": identity.package_name,
        "packageVersion": identity.package_version,
        "publisherStableId": _publisher_stable_id(publisher_source),
        "transport": identity.transport,
        "transportHash": _transport_hash(identity.transport),
    }


def _portal_mcp_server_identity_from_parts(
    *,
    config_path: str,
    command: str,
    args: tuple[str, ...],
    transport: str,
    env: dict[str, str] | None = None,
    publisher: str | None = None,
    install_source: str | None = None,
) -> dict[str, object]:
    identity = build_mcp_server_identity(
        config_path=config_path,
        command=command,
        args=args,
        transport=transport,
        env=env,
    )
    return portal_mcp_server_identity(
        identity,
        config_path=config_path,
        args=args,
        publisher=publisher,
        install_source=install_source,
    )


def portal_mcp_tool_identity(
    identity: McpToolIdentity,
    *,
    schema: object | None = None,
    description: str | None = None,
) -> dict[str, object]:
    has_schema = schema is not None
    has_description = isinstance(description, str) and bool(description.strip())
    hash_scope = "full" if has_schema or has_description else "manifest"
    description_hash = identity.description_hash if identity.description_hash else None
    schema_hash = identity.schema_hash if identity.schema_hash else None
    return {
        "descriptionHash": description_hash,
        "descriptorHash": description_hash,
        "hashScope": hash_scope,
        "identityHash": identity.identity_hash,
        "schemaHash": schema_hash,
        "serverHash": identity.server_hash,
        "toolName": identity.tool_name,
    }


def skill_identity_metadata(
    identity: Any,
    *,
    publisher: str | None = None,
) -> dict[str, object]:
    descriptor_hash = _stable_digest(
        {
            "reference_hashes": list(identity.reference_hashes),
            "script_hashes": list(identity.script_hashes),
            "template_hashes": list(identity.template_hashes),
        }
    )
    stable_id = f"skill:{identity.identity_hash[:24]}"
    publisher_stable_id = _publisher_stable_id(publisher)
    return {
        "skill_hash": identity.skill_hash,
        "descriptor_hash": descriptor_hash,
        "identity_hash": identity.identity_hash,
        "stable_id": stable_id,
        "publisher_stable_id": publisher_stable_id,
    }


def portal_skill_identity(
    identity: Any,
    *,
    publisher: str | None = None,
) -> dict[str, object]:
    metadata = skill_identity_metadata(identity, publisher=publisher)
    return {
        "dependencyHashes": [],
        "descriptorHash": metadata["descriptor_hash"],
        "identityHash": metadata["identity_hash"],
        "publisherStableId": metadata.get("publisher_stable_id"),
        "skillHash": metadata["skill_hash"],
        "stableId": metadata["stable_id"],
    }


def build_mcp_skill_firewall_fingerprints(
    *,
    mcp_server: dict[str, object] | None = None,
    mcp_tools: list[dict[str, object]] | None = None,
    skill: dict[str, object] | None = None,
) -> dict[str, object]:
    payload: dict[str, object] = {"mcpTools": mcp_tools or []}
    if mcp_server is not None:
        payload["mcpServer"] = mcp_server
    if skill is not None:
        payload["skill"] = skill
    return payload


def attach_mcp_skill_firewall_metadata(
    metadata: dict[str, object],
    firewall: dict[str, object],
) -> dict[str, object]:
    enriched = dict(metadata)
    enriched["mcpSkillFirewall"] = firewall
    mcp_server = firewall.get("mcpServer")
    if isinstance(mcp_server, dict):
        enriched["mcp_server_identity"] = _legacy_server_identity(mcp_server)
    mcp_tools = firewall.get("mcpTools")
    if isinstance(mcp_tools, list):
        if len(mcp_tools) == 1 and isinstance(mcp_tools[0], dict):
            enriched["mcp_tool_identity"] = _legacy_tool_identity(mcp_tools[0])
        elif mcp_tools:
            enriched["mcp_tool_identities"] = [
                _legacy_tool_identity(item) for item in mcp_tools if isinstance(item, dict)
            ]
    skill = firewall.get("skill")
    if isinstance(skill, dict):
        enriched["mcp_skill_identity"] = _legacy_skill_identity(skill)
    return enriched


def build_runtime_action_record(
    *,
    artifact: GuardArtifact,
    arguments: object | None = None,
    action_envelope: GuardActionEnvelope | None = None,
    risk_categories: tuple[str, ...] = (),
) -> dict[str, object] | None:
    files_touched = _redacted_paths(_argument_paths(arguments))
    domains: list[str] = []
    subprocesses: list[str] = []
    package_managers: list[str] = []
    if action_envelope is not None:
        files_touched.extend(_redacted_paths(action_envelope.target_paths))
        domains.extend(list(action_envelope.network_hosts))
        if action_envelope.package_manager:
            package_managers.append(action_envelope.package_manager)
        if action_envelope.command:
            subprocesses.append(action_envelope.command.split()[0])
    claimed = _claimed_capabilities(artifact)
    observed = _observed_capabilities(risk_categories, artifact)
    sensitive = [
        category for category in (*risk_categories, *claimed, *observed) if _SENSITIVE_CLASS_PATTERN.search(category)
    ]
    for subprocess in subprocesses:
        match = _PACKAGE_MANAGER_PATTERN.search(subprocess)
        if match is not None:
            package_managers.append(match.group(1).lower())
    payload: dict[str, object] = {
        "claimedCapabilities": claimed,
        "domainsContacted": _unique_strings(domains),
        "filesTouched": _unique_strings(files_touched),
        "observedCapabilities": observed,
        "packageManagersInvoked": _unique_strings(package_managers),
        "sensitiveDataClasses": _unique_strings(sensitive),
        "subprocessesSpawned": _unique_strings(subprocesses),
    }
    if not any(payload.values()):
        return None
    return payload


def enrich_artifact_with_mcp_skill_firewall(artifact: GuardArtifact) -> GuardArtifact:
    firewall = _firewall_for_artifact(artifact)
    if firewall is None:
        return artifact
    metadata = attach_mcp_skill_firewall_metadata(dict(artifact.metadata), firewall)
    return replace(artifact, metadata=metadata)


def scanner_evidence_for_mcp_skill_firewall(
    artifact: GuardArtifact,
    *,
    arguments: object | None = None,
    action_envelope: GuardActionEnvelope | None = None,
    risk_categories: tuple[str, ...] = (),
) -> dict[str, object]:
    enriched = enrich_artifact_with_mcp_skill_firewall(artifact)
    evidence: dict[str, object] = {}
    firewall = enriched.metadata.get("mcpSkillFirewall")
    if isinstance(firewall, dict):
        evidence["mcpSkillFirewall"] = firewall
    runtime_action = build_runtime_action_record(
        artifact=enriched,
        arguments=arguments,
        action_envelope=action_envelope,
        risk_categories=risk_categories,
    )
    if runtime_action is not None:
        evidence["runtimeAction"] = runtime_action
    return evidence


def _firewall_for_artifact(artifact: GuardArtifact) -> dict[str, object] | None:
    if artifact.artifact_type == "mcp_server":
        return _firewall_for_mcp_server(artifact)
    if artifact.artifact_type == "skill":
        return _firewall_for_skill(artifact)
    if artifact.artifact_type == "tool_call":
        return _firewall_for_tool_call(artifact)
    return None


def _firewall_for_mcp_server(artifact: GuardArtifact) -> dict[str, object] | None:
    if not isinstance(artifact.command, str) or not artifact.command.strip():
        return None
    env = _string_env(artifact.metadata.get("env"))
    transport = artifact.transport or ("http" if artifact.url else "stdio")
    server = _portal_mcp_server_identity_from_parts(
        config_path=artifact.config_path,
        command=artifact.command,
        args=artifact.args,
        transport=transport,
        env=env,
        publisher=artifact.publisher,
    )
    tool_names = _tool_names_from_metadata(artifact.metadata)
    tools = [
        portal_mcp_tool_identity(
            build_mcp_tool_identity(server_hash=str(server["identityHash"]), tool_name=tool_name),
            schema=None,
            description=None,
        )
        for tool_name in tool_names
    ]
    return build_mcp_skill_firewall_fingerprints(mcp_server=server, mcp_tools=tools)


def _firewall_for_skill(artifact: GuardArtifact) -> dict[str, object] | None:
    content = _read_text_file(artifact.config_path)
    if content is None:
        return None
    identity = _skill_protection_module().build_skill_identity(content, skill_path=artifact.config_path)
    skill = portal_skill_identity(identity, publisher=artifact.publisher)
    return build_mcp_skill_firewall_fingerprints(skill=skill)


def _firewall_for_tool_call(artifact: GuardArtifact) -> dict[str, object] | None:
    server_record = artifact.metadata.get("mcp_server_identity")
    tool_record = artifact.metadata.get("mcp_tool_identity")
    if isinstance(server_record, dict) and isinstance(tool_record, dict):
        server = _portal_server_from_legacy(server_record, artifact)
        tool = _portal_tool_from_legacy(tool_record, artifact.metadata)
        return build_mcp_skill_firewall_fingerprints(mcp_server=server, mcp_tools=[tool])
    if artifact.command is None:
        return None
    transport = artifact.transport or "stdio"
    server_identity = build_mcp_server_identity(
        config_path=artifact.config_path,
        command=artifact.metadata.get("server_name", artifact.name).__str__(),
        args=artifact.args,
        transport=transport,
        env=_string_env(artifact.metadata.get("env")),
    )
    server = portal_mcp_server_identity(
        server_identity,
        config_path=artifact.config_path,
        args=artifact.args,
        publisher=artifact.publisher,
    )
    tool_name = artifact.command
    tool_schema = artifact.metadata.get("tool_schema")
    tool_description = artifact.metadata.get("tool_description")
    description = tool_description if isinstance(tool_description, str) else None
    tool_identity = build_mcp_tool_identity(
        server_hash=str(server["identityHash"]),
        tool_name=tool_name,
        schema=tool_schema,
        description=description,
    )
    tool = portal_mcp_tool_identity(
        tool_identity,
        schema=tool_schema,
        description=description,
    )
    return build_mcp_skill_firewall_fingerprints(mcp_server=server, mcp_tools=[tool])


def _portal_server_from_legacy(record: dict[str, object], artifact: GuardArtifact) -> dict[str, object]:
    identity_hash = str(record.get("identity_hash") or record.get("identityHash") or "")
    command = str(record.get("command") or artifact.command or "unknown")
    args_hash = str(record.get("args_hash") or record.get("argsHash") or identity_hash)
    transport = str(record.get("transport") or artifact.transport or "unknown")
    raw_env_keys = record.get("env_keys") or record.get("envKeys")
    env_keys = [item for item in raw_env_keys if isinstance(item, str)] if isinstance(raw_env_keys, list) else []
    env_values_hash = _legacy_environment_values_hash(record, env_keys=env_keys)
    return {
        "argsHash": args_hash,
        "command": command,
        "commandHash": str(record.get("command_hash") or record.get("commandHash") or args_hash),
        "configPath": str(record.get("config_path") or record.get("configPath") or artifact.config_path),
        "dependencyHash": record.get("dependency_hash") or record.get("dependencyHash"),
        "envKeys": env_keys,
        "envValuesHash": env_values_hash,
        "identityHash": identity_hash,
        "packageName": record.get("package_name") or record.get("packageName"),
        "packageVersion": record.get("package_version") or record.get("packageVersion"),
        "publisherStableId": record.get("publisher_stable_id") or record.get("publisherStableId"),
        "transport": transport,
        "transportHash": str(record.get("transport_hash") or record.get("transportHash") or identity_hash),
    }


def _portal_tool_from_legacy(record: dict[str, object], metadata: dict[str, object]) -> dict[str, object]:
    schema = metadata.get("tool_schema")
    description = metadata.get("tool_description")
    return {
        "descriptionHash": record.get("description_hash") or record.get("descriptionHash"),
        "descriptorHash": record.get("descriptor_hash")
        or record.get("descriptorHash")
        or record.get("description_hash")
        or record.get("descriptionHash"),
        "hashScope": "full" if schema is not None or description else "manifest",
        "identityHash": record.get("identity_hash") or record.get("identityHash"),
        "schemaHash": record.get("schema_hash") or record.get("schemaHash"),
        "serverHash": record.get("server_hash") or record.get("serverHash"),
        "toolName": record.get("tool_name") or record.get("toolName"),
    }


def _legacy_server_identity(server: dict[str, object]) -> dict[str, object]:
    raw_env_keys = server.get("envKeys")
    env_keys = [item for item in raw_env_keys if isinstance(item, str)] if isinstance(raw_env_keys, list) else []
    return {
        "args_hash": server.get("argsHash"),
        "command": server.get("command"),
        "command_hash": server.get("commandHash"),
        "config_path": server.get("configPath"),
        "dependency_hash": server.get("dependencyHash"),
        "env_keys": env_keys,
        "env_values_hash": _legacy_environment_values_hash(server, env_keys=env_keys),
        "identity_hash": server.get("identityHash"),
        "package_name": server.get("packageName"),
        "package_version": server.get("packageVersion"),
        "publisher_stable_id": server.get("publisherStableId"),
        "transport": server.get("transport"),
        "transport_hash": server.get("transportHash"),
    }


def _legacy_environment_values_hash(record: dict[str, object], *, env_keys: list[str]) -> str:
    raw_hash = record.get("env_values_hash") or record.get("envValuesHash")
    if isinstance(raw_hash, str) and raw_hash.strip():
        return raw_hash.strip()
    return build_configured_environment_hash(None, configured_keys=env_keys)


def _legacy_tool_identity(tool: dict[str, object]) -> dict[str, object]:
    return {
        "description_hash": tool.get("descriptionHash"),
        "descriptor_hash": tool.get("descriptorHash"),
        "identity_hash": tool.get("identityHash"),
        "schema_hash": tool.get("schemaHash"),
        "server_hash": tool.get("serverHash"),
        "tool_name": tool.get("toolName"),
    }


def _legacy_skill_identity(skill: dict[str, object]) -> dict[str, object]:
    return {
        "dependency_hashes": skill.get("dependencyHashes") or [],
        "descriptor_hash": skill.get("descriptorHash"),
        "identity_hash": skill.get("identityHash"),
        "publisher_stable_id": skill.get("publisherStableId"),
        "skill_hash": skill.get("skillHash"),
        "stable_id": skill.get("stableId"),
    }


def _tool_names_from_metadata(metadata: dict[str, object]) -> list[str]:
    raw = metadata.get("tool_names") or metadata.get("toolNames")
    if not isinstance(raw, list):
        return []
    return [str(item) for item in raw if isinstance(item, str) and item.strip()]


def _string_env(value: object) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {str(key): str(item) for key, item in value.items() if isinstance(key, str) and isinstance(item, str)}


def _read_text_file(path: str) -> str | None:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _argument_paths(arguments: object) -> list[str]:
    if not isinstance(arguments, dict):
        return []
    paths: list[str] = []
    for key, value in arguments.items():
        normalized = str(key).lower()
        if any(token in normalized for token in ("path", "file", "target", "source")) and isinstance(value, str):
            paths.append(value)
    return paths


def _redacted_paths(paths: tuple[str, ...] | list[str]) -> list[str]:
    redacted: list[str] = []
    for path in paths:
        normalized = path.replace("\\", "/")
        segments = [segment for segment in normalized.split("/") if segment]
        redacted.append(f"[redacted]/{segments[-1]}" if segments else "[redacted-path]")
    return redacted


def _claimed_capabilities(artifact: GuardArtifact) -> list[str]:
    description = artifact.metadata.get("tool_description")
    if isinstance(description, str) and description.strip():
        return ["tool_description"]
    return []


def _observed_capabilities(risk_categories: tuple[str, ...], artifact: GuardArtifact) -> list[str]:
    observed = list(risk_categories)
    if artifact.artifact_type == "tool_call" and observed:
        return observed
    return observed


def _unique_strings(values: list[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        normalized = value.strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        ordered.append(normalized)
    return ordered


__all__ = [
    "attach_mcp_skill_firewall_metadata",
    "build_mcp_skill_firewall_fingerprints",
    "build_runtime_action_record",
    "enrich_artifact_with_mcp_skill_firewall",
    "portal_mcp_server_identity",
    "portal_mcp_tool_identity",
    "portal_skill_identity",
    "scanner_evidence_for_mcp_skill_firewall",
    "skill_identity_metadata",
]
