"""Runtime Guard evaluation for MCP tool calls."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from hashlib import sha256
from pathlib import PurePath

from .config import GuardConfig
from .models import GUARD_ACTION_VALUES, GuardAction, GuardArtifact, GuardReceipt, PolicyDecision
from .receipts import build_receipt
from .runtime.mcp_protection import (
    McpServerIdentity,
    build_mcp_tool_identity,
    mcp_server_identity_metadata,
    mcp_tool_identity_metadata,
)
from .store import GuardStore


@dataclass(frozen=True, slots=True)
class ToolCallDecision:
    """Decision for one MCP tool call."""

    action: GuardAction
    source: str
    signals: tuple[str, ...]
    summary: str
    risk_categories: tuple[str, ...] = ()


def build_tool_call_artifact(
    *,
    harness: str,
    server_name: str,
    tool_name: str,
    source_scope: str,
    config_path: str,
    transport: str,
    server_id: str | None = None,
    server_fingerprint: object | None = None,
    server_identity: McpServerIdentity | None = None,
    tool_schema: object | None = None,
    tool_description: str | None = None,
) -> GuardArtifact:
    metadata = {"server_name": server_name}
    if server_id is not None:
        metadata["server_id"] = server_id
    if server_fingerprint is not None:
        metadata["server_fingerprint"] = server_fingerprint
    if server_identity is not None:
        metadata["mcp_server_identity"] = mcp_server_identity_metadata(server_identity)
    if server_id is not None:
        server_hash = server_id
    elif server_identity is not None:
        server_hash = server_identity.identity_hash
    else:
        server_hash = server_id or sha256(f"{harness}:{source_scope}:{server_name}".encode()).hexdigest()
    tool_identity = build_mcp_tool_identity(
        server_hash=server_hash,
        tool_name=tool_name,
        schema=tool_schema,
        description=tool_description,
    )
    metadata["mcp_tool_identity"] = mcp_tool_identity_metadata(tool_identity)
    if tool_schema is not None:
        metadata["tool_schema"] = tool_schema
    if isinstance(tool_description, str) and tool_description.strip():
        metadata["tool_description"] = tool_description.strip()
    return GuardArtifact(
        artifact_id=f"{harness}:runtime:{source_scope}:{server_name}:{tool_name}",
        name=f"{server_name}:{tool_name}",
        harness=harness,
        artifact_type="tool_call",
        source_scope=source_scope,
        config_path=config_path,
        command=tool_name,
        transport=transport,
        metadata=metadata,
    )


def build_tool_call_hash(artifact: GuardArtifact, arguments: object) -> str:
    payload = json.dumps(
        {
            "artifact_id": artifact.artifact_id,
            "config_path": artifact.config_path,
            "transport": artifact.transport,
            "server_fingerprint": artifact.metadata.get("server_fingerprint"),
            "tool_identity": artifact.metadata.get("mcp_tool_identity"),
            "arguments": arguments,
        },
        sort_keys=True,
    )
    return sha256(payload.encode()).hexdigest()


def evaluate_tool_call(
    *,
    store: GuardStore,
    config: GuardConfig,
    artifact: GuardArtifact,
    artifact_hash: str,
    arguments: object,
) -> ToolCallDecision:
    override = store.resolve_policy(
        artifact.harness,
        artifact.artifact_id,
        artifact_hash=artifact_hash,
        workspace=str(config.workspace) if config.workspace is not None else None,
    )
    if override is None:
        override = config.resolve_action_override(artifact.harness, artifact.artifact_id, artifact.publisher)
    action = _coerce_guard_action(override) if isinstance(override, str) else None
    if action is not None:
        risk_categories = tool_call_risk_categories(artifact, arguments)
        return ToolCallDecision(
            action=action,
            source="policy",
            signals=tool_call_risk_signals(artifact, arguments),
            summary="Local Guard policy matched this exact tool call.",
            risk_categories=risk_categories,
        )

    signals = tool_call_risk_signals(artifact, arguments)
    risk_categories = tool_call_risk_categories(artifact, arguments)
    if len(signals) == 0:
        return ToolCallDecision(
            action="allow",
            source="heuristic",
            signals=(),
            summary="Guard did not detect a high-risk signal in this tool call.",
            risk_categories=(),
        )
    if config.mode == "prompt":
        return ToolCallDecision(
            action="review",
            source="heuristic",
            signals=signals,
            summary=tool_call_risk_summary(artifact, arguments),
            risk_categories=risk_categories,
        )
    return ToolCallDecision(
        action="block",
        source="heuristic",
        signals=signals,
        summary=tool_call_risk_summary(artifact, arguments),
        risk_categories=risk_categories,
    )


def tool_call_risk_signals(artifact: GuardArtifact, arguments: object) -> tuple[str, ...]:
    signals_by_category = {
        "filesystem_access": "call shape implies filesystem path access",
        "destructive_mutation": "tool name implies destructive file or system changes",
        "command_execution": "tool name implies shell or command execution",
        "outbound_network": "call arguments imply outbound network activity",
        "secret_access": "call arguments mention sensitive local files or secrets",
        "privileged_system_mutation": "call arguments imply privileged system mutation",
        "tool_schema_mismatch": "tool name understates dangerous schema capabilities",
    }
    return tuple(signals_by_category[category] for category in tool_call_risk_categories(artifact, arguments))


def tool_call_risk_categories(artifact: GuardArtifact, arguments: object) -> tuple[str, ...]:
    """Return normalized Cloud risk categories for one MCP tool call."""

    categories = _tool_call_risk_category_set(artifact, arguments)
    order = (
        "filesystem_access",
        "command_execution",
        "destructive_mutation",
        "outbound_network",
        "privileged_system_mutation",
        "secret_access",
        "tool_schema_mismatch",
    )
    return tuple(category for category in order if category in categories)


def _tool_call_risk_category_set(artifact: GuardArtifact, arguments: object) -> set[str]:
    tool_name = PurePath(artifact.command or artifact.name).name
    serialized_arguments = _serialized_tool_arguments(arguments)
    combined = _risk_match_text(f"{artifact.name} {serialized_arguments}")
    tool_name_tokens = set(_tool_name_tokens(tool_name))
    categories: set[str] = set()
    argument_categories = _argument_key_risk_categories(arguments)
    schema_categories = _schema_risk_categories(artifact.metadata.get("tool_schema"))
    description_categories = _description_risk_categories(artifact.metadata.get("tool_description"))

    if len(tool_name_tokens.intersection({"delete", "remove", "rm", "destroy", "erase"})) > 0:
        categories.add("destructive_mutation")
    if len(tool_name_tokens.intersection({"shell", "bash", "exec", "execute", "command", "powershell"})) > 0:
        categories.add("command_execution")
    if _matches_any(
        combined,
        (
            r"https?://",
            _token_pattern("curl", "wget", "fetch", "axios", "requests"),
        ),
    ):
        categories.add("outbound_network")
    if _matches_any(
        combined,
        (
            r"(?<![a-z0-9_-])\.env(?![a-z0-9_-])",
            r"(?<![a-z0-9_-])\.ssh(?![a-z0-9_-])",
            r"(?<![a-z0-9])(id[_-]?rsa|credentials|token|secret|passwd)(?![a-z0-9])",
            r"(?<![a-z0-9_-])\.(npmrc|pypirc)(?![a-z0-9_-])",
        ),
    ):
        categories.add("secret_access")
    if _matches_any(
        combined,
        (_token_pattern("sudo", "chmod", "chown", "launchctl", "systemctl"),),
    ):
        categories.add("privileged_system_mutation")
    categories.update(argument_categories)
    categories.update(schema_categories)
    categories.update(description_categories)
    if _tool_schema_understates_name(tool_name_tokens, schema_categories):
        categories.add("tool_schema_mismatch")
    return categories


def _serialized_tool_arguments(arguments: object) -> str:
    if arguments is None:
        return ""
    try:
        return json.dumps(arguments, sort_keys=True, default=str)
    except (TypeError, ValueError):
        return str(arguments)


def _matches_any(value: str, patterns: tuple[str, ...]) -> bool:
    return any(re.search(pattern, value) is not None for pattern in patterns)


def _token_pattern(*tokens: str) -> str:
    alternatives = "|".join(re.escape(token) for token in tokens)
    return rf"(?<![a-z0-9])({alternatives})(?![a-z0-9])"


def _argument_key_risk_categories(arguments: object) -> set[str]:
    if not isinstance(arguments, Mapping):
        return set()
    categories: set[str] = set()
    keys = _argument_key_names(arguments)
    if keys.intersection(
        {
            "file",
            "filepath",
            "filepaths",
            "files",
            "path",
            "paths",
            "source",
            "sourcepath",
            "sourcepaths",
            "sources",
            "target",
            "targetpath",
            "targetpaths",
            "targets",
        }
    ):
        categories.add("filesystem_access")
    if keys.intersection({"command", "cmd", "script", "shell"}):
        categories.add("command_execution")
    if keys.intersection({"callback", "endpoint", "uri", "url", "urls", "webhook"}):
        categories.add("outbound_network")
    return categories


def _argument_key_names(value: object) -> set[str]:
    names: set[str] = set()
    pending: list[object] = [value]
    visited_ids: set[int] = set()
    while pending:
        current = pending.pop()
        if isinstance(current, Mapping):
            current_id = id(current)
            if current_id in visited_ids:
                continue
            visited_ids.add(current_id)
            for key, item in current.items():
                names.add(_normalized_argument_key(str(key)))
                pending.append(item)
        elif isinstance(current, list | tuple):
            current_id = id(current)
            if current_id in visited_ids:
                continue
            visited_ids.add(current_id)
            pending.extend(current)
    return names


def _schema_risk_categories(schema: object) -> set[str]:
    keys = _schema_property_key_names(schema)
    categories: set[str] = set()
    if keys.intersection(
        {
            "file",
            "filepath",
            "filepaths",
            "files",
            "path",
            "paths",
            "source",
            "sourcepath",
            "sourcepaths",
            "sources",
            "target",
            "targetpath",
            "targetpaths",
            "targets",
        }
    ):
        categories.add("filesystem_access")
    if keys.intersection({"command", "cmd", "script", "shell"}):
        categories.add("command_execution")
    if keys.intersection({"callback", "endpoint", "uri", "url", "urls", "webhook"}):
        categories.add("outbound_network")
    return categories


def _schema_property_key_names(
    value: object,
    *,
    _root_schema: Mapping[str, object] | None = None,
    _visited_refs: set[str] | None = None,
    _visited_ids: set[int] | None = None,
) -> set[str]:
    names: set[str] = set()
    if isinstance(value, Mapping):
        root_schema = value if _root_schema is None else _root_schema
        visited_refs = set() if _visited_refs is None else _visited_refs
        visited_ids = set() if _visited_ids is None else _visited_ids
        val_id = id(value)
        if val_id in visited_ids:
            return names
        visited_ids.add(val_id)
        ref_value = value.get("$ref")
        if isinstance(ref_value, str) and ref_value not in visited_refs:
            visited_refs.add(ref_value)
            resolved = _resolve_local_schema_ref(root_schema, ref_value)
            if resolved is not None:
                names.update(
                    _schema_property_key_names(
                        resolved,
                        _root_schema=root_schema,
                        _visited_refs=visited_refs,
                        _visited_ids=visited_ids,
                    )
                )
        properties = value.get("properties")
        if isinstance(properties, Mapping):
            for key, item in properties.items():
                names.add(_normalized_argument_key(str(key)))
                names.update(
                    _schema_property_key_names(
                        item,
                        _root_schema=root_schema,
                        _visited_refs=visited_refs,
                        _visited_ids=visited_ids,
                    )
                )
        for collection_key in (
            "additionalProperties",
            "allOf",
            "anyOf",
            "contains",
            "else",
            "if",
            "items",
            "oneOf",
            "prefixItems",
            "propertyNames",
            "then",
            "unevaluatedItems",
            "unevaluatedProperties",
        ):
            child = value.get(collection_key)
            names.update(
                _schema_property_key_names(
                    child,
                    _root_schema=root_schema,
                    _visited_refs=visited_refs,
                    _visited_ids=visited_ids,
                )
            )
        dependent_schemas = value.get("dependentSchemas")
        if isinstance(dependent_schemas, Mapping):
            for child in dependent_schemas.values():
                names.update(
                    _schema_property_key_names(
                        child,
                        _root_schema=root_schema,
                        _visited_refs=visited_refs,
                        _visited_ids=visited_ids,
                    )
                )
        pattern_properties = value.get("patternProperties")
        if isinstance(pattern_properties, Mapping):
            for child in pattern_properties.values():
                names.update(
                    _schema_property_key_names(
                        child,
                        _root_schema=root_schema,
                        _visited_refs=visited_refs,
                        _visited_ids=visited_ids,
                    )
                )
        return names
    if isinstance(value, list | tuple):
        root_schema = _root_schema
        visited_refs = set() if _visited_refs is None else _visited_refs
        visited_ids = set() if _visited_ids is None else _visited_ids
        for item in value:
            names.update(
                _schema_property_key_names(
                    item,
                    _root_schema=root_schema,
                    _visited_refs=visited_refs,
                    _visited_ids=visited_ids,
                )
            )
    return names


def _resolve_local_schema_ref(root_schema: Mapping[str, object], reference: str) -> object | None:
    if reference.startswith("#/"):
        current: object = root_schema
        for part in reference[2:].split("/"):
            token = part.replace("~1", "/").replace("~0", "~")
            if isinstance(current, Mapping):
                if token not in current:
                    return None
                current = current[token]
            elif isinstance(current, list | tuple):
                if not token.isdigit():
                    return None
                index = int(token)
                if index >= len(current):
                    return None
                current = current[index]
            else:
                return None
        return current
    if not reference.startswith("#"):
        return None
    anchor_name = reference[1:]
    if not anchor_name:
        return root_schema
    return _resolve_local_schema_anchor(root_schema, anchor_name)


def _resolve_local_schema_anchor(root_schema: object, anchor_name: str) -> object | None:
    pending: list[object] = [root_schema]
    visited_ids: set[int] = set()
    while pending:
        current = pending.pop()
        current_id = id(current)
        if current_id in visited_ids:
            continue
        visited_ids.add(current_id)
        if not isinstance(current, Mapping):
            if isinstance(current, list | tuple):
                pending.extend(item for item in current if isinstance(item, (Mapping, list, tuple)))
            continue
        anchor = current.get("$anchor")
        dynamic_anchor = current.get("$dynamicAnchor")
        if anchor == anchor_name or dynamic_anchor == anchor_name:
            return current
        pending.extend(item for item in current.values() if isinstance(item, (Mapping, list, tuple)))
    return None


def _description_risk_categories(description: object) -> set[str]:
    if not isinstance(description, str):
        return set()
    normalized = _risk_match_text(description)
    categories: set[str] = set()
    if _matches_any(normalized, (r"\bread files?\b", r"\bopen files?\b", r"\bview files?\b")):
        categories.add("filesystem_access")
    if _matches_any(normalized, (_token_pattern("delete", "remove", "write"),)):
        categories.add("destructive_mutation")
    if _matches_any(normalized, (r"\brun command", _token_pattern("execute", "shell"))):
        categories.add("command_execution")
    return categories


def _tool_schema_understates_name(tool_name_tokens: set[str], schema_categories: set[str]) -> bool:
    dangerous_categories = {"command_execution", "destructive_mutation", "outbound_network"}
    if len(schema_categories.intersection(dangerous_categories)) == 0:
        return False
    name_sounds_dangerous = (
        len(
            tool_name_tokens.intersection(
                {
                    "bash",
                    "cmd",
                    "command",
                    "delete",
                    "destroy",
                    "exec",
                    "execute",
                    "patch",
                    "remove",
                    "rm",
                    "run",
                    "script",
                    "shell",
                    "write",
                }
            )
        )
        > 0
    )
    return not name_sounds_dangerous


def _normalized_argument_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", _risk_match_text(value))


def tool_call_risk_summary(artifact: GuardArtifact, arguments: object) -> str:
    signals = tool_call_risk_signals(artifact, arguments)
    if len(signals) == 0:
        return "No high-risk signal was detected in this tool call."
    if len(signals) == 1:
        return signals[0].capitalize() + "."
    return f"{signals[0].capitalize()}, and it also {', and it also '.join(signals[1:])}."


def allow_tool_call(
    *,
    store: GuardStore,
    artifact: GuardArtifact,
    artifact_hash: str,
    decision_source: str,
    now: str,
    signals: tuple[str, ...],
    remember: bool,
    risk_categories: tuple[str, ...] = (),
) -> GuardReceipt:
    if remember:
        store.upsert_policy(
            PolicyDecision(
                harness=artifact.harness,
                scope="artifact",
                action="allow",
                artifact_id=artifact.artifact_id,
                artifact_hash=artifact_hash,
                workspace=None,
                reason=f"Approved via Guard runtime ({decision_source})",
                source="runtime-inline",
            ),
            now,
        )
    store.record_inventory_artifact(
        artifact=artifact,
        artifact_hash=artifact_hash,
        policy_action="allow",
        changed=False,
        now=now,
        approved=True,
    )
    receipt = build_receipt(
        harness=artifact.harness,
        artifact_id=artifact.artifact_id,
        artifact_hash=artifact_hash,
        policy_decision="allow",
        capabilities_summary=f"mcp tool call • {artifact.name}",
        changed_capabilities=["runtime_tool_call", decision_source, *signals],
        provenance_summary=f"runtime tool call allowed from {artifact.config_path}",
        artifact_name=artifact.name,
        source_scope=artifact.source_scope,
        user_override="inline-approve" if decision_source == "inline-approved" else None,
    )
    store.add_receipt(receipt)
    store.add_event(
        "runtime_tool_call_allowed",
        {
            "artifact_id": artifact.artifact_id,
            "artifact_hash": artifact_hash,
            "decision_source": decision_source,
            "risk_categories": list(risk_categories),
            "signals": list(signals),
        },
        now,
    )
    return receipt


def block_tool_call(
    *,
    store: GuardStore,
    artifact: GuardArtifact,
    artifact_hash: str,
    decision_source: str,
    now: str,
    signals: tuple[str, ...],
    risk_categories: tuple[str, ...] = (),
) -> GuardReceipt:
    store.record_inventory_artifact(
        artifact=artifact,
        artifact_hash=artifact_hash,
        policy_action="block",
        changed=False,
        now=now,
        approved=False,
    )
    receipt = build_receipt(
        harness=artifact.harness,
        artifact_id=artifact.artifact_id,
        artifact_hash=artifact_hash,
        policy_decision="block",
        capabilities_summary=f"mcp tool call • {artifact.name}",
        changed_capabilities=["runtime_tool_call", decision_source, *signals],
        provenance_summary=f"runtime tool call blocked from {artifact.config_path}",
        artifact_name=artifact.name,
        source_scope=artifact.source_scope,
        user_override="inline-deny" if decision_source == "inline-denied" else None,
    )
    store.add_receipt(receipt)
    store.add_event(
        "runtime_tool_call_blocked",
        {
            "artifact_id": artifact.artifact_id,
            "artifact_hash": artifact_hash,
            "decision_source": decision_source,
            "risk_categories": list(risk_categories),
            "signals": list(signals),
        },
        now,
    )
    return receipt


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        ordered.append(value)
    return ordered


def _tool_name_tokens(tool_name: str) -> tuple[str, ...]:
    camel_normalized = _camel_token_normalized(tool_name)
    return tuple(token for token in re.findall(r"[a-z0-9]+", camel_normalized.lower()) if token)


def _risk_match_text(value: str) -> str:
    return _camel_token_normalized(value).lower()


def _camel_token_normalized(value: str) -> str:
    return re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", value)


def _coerce_guard_action(value: str) -> GuardAction | None:
    for action in GUARD_ACTION_VALUES:
        if value == action:
            return action
    return None
