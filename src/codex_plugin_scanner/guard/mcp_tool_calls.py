"""Runtime Guard evaluation for MCP tool calls."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from hashlib import sha256
from pathlib import PurePath

from .config import GuardConfig
from .models import GUARD_ACTION_VALUES, GuardAction, GuardArtifact, GuardReceipt, PolicyDecision
from .receipts import build_receipt
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
) -> GuardArtifact:
    metadata = {"server_name": server_name}
    if server_id is not None:
        metadata["server_id"] = server_id
    if server_fingerprint is not None:
        metadata["server_fingerprint"] = server_fingerprint
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
            "arguments": arguments,
        },
        sort_keys=True,
    )
    return sha256(payload.encode("utf-8")).hexdigest()


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
        "destructive_mutation": "tool name implies destructive file or system changes",
        "command_execution": "tool name implies shell or command execution",
        "outbound_network": "call arguments imply outbound network activity",
        "secret_access": "call arguments mention sensitive local files or secrets",
        "privileged_system_mutation": "call arguments imply privileged system mutation",
    }
    return tuple(signals_by_category[category] for category in tool_call_risk_categories(artifact, arguments))


def tool_call_risk_categories(artifact: GuardArtifact, arguments: object) -> tuple[str, ...]:
    """Return normalized Cloud risk categories for one MCP tool call."""

    categories = _tool_call_risk_category_set(artifact, arguments)
    order = (
        "command_execution",
        "destructive_mutation",
        "outbound_network",
        "privileged_system_mutation",
        "secret_access",
    )
    return tuple(category for category in order if category in categories)


def _tool_call_risk_category_set(artifact: GuardArtifact, arguments: object) -> set[str]:
    tool_name = PurePath(artifact.command or artifact.name).name
    serialized_arguments = _serialized_tool_arguments(arguments)
    combined = f"{artifact.name.lower()} {serialized_arguments}"
    tool_name_tokens = set(_tool_name_tokens(tool_name))
    categories: set[str] = set()

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
    return categories


def _serialized_tool_arguments(arguments: object) -> str:
    if arguments is None:
        return ""
    try:
        return json.dumps(arguments, sort_keys=True, default=str).lower()
    except (TypeError, ValueError):
        return str(arguments).lower()


def _matches_any(value: str, patterns: tuple[str, ...]) -> bool:
    return any(re.search(pattern, value) is not None for pattern in patterns)


def _token_pattern(*tokens: str) -> str:
    alternatives = "|".join(re.escape(token) for token in tokens)
    return rf"(?<![a-z0-9])({alternatives})(?![a-z0-9])"


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
    camel_normalized = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", tool_name)
    return tuple(token for token in re.findall(r"[a-z0-9]+", camel_normalized.lower()) if token)


def _coerce_guard_action(value: str) -> GuardAction | None:
    for action in GUARD_ACTION_VALUES:
        if value == action:
            return action
    return None
