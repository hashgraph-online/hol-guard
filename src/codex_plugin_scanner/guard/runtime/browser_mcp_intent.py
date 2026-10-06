"""Typed projections of native browser MCP semantics.

Python transports artifact/argument DTOs and renders the native result. Browser
classification, target redaction, profile detection, and sensitive surfaces are
owned by the bundled Rust runtime; native failure never means a safe/non-browser
match.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal

from ..models import GuardArtifact
from ..native_context import context_browser_mcp

BrowserIntent = Literal[
    "browser.navigation",
    "browser.inspect",
    "browser.interact",
    "browser.transfer",
    "browser.privileged",
]
BrowserMethod = Literal["navigate", "read", "interact", "submit", "upload", "download", "privileged"]
BrowserProfileMode = Literal["isolated", "dedicated", "remote-debugging", "shared", "unknown"]


@dataclass(frozen=True, slots=True)
class GuardBrowserAutomationIntentV1:
    """Native intent projected into the existing immutable presentation model."""

    version: int
    intent: BrowserIntent
    operation: str
    target_url: str | None = None
    target_origin: str | None = None
    target_domain: str | None = None
    target_path_prefix: str | None = None
    method: BrowserMethod | None = None
    profile_mode: BrowserProfileMode = "unknown"
    mcp_server_name: str = ""
    mcp_server_identity_hash: str | None = None
    mcp_tool_name: str = ""
    mcp_tool_identity_hash: str | None = None
    mcp_schema_hash: str | None = None
    sensitive_surface_flags: tuple[str, ...] = ()
    volatile_fields_dropped: tuple[str, ...] = ()


def _artifact_dto(artifact: GuardArtifact) -> dict[str, object]:
    return {"name": artifact.name, "command": artifact.command, "metadata": dict(artifact.metadata)}


def _argument_dto(arguments: object) -> dict[str, object]:
    if isinstance(arguments, Mapping):
        entries = [(str(key), value) for key, value in arguments.items()]
        return {"format": "mapping", "entries": json.loads(json.dumps(entries, default=str))}
    if isinstance(arguments, str):
        return {"format": "json", "text": arguments}
    return {"format": "other"}


def is_browser_mcp_server(artifact: GuardArtifact) -> bool:
    return context_browser_mcp({"operation": "server", "artifact": _artifact_dto(artifact)})["is_browser"]


def classify_browser_operation(operation: str, server_name: str = "") -> BrowserIntent | None:
    return context_browser_mcp(
        {
            "operation": "classify",
            "tool_operation": operation,
            "server_name": server_name,
        }
    )["intent"]


def normalize_browser_mcp_intent(
    artifact: GuardArtifact,
    arguments: object,
) -> GuardBrowserAutomationIntentV1 | None:
    model = context_browser_mcp(
        {
            "operation": "normalize",
            "artifact": _artifact_dto(artifact),
            "arguments": _argument_dto(arguments),
        }
    )["intent"]
    if model is None:
        return None
    return GuardBrowserAutomationIntentV1(
        version=model["version"],
        intent=model["intent"],
        operation=model["operation"],
        target_url=model["target_url"],
        target_origin=model["target_origin"],
        target_domain=model["target_domain"],
        target_path_prefix=model["target_path_prefix"],
        method=model["method"],
        profile_mode=model["profile_mode"],
        mcp_server_name=model["mcp_server_name"],
        mcp_server_identity_hash=model["mcp_server_identity_hash"],
        mcp_tool_name=model["mcp_tool_name"],
        mcp_tool_identity_hash=model["mcp_tool_identity_hash"],
        mcp_schema_hash=model["mcp_schema_hash"],
        sensitive_surface_flags=tuple(model["sensitive_surface_flags"]),
        volatile_fields_dropped=tuple(model["volatile_fields_dropped"]),
    )


def browser_intent_display_target(
    intent: GuardBrowserAutomationIntentV1,
    arguments: object,
) -> str:
    return context_browser_mcp(
        {
            "operation": "display",
            "intent": {
                "intent": intent.intent,
                "operation": intent.operation,
                "target_domain": intent.target_domain,
                "target_origin": intent.target_origin,
            },
            "arguments": _argument_dto(arguments),
        }
    )["target"]


__all__ = [
    "BrowserIntent",
    "BrowserMethod",
    "BrowserProfileMode",
    "GuardBrowserAutomationIntentV1",
    "browser_intent_display_target",
    "classify_browser_operation",
    "is_browser_mcp_server",
    "normalize_browser_mcp_intent",
]
