"""What the MCP proxy shows and binds for one ``tools/call``, in one round trip.

The resident's ``call_projection`` check masks the arguments and params,
builds the launch target, normalizes the browser intent and renders the risk
evidence together. Handling one message asks for the same projection from
several places, so the proxy keeps the last few answers; the projection is a
pure function of its query.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from ..models import GuardArtifact
from ..native_context import _MCP_RISK_CATEGORIES
from ..native_mcp_proxy_decision import NativeMcpProxyDecisionError, native_mcp_proxy_decide
from ..native_mcp_tool_evidence import risk_input

_UNAVAILABLE = "native_mcp_arguments_projection_unavailable"
_MEMO_SIZE = 8


@dataclass(frozen=True, slots=True)
class McpCallProjection:
    safe_arguments: object
    safe_params: dict[str, object]
    launch_target: str
    browser_launch_target: str | None
    browser_intent: dict[str, object] | None
    # Empty unless the call was projected with its artifact.
    risk_categories: tuple[str, ...]
    risk_summary: str

    @property
    def display_launch_target(self) -> str:
        """The browser label for a browser navigation, else the plain target."""
        return self.browser_launch_target or self.launch_target


class McpCallProjector:
    """Answers ``call_projection`` for one proxy, reusing recent answers."""

    def __init__(self, guard_home: Path) -> None:
        self._guard_home = guard_home
        self._memo: dict[str, McpCallProjection] = {}

    def project(
        self,
        tool_name: str,
        params: object,
        artifact: GuardArtifact | None = None,
    ) -> McpCallProjection:
        params = params if isinstance(params, dict) else {}
        risk = None if artifact is None else risk_input(artifact, params.get("arguments"))
        query = {"check": "call_projection", "tool_name": tool_name, "params": params, "risk": risk}
        try:
            key = json.dumps(query)
        except (TypeError, ValueError) as error:
            raise ValueError(_UNAVAILABLE) from error
        cached = self._memo.get(key)
        if cached is not None:
            return cached
        try:
            payload = native_mcp_proxy_decide(query, guard_home=self._guard_home)
            projection = _projection(payload)
        except (NativeMcpProxyDecisionError, KeyError, TypeError) as error:
            raise ValueError(_UNAVAILABLE) from error
        if len(self._memo) >= _MEMO_SIZE:
            self._memo.clear()
        self._memo[key] = projection
        return projection


def review_artifact_payload(
    projection: McpCallProjection,
    artifact: Any,
    artifact_hash: str,
    signals: tuple[str, ...],
    *,
    policy_action: str,
    scanner_evidence: tuple[dict[str, object], ...] = (),
) -> dict[str, Any]:
    """The evaluation item a queued ``tools/call`` is written to the inbox with.

    Includes browser intent metadata when the MCP tool call is a browser
    automation call (HGBM063-HGBM065). ``projection`` is the call projected
    with its artifact.
    """

    changed_fields: list[str] = ["runtime_tool_call"]
    if projection.browser_intent is not None:
        changed_fields.append("runtime_browser_tool_call")
    payload: dict[str, Any] = {
        "artifact_id": artifact.artifact_id,
        "artifact_name": artifact.name,
        "artifact_hash": artifact_hash,
        "artifact_type": artifact.artifact_type,
        "source_scope": artifact.source_scope,
        "config_path": artifact.config_path,
        "changed_fields": changed_fields,
        "policy_action": policy_action,
        "launch_target": projection.display_launch_target,
        "risk_summary": projection.risk_summary,
        "risk_signals": list(signals),
    }
    if projection.browser_intent is not None:
        payload["browser_intent"] = projection.browser_intent
    if scanner_evidence:
        payload["scanner_evidence"] = list(scanner_evidence)
    return payload


def _projection(payload: dict[str, Any]) -> McpCallProjection:
    launch_target = payload["launch_target"]
    safe_params = payload["safe_params"]
    browser = payload["browser"]
    risk = payload["risk"]
    if not isinstance(launch_target, str) or not isinstance(safe_params, dict) or "safe_arguments" not in payload:
        raise TypeError("call_projection")
    if browser is not None and (not isinstance(browser, dict) or not isinstance(browser["intent"], dict)):
        raise TypeError("call_projection")
    if risk is not None and (
        not isinstance(risk, dict)
        or not isinstance(risk["summary"], str)
        or not isinstance(risk["risk_categories"], list)
        or any(category not in _MCP_RISK_CATEGORIES for category in risk["risk_categories"])
    ):
        raise TypeError("call_projection")
    return McpCallProjection(
        safe_arguments=payload["safe_arguments"],
        safe_params=cast(dict[str, object], safe_params),
        launch_target=launch_target,
        browser_launch_target=None if browser is None else str(browser["launch_target"]),
        browser_intent=None if browser is None else cast(dict[str, object], browser["intent"]),
        risk_categories=() if risk is None else tuple(risk["risk_categories"]),
        risk_summary="" if risk is None else risk["summary"],
    )
