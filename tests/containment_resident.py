"""Answer containment routing from the compiled resident in tests that patch the host.

Many routing tests patch ``sys.platform`` to replay another host's sink, and
point ``guard_home`` at a scratch directory with no enrolled resident. This
fixture keeps the routing answer the resident's own: every containment query
is sent to the session's resident, on the real platform, carrying the host the
test chose. Only the platform the transport runs on and the home it asks are
redirected; the routing table and the rewrite are never re-implemented.
"""

from __future__ import annotations

import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any, NamedTuple

import pytest

from codex_plugin_scanner.guard.native_hook_decision import _INVALID, NativeHookDecisionError
from tests import containment_rewrite_client as route_module


@pytest.fixture
def containment_resident(monkeypatch: pytest.MonkeyPatch, native_approval_reuse_runtime: Path) -> Path:
    """Route every containment question through the session resident; returns its home."""

    home = native_approval_reuse_runtime
    real_platform = sys.platform
    real_ask = route_module._ask

    def ask(
        kind: str,
        inputs: Mapping[str, object],
        guard_home: Path | None,
        validate: Any,
        deadline: float | None,
        feature: str = route_module.HOOK_DECISION_CONTAINMENT_ROUTE_FEATURE,
    ) -> dict[str, Any]:
        # The inputs already name the host the test chose; only the transport
        # runs on the real platform, against the session's resident.
        del guard_home, deadline
        with monkeypatch.context() as patch:
            patch.setattr(sys, "platform", real_platform)
            return real_ask(kind, inputs, home, validate, None, feature)

    monkeypatch.setattr(route_module, "_ask", ask)
    return home


_ROUTES = frozenset({"none", "sink", "grant"})


def native_containment_route(
    result: Mapping[str, object],
    *,
    event_name: object,
    recording_only: bool,
    guard_home: Path | None,
    deadline: float | None = None,
) -> str:
    """Ask the resident which containment step a native PreToolUse ``result`` takes.

    The resident stamps this route on every edge answer, so the hooks never
    ask it; tests ask it directly to read the routing table.
    """

    action = result.get("action")
    action_type = action.get("action_type") if isinstance(action, Mapping) else None
    inputs = {
        "event_name": route_module._text(event_name),
        "recording_only": bool(recording_only),
        "minimum_action": route_module._text(result.get("minimum_action")),
        "policy_action": route_module._text(result.get("policy_action")),
        "reason_code": route_module._text(result.get("reason_code")),
        "action_type": action_type,
    }

    def validate(payload: dict[str, Any]) -> None:
        route = payload.get("route")
        if set(payload) != {"kind", "route"} or not isinstance(route, str) or route not in _ROUTES:
            raise NativeHookDecisionError(_INVALID)

    return str(route_module._ask("containment_route", inputs, guard_home, validate, deadline)["route"])


class ContainmentSink(NamedTuple):
    """The profile the sink runs a call under, or why its receipt stands."""

    profile: str | None
    kept_because: str | None


def native_containment_sink(
    response: Mapping[str, object],
    *,
    harness: str,
    bridge: bool,
    payload: Mapping[str, object],
    guard_home: Path | None,
    deadline: float | None = None,
) -> ContainmentSink:
    """Ask the resident whether the sink takes the rendered receipt ``response`` for ``payload``.

    The hooks never ask this on its own: the resident answers it inside
    ``containment_rewrite``. Tests ask it directly to read the host and
    harness tables without writing a request snapshot.
    """

    tool_input = route_module._tool_input(payload)
    inputs = {
        **route_module._receipt_facts(response, harness=harness, bridge=bridge, payload=payload),
        "command_is_text": isinstance(tool_input, dict) and isinstance(tool_input.get("command"), str),
    }

    def validate(answer: dict[str, Any]) -> None:
        if set(answer) != {"kind", "profile", "kept_because"}:
            raise NativeHookDecisionError(_INVALID)
        route_module._validate_sink(answer, inputs)

    answer = route_module._ask("containment_sink", inputs, guard_home, validate, deadline)
    return ContainmentSink(answer["profile"], answer["kept_because"])
