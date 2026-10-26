"""Shared fakes for the native extension-control bridge tests: a scripted resident and its bound replies."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from codex_plugin_scanner.guard import native_daemon_route as route
from codex_plugin_scanner.guard import native_extension_control as bridge
from codex_plugin_scanner.guard import native_resident_decision as shared
from codex_plugin_scanner.guard.runtime.extension_control_contract import (
    CONTROL_SCHEMA_VERSION,
    ControlLayerKind,
    ControlState,
    ControlTarget,
    ControlTargetKind,
    ExtensionControl,
    ExtensionControlLayer,
)

DIGEST = "a" * 64
EXTENSION = "command.git"
PERMISSION = "command.git.permission.push"
UNBOUND_DIGEST = "sha256:" + "0" * 64
COMPOSED: dict[str, object] = {"global_lockdown": False, "controls": [], "failures": []}


def make_layer(
    kind: ControlLayerKind = ControlLayerKind.LOCAL_ADMIN,
    *controls: ExtensionControl,
    lockdown: bool = False,
) -> ExtensionControlLayer:
    return ExtensionControlLayer(CONTROL_SCHEMA_VERSION, kind, DIGEST, lockdown, controls)


def make_disabled(kind: ControlTargetKind, target_id: str) -> ExtensionControl:
    return ExtensionControl(ControlTarget(kind, target_id), ControlState.DISABLED)


def make_registry() -> SimpleNamespace:
    return SimpleNamespace(
        catalog_digest=DIGEST,
        extensions=(
            SimpleNamespace(
                extension_id=EXTENSION,
                aliases=("command.legacy-git",),
                dependencies=("command.shell",),
                required=False,
            ),
            SimpleNamespace(extension_id="command.shell", aliases=(), dependencies=(), required=True),
        ),
        permissions=(
            SimpleNamespace(
                permission_id=PERMISSION,
                extension_id=EXTENSION,
                dependencies=("command.shell.permission.run",),
                implied_permissions=("command.git.permission.fetch",),
            ),
        ),
    )


def item_answer(**overrides: object) -> dict[str, object]:
    answer: dict[str, object] = {
        "blocked": False,
        "factor_reason_codes": [],
        "failures": [],
        "explicitly_enabled_permission_ids": [],
        "active": None,
    }
    answer.update(overrides)
    return answer


def bound_reply(request: dict[str, object], body: dict[str, object], **overrides: object) -> dict[str, object]:
    reply: dict[str, object] = {
        "schema": "guard-extension-control-result.v1",
        "request_id": request["request_id"],
        "request_sha256": "sha256:" + shared._canonical_request_sha256(request),
        "status": "ok",
        "code": "ok",
        "payload": body,
    }
    reply.update(overrides)
    return reply


def resident_answers(
    monkeypatch: pytest.MonkeyPatch, reply: Callable[[dict[str, object]], object]
) -> list[dict[str, object]]:
    """Answer every ask with ``reply(request)``; the returned list collects the requests."""

    requests: list[dict[str, object]] = []
    status = SimpleNamespace(
        available=True,
        compatible=True,
        identity=object(),
        capabilities=SimpleNamespace(features={"resident-protocol-v2", bridge.EXTENSION_CONTROL_FEATURE}),
    )

    def transport(*, request: dict[str, object], **_kwargs: object) -> object:
        requests.append(request)
        return reply(request)

    monkeypatch.setattr(shared, "native_runtime_status", lambda: status)
    monkeypatch.setattr(shared, "_resolve_digest_home", lambda _home: Path("/tmp/extension-control-home"))
    monkeypatch.setattr(shared, "ensure_resident_prerequisite", lambda _home: True)
    monkeypatch.setattr(shared, "record_resident", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(route, "_resident_request", transport)
    return requests


def resolve_payload(*scenarios: list[dict[str, object]], lockdown: bool = False) -> dict[str, object]:
    return {
        "kind": "resolve",
        "scenarios": [{"global_lockdown": lockdown, "results": list(results)} for results in scenarios],
    }


def request_query(request: dict[str, object]) -> dict[str, Any]:
    return cast(dict[str, Any], request["query"])


def echo_answers(request: dict[str, object]) -> dict[str, object]:
    """Answer every asked item, echoing its extension ids as reason codes so order is observable."""

    return bound_reply(
        request,
        resolve_payload(
            *[
                [
                    item_answer(
                        blocked=bool(item["extension_ids"]),
                        factor_reason_codes=list(item["extension_ids"]),
                        active=None if item["active_extension_id"] is None else True,
                    )
                    for item in scenario["items"]
                ]
                for scenario in request_query(request)["scenarios"]
            ]
        ),
    )
