"""What the relay package evidence drain is given, and what it is allowed to call.

The receipt tests live in ``test_mcp_relay_package_evidence_drain``; the approval
and observation modes live in ``test_mcp_relay_package_evidence_modes``. Both
rebuild the same record, so the record builders and the patched parser, artifact
builder, projector and tool-call recorders are stated once here.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any, ClassVar

import pytest

from codex_plugin_scanner.guard import mcp_tool_calls, native_mcp_tool_call_identity
from codex_plugin_scanner.guard.daemon import mcp_relay_package_evidence_drain
from codex_plugin_scanner.guard.proxy import runtime_mcp_projection
from codex_plugin_scanner.guard.runtime import package_intent_common, package_intent_parser

COMMAND = "npm install left-pad"
CONFIG_PATH = "/work/.codex/config.toml"
SOURCE_SCOPE = "project"
ARTIFACT_ID = "package-request:npm:left-pad"
ARTIFACT = SimpleNamespace(harness="codex", config_path=CONFIG_PATH, source_scope=SOURCE_SCOPE)
TOKEN = "guard-approval-context:v1:token"
WORKSPACE = "package-request-workspace:v2:abc"
EVIDENCE = [{"kind": "package_execution_context", "portable": True}]
PATH = "/usr/bin:/bin"


def _decision(action: str = "allow", **fields: object) -> dict[str, object]:
    return {
        "action": action,
        "policy_action": action,
        "source": "policy",
        "signals": ["tool signal"],
        "summary": "summary",
        "risk_categories": ["network"],
        "normalization_reason_code": None,
        "original_action": None,
        "approval_reuse_status": None,
        "approval_reuse_reason_code": None,
        "current_action": None,
        "saved_action": None,
        "pending_approval_reuse_decision": None,
        "approval_reuse_claim_disposition": None,
        "post_claim_revalidated": False,
        "post_claim_authority": None,
        **fields,
    }


def _package(**fields: object) -> dict[str, object]:
    return {
        "artifact_id": ARTIFACT_ID,
        "artifact_hash": TOKEN,
        "workspace": "/work",
        "path": PATH,
        "evaluation": {"decision": "warn"},
        "evidence": EVIDENCE,
        "signals": ["left-pad has an advisory"],
        "policy_workspace": WORKSPACE,
        **fields,
    }


def _record(**fields: object) -> dict[str, object]:
    return {
        "kind": "mcp_package_call",
        "harness": "codex",
        "outcome": "forward",
        "decision_source": "policy-warn",
        "policy_action": "warn",
        "tool_name": "shell",
        "params": {"name": "shell", "arguments": {"command": COMMAND, "cwd": "/work"}},
        "arguments": {"format": "mapping", "entries": [["cwd", "/work"], ["command", COMMAND]]},
        "identity": {"wire": True},
        "decision": _decision(),
        "package": _package(),
        **fields,
    }


class _Projector:
    projected: ClassVar[list[tuple[str, object, object]]] = []

    def __init__(self, guard_home: Path) -> None:
        self.guard_home = guard_home

    def project(self, tool_name: str, params: object, artifact: object = None) -> SimpleNamespace:
        _Projector.projected.append((tool_name, params, artifact))
        # The proxy projects a call with its artifact to carry risk
        # categories; a projection without one carries none.
        return SimpleNamespace(
            safe_arguments={"safe": True, "artifact": artifact is not None},
            risk_categories=["supply-chain"] if artifact is not None else [],
        )


@pytest.fixture
def parsed() -> dict[str, Any]:
    """What the drain asks the package parser and artifact builder for."""

    return {"extract": [], "build": [], "intent": SimpleNamespace(package_manager="npm"), "artifact_id": ARTIFACT_ID}


@pytest.fixture
def calls(monkeypatch: pytest.MonkeyPatch, parsed: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    recorded: list[tuple[str, dict[str, Any]]] = []
    _Projector.projected = []

    def decode(payload: object, *, expect_hash: bool, token: bool) -> SimpleNamespace:
        assert payload == {"wire": True} and expect_hash and token
        return SimpleNamespace(artifact=ARTIFACT, artifact_hash=TOKEN)

    def extract(tool_name: object, arguments: object, **kwargs: object) -> object:
        parsed["extract"].append((tool_name, arguments, kwargs))
        return parsed["intent"]

    def build(
        *, harness: str, intent: object, config_path: str, source_scope: str, guard_home: object = None
    ) -> SimpleNamespace:
        parsed["build"].append((harness, intent, config_path, source_scope))
        return SimpleNamespace(artifact_id=parsed["artifact_id"], artifact_type="package_request")

    monkeypatch.setattr(native_mcp_tool_call_identity, "_decode", decode)
    monkeypatch.setattr(package_intent_parser, "extract_package_intent_request", extract)
    monkeypatch.setattr(package_intent_common, "build_package_request_artifact", build)
    monkeypatch.setattr(runtime_mcp_projection, "McpCallProjector", _Projector)
    monkeypatch.setattr(mcp_tool_calls, "allow_tool_call", lambda **kwargs: recorded.append(("allow", kwargs)))
    monkeypatch.setattr(mcp_tool_calls, "block_tool_call", lambda **kwargs: recorded.append(("block", kwargs)))
    return recorded


def _reviewed(**fields: object) -> dict[str, object]:
    """The record a request blocked in place under `safe-alternative` leaves."""

    package = _package()
    del package["policy_workspace"]
    queued: dict[str, object] = {
        "outcome": "block",
        "decision_source": "policy-safe-alternative",
        "policy_action": "review",
        "decision": _decision("review"),
        "package": package,
        "review": {"redaction_level": "partial"},
    }
    queued.update(fields)
    return _record(**queued)


@pytest.fixture
def reviews(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    """The inbox rows the drain writes after a queued request's receipt."""

    written: list[dict[str, Any]] = []

    def record_review(
        store: object,
        artifact: object,
        artifact_hash: str,
        projection: object,
        signals: object,
        **kwargs: object,
    ) -> None:
        written.append(
            {
                "store": store,
                "artifact": artifact,
                "artifact_hash": artifact_hash,
                "projection": projection,
                "signals": signals,
                **kwargs,
            }
        )

    monkeypatch.setattr(mcp_relay_package_evidence_drain, "_record_unprompted_review", record_review)
    return written
