"""Vectors for the resident's saved exact-action answer to a reviewed PreToolUse.

The resident's direct lane builds the daemon's exact-action query and reads a
saved decision's verdict as ``native_exact_action`` and
``native_saved_decision_response`` do. These vectors record both from the
Python composition; ``hook_direct_saved_query_tests.rs`` and
``hook_direct_saved_decision_tests.rs`` replay them. Set
``HOL_GUARD_WRITE_SAVED_DECISION_VECTORS=1`` to rewrite the fixture.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import types
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard.daemon import (
    hook_fail_closed,
    hook_native_exact_action,
    hook_native_saved_approval,
)
from codex_plugin_scanner.guard.daemon.hook_native_review_approval import _native_review_tool_name
from tests.test_native_command_observations import _edge, _observations, _receipt

_FIXTURE = (
    Path(__file__).parents[1]
    / "rust"
    / "crates"
    / "guard-runtime"
    / "tests"
    / "fixtures"
    / "hook_direct_saved_decision_vectors.json"
)
_ENVIRONMENT = {"HOME": "/home/dev", "LANG": "C.UTF-8", "PATH": "/usr/bin:/bin"}
_CONTROL_DIGEST = "e" * 64
_WORKSPACE = "/work/repo"
_HOME = "/home/dev"
_TOKEN = "guard-exact-action:v1:" + "f" * 64


def _rehash(receipt: dict[str, Any]) -> dict[str, Any]:
    identity = {
        **{
            key: value
            for key, value in receipt.items()
            if key not in {"authority", "decision_id", "review_anchor_digest"}
        },
        "schema": "guard-native-hook-decision-identity.v1",
    }
    receipt["decision_id"] = hashlib.sha256(
        json.dumps(identity, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
    ).hexdigest()
    return receipt


def _reviewed(**changes: Any) -> tuple[dict[str, Any], dict[str, Any] | None]:
    observations = _observations()
    result = {**_edge(observations)["result"], "minimum_action": "review", "action": {"action_type": "shell"}}
    receipt: dict[str, Any] | None = _receipt(observations, review_anchor=True)
    for key, value in changes.items():
        if key == "receipt":
            receipt = value(receipt)
        else:
            result[key] = value
    return result, receipt


def _without_extensions() -> tuple[dict[str, Any], dict[str, Any]]:
    result, _ = _reviewed()
    result.pop("command_extensions")
    return result, _receipt(None, review_anchor=True)


def _receipt_with(**fields: Any):
    def change(receipt: dict[str, Any]) -> dict[str, Any]:
        changed = copy.deepcopy(receipt)
        for key, value in fields.items():
            if key == "uncertainty_count":
                changed["command_extensions"]["uncertainty_count"] = value
            else:
                changed[key] = value
        return _rehash(changed)

    return change


_QUERY_CASES: list[tuple[str, str, dict[str, Any], tuple[dict[str, Any], dict[str, Any] | None]]] = [
    (
        "bash-command",
        "claude-code",
        {"tool_name": "Bash", "tool_input": {"command": "npm test", "description": "run"}, "cwd": "/work/repo"},
        _reviewed(),
    ),
    (
        "camel-case-read",
        "claude-code",
        {"toolName": " Read ", "toolInput": {"file_path": "src/a.py", "limit": 20}},
        _reviewed(),
    ),
    ("arguments-cmd", "claude-code", {"tool": "shell", "arguments": {"cmd": "ls -la"}}, _reviewed()),
    (
        "top-level-command-blank-cwd",
        "claude-code",
        {"tool_name": "Bash", "command": "git status", "cwd": "   "},
        _reviewed(),
    ),
    (
        "blank-tool-name-later-command",
        "claude-code",
        {"tool_name": "  ", "tool_input": {"command": "  ", "shell_command": "make"}},
        _reviewed(),
    ),
    (
        "grep-nested-values",
        "claude-code",
        {
            "tool_name": "Grep",
            "tool_input": {"pattern": "x", "path": "src", "-n": True, "head_limit": 5, "glob": None, "z": [1, {}]},
        },
        _reviewed(),
    ),
    ("no-tool-input", "claude-code", {"tool_name": "WebFetch"}, _reviewed()),
    (
        "require-reapproval-no-action",
        "claude-code",
        {"tool_name": "Bash", "tool_input": {"command": "rm -rf build"}},
        _reviewed(minimum_action="require-reapproval", action=None),
    ),
    (
        "unbound-legacy-review",
        "claude-code",
        {"tool_name": "Bash", "tool_input": {"command": "npm test"}},
        _without_extensions(),
    ),
    (
        "receipt-decision-mismatch",
        "claude-code",
        {"tool_name": "Bash", "tool_input": {"command": "npm test"}},
        _reviewed(receipt=_receipt_with(decision="allow")),
    ),
    (
        "receipt-observe-mode-mismatch",
        "claude-code",
        {"tool_name": "Bash", "tool_input": {"command": "npm test"}},
        _reviewed(receipt=_receipt_with(observe_mode=True)),
    ),
    (
        "negative-uncertainty",
        "claude-code",
        {"tool_name": "Bash", "tool_input": {"command": "npm test"}},
        _reviewed(receipt=_receipt_with(uncertainty_count=-1)),
    ),
    ("harness-mismatch", "codex", {"tool_name": "Bash", "tool_input": {"command": "npm test"}}, _reviewed()),
    (
        "prompt-risk-classes",
        "claude-code",
        {"tool_name": "Bash", "tool_input": {"command": "npm test"}},
        _reviewed(prompt_risk_classes=["secrets"]),
    ),
    (
        "missing-receipt",
        "claude-code",
        {"tool_name": "Bash", "tool_input": {"command": "npm test"}},
        _reviewed(receipt=lambda _receipt: None),
    ),
]


def _query_vector(monkeypatch: pytest.MonkeyPatch, case) -> dict[str, Any]:
    name, harness, payload, (result, receipt) = case
    captured: list[dict[str, Any]] = []

    def answer(query: dict[str, Any], _guard_home: object) -> dict[str, Any]:
        captured.append(json.loads(json.dumps(query)))
        return {"token": _TOKEN, "once_only_reason": None}

    monkeypatch.setattr(hook_native_exact_action, "_answer", answer)
    monkeypatch.setattr(hook_native_exact_action, "os", types.SimpleNamespace(environ=dict(_ENVIRONMENT)))
    monkeypatch.setattr(hook_native_exact_action, "current_extension_control_binding_digest", lambda: _CONTROL_DIGEST)
    tool_name = _native_review_tool_name(payload)
    hook_native_exact_action.native_exact_action(
        harness=harness,
        tool_name=tool_name,
        payload=payload,
        native_result=result,
        native_receipt=receipt,
        workspace=Path(_WORKSPACE),
        home_dir=Path(_HOME),
    )
    (query,) = captured
    bound = query["policy_binding"]["state"] == "bound"
    return {
        "name": name,
        "harness": harness,
        "payload": payload,
        "result": result,
        "receipt": receipt,
        "artifact_id": f"{harness}:native-pretool:{tool_name}" if bound else None,
        "query": query if bound else None,
    }


class _Store:
    def __init__(self, lookup: object) -> None:
        self._lookup = lookup

    def resolve_policy_decision_lookup(self, *_args: object, **_kwargs: object) -> object:
        return copy.deepcopy(self._lookup)


_ARTIFACT_ID = "claude-code:native-pretool:Bash"


def _decision(**changes: Any) -> dict[str, Any]:
    decision = {
        "scope": "artifact",
        "artifact_id": _ARTIFACT_ID,
        "artifact_hash": _TOKEN,
        "action": "allow",
        "source": "approval-gate",
        "expires_at": None,
    }
    decision.update(changes)
    return decision


_REVIEW = {
    "decision": "deny",
    "minimum_action": "review",
    "policy_action": "review",
    "reason_code": "native_command_extension_review",
    "reason": "Review this command.",
    "action": {"action_type": "shell"},
}

_VERDICT_CASES: list[tuple[str, dict[str, Any], object]] = [
    ("allow", _REVIEW, {"decision": _decision()}),
    ("allow-require-reapproval", {**_REVIEW, "minimum_action": "require-reapproval"}, {"decision": _decision()}),
    ("allow-no-action", {key: value for key, value in _REVIEW.items() if key != "action"}, {"decision": _decision()}),
    ("allow-int-action-type", {**_REVIEW, "action": {"action_type": 7}}, {"decision": _decision()}),
    ("block", _REVIEW, {"decision": _decision(action="block")}),
    (
        "block-guard-control",
        {**_REVIEW, "action": {"action_type": "guard_control"}},
        {"decision": _decision(action="block")},
    ),
    (
        "block-policy-block",
        {**_REVIEW, "policy_action": "block"},
        {"decision": _decision(action="block", source="cli")},
    ),
    ("allow-expiring", _REVIEW, {"decision": _decision(expires_at="2030-01-01T00:00:00+00:00")}),
    ("allow-empty-expiry", _REVIEW, {"decision": _decision(expires_at="")}),
    ("allow-zero-expiry", _REVIEW, {"decision": _decision(expires_at=0)}),
    ("allow-cli-source", _REVIEW, {"decision": _decision(source="cli")}),
    (
        "allow-guard-control",
        {**_REVIEW, "action": {"action_type": "guard-control-operation"}},
        {"decision": _decision()},
    ),
    ("allow-package", {**_REVIEW, "action": {"action_type": "package"}}, {"decision": _decision()}),
    ("allow-policy-block", {**_REVIEW, "policy_action": "block"}, {"decision": _decision()}),
    ("allow-minimum-allow", {**_REVIEW, "minimum_action": "allow"}, {"decision": _decision()}),
    ("other-scope", _REVIEW, {"decision": _decision(scope="workspace")}),
    ("other-artifact", _REVIEW, {"decision": _decision(artifact_id="claude-code:native-pretool:Read")}),
    ("other-token", _REVIEW, {"decision": _decision(artifact_hash="other")}),
    ("ignored-integrity", _REVIEW, {"decision": _decision(), "ignored_local_integrity": True}),
    ("ignored-integrity-empty", _REVIEW, {"decision": _decision(), "ignored_local_integrity": []}),
    ("no-decision", _REVIEW, {"decision": None}),
    ("decision-not-mapping", _REVIEW, {"decision": ["allow"]}),
    ("lookup-not-mapping", _REVIEW, ["allow"]),
    ("other-action", _REVIEW, {"decision": _decision(action="review")}),
]


def _verdict_vector(monkeypatch: pytest.MonkeyPatch, case) -> dict[str, Any]:
    name, result, lookup = case
    monkeypatch.setattr(hook_native_saved_approval, "policy_decision_hash_exists", lambda *_a, **_k: True)
    monkeypatch.setattr(
        hook_fail_closed, "native_render_pre_tool", lambda _harness, verdict, **_kwargs: {"verdict": dict(verdict)}
    )
    response = hook_native_saved_approval.native_saved_decision_response(
        _Store(lookup),
        harness="claude-code",
        token=_TOKEN,
        artifact_id=_ARTIFACT_ID,
        native_result=result,
        workspace=Path(_WORKSPACE),
    )
    expected = None
    if response is not None:
        expected = {"verdict": response["verdict"], "status": response["approval_reuse_status"]}
    return {"name": name, "result": result, "lookup": lookup, "expected": expected}


def _vectors(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    return {
        "schema": "hol-guard.hook-direct-saved-decision-vectors.v1",
        "environment": _ENVIRONMENT,
        "control_digest": _CONTROL_DIGEST,
        "workspace": _WORKSPACE,
        "home_dir": _HOME,
        "token": _TOKEN,
        "artifact_id": _ARTIFACT_ID,
        "queries": [_query_vector(monkeypatch, case) for case in _QUERY_CASES],
        "verdicts": [_verdict_vector(monkeypatch, case) for case in _VERDICT_CASES],
    }


def test_recorded_saved_decision_vectors_match_python(monkeypatch: pytest.MonkeyPatch) -> None:
    vectors = _vectors(monkeypatch)
    if os.environ.get("HOL_GUARD_WRITE_SAVED_DECISION_VECTORS") == "1":
        _FIXTURE.write_text(json.dumps(vectors, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    assert json.loads(_FIXTURE.read_text(encoding="utf-8")) == vectors


def test_vectors_cover_bound_and_unbound_reviews_and_every_outcome(monkeypatch: pytest.MonkeyPatch) -> None:
    vectors = _vectors(monkeypatch)
    bound = [vector for vector in vectors["queries"] if vector["query"] is not None]
    assert 0 < len(bound) < len(vectors["queries"])
    statuses = {vector["expected"]["status"] if vector["expected"] else None for vector in vectors["verdicts"]}
    assert statuses == {"accepted", "blocked", None}
