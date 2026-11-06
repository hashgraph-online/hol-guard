"""Vectors for the resident's saved exact-action answer to a reviewed PreToolUse.

The resident's direct lane reads a saved decision's verdict as
``native_saved_decision_response`` does; these vectors record that from the
Python composition and ``hook_direct_saved_decision_tests.rs`` replays them.
The ``queries`` half is a frozen record of the exact-action query the daemon
once built for each reviewed hook request. The resident now derives that query
itself, and ``hook_direct_saved_query_tests.rs`` and ``hook_review_tests.rs``
replay the record. Set ``HOL_GUARD_WRITE_SAVED_DECISION_VECTORS=1`` to rewrite
the verdict half.
"""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard.daemon import hook_fail_closed, hook_native_saved_approval

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


def _recorded() -> dict[str, Any]:
    return json.loads(_FIXTURE.read_text(encoding="utf-8"))


def _vectors(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    return {
        "schema": "hol-guard.hook-direct-saved-decision-vectors.v1",
        "environment": _ENVIRONMENT,
        "control_digest": _CONTROL_DIGEST,
        "workspace": _WORKSPACE,
        "home_dir": _HOME,
        "token": _TOKEN,
        "artifact_id": _ARTIFACT_ID,
        "queries": _recorded()["queries"],
        "verdicts": [_verdict_vector(monkeypatch, case) for case in _VERDICT_CASES],
    }


def test_recorded_saved_decision_vectors_match_python(monkeypatch: pytest.MonkeyPatch) -> None:
    vectors = _vectors(monkeypatch)
    if os.environ.get("HOL_GUARD_WRITE_SAVED_DECISION_VECTORS") == "1":
        _FIXTURE.write_text(json.dumps(vectors, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    assert _recorded() == vectors


def test_vectors_cover_bound_and_unbound_reviews_and_every_outcome(monkeypatch: pytest.MonkeyPatch) -> None:
    vectors = _vectors(monkeypatch)
    bound = [vector for vector in vectors["queries"] if vector["query"] is not None]
    assert 0 < len(bound) < len(vectors["queries"])
    statuses = {vector["expected"]["status"] if vector["expected"] else None for vector in vectors["verdicts"]}
    assert statuses == {"accepted", "blocked", None}
