"""Transport package evaluator and saved-approval evidence into hook settlement."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_package_review_plan as package_review
from codex_plugin_scanner.guard.native_package_review_plan import NativePackageReviewPlanError
from codex_plugin_scanner.guard.native_supply_chain_registry_cache import RegistryDeadlineError

SAFE_FLAGS = "--ignore-scripts --allow-git=none"
REVIEW = {"reason_code": "native_package_review", "minimum_action": "review"}
KEY = {"harness": "omp", "artifact_id": "omp:project:package-request:abc", "artifact_hash": "token"}
ARTIFACT = SimpleNamespace(
    metadata={"redacted_command": "npm ci --ignore-scripts"}, harness=KEY["harness"], artifact_id=KEY["artifact_id"]
)


def _plan(answer: object):
    """A stand-in for the resident's plan, which the Rust tests cover."""

    def plan(*_args: object, **_kwargs: object) -> object:
        if isinstance(answer, Exception):
            raise answer
        return answer

    return plan


def _respond(tmp_path: Path, native_result: dict[str, object] = REVIEW, *, guard_home: Path | None = None):
    return _outcome(tmp_path, native_result, guard_home=guard_home).response


def _outcome(tmp_path: Path, native_result: dict[str, object] = REVIEW, *, guard_home: Path | None = None):
    return package_review.native_package_review_response(
        object(),
        harness="omp",
        payload={"tool_input": {"command": f"npm install zod {SAFE_FLAGS}"}},
        native_result=native_result,
        workspace=tmp_path,
        guard_home=guard_home if guard_home is not None else tmp_path / "guard",
    )


@pytest.mark.parametrize(
    "native_result",
    [
        {"reason_code": "native_file_read_review", "minimum_action": "review"},
        {"reason_code": "native_package_review", "minimum_action": "block"},
        {"reason_code": "native_command_review_required", "minimum_action": "block"},
    ],
)
def test_only_a_package_or_command_review_is_planned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, native_result: dict[str, object]
) -> None:
    monkeypatch.setattr(package_review, "package_review_plan", _plan(AssertionError("planned")))

    assert _respond(tmp_path, native_result) is None


@pytest.mark.parametrize("reason_code", ["native_package_review", "native_command_review_required"])
def test_the_plan_is_told_which_review_it_settles(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reason_code: str
) -> None:
    """The resident plans a command review only for `npx`/`bunx`, block-only."""

    reasons: list[object] = []

    def plan(*_args: object, **kwargs: object) -> package_review.PackageReviewPlan:
        reasons.append(kwargs["review_reason"])
        return package_review.PackageReviewPlan(None, False, tmp_path, False)

    monkeypatch.setattr(package_review, "package_review_plan", plan)

    assert _respond(tmp_path, {"reason_code": reason_code, "minimum_action": "review"}) is None
    assert reasons == [reason_code]


@pytest.mark.parametrize(
    "answer",
    [package_review.PackageReviewPlan(None, False, Path("/w"), False), NativePackageReviewPlanError("unavailable")],
)
def test_a_review_with_no_plan_stays_queued(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, answer: object) -> None:
    monkeypatch.setattr(package_review, "package_review_plan", _plan(answer))
    monkeypatch.setattr(package_review, "_evaluate", _plan(AssertionError("evaluated")))

    assert _respond(tmp_path) is None


def test_a_block_only_review_still_downloading_stays_queued(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Asking for a retry would only ever lead to a block or the same review."""

    monkeypatch.setattr(
        package_review, "package_review_plan", _plan(package_review.PackageReviewPlan(ARTIFACT, False, tmp_path, True))
    )
    monkeypatch.setattr(package_review, "_evaluate", _plan(RegistryDeadlineError()))

    assert _respond(tmp_path) is None


@pytest.mark.parametrize(
    ("settlement", "expected"),
    [
        (("allow", None), {"decision": "allow"}),
        (
            ("guide", "Rerun with the flags."),
            {"decision": "deny", "reason": "Rerun with the flags.", "prompted": False},
        ),
        (
            ("block", "zod@9.9.9 is malicious."),
            {"decision": "deny", "reason": "zod@9.9.9 is malicious.", "prompted": False},
        ),
        (("review", None), None),
    ],
)
@pytest.mark.parametrize("may_allow", [True, False])
def test_the_resident_settlement_settles_the_review(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    native_context_digest: Path,
    settlement: tuple[str, str | None],
    expected: dict | None,
    may_allow: bool,
) -> None:
    """Which verdict settles a review is the resident's call; the Rust tests cover it."""

    evaluated: list[object] = []
    monkeypatch.setattr(
        package_review,
        "package_review_plan",
        _plan(package_review.PackageReviewPlan(ARTIFACT, may_allow, tmp_path, False)),
    )
    monkeypatch.setattr(
        package_review,
        "_evaluate",
        lambda _store, *, artifact, workspace: (
            evaluated.append((artifact, workspace)) or SimpleNamespace(review_settlement=settlement)
        ),
    )

    response = _respond(tmp_path, {**REVIEW, "padding": "x" * (512 * 1024)}, guard_home=native_context_digest)

    assert evaluated == [(ARTIFACT, tmp_path)]
    # Without the resident's npm proof only a block applies; stopping a
    # command runs nothing.
    if expected is None or (not may_allow and settlement[0] != "block"):
        assert response is None
    else:
        assert response is not None
        assert {field: response[field] for field in expected} == expected


@pytest.mark.parametrize("may_allow", [True, False])
@pytest.mark.parametrize("settlement", [("review", None), ("allow", None)])
def test_a_saved_package_always_allow_lets_the_install_continue(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    native_context_digest: Path,
    may_allow: bool,
    settlement: tuple[str, None],
) -> None:
    """An Always allow saved under the package key answers the same install in
    another checkout, even where only a block verdict applies."""

    linked = tmp_path / "linked"
    looked_up: list[Path] = []
    monkeypatch.setattr(
        package_review,
        "package_review_plan",
        _plan(package_review.PackageReviewPlan(ARTIFACT, may_allow, linked, True)),
    )
    monkeypatch.setattr(package_review, "_evaluate", _plan(SimpleNamespace(review_settlement=settlement)))

    def reuse(_store, _artifact, _evaluation, install_dir, _argv, _env):
        looked_up.append(install_dir)
        return {"artifact_hash": KEY["artifact_hash"], "found": True, "policy_action": "allow"}

    monkeypatch.setattr(package_review, "_package_reuse_evidence", reuse)

    outcome = _outcome(tmp_path, guard_home=native_context_digest)

    assert looked_up == [linked]
    assert outcome.response is not None
    assert outcome.response["decision"] == "allow"


def test_a_queued_install_review_carries_its_package_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, native_context_digest: Path
) -> None:
    monkeypatch.setattr(
        package_review, "package_review_plan", _plan(package_review.PackageReviewPlan(ARTIFACT, False, tmp_path, True))
    )
    monkeypatch.setattr(package_review, "_evaluate", _plan(SimpleNamespace(review_settlement=("review", None))))
    monkeypatch.setattr(
        package_review, "_package_reuse_evidence", _plan({"artifact_hash": KEY["artifact_hash"], "found": False})
    )

    assert _outcome(tmp_path, guard_home=native_context_digest) == package_review.PackageReviewOutcome(None, KEY)


def test_a_block_is_never_overridden_by_a_saved_approval(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, native_context_digest: Path
) -> None:
    monkeypatch.setattr(
        package_review, "package_review_plan", _plan(package_review.PackageReviewPlan(ARTIFACT, True, tmp_path, True))
    )
    monkeypatch.setattr(package_review, "_evaluate", _plan(SimpleNamespace(review_settlement=("block", "bad"))))
    monkeypatch.setattr(package_review, "_package_reuse_evidence", _plan(AssertionError("looked up")))

    assert _respond(tmp_path, guard_home=native_context_digest)["decision"] == "deny"


def test_an_unavailable_settlement_cannot_queue_an_evaluated_block(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        package_review, "package_review_plan", _plan(package_review.PackageReviewPlan(ARTIFACT, False, tmp_path, True))
    )
    monkeypatch.setattr(package_review, "_evaluate", _plan(SimpleNamespace(review_settlement=("block", "bad"))))
    monkeypatch.setattr(package_review, "native_render_cli", _plan(None))

    response = _respond(tmp_path)

    assert response is not None
    assert response["decision"] == "deny"
    assert response["reason"] == "bad"
    assert response["prompted"] is False


_APPROVAL_KEY_FROM_LOOKUP = {"harness": "omp", "artifact_id": "omp:project:package-request:resident"}
_LOOKUP = {"argv": ["npm", "ci"], "environment": {}, "approval_key": _APPROVAL_KEY_FROM_LOOKUP}


@pytest.mark.parametrize(
    ("lookup", "reuse", "approval"),
    [
        (None, None, None),
        (_LOOKUP, None, None),
        (
            _LOOKUP,
            {"artifact_hash": KEY["artifact_hash"], "found": False, "policy_action": "review"},
            {**_APPROVAL_KEY_FROM_LOOKUP, "artifact_hash": KEY["artifact_hash"]},
        ),
        (
            _LOOKUP,
            {"artifact_hash": KEY["artifact_hash"], "found": True, "policy_action": "allow"},
            {**_APPROVAL_KEY_FROM_LOOKUP, "artifact_hash": KEY["artifact_hash"]},
        ),
    ],
)
def test_an_unavailable_settlement_keeps_a_review_queued(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    lookup: dict[str, object] | None,
    reuse: dict[str, object] | None,
    approval: dict[str, str] | None,
) -> None:
    monkeypatch.setattr(
        package_review, "package_review_plan", _plan(package_review.PackageReviewPlan(ARTIFACT, False, tmp_path, True))
    )
    monkeypatch.setattr(package_review, "_evaluate", _plan(SimpleNamespace(review_settlement=("review", None))))
    monkeypatch.setattr(package_review, "_package_reuse_evidence", _plan(reuse))
    replies = iter(
        [("document", {"response": None, "package_approval": None, "lookup": lookup}), None]
        if lookup is not None
        else [None]
    )
    monkeypatch.setattr(package_review, "native_render_cli", lambda *_a, **_k: next(replies))

    assert _outcome(tmp_path) == package_review.PackageReviewOutcome(None, approval)
    assert list(replies) == []


def test_an_install_piped_into_a_workspace_program_is_not_keyed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, native_context_digest: Path
) -> None:
    """A pipe into a program the workspace may own is not what the key stands for."""

    monkeypatch.setattr(
        package_review, "package_review_plan", _plan(package_review.PackageReviewPlan(ARTIFACT, False, tmp_path, False))
    )
    monkeypatch.setattr(package_review, "_evaluate", _plan(SimpleNamespace(review_settlement=("review", None))))
    monkeypatch.setattr(package_review, "_package_reuse_evidence", _plan(AssertionError("looked up")))

    assert _outcome(tmp_path, guard_home=native_context_digest) == package_review.PackageReviewOutcome(None)


def test_a_launch_review_never_reads_a_package_approval(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, native_context_digest: Path
) -> None:
    monkeypatch.setattr(
        package_review, "package_review_plan", _plan(package_review.PackageReviewPlan(ARTIFACT, False, tmp_path, True))
    )
    monkeypatch.setattr(package_review, "_evaluate", _plan(SimpleNamespace(review_settlement=("review", None))))
    monkeypatch.setattr(package_review, "_package_reuse_evidence", _plan(AssertionError("looked up")))

    outcome = _outcome(
        tmp_path,
        {"reason_code": "native_command_review_required", "minimum_action": "review"},
        guard_home=native_context_digest,
    )

    assert outcome == package_review.PackageReviewOutcome(None)


def test_an_install_whose_key_cannot_be_derived_carries_none(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, native_context_digest: Path
) -> None:
    artifact = SimpleNamespace(metadata={"redacted_command": ""}, harness="omp", artifact_id="x")
    monkeypatch.setattr(
        package_review, "package_review_plan", _plan(package_review.PackageReviewPlan(artifact, False, tmp_path, True))
    )
    monkeypatch.setattr(package_review, "_evaluate", _plan(SimpleNamespace(review_settlement=("review", None))))
    monkeypatch.setattr(package_review, "_package_reuse_evidence", _plan(AssertionError("looked up")))

    assert _outcome(tmp_path, guard_home=native_context_digest) == package_review.PackageReviewOutcome(None)


def test_the_package_key_resolves_npm_through_the_agents_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, native_context_digest: Path
) -> None:
    """The key is built with the PATH and HOME the hook stamped, not the hook
    process's own, so the npm the agent runs keeps the key portable."""

    from codex_plugin_scanner.guard import local_supply_chain, package_execution_context

    built: list[dict[str, object]] = []

    def context(**kwargs: object) -> object:
        built.append(kwargs)
        raise RuntimeError("stop after the context")

    monkeypatch.setattr(package_execution_context, "build_package_execution_context", context)
    monkeypatch.setattr(local_supply_chain, "package_current_action_and_hash", _plan(AssertionError("hashed")))
    monkeypatch.setattr(
        package_review, "package_review_plan", _plan(package_review.PackageReviewPlan(ARTIFACT, False, tmp_path, True))
    )
    monkeypatch.setattr(package_review, "_evaluate", _plan(SimpleNamespace(review_settlement=("review", None))))
    stamp = {
        "environment_names": ["PATH", "HOME"],
        "path": "/opt/node/bin",
        "home": "/home/agent",
        "pager_disabled": False,
    }

    outcome = package_review.native_package_review_response(
        object(),
        harness="omp",
        payload={"tool_input": {"command": "npm ci --ignore-scripts"}, "guard_execution_environment": stamp},
        native_result=REVIEW,
        workspace=tmp_path,
        guard_home=native_context_digest,
    )

    assert outcome == package_review.PackageReviewOutcome(None)
    assert [call["environment"] for call in built] == [{"PATH": "/opt/node/bin", "HOME": "/home/agent"}]


def test_a_saved_package_allow_is_reused_for_an_install_the_evaluator_allows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`npm ci --ignore-scripts` is rated allow by the evaluator but still
    reviewed by the hook route, so the saved allow is looked up as a review."""

    from codex_plugin_scanner.guard import local_supply_chain, package_execution_context

    asked: list[object] = []

    def resolve(evaluation: object, **kwargs: object) -> object:
        asked.append(kwargs.get("current_action"))
        return SimpleNamespace(
            approval_reuse_decision={"decision_id": 1}, evaluation=SimpleNamespace(policy_action="allow")
        )

    monkeypatch.setattr(package_execution_context, "build_package_execution_context", _plan(object()))
    monkeypatch.setattr(
        local_supply_chain, "package_current_action_and_hash", _plan(("allow", "guard-approval-context:v1:x"))
    )
    monkeypatch.setattr(local_supply_chain, "_resolve_stored_package_policy_override", resolve)
    artifact = SimpleNamespace(metadata={"redacted_command": "npm ci --ignore-scripts"}, harness="omp", artifact_id="x")
    evaluation = SimpleNamespace(review_settlement=("review", None), policy_action="allow")

    evidence = package_review._package_reuse_evidence(
        object(), artifact, evaluation, tmp_path, ["npm", "ci", "--ignore-scripts"], {}
    )

    assert asked == ["review"]
    assert evidence == {"artifact_hash": "guard-approval-context:v1:x", "found": True, "policy_action": "allow"}
