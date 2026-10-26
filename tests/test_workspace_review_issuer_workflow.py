"""The release-root issuer stays behind its reviewed main and custodian gates."""

from __future__ import annotations

import json
import re
import shutil
import stat
import subprocess
from pathlib import Path
from typing import cast

import pytest
import yaml

from scripts.approval.workspace_review_authority_workflow import (
    WorkflowAuthorityError,
    record_request,
    verify_custodian_approval,
    verify_reviewed_request,
    write_request,
)

_PATH = Path(__file__).resolve().parents[1] / ".github/workflows/issue-workspace-review-authority.yml"
_MAIN_GATE = (
    "github.repository == 'hashgraph-online/hol-guard' && github.ref == 'refs/heads/main' && github.run_attempt == 1"
)
_ROOT_SEED = "HOL_GUARD_APPROVAL_ENROLLMENT_ROOT_SEED_HEX"


def _mapping(value: object) -> dict[str, object]:
    assert isinstance(value, dict)
    raw = cast(dict[object, object], value)
    assert all(isinstance(key, str) for key in raw)
    return {cast(str, key): item for key, item in raw.items()}


def _workflow() -> dict[str, object]:
    return _mapping(cast(object, yaml.safe_load(_PATH.read_text(encoding="utf-8"))))


def _jobs(workflow: dict[str, object]) -> dict[str, dict[str, object]]:
    return {name: _mapping(job) for name, job in _mapping(workflow["jobs"]).items()}


def _steps(job: dict[str, object]) -> list[dict[str, object]]:
    value = job["steps"]
    assert isinstance(value, list)
    return [_mapping(step) for step in cast(list[object], value)]


def test_issuer_only_runs_from_main_after_public_validation_and_custodian_review() -> None:
    workflow = _workflow()
    triggers = _mapping(workflow["on"])
    assert set(triggers) == {"workflow_dispatch"}
    assert workflow["permissions"] == {"contents": "read"}
    jobs = _jobs(workflow)
    assert set(jobs) == {"validate", "sign"}
    assert jobs["validate"]["if"] == jobs["sign"]["if"] == _MAIN_GATE
    assert jobs["sign"]["needs"] == "validate"
    assert jobs["sign"]["environment"] == "guard-approval-root"
    for job in jobs.values():
        assert job["permissions"] == {"contents": "read", "actions": "read"}
        assert "env" not in job
        protection = str(_steps(job)[0]["run"])
        assert "environments/guard-approval-root" in protection
        assert "grep -qx true" in protection


def test_root_seed_only_reaches_the_signer_and_public_artifacts_are_exact_files() -> None:
    workflow = _workflow()
    seed_steps: list[dict[str, object]] = []
    for job in _jobs(workflow).values():
        for step in _steps(job):
            if _ROOT_SEED in json.dumps(step):
                seed_steps.append(step)
            if "uses" in step:
                assert re.fullmatch(r"[^@]+@[0-9a-f]{40}", str(step["uses"]))
            if str(step.get("uses", "")).startswith("actions/checkout@"):
                assert step["with"] == {"ref": "${{ github.sha }}", "persist-credentials": False}
            if str(step.get("uses", "")).startswith("actions/upload-artifact@"):
                config = _mapping(step["with"])
                assert config["path"] in {"authority-request.json", "workspace-review-authority.json"}
                assert config["if-no-files-found"] == "error"
    assert len(seed_steps) == 1
    signer = seed_steps[0]
    assert signer["run"] == (
        "uv run --no-sync python scripts/approval/issue_workspace_review_authority.py "
        '--request authority-request.json --expected-request-sha256 "$EXPECTED_REQUEST_DIGEST" '
        "--output workspace-review-authority.json"
    )
    assert _mapping(signer["env"])["EXPECTED_REQUEST_DIGEST"] == "${{ needs.validate.outputs.request_digest }}"
    steps = _steps(_jobs(workflow)["sign"])
    assert steps.index(signer) > next(
        i for i, step in enumerate(steps) if step.get("name") == "Verify reviewed request digest"
    )
    assert steps.index(signer) > next(
        i for i, step in enumerate(steps) if step.get("name") == "Verify independent custodian reviewed these bytes"
    )
    assert all("secrets." not in json.dumps(step) for step in steps[: steps.index(signer)])


_GATE_CASES: tuple[tuple[list[object], bool], ...] = (
    ([], False),
    ([{"type": "wait_timer", "wait_timer": 1}], False),
    ([{"type": "required_reviewers", "prevent_self_review": False, "reviewers": [{"type": "User"}]}], False),
    ([{"type": "required_reviewers", "prevent_self_review": True, "reviewers": []}], False),
    ([{"type": "required_reviewers", "prevent_self_review": True, "reviewers": [{"type": "Team"}]}], False),
    ([{"type": "required_reviewers", "prevent_self_review": True, "reviewers": [{"type": "User"}]}], True),
)


@pytest.mark.parametrize(("rules", "accepted"), _GATE_CASES)
def test_custodian_gate_rejects_missing_or_self_reviewable_protection(rules: list[object], accepted: bool) -> None:
    jq = shutil.which("jq")
    if jq is None:
        pytest.skip("jq is required to execute the workflow's environment predicate")
    workflow = _workflow()
    for job in _jobs(workflow).values():
        command = str(_steps(job)[0]["run"])
        predicate = re.search(r"--jq '([^']+)'", command)
        assert predicate is not None
        result = subprocess.run(
            [jq, predicate.group(1)],
            input=json.dumps({"protection_rules": rules}),
            text=True,
            capture_output=True,
            check=True,
        )
        assert json.loads(result.stdout) is accepted


@pytest.mark.parametrize(
    ("change", "accepted"),
    (
        ("approved", True),
        ("no_review", False),
        ("wrong_digest", False),
        ("unlisted_reviewer", False),
        ("self_review", False),
        ("rerun_self_review", False),
        ("wrong_environment", False),
        ("rejected", False),
        ("team_only", False),
        ("self_review_allowed", False),
        ("missing_environment_id", False),
        ("null_environment_id", False),
        ("missing_custodian_id", False),
        ("null_custodian_id", False),
        ("boolean_ids", False),
        ("negative_ids", False),
    ),
)
def test_actual_digest_bound_custodian_approval_is_required(tmp_path: Path, change: str, accepted: bool) -> None:
    rule: dict[str, object] = {
        "type": "required_reviewers",
        "prevent_self_review": change != "self_review_allowed",
        "reviewers": [{"type": "Team" if change == "team_only" else "User", "reviewer": {"id": 2}}],
    }
    login = {"self_review": "Initiator", "rerun_self_review": "Rerunner"}.get(change, "Custodian")
    review: dict[str, object] = {
        "state": "rejected" if change == "rejected" else "approved",
        "comment": "authority-request-sha256:" + ("b" if change == "wrong_digest" else "a") * 64,
        "user": {"id": 3 if change == "unlisted_reviewer" else 2, "login": login},
        "environments": [{"id": 43 if change == "wrong_environment" else 42}],
    }
    environment: dict[str, object] = {"id": 42, "protection_rules": [rule]}
    if change == "missing_environment_id":
        del environment["id"]
        review["environments"] = [{}]
    elif change == "null_environment_id":
        environment["id"] = None
        review["environments"] = [{"id": None}]
    elif change in {"missing_custodian_id", "null_custodian_id"}:
        rule["reviewers"] = [{"type": "User", "reviewer": {} if change == "missing_custodian_id" else {"id": None}}]
        review["user"] = {"id": None, "login": login}
    elif change in {"boolean_ids", "negative_ids"}:
        invalid_id = True if change == "boolean_ids" else -2
        environment["id"] = invalid_id
        rule["reviewers"] = [{"type": "User", "reviewer": {"id": invalid_id}}]
        review["user"] = {"id": invalid_id, "login": login}
        review["environments"] = [{"id": invalid_id}]
    _ = (tmp_path / "authority-environment.json").write_text(json.dumps(environment), encoding="utf-8")
    _ = (tmp_path / "authority-reviews.json").write_text(
        json.dumps([] if change == "no_review" else [review]), encoding="utf-8"
    )
    try:
        verify_custodian_approval(
            tmp_path / "authority-environment.json",
            tmp_path / "authority-reviews.json",
            expected_digest="a" * 64,
            initiators={"initiator", "rerunner"},
        )
    except WorkflowAuthorityError:
        assert not accepted
    else:
        assert accepted


def test_workflow_helpers_preserve_request_bytes_and_review_digest(tmp_path: Path) -> None:
    raw = '{"schema":"public"}\n'
    request = tmp_path / "authority-request.json"
    write_request(request, raw)
    assert request.read_text(encoding="utf-8") == raw
    assert stat.S_IMODE(request.stat().st_mode) == 0o600

    output = tmp_path / "github-output"
    summary = tmp_path / "github-summary"
    digest = record_request(request, output=output, summary=summary)
    assert output.read_text(encoding="utf-8") == f"digest={digest}\n"
    assert f"authority-request-sha256:{digest}" in summary.read_text(encoding="utf-8")
    verify_reviewed_request(request, expected_digest=digest)

    _ = request.write_text('{"schema":"changed"}\n', encoding="utf-8")
    with pytest.raises(WorkflowAuthorityError, match="Reviewed authority request changed"):
        verify_reviewed_request(request, expected_digest=digest)


def test_workflow_request_writer_rejects_oversized_input(tmp_path: Path) -> None:
    with pytest.raises(WorkflowAuthorityError, match="size limit"):
        write_request(tmp_path / "authority-request.json", "x" * (16 * 1024 + 1))
