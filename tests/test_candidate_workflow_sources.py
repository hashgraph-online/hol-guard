"""Keep candidate verification bound to push commits with read-only jobs."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import cast

import yaml

ROOT = Path(__file__).resolve().parents[1]
CANDIDATE_BRANCH = "hgp/batch-11b-release-gating"


def workflow(name: str) -> dict[str, object]:
    # BaseLoader preserves GitHub's `on` key rather than treating it as YAML 1.1 true.
    value = yaml.load((ROOT / ".github/workflows" / name).read_text(), Loader=yaml.BaseLoader)
    assert isinstance(value, dict)
    return cast(dict[str, object], value)


def mapping(value: object) -> Mapping[str, object]:
    assert isinstance(value, dict)
    return cast(dict[str, object], value)


def test_native_push_verifies_the_candidate_without_replacing_merge_checks() -> None:
    native = workflow("native-wheel-ci.yml")
    events = mapping(native["on"])
    assert mapping(events["push"])["branches"] == ["main", CANDIDATE_BRANCH]
    assert mapping(events["pull_request"])["branches"] == ["main", "release/3.2"]
    assert "pull_request_target" not in events
    assert "workflow_dispatch" in events
    # Branch push and PR merge work retain separate concurrency identities.
    assert (
        mapping(native["concurrency"])["group"] == "native-wheel-${{ github.event.pull_request.number || github.ref }}"
    )


def test_native_artifacts_keep_the_actual_event_commit_identity() -> None:
    native = workflow("native-wheel-ci.yml")
    for job_value in mapping(native["jobs"]).values():
        job = mapping(job_value)
        assert "GITHUB_SHA" not in mapping(job.get("env", {}))
        steps = job["steps"]
        assert isinstance(steps, list)
        checkout = [
            mapping(step) for step in steps if str(mapping(step).get("uses", "")).startswith("actions/checkout@")
        ]
        assert len(checkout) == 1
        options = mapping(checkout[0]["with"])
        assert options["persist-credentials"] == "false"
        assert "ref" not in options  # checkout uses the immutable push/merge event SHA.
        build_bindings = []
        source_bindings = []
        for step_value in steps:
            env = mapping(mapping(step_value).get("env", {}))
            assert "GITHUB_SHA" not in env
            if "HOL_GUARD_BUILD_SHA" in env:
                build_bindings.append(env["HOL_GUARD_BUILD_SHA"])
            if "SOURCE_SHA" in env:
                source_bindings.append(env["SOURCE_SHA"])
        assert build_bindings and set(build_bindings) == {"${{ github.sha }}"}
        assert source_bindings and set(source_bindings) == {"${{ github.sha }}"}


def test_candidate_lab_calls_the_existing_jobs_without_extra_authority() -> None:
    candidate = workflow("candidate-integration-lab.yml")
    assert candidate["on"] == {"push": {"branches": [CANDIDATE_BRANCH]}}
    assert candidate["permissions"] == {"contents": "read"}
    jobs = mapping(candidate["jobs"])
    assert set(jobs) == {"integration"}
    assert jobs["integration"] == {"uses": "./.github/workflows/mdm-cloud-integration-lab.yml"}
    # A local reusable workflow is resolved from the same immutable caller commit.
    assert "secrets" not in mapping(jobs["integration"])
    assert "inputs" not in candidate


def test_reusable_lab_preserves_existing_events_and_source_checks() -> None:
    lab = workflow("mdm-cloud-integration-lab.yml")
    events = mapping(lab["on"])
    assert "workflow_call" in events and not events["workflow_call"]
    assert "workflow_dispatch" in events
    assert mapping(events["pull_request"])["branches"] == ["release/3.0"]
    assert mapping(events["push"])["branches"] == ["release/3.0"]
    assert mapping(events["push"])["paths"] == mapping(events["pull_request"])["paths"]
    assert lab["permissions"] == {"contents": "read"}
    assert "pull_request_target" not in events
    for job_value in mapping(lab["jobs"]).values():
        job = mapping(job_value)
        assert "secrets" not in job
        assert mapping(job.get("permissions", {"contents": "read"})) == {"contents": "read"}
        steps = job["steps"]
        assert isinstance(steps, list)
        for step_value in steps:
            step = mapping(step_value)
            assert "GITHUB_SHA" not in mapping(step.get("env", {}))
            if str(step.get("uses", "")).startswith("actions/checkout@"):
                assert mapping(step["with"]) == {"persist-credentials": "false"}
    native = mapping(mapping(lab["jobs"])["native-policy-activation"])
    assert isinstance(native["steps"], list)
    commands = "\n".join(str(mapping(step).get("run", "")) for step in native["steps"])
    assert 'test "$(git rev-parse HEAD)" = "$GITHUB_SHA"' in commands
    assert 'export HOL_GUARD_BUILD_SHA="$GITHUB_SHA"' in commands
