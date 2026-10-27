from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import workspace_assessment_fix_proposals as fixes
from codex_plugin_scanner.guard import workspace_assessment_store as assessments
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_workspace_assessment_schema import MAX_FINDINGS
from codex_plugin_scanner.guard.workspace_assessment_carry import carry_unchecked_findings, listed_packages
from tests.workspace_fix_support import admit_worktree

DETECTORS = "d" * 64
T0 = 1_000_000_000


def digest(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


KEYS = assessments.WorktreeKeys(digest("codebase"), digest("worktree"))


def finding(finding_id: str, detector: str = "ci_workflow_v1", severity: str = "high") -> dict[str, object]:
    return {
        "finding_id": finding_id,
        "source_kind": "workspace_source",
        "detector": detector,
        "severity": severity,
        "path": ".github/workflows/ci.yml",
        "validation_state": "unvalidated",
        "lifecycle_state": "open",
    }


def outcome(
    state: str,
    findings: list[dict[str, object]],
    listed: frozenset[tuple[str, str, str]] | None = None,
    **detectors: str,
) -> assessments.RunOutcome:
    reasons = [f"{name}_incomplete" for name, status in detectors.items() if status != "complete"]
    return assessments.RunOutcome(
        state=state,
        snapshot_digest=digest(f"snapshot-{len(findings)}-{sorted(detectors.items())}"),
        coverage={"status": "partial" if reasons else "complete", "reasons": reasons, "detectors": detectors},
        findings=findings,
        listed_packages=listed,
    )


def package_finding(finding_id: str, version: str) -> dict[str, object]:
    return {
        **finding(finding_id, detector="supply_chain_local_v1"),
        "source_kind": "supply_chain",
        "ecosystem": "npm",
        "package_name": "minimist",
        "package_version": version,
    }


def assess(store: GuardStore, result: assessments.RunOutcome, *, at: int) -> dict[str, object]:
    assessments.enqueue(store, KEYS, trigger_kind="manual", detector_set_digest=DETECTORS, now_ms=at)
    claimed = assessments.claim_next(store, owner="w", now_ms=at)
    assert claimed is not None
    assert assessments.finish(store, claimed, result, now_ms=at + 1)
    run = assessments.latest_assessed_run(store, KEYS)
    assert run is not None and run["run_id"] == claimed.run_id
    return run


def admitted(tmp_path: Path) -> GuardStore:
    store = GuardStore(tmp_path / "home")
    admit_worktree(store, KEYS, root="/work/0", now_ms=T0)
    return store


def test_a_detector_that_did_not_finish_keeps_its_earlier_findings_listed(tmp_path: Path) -> None:
    store = admitted(tmp_path)
    first = assess(store, outcome("completed", [finding("a" * 32)], ci_workflow_v1="complete"), at=T0)

    second = assess(store, outcome("partial", [], ci_workflow_v1="not_run"), at=T0 + 10)

    assert [item["finding_id"] for item in second["findings"]] == ["a" * 32]
    assert second["findings"][0]["carried_from_run_id"] == first["run_id"]
    assert second["findings"][0]["severity"] == "high"
    assert second["coverage"]["carried_findings"] == 1
    assert second["coverage"]["reasons"] == ["ci_workflow_v1_incomplete"]

    # It stays tied to the run that last observed it while the gap lasts.
    third = assess(store, outcome("partial", [], ci_workflow_v1="incomplete"), at=T0 + 20)
    assert third["findings"][0]["carried_from_run_id"] == first["run_id"]


def test_a_detector_that_completes_again_settles_its_earlier_findings(tmp_path: Path) -> None:
    store = admitted(tmp_path)
    assess(store, outcome("completed", [finding("a" * 32)], ci_workflow_v1="complete"), at=T0)
    assess(store, outcome("partial", [], ci_workflow_v1="incomplete"), at=T0 + 10)

    # Another detector's gap keeps the run partial; this one is settled.
    run = assess(store, outcome("partial", [], ci_workflow_v1="complete", secrets="incomplete"), at=T0 + 20)
    assert run["findings"] == []
    assert "carried_findings" not in run["coverage"]


def test_a_detector_with_nothing_left_to_read_settles_its_earlier_findings(tmp_path: Path) -> None:
    store = admitted(tmp_path)
    assess(store, outcome("completed", [finding("a" * 32)], ci_workflow_v1="complete"), at=T0)

    run = assess(store, outcome("partial", [], ci_workflow_v1="no_inputs", secrets="incomplete"), at=T0 + 10)

    assert run["findings"] == []


def test_a_finding_the_run_found_again_is_listed_once_as_observed(tmp_path: Path) -> None:
    store = admitted(tmp_path)
    assess(store, outcome("completed", [finding("a" * 32), finding("b" * 32)], ci_workflow_v1="complete"), at=T0)

    run = assess(store, outcome("partial", [finding("a" * 32)], ci_workflow_v1="incomplete"), at=T0 + 10)

    by_id = {item["finding_id"]: item for item in run["findings"]}
    assert set(by_id) == {"a" * 32, "b" * 32}
    assert "carried_from_run_id" not in by_id["a" * 32]
    assert "carried_from_run_id" in by_id["b" * 32]
    assert run["coverage"]["carried_findings"] == 1


def test_only_the_unfinished_detector_carries_and_supply_chain_maps_to_its_coverage_name(tmp_path: Path) -> None:
    store = admitted(tmp_path)
    earlier = [
        finding("a" * 32, detector="supply_chain_local_v1"),
        finding("b" * 32, detector="ci_workflow_v1"),
        finding("c" * 32, detector="retired_detector_v0"),
    ]
    assess(store, outcome("completed", earlier, supply_chain="complete", ci_workflow_v1="complete"), at=T0)

    run = assess(store, outcome("partial", [], supply_chain="incomplete", ci_workflow_v1="complete"), at=T0 + 10)

    assert [item["finding_id"] for item in run["findings"]] == ["a" * 32]


def test_a_completed_run_or_a_first_run_carries_nothing() -> None:
    previous = {"run_id": "r1", "findings": [finding("a" * 32)]}
    done = outcome("completed", [], ci_workflow_v1="complete")
    assert carry_unchecked_findings(done, previous) is done
    first = outcome("partial", [], ci_workflow_v1="incomplete")
    assert carry_unchecked_findings(first, None) is first
    unshaped = assessments.RunOutcome(state="partial", coverage={"status": "partial"})
    assert carry_unchecked_findings(unshaped, previous) is unshaped


def test_carried_findings_stay_within_the_finding_bound(tmp_path: Path) -> None:
    store = admitted(tmp_path)
    earlier = [finding(f"{index:032x}") for index in range(MAX_FINDINGS)]
    assess(store, outcome("completed", earlier, ci_workflow_v1="complete"), at=T0)
    current = [finding("f" * 32, detector="secrets")]

    run = assess(store, outcome("partial", current, ci_workflow_v1="incomplete", secrets="complete"), at=T0 + 10)

    assert len(run["findings"]) == MAX_FINDINGS
    assert run["findings"][0]["finding_id"] == "f" * 32
    assert run["coverage"]["carried_findings"] == MAX_FINDINGS - 1
    # The run's own findings are whole, so the overflow does not read as a
    # finding cap that would hold back supply chain fix verification.
    assert "carried_finding_cap" in run["coverage"]["reasons"]
    assert "finding_cap" not in run["coverage"]["reasons"]
    coverage = {**run["coverage"], "detectors": {**run["coverage"]["detectors"], "supply_chain": "complete"}}
    coverage["reasons"] = [reason for reason in coverage["reasons"] if reason != "ci_workflow_v1_incomplete"]
    assert fixes._supply_chain_verifiable(coverage)


def test_a_package_the_audit_no_longer_lists_settles_its_earlier_finding(tmp_path: Path) -> None:
    store = admitted(tmp_path)
    earlier = [package_finding("a" * 32, "1.2.8"), package_finding("b" * 32, "1.2.5")]
    assess(store, outcome("completed", earlier, supply_chain="complete"), at=T0)

    # The lockfile now pins 1.2.9 and 1.2.5, and the advisory lookup for
    # 1.2.9 did not finish.
    listed = frozenset({("npm", "minimist", "1.2.9"), ("npm", "minimist", "1.2.5")})
    run = assess(store, outcome("partial", [], listed, supply_chain="incomplete"), at=T0 + 10)

    assert [item["finding_id"] for item in run["findings"]] == ["b" * 32]

    # An audit that could not list every package settles nothing.
    run = assess(store, outcome("partial", [], None, supply_chain="incomplete"), at=T0 + 20)
    assert [item["finding_id"] for item in run["findings"]] == ["b" * 32]


def test_the_listed_packages_name_packages_as_their_findings_do() -> None:
    packages = [
        {"ecosystem": " npm ", "name": "minimist", "resolvedVersion": "1.2.9", "requestedVersion": "^1.2.0"},
        {"name": "left-pad", "requestedVersion": "1.3.0"},
        {"ecosystem": "npm", "name": "bare"},
        {"ecosystem": "npm", "resolvedVersion": "1.0.0"},
        "not a package",
    ]
    payload: dict[str, object] = {"audit_status": "complete", "evaluation": {"packages": packages}}

    assert listed_packages(payload) == {
        ("npm", "minimist", "1.2.9"),
        ("unknown", "left-pad", "1.3.0"),
        ("npm", "bare", ""),
    }
    assert listed_packages({**payload, "audit_status": "incomplete"}) is None
    assert listed_packages({**payload, "lockfile_warnings": ["drift"]}) is None
    assert listed_packages({"audit_status": "complete"}) is None


def test_runs_finished_in_the_same_millisecond_carry_from_the_one_queued_last(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Run ids that sort against the queue order, so only the queue order can
    # pick the later run.
    store = admitted(tmp_path)
    ids = iter(["f" * 32, "e" * 32, "0" * 32])
    monkeypatch.setattr(assessments.uuid, "uuid4", lambda: SimpleNamespace(hex=next(ids)))
    assess(store, outcome("completed", [finding("a" * 32)], ci_workflow_v1="complete"), at=T0)
    second = assess(store, outcome("completed", [finding("b" * 32)], ci_workflow_v1="complete"), at=T0)

    assert second["run_id"] == "e" * 32
    third = assess(store, outcome("partial", [], ci_workflow_v1="incomplete"), at=T0 + 10)
    assert [item["finding_id"] for item in third["findings"]] == ["b" * 32]
