"""Contracts for the approve-then-retry lane's catalog rules and judge predicate.

The judge tests exercise recorded case shapes, and focused integration tests cover the
lane-owned approval and authenticated-journal plumbing. Whether a real agent's retry
reuses an approval is answered only by running the lane against a harness CLI.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from copy import deepcopy
from pathlib import Path

import pytest

from ci.gauntlet.approval_retry import (
    ReviewApprover,
    write_review_config,
)
from ci.gauntlet.approval_retry_bash import (
    CONCURRENCY_CASE,
    DENIAL_CASE,
    MUTATION_CASE,
    ONCE_CASE,
    PERSISTENT_RESTART_CASE,
    targets_script,
)
from ci.gauntlet.approval_retry_bash import (
    assessment as bash_lifecycle_assessment,
)
from ci.gauntlet.approval_retry_bash import evidence as bash_lifecycle_evidence
from ci.gauntlet.approval_retry_bash import stage as stage_bash_lifecycle
from ci.gauntlet.catalog import load_catalog_data
from tests.test_guard_gauntlet_approval_retry import _catalog_data, _decision


@pytest.mark.parametrize(
    "change",
    [
        {"id": "approved-bash-script-unknown"},
        {"profiles": ["core"]},
        {"required_tools": []},
        {"commands": ["/bin/bash other.sh dry"]},
        {"expectation": "allow"},
    ],
)
def test_catalog_rejects_a_bash_lifecycle_case_outside_its_shape(change: dict):
    data = _catalog_data()
    source = next(row for row in data["scenarios"] if row["id"] == MUTATION_CASE)
    data["scenarios"] = [{**source, **change}]
    with pytest.raises(ValueError):
        load_catalog_data(data)


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        ("/bin/bash /fixture/scripts/gauntlet-maintenance.sh dry", True),
        ("/bin/bash '/fixture with space/scripts/gauntlet-maintenance.sh' dry", True),
        ("echo gauntlet-maintenance.sh dry", False),
        ("/bin/bash /fixture/scripts/gauntlet-maintenance.sh delete", False),
        ("/bin/bash /fixture/scripts/gauntlet-maintenance.sh dry extra", False),
    ],
)
def test_bash_lifecycle_target_matching_is_exact(command: str, expected: bool):
    assert targets_script(command) is expected


_LIFECYCLE_COMMAND = "/bin/bash /fixture/scripts/gauntlet-maintenance.sh dry"
_LIFECYCLE_HASH = "bash-exact-v1"


def _lifecycle_case(
    *,
    runs: int,
    persist: bool,
    decisions: list[dict],
    journal_runs: int | None = None,
    withheld: bool = False,
    withheld_hash: str = _LIFECYCLE_HASH,
    lifecycle: dict | None = None,
    max_active: int = 0,
) -> dict:
    return {
        "approval_grants": {
            "granted": [
                {
                    "request_id": "req-1",
                    "target": _LIFECYCLE_COMMAND,
                    "persist_policy": persist,
                    "artifact_hash": _LIFECYCLE_HASH,
                }
            ],
            "withheld": (
                [
                    {
                        "request_id": "req-2",
                        "target": _LIFECYCLE_COMMAND,
                        "artifact_hash": withheld_hash,
                    }
                ]
                if withheld
                else []
            ),
            "errors": [],
            "lifecycle": lifecycle or {},
            "max_active_operations": max_active,
        },
        "bash_lifecycle": {
            "report_runs": runs,
            "report_exact": True,
            "maintenance_report_exact": True,
            "journal": [
                {
                    "artifact_hash": _LIFECYCLE_HASH,
                    "authorization": "saved_grant",
                    "state": "completed",
                    "dispatch_acknowledged": True,
                    "exit_code": 0,
                }
                for _ in range(runs if journal_runs is None else journal_runs)
            ],
        },
        "guard_decisions": decisions,
    }


def test_bash_once_requires_one_real_effect_and_one_nonpersistent_grant():
    case = _lifecycle_case(
        runs=1,
        persist=False,
        decisions=[_decision(_LIFECYCLE_COMMAND, "deny"), _decision(_LIFECYCLE_COMMAND, "allow")],
    )
    assert bash_lifecycle_assessment(ONCE_CASE, case, case["guard_decisions"])[0] == "pass"


def test_bash_persistent_consent_survives_restart_for_ten_real_effects():
    decisions = [_decision(_LIFECYCLE_COMMAND, "deny")] + [_decision(_LIFECYCLE_COMMAND, "allow") for _ in range(10)]
    case = _lifecycle_case(
        runs=10,
        persist=True,
        decisions=decisions,
        lifecycle={"resident_restarted": True, "restart_after_initial_delivery": True},
    )
    assert bash_lifecycle_assessment(PERSISTENT_RESTART_CASE, case, decisions)[0] == "pass"


def test_bash_mutation_requires_a_fresh_ungranted_review_before_effects():
    decisions = [
        _decision(_LIFECYCLE_COMMAND, "deny"),
        _decision(_LIFECYCLE_COMMAND, "deny", "native_policy_reapproval_required"),
    ]
    case = _lifecycle_case(
        runs=0,
        persist=True,
        decisions=decisions,
        withheld=True,
        withheld_hash="bash-exact-v2",
        lifecycle={"script_mutated": True, "resident_restarted": True},
    )
    assert bash_lifecycle_assessment(MUTATION_CASE, case, decisions)[0] == "pass"


def test_bash_current_deny_overrides_saved_consent_before_effects():
    decisions = [
        _decision(_LIFECYCLE_COMMAND, "deny"),
        _decision(_LIFECYCLE_COMMAND, "deny", "native_policy_block"),
    ]
    case = _lifecycle_case(
        runs=0,
        persist=True,
        decisions=decisions,
        lifecycle={"policy_denied": True, "resident_restarted": True, "restart_after_initial_delivery": True},
    )
    assert bash_lifecycle_assessment(DENIAL_CASE, case, decisions)[0] == "pass"


def test_bash_concurrency_spends_a_once_grant_for_only_one_real_effect():
    decisions = [
        _decision(_LIFECYCLE_COMMAND, "deny"),
        _decision(_LIFECYCLE_COMMAND, "allow"),
        _decision(_LIFECYCLE_COMMAND, "deny", "native_policy_reapproval_required"),
    ]
    case = _lifecycle_case(
        runs=1,
        persist=False,
        decisions=decisions,
        max_active=0,
        withheld=True,
    )
    assert bash_lifecycle_assessment(CONCURRENCY_CASE, case, decisions)[0] == "not-exercised"
    case["approval_grants"]["max_active_operations"] = 1
    case["approval_grants"]["lifecycle"]["once_contention_observed"] = True
    assert bash_lifecycle_assessment(CONCURRENCY_CASE, case, decisions)[0] == "not-exercised"
    for index, row in enumerate(decisions):
        row["tool_call_id"] = f"c{index}"
    decisions[2]["execution_reason_code"] = "native_bash_operation_active"
    case["events"] = [{"type": "model_turn", "calls": [{"id": "c1"}, {"id": "c2"}]}]
    case["bash_lifecycle"]["busy_calls"] = [
        {
            "call_sha256": hashlib.sha256(b"c2").hexdigest(),
            "artifact_hash": _LIFECYCLE_HASH,
        }
    ]
    assert bash_lifecycle_assessment(CONCURRENCY_CASE, case, decisions)[0] == "pass"
    for damage in ("missing", "foreign", "digest", "sequential", "not-busy"):
        broken = deepcopy(case)
        changed = deepcopy(decisions)
        if damage == "missing":
            broken["bash_lifecycle"]["busy_calls"] = []
        elif damage == "foreign":
            broken["bash_lifecycle"]["busy_calls"][0]["artifact_hash"] = "foreign"
        elif damage == "digest":
            broken["bash_lifecycle"]["busy_calls"][0]["call_sha256"] = "0" * 64
        elif damage == "sequential":
            broken["events"] = [{"type": "model_turn", "calls": [{"id": call}]} for call in ("c1", "c2")]
        else:
            changed[2]["execution_reason_code"] = "native_policy_block"
        assert bash_lifecycle_assessment(CONCURRENCY_CASE, broken, changed)[0] != "pass", damage


@pytest.mark.parametrize(("runs", "journal_runs"), [(0, 1), (1, 0)])
def test_bash_lifecycle_rejects_missing_physical_or_journal_effects(runs: int, journal_runs: int):
    decisions = [_decision(_LIFECYCLE_COMMAND, "deny"), _decision(_LIFECYCLE_COMMAND, "allow")]
    case = _lifecycle_case(
        runs=runs,
        persist=False,
        decisions=decisions,
        journal_runs=journal_runs,
    )
    assert bash_lifecycle_assessment(ONCE_CASE, case, decisions)[0] == "fail"


def test_bash_lifecycle_ignores_completed_operations_for_other_artifacts():
    decisions = [_decision(_LIFECYCLE_COMMAND, "deny"), _decision(_LIFECYCLE_COMMAND, "allow")]
    case = _lifecycle_case(runs=1, persist=False, decisions=decisions, journal_runs=0)
    case["bash_lifecycle"]["journal"] = [
        {
            "artifact_hash": "other-artifact",
            "state": "completed",
            "dispatch_acknowledged": True,
            "exit_code": 0,
        }
    ]
    assert bash_lifecycle_assessment(ONCE_CASE, case, decisions)[0] == "fail"


@pytest.mark.parametrize("tamper_table", ["guard_bash_operations", "guard_bash_invocations"])
def test_bash_lifecycle_evidence_verifies_native_journal_integrity(tmp_path: Path, tamper_table: str):
    from codex_plugin_scanner.guard.local_authority_integrity import sign_local_authority_payload
    from codex_plugin_scanner.guard.native_policy_snapshot_codec import (
        derive_native_policy_verifier_key,
        native_policy_verifier_key_id,
    )

    database = tmp_path / "guard.db"
    master_key = b"m" * 32
    verifier_key = derive_native_policy_verifier_key(master_key)
    payload = {
        "authorization": "saved_grant",
        "state": "completed",
        "dispatch_acknowledged": True,
        "completion": {"exit_code": 0},
        "artifact_hash": _LIFECYCLE_HASH,
    }
    integrity = sign_local_authority_payload(
        payload,
        key=verifier_key,
        key_id=native_policy_verifier_key_id(verifier_key),
        purpose="guard-native-bash-operation-v1",
        signed_at="2026-10-18T00:00:00+00:00",
    )
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE guard_bash_operations(operation_id TEXT, payload TEXT, integrity TEXT)")
        connection.execute(
            "INSERT INTO guard_bash_operations VALUES(?, ?, ?)",
            ("op-1", json.dumps(payload), json.dumps(integrity)),
        )
        busy = {
            "generation": 0,
            "artifact_hash": _LIFECYCLE_HASH,
            "busy_calls": {hashlib.sha256(b"busy-call").hexdigest(): 0},
        }
        signed_busy = sign_local_authority_payload(
            busy,
            key=verifier_key,
            key_id=native_policy_verifier_key_id(verifier_key),
            purpose="guard-native-bash-invocation-lifetime-v1",
            signed_at="2026-10-18T00:00:00+00:00",
        )
        connection.execute("CREATE TABLE guard_bash_invocations(base_id TEXT, payload TEXT, integrity TEXT)")
        connection.execute(
            "INSERT INTO guard_bash_invocations VALUES(?, ?, ?)", ("base-1", json.dumps(busy), json.dumps(signed_busy))
        )

    class Store:
        def _connect(self):
            return sqlite3.connect(database)

        def _policy_integrity_secret_material(self, *, create: bool):
            assert create is False
            return master_key, "synthetic"

    workspace = tmp_path / "workspace"
    home = tmp_path / "home"
    home.mkdir()
    stage_bash_lifecycle(workspace, ONCE_CASE)
    summary = bash_lifecycle_evidence(home, workspace, ONCE_CASE, Store())
    assert summary["journal_error"] is None
    assert summary["busy_calls"] == [
        {
            "call_sha256": hashlib.sha256(b"busy-call").hexdigest(),
            "artifact_hash": _LIFECYCLE_HASH,
        }
    ]
    assert summary["journal"] == [
        {
            "authorization": "saved_grant",
            "state": "completed",
            "dispatch_acknowledged": True,
            "exit_code": 0,
            "artifact_hash": _LIFECYCLE_HASH,
        }
    ]

    with sqlite3.connect(database) as connection:
        connection.execute(
            f"UPDATE {tamper_table} SET payload=?",
            (json.dumps({**payload, "artifact_hash": "tampered"}),),
        )
    assert bash_lifecycle_evidence(home, workspace, ONCE_CASE, Store())["journal_error"] == "RuntimeError"


def test_review_config_sets_the_only_floor_that_reaches_a_shell_command(tmp_path: Path):
    recorded = write_review_config(tmp_path / "guard-home")
    text = (tmp_path / "guard-home" / "config.toml").read_text(encoding="utf-8")
    assert 'subprocess_action = "review"' in text
    assert 'mode = "enforce"' in text
    # ``ask`` would let the first attempt run and make any retry case pass vacuously.
    assert "blocked_request_mode" not in text
    assert recorded == {"subprocess_action": "review", "blocked_request_mode": "safe-alternative"}


def test_lifecycle_approver_uses_one_real_once_resolution_and_withholds_the_duplicate(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
):
    from codex_plugin_scanner.guard import approvals

    calls: list[dict] = []
    monkeypatch.setattr(approvals, "apply_approval_resolution", lambda **kwargs: calls.append(kwargs) or {})
    approver = ReviewApprover(
        object(),
        known_ids=set(),
        workspace=Path("/fixture"),
        scenario_id=ONCE_CASE,
    )
    row = {
        "request_id": "req-1",
        "artifact_hash": _LIFECYCLE_HASH,
        "scope_contract_version": "v1",
        "scope_contract_digest": "d" * 64,
    }
    approver._grant(row, _LIFECYCLE_COMMAND)
    approver._grant({**row, "request_id": "req-2"}, _LIFECYCLE_COMMAND)

    assert len(calls) == 1
    assert calls[0]["persist_policy"] is None
    assert calls[0]["scope_contract_version"] == "v1"
    report = approver.report()
    assert len(report["granted"]) == 1
    assert len(report["withheld"]) == 1
    assert report["granted"][0]["artifact_hash"] == _LIFECYCLE_HASH


@pytest.mark.parametrize(
    "unrelated",
    [
        "sleep 3",
        "echo ready",
        _LIFECYCLE_COMMAND.replace(" dry", " delete"),
        _LIFECYCLE_COMMAND.replace("/fixture/", "/other/"),
    ],
)
def test_bash_lifecycle_approver_never_grants_unrelated_pending_actions(monkeypatch, unrelated):
    from codex_plugin_scanner.guard import approvals

    calls: list[dict] = []
    monkeypatch.setattr(approvals, "apply_approval_resolution", lambda **kwargs: calls.append(kwargs) or {})
    approver = ReviewApprover(object(), known_ids=set(), workspace=Path("/fixture"), scenario_id=ONCE_CASE)
    row = {"request_id": "unrelated-first", "artifact_hash": _LIFECYCLE_HASH}
    approver._grant(row, unrelated)
    assert calls == []
    approver._grant({**row, "request_id": "target"}, _LIFECYCLE_COMMAND)
    approver._grant({**row, "request_id": "unrelated-after"}, unrelated)
    assert [call["request_id"] for call in calls] == ["target"]
    report = approver.report()
    assert [item["target"] for item in report["withheld"]] == [unrelated, unrelated]
    assert not report["lifecycle"].get("once_contention_observed")


@pytest.mark.parametrize("scenario_id,restarted", [(PERSISTENT_RESTART_CASE, True), (MUTATION_CASE, False)])
def test_lifecycle_transition_restarts_only_the_requested_restart_case(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    scenario_id: str,
    restarted: bool,
):
    from ci.gauntlet import approval_retry_bash
    from codex_plugin_scanner.guard import approvals, native_resident_client

    calls: list[dict] = []
    closed: list[Path] = []
    monkeypatch.setattr(approvals, "apply_approval_resolution", lambda **kwargs: calls.append(kwargs) or {})
    monkeypatch.setattr(
        native_resident_client, "close_native_residents", lambda guard_home: closed.append(guard_home) or True
    )
    monkeypatch.setattr(approval_retry_bash, "mutate", lambda workspace: None)
    guard_home = tmp_path / "guard-home"
    approver = ReviewApprover(
        object(),
        known_ids=set(),
        workspace=Path("/fixture"),
        scenario_id=scenario_id,
        guard_home=guard_home,
    )
    approver._grant(
        {
            "request_id": "req-1",
            "artifact_hash": _LIFECYCLE_HASH,
            "scope_contract_version": "v1",
            "scope_contract_digest": "d" * 64,
        },
        _LIFECYCLE_COMMAND,
    )

    assert calls[0]["persist_policy"] is True
    assert bool(closed) is restarted
    assert approver.report()["lifecycle"] == ({"resident_restarted": True} if restarted else {"script_mutated": True})


@pytest.mark.parametrize("early_retry", [False, True])
def test_restart_follows_initial_delivery_and_precedes_retry(monkeypatch, tmp_path: Path, early_retry: bool):
    from ci.gauntlet.approval_retry_bash import PLANS
    from codex_plugin_scanner.guard import native_resident_client

    log = tmp_path / "events.jsonl"
    log.write_text(json.dumps({"type": "tool_execution_start"}) + "\n")

    def finish():
        with log.open("a") as stream:
            stream.write(json.dumps({"type": "tool_execution_end", "toolName": "bash"}) + "\n")
            if early_retry:
                stream.write(json.dumps({"type": "tool_execution_start"}) + "\n")

    def close(*, guard_home):
        assert "tool_execution_end" in log.read_text(), "restart interrupted initial output validation"
        return True

    monkeypatch.setattr(native_resident_client, "close_native_residents", close)
    approver = ReviewApprover(
        object(), known_ids=set(), workspace=tmp_path, guard_home=tmp_path / "guard", initial_result_log=log
    )
    writer = threading.Timer(0.02, finish)
    writer.start()
    try:
        approver._apply_lifecycle_transition(PLANS[PERSISTENT_RESTART_CASE])
    finally:
        writer.join()
    report = approver.report()
    if early_retry:
        assert report["errors"] and not report["lifecycle"].get("restart_after_initial_delivery")
    else:
        assert not report["errors"]
        assert report["lifecycle"] == {"resident_restarted": True, "restart_after_initial_delivery": True}
