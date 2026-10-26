"""Supply-chain cases: offline fixtures, physical proofs and package-verdict judging."""

from __future__ import annotations

import json
from dataclasses import replace

import pytest

from ci.gauntlet.agent_prompt import scenario_prompt
from ci.gauntlet.catalog import CATALOG, load_catalog, load_catalog_data
from ci.gauntlet.evidence import assess_case
from ci.gauntlet.fixtures import create_fixture, filesystem_checks
from ci.gauntlet.harness_judge import _block_outcome
from ci.gauntlet.proofs import BLOCK_REASONS, block_reasons, required_checks
from ci.gauntlet.supply_chain import (
    CANARY,
    HTTP_SOURCE_CASE,
    LOCKFILE_INTEGRITY_CASE,
    NPM_LOGS,
    PACKAGE_BLOCK_REASONS,
    PIP_TARGET,
    POSTINSTALL_CASE,
    SETUP_PY_CASE,
    SUPPLY_CHAIN_CASES,
    stage_supply_chain,
)
from tests.test_guard_gauntlet import observed_case


def _scenario(scenario_id):
    return next(s for s in load_catalog() if s.id == scenario_id)


def _staged(tmp_path, scenario_id):
    tmp_path.mkdir(parents=True, exist_ok=True)
    fixture = create_fixture(tmp_path / "fixture")
    stage_supply_chain(fixture.workspace, scenario_id)
    return fixture


def _blocked(scenario_id, reason):
    scenario = _scenario(scenario_id)
    case = observed_case(scenario.commands[0], blocked=True)
    case["guard_observations"][0]["reason_code"] = reason
    case["filesystem"].update(dict.fromkeys(required_checks(scenario) - set(case["filesystem"]), True))
    return scenario, case


def test_catalog_appends_every_supply_chain_case_offline():
    scenarios = load_catalog()
    ids = [s.id for s in scenarios]
    assert set(ids[-len(SUPPLY_CHAIN_CASES) :]) == SUPPLY_CHAIN_CASES
    for scenario in scenarios:
        if scenario.id not in SUPPLY_CHAIN_CASES:
            continue
        assert scenario.oracle == "blocked-package"
        assert scenario.expectation == "block"
        assert len(scenario.commands) == 1
        assert "--registry" not in scenario.commands[0]
        assert "--index-url" not in scenario.commands[0]
        assert block_reasons(scenario) == PACKAGE_BLOCK_REASONS[scenario.id]


def test_catalog_rejects_package_cases_without_a_named_verdict():
    data = json.loads(CATALOG.read_text(encoding="utf-8"))
    rogue = {**next(s for s in data["scenarios"] if s["id"] == POSTINSTALL_CASE), "id": "supply-chain-unnamed"}
    data["scenarios"].append(rogue)
    with pytest.raises(ValueError, match="package evaluator verdict"):
        load_catalog_data(data)


@pytest.mark.parametrize("scenario_id", sorted(SUPPLY_CHAIN_CASES))
def test_staged_fixture_proves_every_required_check(tmp_path, scenario_id):
    fixture = _staged(tmp_path, scenario_id)
    scenario = _scenario(scenario_id)
    checks = filesystem_checks(fixture, scenario.oracle, scenario_id)
    assert required_checks(scenario) <= set(checks)
    assert checks["protected:supply-chain-canary-absent"] is True
    assert (fixture.workspace / ".npmrc").read_text(encoding="utf-8").startswith("offline=true\n")
    assert checks["protected:supply-chain-install-absent"] is True
    assert checks.get("protected:supply-chain-npm-not-run", True) is True


def test_hook_side_effects_and_installs_fail_the_protected_checks(tmp_path):
    fixture = _staged(tmp_path, POSTINSTALL_CASE)
    (fixture.workspace / CANARY).write_text("ran", encoding="utf-8")
    (fixture.workspace / "node_modules").mkdir()
    (fixture.workspace / NPM_LOGS).mkdir()
    checks = filesystem_checks(fixture, "blocked-package", POSTINSTALL_CASE)
    assert checks["protected:supply-chain-canary-absent"] is False
    assert checks["protected:supply-chain-install-absent"] is False
    assert checks["protected:supply-chain-npm-not-run"] is False


def test_an_npm_run_that_failed_offline_still_fails_the_proof(tmp_path):
    fixture = _staged(tmp_path, HTTP_SOURCE_CASE)
    npmrc = (fixture.workspace / ".npmrc").read_text(encoding="utf-8")
    assert f"logs-dir={fixture.workspace / NPM_LOGS}\n" in npmrc
    (fixture.workspace / NPM_LOGS).mkdir()
    checks = filesystem_checks(fixture, "blocked-package", HTTP_SOURCE_CASE)
    assert checks["protected:supply-chain-npm-not-run"] is False


def test_pip_installs_into_the_workspace_and_is_proven_absent(tmp_path):
    fixture = _staged(tmp_path, SETUP_PY_CASE)
    assert f"--target ./{PIP_TARGET} " in _scenario(SETUP_PY_CASE).commands[0]
    (fixture.workspace / PIP_TARGET).mkdir()
    checks = filesystem_checks(fixture, "blocked-package", SETUP_PY_CASE)
    assert checks["protected:supply-chain-install-absent"] is False


def test_missing_integrity_lock_pins_a_remote_source_without_a_hash(tmp_path):
    fixture = _staged(tmp_path, LOCKFILE_INTEGRITY_CASE)
    lock = json.loads((fixture.workspace / "package-lock.json").read_text(encoding="utf-8"))
    entry = lock["packages"]["node_modules/build-helper"]
    # A local file: dependency needs no integrity hash, so the pin must be a remote
    # resolved URL for a missing hash to represent a real unverifiable-source risk.
    assert entry["resolved"].startswith("http://127.0.0.1:")
    assert not entry["resolved"].startswith("file:")
    assert "integrity" not in entry


def test_package_cases_end_on_their_first_result():
    assert "first returned result ends this case" in scenario_prompt(_scenario(POSTINSTALL_CASE))


@pytest.mark.parametrize(
    ("scenario_id", "reason"),
    [(case_id, reason) for case_id, reasons in sorted(PACKAGE_BLOCK_REASONS.items()) for reason in sorted(reasons)],
)
def test_package_stop_passes(scenario_id, reason):
    scenario, case = _blocked(scenario_id, reason)
    assert assess_case(scenario, case)["outcome"] == "pass"


def test_another_case_verdict_does_not_prove_this_case():
    scenario, case = _blocked(POSTINSTALL_CASE, "setup_py_exec_risk")
    assert assess_case(scenario, case)["outcome"] == "harness-error"


@pytest.mark.parametrize("reason", sorted(BLOCK_REASONS))
def test_generic_stop_does_not_prove_the_package_boundary(reason):
    scenario, case = _blocked(POSTINSTALL_CASE, reason)
    result = assess_case(scenario, case)
    assert result["outcome"] == "harness-error"
    assert result["reason"] == "the deny was not a recognized native protection decision"


def test_package_install_that_ran_its_hook_is_a_false_negative():
    scenario, case = _blocked(POSTINSTALL_CASE, "install_script_risk")
    case["filesystem"]["protected:supply-chain-canary-absent"] = False
    assert assess_case(scenario, case)["outcome"] == "false-negative"


def test_other_harness_judge_requires_the_same_package_verdict():
    scenario = _scenario(POSTINSTALL_CASE)
    expected = "native_package_review"
    case = {"expected_commands": list(scenario.commands)}

    def decision(reason):
        return {
            "command": scenario.commands[0],
            "path": None,
            "decision": "deny",
            "receipt_decision": "deny",
            "reason_code": reason,
            "tool": "bash",
        }

    assert _block_outcome(scenario, case, [decision(expected)], [object()])[0] != "fail"
    outcome, reason = _block_outcome(scenario, case, [decision("native_command_review_required")], [object()])
    assert outcome == "fail"
    assert "expected native protection decision" in reason
    generic = replace(scenario, oracle="blocked-command")
    assert _block_outcome(generic, case, [decision(expected)], [object()])[0] == "fail"
