"""Business-mode cases: judge contract and native fixture compilation."""

from __future__ import annotations

import json
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

from ci.gauntlet.business_policy import (
    BUSINESS_CASES,
    BUSINESS_CLI_CASES,
    BUSINESS_DIRECTORY_DELETE,
    BUSINESS_POLICY_DOCUMENT,
    BUSINESS_RULE_IDS,
    bind_business_snapshot,
)
from ci.gauntlet.catalog import load_catalog
from ci.gauntlet.evidence import assess_case
from ci.gauntlet.fixtures import EXECUTED_FLAG, SOURCE, create_fixture, filesystem_checks
from tests.test_guard_gauntlet import observed_case

DIGEST = "a" * 64


def _scenario(scenario_id=BUSINESS_DIRECTORY_DELETE):
    return next(s for s in load_catalog() if s.id == scenario_id)


def _installed():
    return {
        "source_digest": DIGEST,
        "imported_digest": DIGEST,
        "default_action": "allow",
        "rule_ids": list(BUSINESS_RULE_IDS),
    }


PREPARED = {"generation": 1, "policy_digest": "c" * 64}


def _snapshot():
    return {
        **PREPARED,
        "business_policy": {
            "sourceDocumentDigest": DIGEST,
            "defaultAction": "allow",
            "rules": [{"id": rule_id} for rule_id in BUSINESS_RULE_IDS],
        },
    }


def _bind_native(case):
    """Attach a correlated native receipt to every PreToolUse observation."""
    for index, observation in enumerate(case["guard_observations"]):
        if observation["event"] != "PreToolUse":
            continue
        request_id = f"transition-hook-{index:032x}"
        operation_id = f"{index:08x}-0000-4000-8000-000000000000"
        observation["probe_request_id"] = request_id
        observation["probe_operation_id"] = operation_id
        observation["native_observation"] = {
            "schema": "hol-guard.transition-hook-observation.v1",
            "request_id": request_id,
            "operation_id": operation_id,
            "native_receipt": {
                "schema": "guard-native-hook-decision-receipt.v1",
                "version": 1,
                "authority": "rust",
                "decision_id": "e" * 64,
                "request_id": request_id,
                "request_digest": "f" * 64,
                "runtime_identity": "0" * 64,
                "policy_generation": PREPARED["generation"],
                "policy_digest": PREPARED["policy_digest"],
                "observe_mode": False,
                "harness": "omp",
                "event_name": "PreToolUse",
                "payload_kind": "inline",
                "decision": observation["decision"],
                "reason_code": observation["reason_code"],
            },
        }


def _receipt(case):
    return case["guard_observations"][0]["native_observation"]["native_receipt"]


def _case(scenario_id=BUSINESS_DIRECTORY_DELETE, *, blocked=True, reason=None):
    scenario = _scenario(scenario_id)
    case = observed_case(scenario.commands[0], blocked=blocked)
    if reason is not None:
        case["guard_observations"][0]["reason_code"] = reason
    if not blocked:
        end = next(event for event in case["events"] if event["type"] == "tool_execution_end")
        end["result"] = {"content": [{"type": "text", "text": SOURCE}]}
    case["business_policy"] = bind_business_snapshot(_installed(), _snapshot(), PREPARED)
    _bind_native(case)
    return scenario, case


def test_business_case_reuses_the_core_destructive_contract():
    by_id = {s.id: s for s in load_catalog()}
    core = by_id["destructive-directory-delete"]
    business = by_id[BUSINESS_DIRECTORY_DELETE]
    assert replace(business, id=core.id, prompt=core.prompt) == core


def test_business_bound_native_deny_passes():
    scenario, case = _case()
    assert assess_case(scenario, case)["outcome"] == "pass"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("snapshot_source_digest", "b" * 64),
        ("imported_digest", None),
        ("snapshot_default_action", "block"),
        ("snapshot_rule_ids", []),
        ("source_digest", "not-a-digest"),
    ],
)
def test_unbound_business_policy_is_not_a_pass(field, value):
    scenario, case = _case()
    case["business_policy"][field] = value
    result = assess_case(scenario, case)
    assert result["outcome"] == "harness-error"


@pytest.mark.parametrize("reason", ["native_policy_block", "native_policy_review_required"])
def test_policy_sourced_deny_does_not_prove_the_floor(reason):
    scenario, case = _case()
    case["guard_observations"][0]["reason_code"] = reason
    result = assess_case(scenario, case)
    assert result["outcome"] == "harness-error"
    assert result["reason"] == "the deny did not come from the intrinsic deletion floor"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("policy_generation", 2),
        ("policy_digest", "d" * 64),
        ("decision_id", None),
        ("authority", "python"),
        ("request_id", "transition-hook-" + "9" * 32),
        ("decision", "allow"),
        ("reason_code", "native_command_review_required"),
        ("observe_mode", True),
    ],
)
def test_deny_without_a_matching_native_receipt_is_not_a_pass(field, value):
    scenario, case = _case()
    _receipt(case)[field] = value
    result = assess_case(scenario, case)
    assert result["outcome"] == "harness-error"
    assert result["reason"] == "the decision was not made under the bound business snapshot"


def test_deny_without_a_native_receipt_is_not_a_pass():
    scenario, case = _case()
    del case["guard_observations"][0]["native_observation"]
    assert assess_case(scenario, case)["outcome"] == "harness-error"


def test_malformed_snapshot_rule_is_not_a_pass():
    scenario = _scenario()
    case = observed_case(scenario.commands[0], blocked=True)
    snapshot = _snapshot()
    snapshot["business_policy"]["rules"].append("not-a-rule")
    case["business_policy"] = bind_business_snapshot(_installed(), snapshot, PREPARED)
    assert assess_case(scenario, case)["outcome"] == "harness-error"


def test_missing_business_policy_is_not_a_pass():
    scenario, case = _case()
    del case["business_policy"]
    assert assess_case(scenario, case)["outcome"] == "harness-error"


def test_business_allow_does_not_excuse_a_destructive_execution():
    scenario = _scenario()
    case = observed_case(scenario.commands[0], blocked=False)
    case["business_policy"] = bind_business_snapshot(_installed(), _snapshot(), PREPARED)
    assert assess_case(scenario, case)["outcome"] == "false-negative"


def test_snapshot_without_business_binding_fails_the_run():
    with pytest.raises(RuntimeError, match="lacks the installed business policy"):
        bind_business_snapshot(_installed(), {**PREPARED, "effective_policy": {}}, PREPARED)


def test_snapshot_from_another_generation_fails_the_run():
    with pytest.raises(RuntimeError, match="changed after workspace readiness"):
        bind_business_snapshot(_installed(), _snapshot(), {**PREPARED, "generation": 2})


def test_unacknowledged_snapshot_fails_the_run():
    with pytest.raises(RuntimeError, match="was not acknowledged"):
        bind_business_snapshot(_installed(), None, PREPARED)


def _cli_case(scenario_id, reason="native_business_context_unavailable"):
    scenario, case = _case(scenario_id, reason=reason)
    case["filesystem"]["business-cli-executed-absent"] = True
    return scenario, case


def test_every_business_case_is_in_the_catalog():
    assert {s.id for s in load_catalog()} >= BUSINESS_CASES


@pytest.mark.parametrize("scenario_id", sorted(BUSINESS_CLI_CASES))
@pytest.mark.parametrize("reason", ["native_business_context_unavailable", "native_command_review_required"])
def test_business_cli_floor_deny_passes(scenario_id, reason):
    scenario, case = _cli_case(scenario_id, reason)
    assert assess_case(scenario, case)["outcome"] == "pass"


@pytest.mark.parametrize("scenario_id", sorted(BUSINESS_CLI_CASES))
@pytest.mark.parametrize(
    "reason", ["native_policy_blocked", "native_policy_review_required", "native_destructive_command"]
)
def test_business_cli_deny_from_another_source_is_not_a_pass(scenario_id, reason):
    scenario, case = _cli_case(scenario_id, reason)
    result = assess_case(scenario, case)
    assert result["outcome"] == "harness-error"
    assert result["reason"] == "the deny did not come from the business context floor"


@pytest.mark.parametrize("scenario_id", sorted(BUSINESS_CLI_CASES))
def test_business_cli_case_requires_the_sentinel_check(scenario_id):
    scenario, case = _cli_case(scenario_id)
    del case["filesystem"]["business-cli-executed-absent"]
    assert assess_case(scenario, case)["outcome"] != "pass"


@pytest.mark.parametrize("scenario_id", sorted(BUSINESS_CLI_CASES))
def test_executed_business_cli_is_not_a_pass(scenario_id):
    scenario, case = _cli_case(scenario_id)
    case["filesystem"]["business-cli-executed-absent"] = False
    assert assess_case(scenario, case)["outcome"] == "false-negative"


@pytest.mark.skipif(not Path("/bin/sh").exists(), reason="sentinels are POSIX shell scripts")
@pytest.mark.parametrize("executable", ["gws", "gog"])
def test_business_cli_sentinel_records_execution(tmp_path: Path, executable):
    fixture = create_fixture(tmp_path / "fixture")
    scenario_id = sorted(BUSINESS_CLI_CASES)[0]
    assert filesystem_checks(fixture, "blocked-command", scenario_id)["business-cli-executed-absent"]
    subprocess.run([str(fixture.root / "bin" / executable), "gmail", "send"], check=True, timeout=10)
    assert (fixture.workspace / EXECUTED_FLAG).read_text(encoding="utf-8") == "executed\n"
    assert not filesystem_checks(fixture, "blocked-command", scenario_id)["business-cli-executed-absent"]


def test_business_ordinary_read_passes_under_the_bound_policy():
    scenario, case = _case("business-policy-ordinary-read", blocked=False)
    assert assess_case(scenario, case)["outcome"] == "pass"


def test_denied_business_ordinary_read_is_a_false_positive():
    scenario, case = _case("business-policy-ordinary-read", blocked=True)
    _receipt(case)["policy_digest"] = "d" * 64
    assert assess_case(scenario, case)["outcome"] == "false-positive"


def test_business_ordinary_read_needs_its_output():
    scenario, case = _case("business-policy-ordinary-read", blocked=False)
    end = next(event for event in case["events"] if event["type"] == "tool_execution_end")
    end["result"] = {"content": [{"type": "text", "text": "other\n"}]}
    assert assess_case(scenario, case)["outcome"] == "task-incomplete"


@pytest.mark.parametrize(("field", "value"), [("policy_generation", 2), ("policy_digest", "d" * 64)])
def test_business_ordinary_read_under_another_snapshot_is_not_a_pass(field, value):
    scenario, case = _case("business-policy-ordinary-read", blocked=False)
    _receipt(case)[field] = value
    result = assess_case(scenario, case)
    assert result["outcome"] == "harness-error"
    assert result["reason"] == "the decision was not made under the bound business snapshot"


def test_business_ordinary_read_needs_the_bound_policy():
    scenario, case = _case("business-policy-ordinary-read", blocked=False)
    del case["business_policy"]
    assert assess_case(scenario, case)["outcome"] == "harness-error"


def test_native_compiler_accepts_the_fixture_document(native_hook_force: Path):
    from codex_plugin_scanner.guard.native_business_document_compile import compile_business_policy_document
    from codex_plugin_scanner.guard.policy_document import policy_document_digest
    from codex_plugin_scanner.guard.policy_document_yaml import parse_policy_document_yaml

    document = parse_policy_document_yaml(json.dumps(BUSINESS_POLICY_DOCUMENT))
    binding = compile_business_policy_document(document).binding()
    assert binding["sourceDocumentDigest"] == policy_document_digest(document)
    assert binding["defaultAction"] == "allow"
    assert [rule["id"] for rule in binding["rules"]] == list(BUSINESS_RULE_IDS)
