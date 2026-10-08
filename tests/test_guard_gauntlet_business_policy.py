"""Business-mode destructive-floor case: judge contract and native fixture compilation."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from ci.gauntlet.business_policy import (
    BUSINESS_DIRECTORY_DELETE,
    BUSINESS_POLICY_DOCUMENT,
    BUSINESS_RULE_IDS,
    bind_business_snapshot,
)
from ci.gauntlet.catalog import load_catalog
from ci.gauntlet.evidence import assess_case
from tests.test_guard_gauntlet import observed_case

DIGEST = "a" * 64


def _scenario():
    return next(s for s in load_catalog() if s.id == BUSINESS_DIRECTORY_DELETE)


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


def _case():
    scenario = _scenario()
    case = observed_case(scenario.commands[0], blocked=True)
    case["business_policy"] = bind_business_snapshot(_installed(), _snapshot(), PREPARED)
    receipt = {"policy_generation": PREPARED["generation"], "policy_digest": PREPARED["policy_digest"]}
    case["guard_observations"][0]["native_observation"] = {"native_receipt": receipt}
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
    "receipt",
    [None, {"policy_generation": 2, "policy_digest": "c" * 64}, {"policy_generation": 1, "policy_digest": "d" * 64}],
)
def test_deny_under_another_snapshot_is_not_a_pass(receipt):
    scenario, case = _case()
    case["guard_observations"][0]["native_observation"] = {"native_receipt": receipt}
    result = assess_case(scenario, case)
    assert result["outcome"] == "harness-error"
    assert result["reason"] == "the deny was not decided under the bound business snapshot"


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


def test_native_compiler_accepts_the_fixture_document(native_hook_force: Path):
    from codex_plugin_scanner.guard.native_business_document_compile import compile_business_policy_document
    from codex_plugin_scanner.guard.policy_document import policy_document_digest
    from codex_plugin_scanner.guard.policy_document_yaml import parse_policy_document_yaml

    document = parse_policy_document_yaml(json.dumps(BUSINESS_POLICY_DOCUMENT))
    binding = compile_business_policy_document(document).binding()
    assert binding["sourceDocumentDigest"] == policy_document_digest(document)
    assert binding["defaultAction"] == "allow"
    assert [rule["id"] for rule in binding["rules"]] == list(BUSINESS_RULE_IDS)
