"""Judge and fixture contracts; only live-agent evidence proves product behavior."""

from copy import deepcopy

import pytest

from ci.gauntlet.catalog import WATCH_COMMAND, WATCH_OUTPUT, WATCH_PROMPT, Scenario, load_catalog_data
from ci.gauntlet.evidence import assess_case
from tests.test_guard_gauntlet import observed_case


def watch_case():
    case = observed_case(WATCH_COMMAND)
    binding = {"mode": "observe", "generation": 1, "policy_digest": "a" * 64, "runtime_identity": "b" * 64}
    case["watch_binding_before"] = binding
    case["watch_binding_after"] = deepcopy(binding)
    case["events"][2]["result"] = {"content": [{"type": "text", "text": WATCH_OUTPUT}]}
    pre = case["guard_observations"][0]
    pre.update(
        policy_action="warn",
        probe_operation_id="12345678-1234-1234-1234-123456789abc",
        probe_request_id="transition-hook-" + "b" * 32,
    )
    pre["native_observation"] = {
        "schema": "hol-guard.transition-hook-observation.v1",
        "operation_id": pre["probe_operation_id"],
        "request_id": pre["probe_request_id"],
        "native_receipt": {
            "schema": "guard-native-hook-decision-receipt.v1",
            "authority": "rust",
            "version": 1,
            "harness": "omp",
            "event_name": "PreToolUse",
            "request_id": pre["probe_request_id"],
            "request_digest": "d" * 64,
            "policy_generation": 1,
            "policy_digest": "a" * 64,
            "runtime_identity": "b" * 64,
            "observe_mode": False,
            "decision_id": "c" * 64,
            "decision": "deny",
            "policy_action": "sandbox-required",
            "reason_code": pre["reason_code"],
        },
    }
    return case


def scenario():
    return Scenario("watch", "allow", "watch-command", WATCH_PROMPT, (WATCH_COMMAND,))


def test_watch_requires_a_correlated_would_have_stopped_receipt():
    assert assess_case(scenario(), watch_case())["outcome"] == "pass"


@pytest.mark.parametrize(
    "field,value", [("commands", ["echo substituted"]), ("prompt", "Run anything"), ("required_tools", ["read"])]
)
def test_watch_catalog_rejects_model_scope_changes(field, value):
    row = {
        "id": "watch",
        "expectation": "allow",
        "oracle": "watch-command",
        "prompt": WATCH_PROMPT,
        "commands": [WATCH_COMMAND],
    }
    row[field] = value
    with pytest.raises(ValueError, match="fixed harmless"):
        load_catalog_data({"schema": "hol.guard-gauntlet.scenarios.v1", "scenarios": [row]})


@pytest.mark.parametrize("change", ["binding", "receipt", "allow", "correlation", "version", "output", "policy"])
def test_watch_cannot_pass_from_an_ordinary_allow_or_incomplete_proof(change):
    case = watch_case()
    pre = case["guard_observations"][0]
    if change == "binding":
        del case["watch_binding_before"]
    elif change == "receipt":
        del pre["native_observation"]["native_receipt"]
    elif change == "allow":
        pre["native_observation"]["native_receipt"]["decision"] = "allow"
    elif change == "version":
        pre["native_observation"]["native_receipt"]["version"] = True
    elif change == "output":
        case["events"][2]["result"] = {"content": []}
    elif change == "policy":
        pre["native_observation"]["native_receipt"]["policy_digest"] = "e" * 64
    else:
        pre["probe_request_id"] = "transition-hook-" + "d" * 32
    assert assess_case(scenario(), case)["outcome"] == "harness-error"
