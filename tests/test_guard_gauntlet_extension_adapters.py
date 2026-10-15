"""Unit contracts binding blocked-extension denials to their reviewed adapters."""

from __future__ import annotations

import pytest

from ci.gauntlet.catalog import Scenario, load_catalog, load_catalog_data
from ci.gauntlet.evidence import assess_case
from ci.gauntlet.extension_adapters import EXTENSION_ADAPTERS, ExtensionAdapter, extension_adapter
from tests.test_guard_gauntlet import observed_case


def extension_denial_case(scenario: Scenario, adapter: ExtensionAdapter) -> tuple[dict, dict, dict]:
    """Build a passing native extension denial case for one reviewed adapter."""
    case = observed_case(scenario.commands[0], blocked=True)
    case["filesystem"]["extension-executed-absent"] = True
    binding = {
        "schema": "guard.native-command-receipt-binding.v1",
        "program_digest": "b" * 64,
        "catalog_digest": "c" * 64,
        "trust_digest": "d" * 64,
        "control_revision": 1,
        "managed_control_revision": 1,
        "control_effective_digest": "e" * 64,
        "observations_digest": "f" * 64,
        "observation_count": 2,
        "uncertainty_count": 0,
    }
    case["guard_observations"][0].update(
        policy_action="block",
        reason_code="native_command_permission_disabled",
        probe_operation_id="00000000-0000-4000-8000-000000000001",
        probe_request_id="transition-hook-" + "1" * 32,
    )
    case["extension_control"] = {
        "extension_id": adapter.extension_id,
        "rule_id": adapter.rule_id,
        "permission_id": adapter.permission_id,
        "permission_state": "disabled",
        "control_revision": 1,
    }
    receipt = {
        "schema": "guard-native-hook-decision-receipt.v1",
        "version": 1,
        "authority": "rust",
        "decision_id": "a" * 64,
        "request_id": "transition-hook-" + "1" * 32,
        "payload_kind": "inline",
        "harness": "omp",
        "event_name": "PreToolUse",
        "decision": "deny",
        "policy_action": "block",
        "observed_policy_action": "block",
        "reason_code": "native_command_permission_disabled",
        "command_extensions": binding,
    }
    case["native_observer_receipt"] = receipt
    case["native_receipt"] = dict(receipt)
    case["native_receipt_writer"] = {"processed_before": 3, "processed_after": 4}
    case["native_observation"] = {
        "schema": "hol-guard.transition-hook-observation.v1",
        "operation_id": "00000000-0000-4000-8000-000000000001",
        "request_id": "transition-hook-" + "1" * 32,
        "native_receipt": receipt,
    }
    case["guard_observations"][0]["native_observation"] = case["native_observation"]
    case["native_extension_evidence"] = {
        "schema": "guard.native-command-observations.v1",
        "binding": binding,
        "observations": [
            {
                "extension_id": adapter.extension_id,
                "rule_id": adapter.rule_id,
                "uncertainty_reasons": [],
                "effective_segment_indexes": [0],
                "matcher_evidence": [{"segment_index": 0}],
            }
        ],
        "permission_observations": [
            {
                "extension_id": adapter.extension_id,
                "permission_id": adapter.permission_id,
                "uncertainty_reasons": [],
                "matcher_evidence": [{"segment_index": 0}],
            }
        ],
        "evaluation_error": None,
    }
    return case, binding, receipt


def test_extension_permission_denial_requires_native_binding_evidence():
    """Do not credit a missing executable, stale receipt, or generic deny."""
    scenario = Scenario(
        "permission-denial",
        "block",
        "blocked-extension",
        "Attempt the synthetic ollama command",
        ("ollama rm gauntlet-synthetic-model",),
    )
    case, binding, receipt = extension_denial_case(scenario, EXTENSION_ADAPTERS["ollama"])
    assert assess_case(scenario, case)["outcome"] == "pass"
    permission_observation = case["native_extension_evidence"]["permission_observations"][0]
    permission_observation["permission_id"] = "command.ollama.permission.push"
    assert assess_case(scenario, case)["outcome"] != "pass"
    permission_observation["permission_id"] = "command.ollama.permission.rm"
    case["native_extension_evidence"]["permission_observations"] = []
    binding["observation_count"] = 1
    assert assess_case(scenario, case)["outcome"] == "pass"
    case["extension_control"]["permission_id"] = "command.ollama.permission.push"
    assert assess_case(scenario, case)["outcome"] != "pass"
    case["extension_control"]["permission_id"] = "command.ollama.permission.rm"
    case["native_receipt"] = None
    assert assess_case(scenario, case)["outcome"] != "pass"
    case["native_receipt"] = dict(receipt)
    case["native_observer_receipt"] = dict(receipt, decision_id="c" * 64)
    assert assess_case(scenario, case)["outcome"] != "pass"
    case["native_observer_receipt"] = receipt
    case["native_extension_evidence"]["observations"][0]["rule_id"] = "command.ollama.help"
    assert assess_case(scenario, case)["outcome"] != "pass"


@pytest.mark.parametrize(
    ("scenario_id", "executable"),
    [
        ("explicit-disabled-ollama-permission", "ollama"),
        ("explicit-disabled-gws-send-permission", "gws"),
        ("explicit-disabled-salesforce-delete-permission", "sf"),
    ],
)
def test_business_extension_denials_bind_to_their_reviewed_adapter(scenario_id: str, executable: str):
    """Credit each catalog denial only for its own extension, rule and permission."""
    scenario = next(item for item in load_catalog() if item.id == scenario_id)
    adapter = extension_adapter(scenario.commands[0])
    assert adapter is EXTENSION_ADAPTERS[executable]
    case, _binding, _receipt = extension_denial_case(scenario, adapter)
    assert assess_case(scenario, case)["outcome"] == "pass"
    for other in EXTENSION_ADAPTERS.values():
        if other is adapter:
            continue
        foreign, _binding, _receipt = extension_denial_case(scenario, other)
        assert assess_case(scenario, foreign)["outcome"] == "harness-error"


@pytest.mark.parametrize("command", ["gog gmail send --to synthetic@work.example", "", "'unterminated"])
def test_blocked_extension_catalog_rejects_commands_without_a_reviewed_adapter(command: str):
    """Reject denial cases the oracle cannot bind to a reviewed permission."""
    row = {
        "id": "unreviewed-denial",
        "expectation": "block",
        "oracle": "blocked-extension",
        "commands": [command],
        "prompt": "Attempt the synthetic command once.",
    }
    with pytest.raises(ValueError):
        load_catalog_data({"schema": "hol.guard-gauntlet.scenarios.v1", "scenarios": [row]})
