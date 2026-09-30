"""Mutation regressions for the separately authored native capability contract."""

from __future__ import annotations

import copy
import json
from dataclasses import replace
from itertools import chain
from types import SimpleNamespace
from typing import TYPE_CHECKING, cast

import pytest

from tests import guard_command_corpus_native_contract as contract
from tests.guard_command_corpus import CommandCorpusCase, iter_adversarial_corpus, iter_benign_corpus
from tests.guard_command_corpus_oracle import iter_adversarial_oracle, iter_benign_oracle
from tests.guard_command_corpus_oracle_types import OracleRecord

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from codex_plugin_scanner.guard.runtime.native_command_evaluation import NativeCommandEvaluation


def _pairs() -> Iterator[tuple[CommandCorpusCase, OracleRecord]]:
    return chain(
        zip(iter_benign_corpus(), iter_benign_oracle(), strict=True),
        zip(iter_adversarial_corpus(), iter_adversarial_oracle(), strict=True),
    )


def test_native_contract_keeps_complete_original_inputs_and_visible_stronger_differences() -> None:
    groups = contract.expected_native_groups()
    original = contract.expected_original_gap_groups()
    rejected = contract.expected_native_rejection_groups()
    metadata = contract.load_native_contract()
    assert len(groups) == 58
    assert sum(count for count, _ in groups.values()) == 51_000
    assert sum(count for count, _ in original.values()) == 11_558
    assert rejected["native_command_evaluation_failed"][0] == 27_084
    assert metadata["totals"] == {
        "cases": 51_000,
        "sources": 52,
        "groups": 58,
        "equal_to_original_oracle": 39_442,
        "stronger_than_original_oracle": 11_558,
        "below_original_oracle": 0,
        "native_evaluation_errors": 27_084,
        "improved_upstream_benign_sources": 3,
        "improved_upstream_benign_cases": 75,
        "improved_bounded_git_sources": 2,
        "improved_bounded_git_cases": 50,
    }


@pytest.mark.parametrize("mutation", ("command", "context", "case_id", "oracle_source", "oracle_floor"))
def test_native_contract_rejects_changed_inputs_and_oracles(mutation: str) -> None:
    case, oracle = next(_pairs())
    if mutation == "command":
        case = replace(case, command=case.command + " && echo changed")
    elif mutation == "context":
        case = replace(case, context=(("cwd", "changed"),))
    elif mutation == "case_id":
        case = replace(case, case_id="c-unknown-case")
    elif mutation == "oracle_source":
        oracle = replace(oracle, source_id="workflow:unreviewed:unknown")
    else:
        oracle = replace(oracle, minimum_floor="allow")
    with pytest.raises(ValueError, match="immutable contracted"):
        contract.expected_native_case(case, oracle)


def test_native_contract_rejects_changed_immutable_source_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = contract.load_native_contract()
    data = copy.deepcopy(original)
    identities = cast(dict[str, str], data["immutable_input_sha256"])
    identities["tests/guard_command_corpus_oracle_benign.py"] = "0" * 64
    changed = tmp_path / "native-contract.json"
    changed.write_text(json.dumps(data))
    monkeypatch.setattr(contract, "NATIVE_CONTRACT_PATH", changed)
    contract._contract_data.cache_clear()
    try:
        with pytest.raises(ValueError, match="immutable input changed"):
            contract.load_native_contract()
    finally:
        contract._contract_data.cache_clear()


@pytest.fixture(scope="module")
def native_samples() -> dict[str, tuple[CommandCorpusCase, OracleRecord, NativeCommandEvaluation]]:
    from codex_plugin_scanner.guard.runtime import package_protect_projection
    from tests.guard_command_corpus_native import evaluate_native_corpus_batch
    from tests.harness_attribution_env import HARNESS_ENV_MARKERS

    selected: dict[str, tuple[CommandCorpusCase, OracleRecord]] = {}
    for case, oracle in _pairs():
        expected = contract.expected_native_case(case, oracle)
        selected.setdefault(expected.group_id, (case, oracle))
        if len(selected) == 58:
            break
    assert len(selected) == 58
    with pytest.MonkeyPatch.context() as attribution:
        for marker in HARNESS_ENV_MARKERS:
            attribution.delenv(marker, raising=False)
        attribution.setenv("__CFBundleIdentifier", "com.apple.Terminal")
        attribution.setattr(package_protect_projection, "resolve_parent_process_harness", lambda: None)
        evaluated = evaluate_native_corpus_batch(
            [case for case, _ in selected.values()], cwd=contract.ROOT / "workspace", home_dir=contract.ROOT / "home"
        )
    return {
        key: (case, oracle, reviewed)
        for (key, (case, oracle)), reviewed in zip(selected.items(), evaluated, strict=True)
    }


def test_native_contract_validates_every_authored_signature_without_rewriting_evidence(
    native_samples: dict[str, tuple[CommandCorpusCase, OracleRecord, NativeCommandEvaluation]],
) -> None:
    for group_id, (case, oracle, reviewed) in native_samples.items():
        before = json.dumps(reviewed.payload, sort_keys=True)
        assert contract.validate_native_case(case, oracle, reviewed) == group_id
        assert json.dumps(reviewed.payload, sort_keys=True) == before


@pytest.mark.parametrize("mutation", ("model_uncertainty", "evaluation_error", "native_reason", "benign_proof"))
def test_native_contract_rejects_changed_failure_signatures_even_when_action_is_still_block(
    native_samples: dict[str, tuple[CommandCorpusCase, OracleRecord, NativeCommandEvaluation]], mutation: str
) -> None:
    case, oracle, reviewed = native_samples["adversarial:substitutions|all"]
    payload = copy.deepcopy(reviewed.payload)
    if mutation == "model_uncertainty":
        cast(dict[str, object], payload["command_model"])["uncertainty_reason"] = "different-parser-failure"
    elif mutation == "evaluation_error":
        cast(dict[str, object], payload["command_extensions"])["evaluation_error"] = None
    elif mutation == "native_reason":
        payload["reason_code"] = "different-native-failure"
    else:
        payload["explicitly_benign"] = True
    changed = replace(reviewed, payload=payload)
    before = json.dumps(changed.payload, sort_keys=True)
    with pytest.raises(ValueError, match="native corpus contract mismatch"):
        contract.validate_native_case(case, oracle, changed)
    assert json.dumps(changed.payload, sort_keys=True) == before


def test_native_contract_rejects_missing_owned_uncertainty_even_when_action_is_still_block(
    native_samples: dict[str, tuple[CommandCorpusCase, OracleRecord, NativeCommandEvaluation]],
) -> None:
    case, oracle, reviewed = native_samples["workflow:workspace-patch-write:patch-apply|all"]
    payload = copy.deepcopy(reviewed.payload)
    evidence = cast(dict[str, object], payload["command_extensions"])
    observations = cast(list[dict[str, object]], evidence["observations"])
    assert len(observations) == 15
    observations.pop()
    with pytest.raises(ValueError, match="uncertain_rules"):
        contract.validate_native_case(case, oracle, replace(reviewed, payload=payload))


@pytest.mark.parametrize("wrong_floor", ("allow", "block"))
def test_native_contract_rejects_decision_floor_drift_in_either_direction(
    native_samples: dict[str, tuple[CommandCorpusCase, OracleRecord, NativeCommandEvaluation]], wrong_floor: str
) -> None:
    case, oracle, reviewed = native_samples["workflow:navigation-public-read:working-directory|all"]
    changed = SimpleNamespace(
        payload=reviewed.payload,
        evaluation=SimpleNamespace(decision_plane=SimpleNamespace(action=wrong_floor)),
    )
    with pytest.raises(ValueError, match="decision_plane_floor"):
        contract.validate_native_case(case, oracle, cast("NativeCommandEvaluation", changed))
