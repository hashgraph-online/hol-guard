"""Independent, input-bound contract for the inherited native corpus behavior.

The original security oracle remains separate. This sidecar records the native
capability boundary, including stronger blocks and explicit evaluation errors;
it never derives an expected action or group from a runtime response.
"""

from __future__ import annotations

import copy
import hashlib
import json
from collections import defaultdict
from collections.abc import Iterator
from dataclasses import dataclass
from functools import lru_cache
from itertools import chain
from pathlib import Path
from typing import TYPE_CHECKING, cast

from tests.guard_command_corpus import (
    CommandCorpusCase,
    iter_adversarial_corpus,
    iter_benign_corpus,
    load_seed_manifest,
    stable_case_id,
)
from tests.guard_command_corpus_oracle import iter_adversarial_oracle, iter_benign_oracle
from tests.guard_command_corpus_oracle_types import OracleRecord

if TYPE_CHECKING:
    from codex_plugin_scanner.guard.runtime.native_command_evaluation import NativeCommandEvaluation

ROOT = Path(__file__).resolve().parents[1]
NATIVE_CONTRACT_PATH = Path(__file__).parent / "fixtures" / "guard-command-corpus" / "native-contract.json"
_ACTIONS = ("allow", "warn", "review", "require-reapproval", "sandbox-required", "block")
_WORKER_SHARD: tuple[int, int] | None = None


def configure_native_contract_shard(shard_index: int, shard_count: int) -> None:
    """Retain only this worker's input identities while checking all memberships."""

    if type(shard_index) is not int or type(shard_count) is not int or not 0 <= shard_index < shard_count <= 16:
        raise ValueError("native corpus shard is invalid")
    global _WORKER_SHARD
    selected = shard_index, shard_count
    if selected != _WORKER_SHARD:
        _WORKER_SHARD = selected
        _input_contracts.cache_clear()


@dataclass(frozen=True, slots=True)
class NativeCaseContract:
    group_id: str
    source_id: str
    variant_modulus: int
    variant_remainder: int
    original_floor: str
    expected_floor: str
    expected_native_floor: str
    expected_confidence: str
    expected_uncertainty: str | None
    expected_evalerror: str | None
    expected_uncertain_rule_ids: tuple[str, ...]
    expected_native_reason: str
    expected_path_overridden: bool


def _mapping(value: object, name: str) -> dict[str, object]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise ValueError(f"native corpus contract {name} must be an object")
    return cast(dict[str, object], value)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("native corpus contract contains a duplicate JSON key")
        result[key] = value
    return result


@lru_cache(maxsize=1)
def _contract_data() -> dict[str, object]:
    encoded = NATIVE_CONTRACT_PATH.read_bytes()
    if len(encoded) > 1_048_576:
        raise ValueError("native corpus contract exceeds its size bound")
    data = _mapping(json.loads(encoded, object_pairs_hook=_unique_object), "document")
    if data.get("schema") != "guard.command-corpus-native-contract.v1":
        raise ValueError("native corpus contract schema mismatch")
    for relative, digest in _mapping(data.get("immutable_input_sha256"), "input identities").items():
        if hashlib.sha256((ROOT / relative).read_bytes().replace(b"\r\n", b"\n")).hexdigest() != digest:
            raise ValueError(f"native corpus immutable input changed: {relative}")
    provenance = _mapping(data.get("inherited_source_identities"), "source identities")
    for relative, raw in _mapping(provenance.get("sources"), "sources").items():
        identity = _mapping(raw, "source identity")
        if hashlib.sha256((ROOT / relative).read_bytes().replace(b"\r\n", b"\n")).hexdigest() != identity.get("candidate_sha256"):
            raise ValueError(f"native corpus reviewed implementation changed: {relative}")
    return data


def load_native_contract() -> dict[str, object]:
    """Return review metadata without exposing the cached expectation object."""

    return copy.deepcopy(_contract_data())


@lru_cache(maxsize=1)
def _groups() -> dict[str, NativeCaseContract]:
    rows = _contract_data().get("groups")
    if not isinstance(rows, list) or len(rows) != 58:
        raise ValueError("native corpus contract must enumerate 58 fixed groups")
    groups: dict[str, NativeCaseContract] = {}
    for raw in rows:
        row = _mapping(raw, "group")
        expected = _mapping(row.get("expected"), "expectation")
        rules = expected.get("uncertain_rule_ids")
        if not isinstance(rules, list) or any(not isinstance(rule, str) for rule in rules):
            raise ValueError("native corpus uncertain rules must be explicit strings")
        if rules != sorted(set(rules)):
            raise ValueError("native corpus uncertain rules must be sorted and unique")
        value = NativeCaseContract(
            group_id=cast(str, row["group_id"]),
            source_id=cast(str, row["source_id"]),
            variant_modulus=cast(int, row["variant_modulus"]),
            variant_remainder=cast(int, row["variant_remainder"]),
            original_floor=cast(str, row["original_floor"]),
            expected_floor=cast(str, expected["decision_plane_floor"]),
            expected_native_floor=cast(str, expected["native_floor"]),
            expected_confidence=cast(str, expected["model_confidence"]),
            expected_uncertainty=cast(str | None, expected["model_uncertainty"]),
            expected_evalerror=cast(str | None, expected["evaluation_error"]),
            expected_uncertain_rule_ids=tuple(cast(list[str], rules)),
            expected_native_reason=cast(str, expected["native_reason"]),
            expected_path_overridden=cast(bool, expected["path_overridden"]),
        )
        if (
            not isinstance(value.group_id, str)
            or not isinstance(value.source_id, str)
            or value.group_id in groups
            or type(value.variant_modulus) is not int
            or value.variant_modulus not in (1, 4)
            or type(value.variant_remainder) is not int
            or not 0 <= value.variant_remainder < value.variant_modulus
            or value.original_floor not in _ACTIONS
            or value.expected_floor not in _ACTIONS
            or value.expected_native_floor not in ("review", "block")
            or value.expected_confidence not in ("exact", "uncertain")
            or value.expected_evalerror not in (None, "native_command_evaluation_failed")
            or type(value.expected_path_overridden) is not bool
            or not isinstance(value.expected_native_reason, str)
            or _ACTIONS.index(value.expected_floor) < _ACTIONS.index(value.original_floor)
        ):
            raise ValueError("native corpus group contract is invalid")
        groups[value.group_id] = value
    if len({group.source_id for group in groups.values()}) != 52:
        raise ValueError("native corpus contract must enumerate all 52 sources")
    return groups


def _input_pairs() -> Iterator[tuple[CommandCorpusCase, OracleRecord]]:
    yield from chain(
        zip(iter_benign_corpus(), iter_benign_oracle(), strict=True),
        zip(iter_adversarial_corpus(), iter_adversarial_oracle(), strict=True),
    )


def _input_digest(case: CommandCorpusCase) -> bytes:
    return hashlib.sha256(
        json.dumps([case.command, case.context], separators=(",", ":"), ensure_ascii=False).encode()
    ).digest()


def _oracle_facts(oracle: OracleRecord) -> tuple[object, ...]:
    return (
        oracle.workflow_family,
        oracle.effects,
        oracle.target_scope,
        oracle.uncertainties,
        oracle.required_proofs,
        oracle.provided_proofs,
        oracle.minimum_floor,
        oracle.decision_status,
        oracle.owner,
    )


def _framed_ids(ids: list[str]) -> str:
    digest = hashlib.sha256()
    for case_id in sorted(ids):
        encoded = case_id.encode("ascii")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return digest.hexdigest()


@lru_cache(maxsize=2)
def _input_contracts(
    retain_inputs: bool,
) -> tuple[
    dict[str, tuple[str, bytes]],
    dict[str, tuple[object, ...]],
    dict[str, tuple[int, str]],
    dict[str, tuple[int, str]],
    dict[str, tuple[int, str]],
]:
    """Bind authored selectors to immutable input identities, never responses."""

    groups = _groups()
    by_source: defaultdict[str, list[NativeCaseContract]] = defaultdict(list)
    for group in groups.values():
        by_source[group.source_id].append(group)
    manifest = load_seed_manifest()
    variant_ids: dict[str, int] = {}
    benign_variants = cast(int, manifest["benign_variants_per_seed"])
    for source_id in by_source:
        if source_id.startswith("workflow:"):
            for variant in range(benign_variants):
                variant_ids[stable_case_id(source_id, variant)] = variant
    categories = cast(list[list[str]], manifest["adversarial_categories"])
    for index in range(cast(int, manifest["adversarial_target_count"])):
        source_id = f"adversarial:{categories[index % len(categories)][0]}"
        variant = index // len(categories)
        variant_ids[stable_case_id(source_id, variant)] = variant

    inputs: dict[str, tuple[str, bytes]] = {}
    facts: dict[str, tuple[object, ...]] = {}
    members: defaultdict[str, list[str]] = defaultdict(list)
    original_gaps: defaultdict[str, list[str]] = defaultdict(list)
    rejected: defaultdict[str, list[str]] = defaultdict(list)
    stronger = 0
    total = 0
    for position, (case, oracle) in enumerate(_input_pairs()):
        if case.case_id != oracle.case_id or case.case_id not in variant_ids:
            raise ValueError("native corpus input/oracle identity mismatch")
        variant = variant_ids.pop(case.case_id)
        source_id = oracle.source_id
        if source_id not in by_source:
            raise ValueError("native corpus source is not explicitly contracted")
        selected = [
            group for group in by_source[source_id] if variant % group.variant_modulus == group.variant_remainder
        ]
        if len(selected) != 1:
            raise ValueError("native corpus selector must match exactly once")
        group = selected[0]
        if group.original_floor != oracle.minimum_floor:
            raise ValueError("native corpus original oracle floor changed")
        oracle_facts = _oracle_facts(oracle)
        if facts.setdefault(source_id, oracle_facts) != oracle_facts:
            raise ValueError("native corpus source oracle facts changed")
        # Original benign and adversarial generators shard each stream by its
        # own position. Preserve that rule, independent of native responses.
        stream_position = position if position < 1_000 else position - 1_000
        if retain_inputs and (_WORKER_SHARD is None or stream_position % _WORKER_SHARD[1] == _WORKER_SHARD[0]):
            inputs[case.case_id] = group.group_id, _input_digest(case)
        members[group.group_id].append(case.case_id)
        is_stronger = _ACTIONS.index(group.expected_floor) > _ACTIONS.index(group.original_floor)
        stronger += is_stronger
        total += 1
        if is_stronger:
            original_gaps[
                "|".join((oracle.owner, "overclassified", oracle.minimum_floor, group.expected_floor))
            ].append(case.case_id)
        if group.expected_evalerror is not None:
            rejected[group.expected_evalerror].append(case.case_id)
    if variant_ids or total != 51_000 or stronger != 11_558 or set(members) != set(groups):
        raise ValueError("native corpus fixed input coverage changed")
    expected: dict[str, tuple[int, str]] = {}
    for raw in cast(list[object], _contract_data()["groups"]):
        row = _mapping(raw, "group")
        group_id = cast(str, row["group_id"])
        membership = _mapping(row["membership"], "membership")
        calculated = len(members[group_id]), _framed_ids(members[group_id])
        if calculated != (membership.get("count"), membership.get("case_ids_framed_sha256")):
            raise ValueError(f"native corpus group membership changed: {group_id}")
        expected[group_id] = calculated
    return (
        inputs,
        facts,
        expected,
        {
            key: (len(ids), hashlib.sha256(("\n".join(sorted(ids)) + "\n").encode("ascii")).hexdigest())
            for key, ids in original_gaps.items()
        },
        {key: (len(ids), _framed_ids(ids)) for key, ids in rejected.items()},
    )


def expected_native_groups() -> dict[str, tuple[int, str]]:
    """Return verified, complete fixed group counts and input identity digests."""

    return dict(_input_contracts(False)[2])


def expected_original_gap_groups() -> dict[str, tuple[int, str]]:
    """Keep the original oracle's stronger differences separately visible."""

    return dict(_input_contracts(False)[3])


def expected_native_rejection_groups() -> dict[str, tuple[int, str]]:
    """Bind explicit inherited evaluation errors to their exact input cases."""

    return dict(_input_contracts(False)[4])


def expected_native_case(case: CommandCorpusCase, oracle: OracleRecord) -> NativeCaseContract:
    inputs, facts, _, _, _ = _input_contracts(True)
    record = inputs.get(case.case_id)
    if record is None or case.case_id != oracle.case_id or record[1] != _input_digest(case):
        raise ValueError("native corpus case is not the immutable contracted input")
    expected = _groups()[record[0]]
    if oracle.source_id != expected.source_id or _oracle_facts(oracle) != facts[expected.source_id]:
        raise ValueError("native corpus oracle is not the immutable contracted oracle")
    return expected


def validate_native_case(case: CommandCorpusCase, oracle: OracleRecord, reviewed: NativeCommandEvaluation) -> str:
    """Require the authored native signature without modifying its evidence."""

    expected = expected_native_case(case, oracle)
    payload = _mapping(reviewed.payload, "native payload")
    model = _mapping(payload.get("command_model"), "native model")
    evidence = _mapping(payload.get("command_extensions"), "native observations")
    binding = _mapping(evidence.get("binding"), "native binding")
    observations = evidence.get("observations")
    permissions = evidence.get("permission_observations")
    if not isinstance(observations, list) or not isinstance(permissions, list):
        raise ValueError("native corpus observation arrays are missing")
    uncertain_rules: list[str] = []
    for raw in observations:
        observation = _mapping(raw, "observation")
        reasons = observation.get("uncertainty_reasons")
        if reasons:
            if reasons != ["matcher-failure"] or not isinstance(observation.get("rule_id"), str):
                raise ValueError("native corpus uncertainty evidence changed")
            uncertain_rules.append(cast(str, observation["rule_id"]))
    if any(_mapping(raw, "permission").get("uncertainty_reasons") for raw in permissions):
        raise ValueError("native corpus unexpected permission uncertainty")
    checks: tuple[tuple[str, object, object], ...] = (
        ("decision_plane_floor", reviewed.evaluation.decision_plane.action, expected.expected_floor),
        ("native_floor", payload.get("minimum_action"), expected.expected_native_floor),
        ("policy_action", payload.get("policy_action"), expected.expected_native_floor),
        ("native_reason", payload.get("reason_code"), expected.expected_native_reason),
        ("model_text", model.get("normalized_text"), case.command.strip()),
        ("model_confidence", model.get("confidence"), expected.expected_confidence),
        ("model_uncertainty", model.get("uncertainty_reason"), expected.expected_uncertainty),
        ("path_overridden", model.get("path_overridden"), expected.expected_path_overridden),
        ("evaluation_error", evidence.get("evaluation_error"), expected.expected_evalerror),
        ("uncertain_rules", tuple(sorted(uncertain_rules)), expected.expected_uncertain_rule_ids),
        ("explicitly_benign", payload.get("explicitly_benign"), False),
        ("decision", payload.get("decision"), "deny"),
        ("authority", payload.get("authority"), "rust"),
        ("observation_count", binding.get("observation_count"), len(observations) + len(permissions)),
        (
            "uncertainty_count",
            binding.get("uncertainty_count"),
            len(uncertain_rules) + int(expected.expected_evalerror is not None),
        ),
    )
    for field, actual, authored in checks:
        if actual != authored or (isinstance(authored, bool) and type(actual) is not bool):
            raise ValueError(f"native corpus contract mismatch: {case.case_id} {field}")
    if expected.expected_evalerror is not None and (observations or permissions):
        raise ValueError("native corpus failed evaluation must retain empty observations")
    if _ACTIONS.index(reviewed.evaluation.decision_plane.action) < _ACTIONS.index(oracle.minimum_floor):
        raise ValueError("native corpus decision is below the unchanged security oracle")
    canonical_evidence = json.dumps(
        {key: evidence[key] for key in ("observations", "permission_observations", "evaluation_error")},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode()
    digest = hashlib.sha256(b"hol-guard.native-command-observations.v1\0" + canonical_evidence).hexdigest()
    if binding.get("observations_digest") != digest:
        raise ValueError("native corpus observation evidence digest mismatch")
    return expected.group_id
