"""Manifest-bound loaders for reviewed command corpus oracle records."""

from __future__ import annotations

from collections.abc import Iterator
from typing import cast

from tests.guard_command_corpus import load_seed_manifest, stable_case_id
from tests.guard_command_corpus_oracle_adversarial import ADVERSARIAL_ORACLE
from tests.guard_command_corpus_oracle_benign import BENIGN_ORACLE
from tests.guard_command_corpus_oracle_types import OracleRecord, OracleSeed


def oracle_record(source_id: str, variant: int, seed: OracleSeed) -> OracleRecord:
    return OracleRecord(
        case_id=stable_case_id(source_id, variant),
        workflow_family=seed.workflow_family,
        effects=seed.effects,
        target_scope=seed.target_scope,
        uncertainties=seed.uncertainties,
        required_proofs=seed.required_proofs,
        provided_proofs=(),
        minimum_floor=seed.minimum_floor,
        decision_status=seed.decision_status,
        source_id=source_id,
        owner=seed.owner,
    )


def iter_benign_oracle(*, shard_index: int = 0, shard_count: int = 1) -> Iterator[OracleRecord]:
    _validate_shard(shard_index, shard_count)
    manifest = load_seed_manifest()
    variants_value = manifest["benign_variants_per_seed"]
    if not isinstance(variants_value, int):
        raise ValueError("benign_variants_per_seed must be an integer")
    workflows_value = manifest["benign_workflows"]
    if not isinstance(workflows_value, list):
        raise ValueError("benign_workflows must be a list")
    records: list[OracleRecord] = []
    for workflow_value in cast(list[object], workflows_value):
        if not isinstance(workflow_value, dict):
            raise ValueError("benign workflow must be an object")
        workflow = cast(dict[str, object], workflow_value)
        workflow_id, seeds_value = workflow["id"], workflow["seeds"]
        if not isinstance(workflow_id, str) or not isinstance(seeds_value, list):
            raise ValueError("benign workflow shape is invalid")
        for seed_value in cast(list[object], seeds_value):
            if not isinstance(seed_value, list):
                raise ValueError("benign seed shape is invalid")
            seed_list = cast(list[object], seed_value)
            if len(seed_list) != 2 or not isinstance(seed_list[0], str):
                raise ValueError("benign seed shape is invalid")
            seed_id = seed_list[0]
            seed = BENIGN_ORACLE[seed_id]
            if seed.workflow_family != workflow_id:
                raise ValueError(f"oracle workflow mismatch for {seed_id}")
            source_id = f"workflow:{workflow_id}:{seed_id}"
            for variant in range(variants_value):
                records.append(oracle_record(source_id, variant, seed))
    yield from sorted(records, key=lambda record: record.case_id)[shard_index::shard_count]


def iter_adversarial_oracle(*, shard_index: int = 0, shard_count: int = 1) -> Iterator[OracleRecord]:
    _validate_shard(shard_index, shard_count)
    manifest = load_seed_manifest()
    target_value, categories_value = manifest["adversarial_target_count"], manifest["adversarial_categories"]
    if not isinstance(target_value, int) or not isinstance(categories_value, list):
        raise ValueError("adversarial manifest shape is invalid")
    categories = cast(list[object], categories_value)
    for position in range(shard_index, target_value, shard_count):
        index = (position * 7919 + 22020) % target_value
        category_value = categories[index % len(categories)]
        if not isinstance(category_value, list) or not category_value or not isinstance(category_value[0], str):
            raise ValueError("adversarial category shape is invalid")
        technique = category_value[0]
        yield oracle_record(f"adversarial:{technique}", index // len(categories), ADVERSARIAL_ORACLE[technique])


def _validate_shard(shard_index: int, shard_count: int) -> None:
    if shard_count < 1 or shard_index < 0 or shard_index >= shard_count:
        raise ValueError("oracle shard must satisfy 0 <= shard_index < shard_count")
