"""Bounded process runner for deterministic command decision-diff evaluation."""

# ruff: noqa: E402

from __future__ import annotations

import importlib.util
import multiprocessing
import sys
from collections import defaultdict
from collections.abc import Iterator
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass
from itertools import chain, islice
from pathlib import Path
from typing import Final, cast

REPO_ROOT: Final = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def _install_evaluator_packages() -> None:
    """Keep package resources available without executing scanner initializers."""

    package_root = REPO_ROOT / "src" / "codex_plugin_scanner"
    for name, path in (
        ("codex_plugin_scanner", package_root),
        ("codex_plugin_scanner.guard", package_root / "guard"),
        ("codex_plugin_scanner.guard.runtime", package_root / "guard" / "runtime"),
    ):
        if name in sys.modules:
            continue
        spec = importlib.util.spec_from_file_location(
            name, path / "__init__.py", submodule_search_locations=[str(path)]
        )
        if spec is None:
            raise RuntimeError(f"could not create package spec for {name}")
        sys.modules[name] = importlib.util.module_from_spec(spec)


_install_evaluator_packages()

from codex_plugin_scanner.guard.action_lattice import guard_action_severity
from codex_plugin_scanner.guard.models import GuardAction
from codex_plugin_scanner.guard.runtime.command_evaluation import (
    CommandDecisionFloor,
    CompositeCommandEvaluation,
)
from codex_plugin_scanner.guard.runtime.effect_decision import (
    EffectDecision,
    EffectDecisionRequest,
    evaluate_effect_decision,
)
from codex_plugin_scanner.guard.runtime.native_command_evaluation import NativeCommandEvaluation
from tests.guard_command_corpus import CommandCorpusCase, iter_adversarial_corpus, iter_benign_corpus
from tests.guard_command_corpus_native import (
    NATIVE_CORPUS_BATCH_SIZE,
    evaluate_native_corpus_batch,
)
from tests.guard_command_corpus_native import (
    pin_neutral_attribution as _pin_neutral_attribution,
)
from tests.guard_command_corpus_native_contract import configure_native_contract_shard, validate_native_case
from tests.guard_command_corpus_oracle import iter_adversarial_oracle, iter_benign_oracle
from tests.guard_command_corpus_oracle_types import OracleRecord
from tests.guard_command_corpus_runner import EVALUATION_SHARD_COUNT, MAX_CONCURRENT_WORKERS, peak_rss_mib

SYNTHETIC_CWD: Final = REPO_ROOT / "workspace"
SYNTHETIC_HOME: Final = REPO_ROOT / "home"


@dataclass(frozen=True, slots=True)
class DecisionDiffShard:
    transition_ids: dict[str, list[str]]
    native_floor_ids: dict[str, list[str]]
    reconciliation_ids: dict[str, list[str]]
    actual_gap_ids: dict[str, list[str]]
    native_contract_ids: dict[str, list[str]]
    native_error_ids: dict[str, list[str]]
    lowered_count: int
    action_changed_count: int
    native_floor_lowered_count: int
    disposition_changed_count: int
    total: int
    rss_mib: float


def evaluate_decision_diff_shards() -> tuple[DecisionDiffShard, ...]:
    """Evaluate fixed corpus partitions with bounded process concurrency."""

    context = multiprocessing.get_context("spawn")
    with ProcessPoolExecutor(max_workers=MAX_CONCURRENT_WORKERS, mp_context=context) as executor:
        return tuple(executor.map(_evaluate_shard, range(EVALUATION_SHARD_COUNT)))


def _evaluate_shard(worker_index: int) -> DecisionDiffShard:
    _pin_neutral_attribution()
    configure_native_contract_shard(worker_index, EVALUATION_SHARD_COUNT)
    transition_ids: defaultdict[str, list[str]] = defaultdict(list)
    native_floor_ids: defaultdict[str, list[str]] = defaultdict(list)
    reconciliation_ids: defaultdict[str, list[str]] = defaultdict(list)
    actual_gap_ids: defaultdict[str, list[str]] = defaultdict(list)
    native_contract_ids: defaultdict[str, list[str]] = defaultdict(list)
    native_error_ids: defaultdict[str, list[str]] = defaultdict(list)
    lowered_count = 0
    action_changed_count = 0
    native_floor_lowered_count = 0
    disposition_changed_count = 0
    total = 0

    for case, oracle, reviewed in _case_evaluations(worker_index):
        total += 1
        group_id = validate_native_case(case, oracle, reviewed)
        native_contract_ids[group_id].append(case.case_id)
        evidence = reviewed.payload.get("command_extensions")
        if isinstance(evidence, dict) and evidence.get("evaluation_error") is not None:
            native_error_ids[str(evidence["evaluation_error"])].append(case.case_id)
        evaluation = reviewed.evaluation
        current = evaluation.decision_plane
        proposed = _baseline_proposal(evaluation)
        native_floor = _canonical_native_floor(cast(CommandDecisionFloor, reviewed.payload["minimum_action"]))
        transition_ids[
            "|".join((current.action, current.disposition.value, proposed.action, proposed.disposition.value))
        ].append(case.case_id)
        native_floor_ids[f"{native_floor}|{current.action}"].append(case.case_id)
        lowered_count += guard_action_severity(proposed.action) < guard_action_severity(current.action)
        action_changed_count += proposed.action != current.action
        native_floor_lowered_count += guard_action_severity(current.action) < guard_action_severity(native_floor)
        disposition_changed_count += current.disposition is not proposed.disposition

        reconciliation = _reconciliation_category(native_floor, current.action, oracle.minimum_floor)
        reconciliation_ids[
            "|".join((reconciliation, native_floor, current.action, oracle.minimum_floor, oracle.owner))
        ].append(case.case_id)
        if guard_action_severity(current.action) != guard_action_severity(oracle.minimum_floor):
            kind = (
                "underclassified"
                if guard_action_severity(current.action) < guard_action_severity(oracle.minimum_floor)
                else "overclassified"
            )
            actual_gap_ids["|".join((oracle.owner, kind, oracle.minimum_floor, current.action))].append(case.case_id)

    return DecisionDiffShard(
        transition_ids=dict(transition_ids),
        native_floor_ids=dict(native_floor_ids),
        reconciliation_ids=dict(reconciliation_ids),
        actual_gap_ids=dict(actual_gap_ids),
        native_contract_ids=dict(native_contract_ids),
        native_error_ids=dict(native_error_ids),
        lowered_count=lowered_count,
        action_changed_count=action_changed_count,
        native_floor_lowered_count=native_floor_lowered_count,
        disposition_changed_count=disposition_changed_count,
        total=total,
        rss_mib=peak_rss_mib(include_children=True),
    )


def _case_evaluations(
    worker_index: int,
) -> Iterator[tuple[CommandCorpusCase, OracleRecord, NativeCommandEvaluation]]:
    pairs = _case_oracle_pairs(worker_index)
    while batch := tuple(islice(pairs, NATIVE_CORPUS_BATCH_SIZE)):
        evaluations = evaluate_native_corpus_batch(
            [case for case, _oracle in batch], cwd=SYNTHETIC_CWD, home_dir=SYNTHETIC_HOME
        )
        for (case, oracle), reviewed in zip(batch, evaluations, strict=True):
            yield case, oracle, reviewed
        del evaluations


def _case_oracle_pairs(worker_index: int) -> Iterator[tuple[CommandCorpusCase, OracleRecord]]:
    yield from chain(
        zip(
            iter_benign_corpus(shard_index=worker_index, shard_count=EVALUATION_SHARD_COUNT),
            iter_benign_oracle(shard_index=worker_index, shard_count=EVALUATION_SHARD_COUNT),
            strict=True,
        ),
        zip(
            iter_adversarial_corpus(shard_index=worker_index, shard_count=EVALUATION_SHARD_COUNT),
            iter_adversarial_oracle(shard_index=worker_index, shard_count=EVALUATION_SHARD_COUNT),
            strict=True,
        ),
    )


def _canonical_native_floor(action: CommandDecisionFloor) -> GuardAction:
    return "warn" if action == "monitor" else cast(GuardAction, action)


def _baseline_proposal(evaluation: CompositeCommandEvaluation) -> EffectDecision:
    return evaluate_effect_decision(
        EffectDecisionRequest(
            factors=evaluation.baseline_factors,
            uncertainties=evaluation.baseline_uncertainties,
        )
    )


def _reconciliation_category(native_floor: GuardAction, current: GuardAction, oracle: GuardAction) -> str:
    native_rank = guard_action_severity(native_floor)
    current_rank = guard_action_severity(current)
    oracle_rank = guard_action_severity(oracle)
    if current_rank < native_rank:
        raise ValueError("current decision lowers its native evidence floor")
    if current_rank == native_rank:
        return "unchanged_meets_oracle" if current_rank >= oracle_rank else "unchanged_below_oracle"
    if current_rank < oracle_rank:
        return "strengthened_below_oracle"
    if current_rank == oracle_rank:
        return "strengthened_meets_oracle"
    return "strengthened_above_oracle"
