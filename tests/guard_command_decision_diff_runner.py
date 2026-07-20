"""Bounded process runner for deterministic command decision-diff evaluation."""

# ruff: noqa: E402

from __future__ import annotations

import multiprocessing
import sys
import types
from collections import defaultdict
from collections.abc import Iterator
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass
from itertools import chain
from pathlib import Path
from typing import Final, cast

REPO_ROOT: Final = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def _install_evaluator_packages() -> None:
    package_root = REPO_ROOT / "src" / "codex_plugin_scanner"
    for name, path in (
        ("codex_plugin_scanner", package_root),
        ("codex_plugin_scanner.guard", package_root / "guard"),
        ("codex_plugin_scanner.guard.runtime", package_root / "guard" / "runtime"),
    ):
        if name in sys.modules:
            continue
        package = types.ModuleType(name)
        package.__dict__["__path__"] = [str(path)]
        sys.modules[name] = package


_install_evaluator_packages()

from codex_plugin_scanner.guard.action_lattice import guard_action_severity
from codex_plugin_scanner.guard.models import GuardAction
from codex_plugin_scanner.guard.runtime.command_critical_floors import command_critical_floor_factors
from codex_plugin_scanner.guard.runtime.command_decision_adapter import (
    command_uncertainties,
    decision_factors,
    extension_evidence_batch,
    extension_uncertainties,
)
from codex_plugin_scanner.guard.runtime.command_evaluation import (
    CommandDecisionFloor,
    CompositeCommandEvaluation,
    evaluate_command,
)
from codex_plugin_scanner.guard.runtime.command_workspace_write_candidates import workspace_write_candidate_factors
from codex_plugin_scanner.guard.runtime.effect_decision import (
    EffectDecision,
    EffectDecisionRequest,
    evaluate_effect_decision,
)
from tests.guard_command_corpus import CommandCorpusCase, iter_adversarial_corpus, iter_benign_corpus
from tests.guard_command_corpus_oracle import iter_adversarial_oracle, iter_benign_oracle
from tests.guard_command_corpus_oracle_types import OracleRecord
from tests.guard_command_corpus_runner import peak_rss_mib

EVALUATION_SHARD_COUNT: Final = 4
MAX_CONCURRENT_WORKERS: Final = 4
SYNTHETIC_CWD: Final = REPO_ROOT / "workspace"
SYNTHETIC_HOME: Final = REPO_ROOT / "home"


@dataclass(frozen=True, slots=True)
class DecisionDiffShard:
    transition_ids: dict[str, list[str]]
    legacy_ids: dict[str, list[str]]
    reconciliation_ids: dict[str, list[str]]
    actual_gap_ids: dict[str, list[str]]
    lowered_count: int
    legacy_lowered_count: int
    disposition_changed_count: int
    total: int
    rss_mib: float


def evaluate_decision_diff_shards() -> tuple[DecisionDiffShard, ...]:
    """Evaluate fixed corpus partitions with bounded process concurrency."""

    context = multiprocessing.get_context("spawn")
    with ProcessPoolExecutor(max_workers=MAX_CONCURRENT_WORKERS, mp_context=context) as executor:
        return tuple(executor.map(_evaluate_shard, range(EVALUATION_SHARD_COUNT)))


def _evaluate_shard(worker_index: int) -> DecisionDiffShard:
    transition_ids: defaultdict[str, list[str]] = defaultdict(list)
    legacy_ids: defaultdict[str, list[str]] = defaultdict(list)
    reconciliation_ids: defaultdict[str, list[str]] = defaultdict(list)
    actual_gap_ids: defaultdict[str, list[str]] = defaultdict(list)
    lowered_count = 0
    legacy_lowered_count = 0
    disposition_changed_count = 0
    total = 0

    for case, oracle in _case_oracle_pairs(worker_index):
        total += 1
        evaluation = evaluate_command(case.command, cwd=SYNTHETIC_CWD, home_dir=SYNTHETIC_HOME)
        current = evaluation.decision_plane
        proposed = _baseline_proposal(evaluation)
        legacy_action = _canonical_legacy_action(evaluation.minimum_action)
        transition_ids[
            "|".join((current.action, current.disposition.value, proposed.action, proposed.disposition.value))
        ].append(case.case_id)
        legacy_ids[f"{legacy_action}|{current.action}"].append(case.case_id)
        lowered_count += guard_action_severity(proposed.action) < guard_action_severity(current.action)
        legacy_lowered_count += guard_action_severity(current.action) < guard_action_severity(legacy_action)
        disposition_changed_count += current.disposition is not proposed.disposition

        reconciliation = _reconciliation_category(legacy_action, current.action, oracle.minimum_floor)
        reconciliation_ids[
            "|".join((reconciliation, legacy_action, current.action, oracle.minimum_floor, oracle.owner))
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
        legacy_ids=dict(legacy_ids),
        reconciliation_ids=dict(reconciliation_ids),
        actual_gap_ids=dict(actual_gap_ids),
        lowered_count=lowered_count,
        legacy_lowered_count=legacy_lowered_count,
        disposition_changed_count=disposition_changed_count,
        total=total,
        rss_mib=peak_rss_mib(),
    )


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


def _canonical_legacy_action(action: CommandDecisionFloor) -> GuardAction:
    return "warn" if action == "monitor" else cast(GuardAction, action)


def _baseline_proposal(evaluation: CompositeCommandEvaluation) -> EffectDecision:
    command = evaluation.command
    observations = evaluation.extension_observations
    evidence = extension_evidence_batch(command, observations)
    uncertainties = tuple(
        sorted(
            {
                *command_uncertainties(command, sensitive=bool(evaluation.matches)),
                *extension_uncertainties(observations),
            },
            key=lambda item: item.value,
        )
    )
    return evaluate_effect_decision(
        EffectDecisionRequest(
            factors=(
                *decision_factors(evidence, compatibility_action_class=None, compatibility_rule=None),
                *workspace_write_candidate_factors(command),
                *command_critical_floor_factors(command),
            ),
            uncertainties=uncertainties,
        )
    )


def _reconciliation_category(legacy: GuardAction, current: GuardAction, oracle: GuardAction) -> str:
    legacy_rank = guard_action_severity(legacy)
    current_rank = guard_action_severity(current)
    oracle_rank = guard_action_severity(oracle)
    if current_rank < legacy_rank:
        raise ValueError("current decision lowers a legacy decision")
    if current_rank == legacy_rank:
        return "unchanged_meets_oracle" if current_rank >= oracle_rank else "unchanged_below_oracle"
    if current_rank < oracle_rank:
        return "strengthened_below_oracle"
    if current_rank == oracle_rank:
        return "strengthened_meets_oracle"
    return "strengthened_above_oracle"
