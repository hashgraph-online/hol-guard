"""Generate the deterministic command decision-diff evidence report."""

# ruff: noqa: E402

from __future__ import annotations

import hashlib
import json
import sys
import time
import types
from collections import defaultdict
from collections.abc import Iterable, Iterator, Mapping
from itertools import chain
from pathlib import Path
from typing import Final, cast

REPO_ROOT: Final = Path(__file__).parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def _install_evaluator_packages() -> None:
    """Import evaluator modules without unrelated optional scanner exports."""

    package_root = REPO_ROOT / "src" / "codex_plugin_scanner"
    packages = (
        ("codex_plugin_scanner", package_root),
        ("codex_plugin_scanner.guard", package_root / "guard"),
        ("codex_plugin_scanner.guard.runtime", package_root / "guard" / "runtime"),
    )
    for name, path in packages:
        if name in sys.modules:
            continue
        package = types.ModuleType(name)
        package.__dict__["__path__"] = [str(path)]
        sys.modules[name] = package


_install_evaluator_packages()

from codex_plugin_scanner.guard.action_lattice import guard_action_severity
from codex_plugin_scanner.guard.models import GuardAction
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
from codex_plugin_scanner.guard.runtime.command_shadow_evaluation import (
    COMMAND_SHADOW_BASELINE_PROPOSAL_VERSION,
    CommandShadowCohort,
    CommandShadowProposal,
)
from codex_plugin_scanner.guard.runtime.effect_decision import (
    EFFECT_DECISION_SCHEMA_VERSION,
    EffectDecisionRequest,
    evaluate_effect_decision,
)
from tests.guard_command_corpus import (
    KNOWN_GAPS_PATH,
    MANIFEST_PATH,
    PAIRS_PATH,
    CommandCorpusCase,
    corpus_digest,
    iter_adversarial_corpus,
    iter_benign_corpus,
    load_seed_manifest,
)
from tests.guard_command_corpus_oracle import iter_adversarial_oracle, iter_benign_oracle
from tests.guard_command_corpus_oracle_types import OracleRecord
from tests.guard_command_corpus_runner import peak_rss_mib

REPORT_SCHEMA_VERSION: Final = "guard.command-decision-diff.v1"
BASE_RELEASE_SHA: Final = "96ec0db6102de5a694b00809312e60686923a15a"
REPORT_PATH: Final = REPO_ROOT / "tests" / "fixtures" / "guard-command-corpus" / "decision-diff-report.json"
SYNTHETIC_CWD: Final = REPO_ROOT / "workspace"
SYNTHETIC_HOME: Final = REPO_ROOT / "home"
_ACTION_VALUES: Final[tuple[GuardAction, ...]] = (
    "allow",
    "warn",
    "review",
    "require-reapproval",
    "sandbox-required",
    "block",
)
_EVIDENCE_SOURCE_PATHS: Final = (
    REPO_ROOT / "src" / "codex_plugin_scanner" / "guard" / "action_lattice.py",
    REPO_ROOT / "src" / "codex_plugin_scanner" / "guard" / "models.py",
    *(REPO_ROOT / "src" / "codex_plugin_scanner" / "guard" / "runtime").glob("*.py"),
    *REPO_ROOT.joinpath("tests").glob("guard_command_corpus*.py"),
    REPO_ROOT / "tests" / "guard_command_decision_diff.py",
    REPO_ROOT / "tests" / "test_guard_command_corpus.py",
    REPO_ROOT / "tests" / "test_guard_command_decision_diff.py",
)


def canonical_json_bytes(value: object) -> bytes:
    """Return stable human-reviewable JSON bytes."""

    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def framed_sha256(payload: bytes) -> str:
    """Hash one length-framed byte string."""

    return hashlib.sha256(len(payload).to_bytes(8, "big") + payload).hexdigest()


def source_binding_id(repo_relative_path: str) -> str:
    """Return a stable opaque identifier for one repository source path."""

    return f"source-{hashlib.sha256(repo_relative_path.encode()).hexdigest()[:24]}"


def report_framed_sha256(report: Mapping[str, object] | None = None) -> str:
    """Return the digest placed in the signed commit trailer."""

    return framed_sha256(canonical_json_bytes(generate_decision_diff_report() if report is None else report))


def generate_decision_diff_report() -> dict[str, object]:
    """Evaluate the complete corpus and reconcile all legacy decisions."""

    manifest = load_seed_manifest()
    known_gaps = _load_object(KNOWN_GAPS_PATH)
    transition_ids: defaultdict[str, list[str]] = defaultdict(list)
    legacy_ids: defaultdict[str, list[str]] = defaultdict(list)
    reconciliation_ids: defaultdict[str, list[str]] = defaultdict(list)
    actual_gap_ids: defaultdict[str, list[str]] = defaultdict(list)
    lowered_count = 0
    legacy_lowered_count = 0
    disposition_changed_count = 0
    total = 0

    for case, oracle in _case_oracle_pairs():
        total += 1
        evaluation = evaluate_command(case.command, cwd=SYNTHETIC_CWD, home_dir=SYNTHETIC_HOME)
        current = evaluation.decision_plane
        proposed = _baseline_proposal(evaluation).decision
        legacy_action = _canonical_legacy_action(evaluation.minimum_action)
        transition_key = "|".join(
            (current.action, current.disposition.value, proposed.action, proposed.disposition.value)
        )
        transition_ids[transition_key].append(case.case_id)
        legacy_ids[f"{legacy_action}|{current.action}"].append(case.case_id)
        if guard_action_severity(proposed.action) < guard_action_severity(current.action):
            lowered_count += 1
        if guard_action_severity(current.action) < guard_action_severity(legacy_action):
            legacy_lowered_count += 1
        if current.disposition is not proposed.disposition:
            disposition_changed_count += 1

        reconciliation = _reconciliation_category(legacy_action, current.action, oracle.minimum_floor)
        reconciliation_key = "|".join(
            (reconciliation, legacy_action, current.action, oracle.minimum_floor, oracle.owner)
        )
        reconciliation_ids[reconciliation_key].append(case.case_id)
        if guard_action_severity(legacy_action) != guard_action_severity(oracle.minimum_floor):
            kind = (
                "underclassified"
                if guard_action_severity(legacy_action) < guard_action_severity(oracle.minimum_floor)
                else "overclassified"
            )
            actual_gap_ids["|".join((oracle.owner, kind, oracle.minimum_floor, evaluation.minimum_action))].append(
                case.case_id
            )

    expected_gaps = _expected_known_gaps(known_gaps)
    actual_gaps = _known_gap_summaries(actual_gap_ids)
    if actual_gaps != expected_gaps:
        raise ValueError("legacy decision gaps do not equal the frozen known-gap fixture")

    benign_count = _integer(manifest["benign_target_count"], "benign_target_count")
    adversarial_count = _integer(manifest["adversarial_target_count"], "adversarial_target_count")
    if total != benign_count + adversarial_count:
        raise ValueError("evaluated case count does not match the seed manifest")
    reconciled_count = sum(len(case_ids) for case_ids in reconciliation_ids.values())
    unreconciled_count = total - reconciled_count
    if unreconciled_count != 0:
        raise ValueError("every corpus case must have an oracle reconciliation category")

    report: dict[str, object] = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "base_release_sha": BASE_RELEASE_SHA,
        "evaluator_schema_version": EFFECT_DECISION_SCHEMA_VERSION,
        "proposal_version": COMMAND_SHADOW_BASELINE_PROPOSAL_VERSION,
        "attestation": {
            "mechanism": "gpg-signed-commit-trailer",
            "trailer": "Decision-Diff-Framed-SHA256",
        },
        "corpus": {
            "benign_count": benign_count,
            "adversarial_count": adversarial_count,
            "total_count": total,
            "canonical_digests": {
                "benign": corpus_digest(iter_benign_corpus()),
                "adversarial": corpus_digest(iter_adversarial_corpus()),
                "oracle": _oracle_digest(chain(iter_benign_oracle(), iter_adversarial_oracle())),
            },
        },
        "bindings": {
            "sources_sha256": _source_bindings(),
            "fixtures_sha256": {
                "known-gaps.json": _sha256(KNOWN_GAPS_PATH),
                "minimal-delta-pairs.json": _sha256(PAIRS_PATH),
                "seed-manifest.json": _sha256(MANIFEST_PATH),
            },
        },
        "current_vs_proposed": {
            "lowered_count": lowered_count,
            "disposition_changed_count": disposition_changed_count,
            "transition_groups": _group_summaries(transition_ids),
        },
        "legacy_to_current": {
            "lowered_count": legacy_lowered_count,
            "transition_groups": _group_summaries(legacy_ids),
        },
        "oracle_reconciliation": {
            "truth_table": {
                "unchanged_meets_oracle": "current equals legacy and meets the oracle floor",
                "unchanged_below_oracle": "current equals legacy and remains assigned to a frozen gap owner",
                "strengthened_meets_oracle": "current raises legacy to the oracle floor",
                "strengthened_below_oracle": "current raises legacy but remains assigned to a frozen gap owner",
                "strengthened_above_oracle": "current conservatively exceeds the oracle floor",
            },
            "category_groups": _group_summaries(reconciliation_ids),
            "legacy_known_gaps": actual_gaps,
            "known_gap_equality": True,
            "reconciled_count": reconciled_count,
            "unreconciled_count": unreconciled_count,
        },
        "privacy": {
            "case_material": "opaque-case-identifiers-only",
            "commands_included": False,
            "local_paths_included": False,
            "resource_measurements_included": False,
        },
    }
    _validate_manifest_digests(report, manifest)
    return report


def _case_oracle_pairs() -> Iterator[tuple[CommandCorpusCase, OracleRecord]]:
    yield from zip(iter_benign_corpus(), iter_benign_oracle(), strict=True)
    yield from zip(iter_adversarial_corpus(), iter_adversarial_oracle(), strict=True)


def _canonical_legacy_action(action: CommandDecisionFloor) -> GuardAction:
    if action == "monitor":
        return "warn"
    return cast(GuardAction, action)


def _baseline_proposal(evaluation: CompositeCommandEvaluation) -> CommandShadowProposal:
    """Recompute the baseline proposal without using the current decision result."""

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
    decision = evaluate_effect_decision(
        EffectDecisionRequest(
            factors=decision_factors(evidence, compatibility_action_class=None, compatibility_rule=None),
            uncertainties=uncertainties,
        )
    )
    return CommandShadowProposal(
        decision=decision,
        cohorts=frozenset({CommandShadowCohort.BASELINE}),
        version=COMMAND_SHADOW_BASELINE_PROPOSAL_VERSION,
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


def _group_summaries(groups: Mapping[str, list[str]]) -> list[dict[str, object]]:
    return [
        {
            "key": key,
            "count": len(case_ids),
            "case_ids_framed_sha256": _framed_values_sha256(case_ids),
        }
        for key, case_ids in sorted(groups.items())
    ]


def _framed_values_sha256(values: Iterable[str]) -> str:
    digest = hashlib.sha256()
    for value in sorted(values):
        payload = value.encode("ascii")
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(payload)
    return digest.hexdigest()


def _known_gap_summaries(groups: Mapping[str, list[str]]) -> dict[str, tuple[int, str]]:
    return {
        key: (len(case_ids), hashlib.sha256(("\n".join(sorted(case_ids)) + "\n").encode()).hexdigest())
        for key, case_ids in sorted(groups.items())
    }


def _expected_known_gaps(payload: Mapping[str, object]) -> dict[str, tuple[int, str]]:
    gaps = payload.get("gaps")
    if not isinstance(gaps, list):
        raise ValueError("known gaps must be a list")
    expected: dict[str, tuple[int, str]] = {}
    gap_ids: set[str] = set()
    for item in cast(list[object], gaps):
        if not isinstance(item, dict):
            raise ValueError("known gap must be an object")
        gap = cast(dict[str, object], item)
        gap_id = str(gap["gap_id"])
        key = "|".join(str(gap[field]) for field in ("owner", "kind", "oracle_floor", "observed_floor"))
        if gap_id in gap_ids or key in expected:
            raise ValueError("known gaps must have unique IDs and reconciliation keys")
        gap_ids.add(gap_id)
        expected[key] = (int(str(gap["count"])), str(gap["case_ids_digest"]))
    return expected


def _source_bindings() -> dict[str, str]:
    paths = sorted({path.resolve() for path in _EVIDENCE_SOURCE_PATHS})
    return {source_binding_id(str(path.relative_to(REPO_ROOT))): _sha256(path) for path in paths}


def _oracle_digest(records: Iterable[OracleRecord]) -> str:
    digest = hashlib.sha256()
    for record in records:
        payload = json.dumps(
            {
                "case_id": record.case_id,
                "workflow_family": record.workflow_family,
                "effects": list(record.effects),
                "target_scope": record.target_scope,
                "uncertainties": list(record.uncertainties),
                "required_proofs": list(record.required_proofs),
                "provided_proofs": list(record.provided_proofs),
                "minimum_floor": record.minimum_floor,
                "decision_status": record.decision_status,
                "source_id": record.source_id,
                "owner": record.owner,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(payload)
    return digest.hexdigest()


def _validate_manifest_digests(report: Mapping[str, object], manifest: Mapping[str, object]) -> None:
    corpus = report.get("corpus")
    if not isinstance(corpus, dict):
        raise ValueError("report corpus section is invalid")
    corpus_map = cast(dict[str, object], corpus)
    digests = cast(dict[str, object] | None, corpus_map.get("canonical_digests"))
    if digests != manifest.get("canonical_digests"):
        raise ValueError("recomputed corpus or oracle digest does not match the seed manifest")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load_object(path: Path) -> dict[str, object]:
    value = cast(object, json.loads(path.read_text(encoding="utf-8")))
    if not isinstance(value, dict):
        raise ValueError(f"{path.name} must contain an object")
    return cast(dict[str, object], value)


def _integer(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ValueError(f"{label} must be a positive integer")
    return value


def _main() -> None:
    arguments = tuple(sys.argv[1:])
    if arguments not in {(), ("--write",), ("--check",), ("--metrics",)}:
        raise SystemExit("usage: guard_command_decision_diff.py [--write|--check|--metrics]")
    started = time.perf_counter()
    report = generate_decision_diff_report()
    payload = canonical_json_bytes(report)
    if arguments == ("--write",):
        _ = REPORT_PATH.write_bytes(payload)
    elif arguments == ("--check",):
        if REPORT_PATH.read_bytes() != payload:
            raise SystemExit("decision-diff report fixture is stale")
    elif arguments == ("--metrics",):
        print(
            json.dumps(
                {
                    "elapsed_seconds": time.perf_counter() - started,
                    "report_framed_sha256": report_framed_sha256(report),
                    "rss_mib": peak_rss_mib(),
                },
                sort_keys=True,
            )
        )
    else:
        print(payload.decode(), end="")


if __name__ == "__main__":
    _main()
