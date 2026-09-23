"""Generate the deterministic command decision-diff evidence report."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import time
import types
from collections import defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from itertools import chain
from pathlib import Path
from typing import TYPE_CHECKING, Final, cast

if TYPE_CHECKING:
    from tests.guard_command_decision_diff_runner import DecisionDiffShard

REPO_ROOT: Final = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


_PACKAGE_PREFIX: Final = "codex_plugin_scanner"
_MISSING_BINDING: Final = object()


@dataclass(frozen=True, slots=True)
class _EvaluatorPackageState:
    modules: dict[str, types.ModuleType]
    parent_snapshots: tuple[tuple[types.ModuleType, dict[str, object]], ...]


def _install_evaluator_packages() -> _EvaluatorPackageState:
    """Import evaluator modules without unrelated optional scanner exports."""

    existing_modules = {
        name: module
        for name, module in sys.modules.items()
        if name == _PACKAGE_PREFIX or name.startswith(f"{_PACKAGE_PREFIX}.")
    }
    existing_parent_snapshots = tuple((module, module.__dict__.copy()) for module in existing_modules.values())
    package_root = REPO_ROOT / "src" / "codex_plugin_scanner"
    packages = (
        ("codex_plugin_scanner", package_root),
        ("codex_plugin_scanner.guard", package_root / "guard"),
        ("codex_plugin_scanner.guard.runtime", package_root / "guard" / "runtime"),
    )
    for name, path in packages:
        if name in sys.modules:
            continue
        package_path = path / "__init__.py"
        spec = importlib.util.spec_from_file_location(
            name,
            package_path,
            submodule_search_locations=[str(path)],
        )
        if spec is None:
            raise RuntimeError(f"could not create package spec for {name}")
        package = types.ModuleType(name)
        package.__dict__.update(
            {
                "__file__": str(package_path),
                "__package__": name,
                "__path__": [str(path)],
                "__spec__": spec,
            }
        )
        sys.modules[name] = package
        # Bind the stub onto its parent package the way a real submodule
        # import would, so later dotted-path monkeypatch resolution in the
        # same test process can find it regardless of import order.
        parent_name, _, leaf = name.rpartition(".")
        parent = sys.modules.get(parent_name)
        if parent is not None and parent_name:
            setattr(parent, leaf, package)
    return _EvaluatorPackageState(
        modules=existing_modules,
        parent_snapshots=existing_parent_snapshots,
    )


def _restore_evaluator_packages(state: _EvaluatorPackageState) -> None:
    """Remove evaluator-only imports and restore any packages already loaded."""

    parent_snapshots = {id(module): snapshot for module, snapshot in state.parent_snapshots}
    for name in tuple(sys.modules):
        if name != _PACKAGE_PREFIX and not name.startswith(f"{_PACKAGE_PREFIX}."):
            continue
        parent_name, _, leaf = name.rpartition(".")
        parent = state.modules.get(parent_name)
        if parent is None:
            continue
        previous = parent_snapshots[id(parent)].get(leaf, _MISSING_BINDING)
        if previous is _MISSING_BINDING:
            parent.__dict__.pop(leaf, None)
        else:
            setattr(parent, leaf, previous)
    for name in tuple(sys.modules):
        if name == _PACKAGE_PREFIX or name.startswith(f"{_PACKAGE_PREFIX}."):
            sys.modules.pop(name)
    sys.modules.update(state.modules)


_evaluator_package_state = _install_evaluator_packages()
try:
    from tests.guard_command_corpus import (
        KNOWN_GAPS_PATH,
        MANIFEST_PATH,
        PAIRS_PATH,
        corpus_digest,
        iter_adversarial_corpus,
        iter_benign_corpus,
        load_seed_manifest,
    )
    from tests.guard_command_corpus_native_contract import (
        NATIVE_CONTRACT_PATH,
        expected_native_groups,
    )
    from tests.guard_command_corpus_oracle import iter_adversarial_oracle, iter_benign_oracle
    from tests.guard_command_corpus_oracle_types import OracleRecord
    from tests.guard_command_corpus_runner import peak_rss_mib
finally:
    _restore_evaluator_packages(_evaluator_package_state)

REPORT_SCHEMA_VERSION: Final = "guard.command-decision-diff.v2"
BASE_RELEASE_SHA: Final = "21a81a6d5ca55e262bac837eb7a2ac8d530c6d28"
REPORT_PATH: Final = REPO_ROOT / "tests" / "fixtures" / "guard-command-corpus" / "decision-diff-report.json"
_EVIDENCE_SOURCE_PATHS: Final = (
    REPO_ROOT / "contracts" / "extensions" / "command-catalog.v1.json",
    REPO_ROOT / "contracts" / "extensions" / "native-command-program.v1.json",
    REPO_ROOT / "docs" / "guard" / "native-command-corpus-contract.md",
    REPO_ROOT / "docs" / "guard" / "declarative-authoring-adr.md",
    REPO_ROOT / "rust" / "crates" / "guard-command" / "src" / "native_command_source_evaluation_batch.rs",
    REPO_ROOT / "rust" / "crates" / "guard-command" / "src" / "native_command_source.rs",
    REPO_ROOT / "rust" / "crates" / "guard-command" / "src" / "bin" / "guard-command-source.rs",
    REPO_ROOT / "src" / "codex_plugin_scanner" / "guard" / "action_lattice.py",
    REPO_ROOT / "src" / "codex_plugin_scanner" / "guard" / "models.py",
    REPO_ROOT / "src" / "codex_plugin_scanner" / "guard" / "cli" / "commands_parser.py",
    REPO_ROOT / "src" / "codex_plugin_scanner" / "guard" / "cli" / "commands_parser_local.py",
    REPO_ROOT / "src" / "codex_plugin_scanner" / "guard" / "cli" / "commands_router.py",
    REPO_ROOT / "src" / "codex_plugin_scanner" / "guard" / "cli" / "commands_support.py",
    REPO_ROOT / "src" / "codex_plugin_scanner" / "guard" / "cli" / "commands_verified_read.py",
    REPO_ROOT / "src" / "codex_plugin_scanner" / "guard" / "cli" / "commands_contained_write.py",
    REPO_ROOT / "src" / "codex_plugin_scanner" / "guard" / "contained_package_script_execution.py",
    REPO_ROOT / "src" / "codex_plugin_scanner" / "guard" / "contained_workspace_write_execution.py",
    REPO_ROOT / "src" / "codex_plugin_scanner" / "guard" / "durable_harness_launcher.py",
    REPO_ROOT / "src" / "codex_plugin_scanner" / "guard" / "package_shim_gate.py",
    REPO_ROOT / "src" / "codex_plugin_scanner" / "guard" / "package_shim_frozen.py",
    REPO_ROOT / "src" / "codex_plugin_scanner" / "guard" / "shims.py",
    *(REPO_ROOT / "src" / "codex_plugin_scanner" / "guard" / "runtime").glob("*.py"),
    *REPO_ROOT.joinpath("tests").glob("guard_command_corpus*.py"),
    *REPO_ROOT.joinpath("tests").glob("guard_command_decision_diff*.py"),
    REPO_ROOT / "tests" / "test_guard_command_corpus.py",
    REPO_ROOT / "tests" / "guard_test_invariants.py",
    REPO_ROOT / "tests" / "test_guard_command_corpus_native_contract.py",
    REPO_ROOT / "tests" / "test_guard_command_decision_diff.py",
    REPO_ROOT / "tests" / "native_command_test_support.py",
    REPO_ROOT / "tests" / "test_native_command_test_support_batch.py",
    REPO_ROOT / "tests" / "test_guard_native_classification_baseline.py",
    REPO_ROOT / "tests" / "test_guard_contained_package_script_execution.py",
    REPO_ROOT / "tests" / "test_guard_contained_workspace_write_cli.py",
    REPO_ROOT / "tests" / "test_guard_contained_workspace_write_contract.py",
    REPO_ROOT / "tests" / "test_guard_contained_workspace_write_execution.py",
    REPO_ROOT / "tests" / "test_guard_containment_external_executable.py",
    REPO_ROOT / "tests" / "test_guard_package_shims.py",
    REPO_ROOT / "tests" / "test_guard_verified_reads.py",
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
    """Verify native decisions and publish every difference from the original oracle."""

    report, _rss_mib = _generate_decision_diff_report()
    return report


def _evaluate_native_diff() -> tuple[str, str, int, tuple[DecisionDiffShard, ...]]:
    """Load evaluator modules only when needed, keeping spawn bootstrap small."""

    state = _install_evaluator_packages()
    try:
        from codex_plugin_scanner.guard.runtime.command_shadow_evaluation import (
            COMMAND_SHADOW_BASELINE_PROPOSAL_VERSION,
        )
        from codex_plugin_scanner.guard.runtime.effect_decision import EFFECT_DECISION_SCHEMA_VERSION
        from tests.guard_command_decision_diff_runner import (
            MAX_CONCURRENT_WORKERS,
            evaluate_decision_diff_shards,
        )

        return (
            EFFECT_DECISION_SCHEMA_VERSION,
            COMMAND_SHADOW_BASELINE_PROPOSAL_VERSION,
            MAX_CONCURRENT_WORKERS,
            evaluate_decision_diff_shards(),
        )
    finally:
        _restore_evaluator_packages(state)


def _generate_decision_diff_report() -> tuple[dict[str, object], float]:
    manifest = load_seed_manifest()
    known_gaps = _load_object(KNOWN_GAPS_PATH)
    transition_ids: defaultdict[str, list[str]] = defaultdict(list)
    native_floor_ids: defaultdict[str, list[str]] = defaultdict(list)
    reconciliation_ids: defaultdict[str, list[str]] = defaultdict(list)
    actual_gap_ids: defaultdict[str, list[str]] = defaultdict(list)
    native_contract_ids: defaultdict[str, list[str]] = defaultdict(list)
    native_error_ids: defaultdict[str, list[str]] = defaultdict(list)
    evaluator_schema_version, proposal_version, max_concurrent_workers, shards = _evaluate_native_diff()
    for shard in shards:
        _merge_groups(transition_ids, shard.transition_ids)
        _merge_groups(native_floor_ids, shard.native_floor_ids)
        _merge_groups(reconciliation_ids, shard.reconciliation_ids)
        _merge_groups(actual_gap_ids, shard.actual_gap_ids)
        _merge_groups(native_contract_ids, shard.native_contract_ids)
        _merge_groups(native_error_ids, shard.native_error_ids)
    lowered_count = sum(shard.lowered_count for shard in shards)
    action_changed_count = sum(shard.action_changed_count for shard in shards)
    native_floor_lowered_count = sum(shard.native_floor_lowered_count for shard in shards)
    disposition_changed_count = sum(shard.disposition_changed_count for shard in shards)
    total = sum(shard.total for shard in shards)

    expected_gaps = _expected_known_gaps(known_gaps)
    actual_gaps = _known_gap_summaries(actual_gap_ids)
    observed_native_groups = {key: (len(ids), _framed_values_sha256(ids)) for key, ids in native_contract_ids.items()}
    if observed_native_groups != expected_native_groups():
        raise ValueError("native decision groups differ from the inherited native contract")
    below_original_count = sum(len(ids) for key, ids in actual_gap_ids.items() if "|underclassified|" in key)
    above_original_count = sum(len(ids) for key, ids in actual_gap_ids.items() if "|overclassified|" in key)
    if below_original_count:
        raise ValueError("native decisions fall below the original oracle")
    if action_changed_count or disposition_changed_count or native_floor_lowered_count:
        raise ValueError("current and proposed native decisions differ or lower a native floor")

    benign_count = _integer(manifest["benign_target_count"], "benign_target_count")
    adversarial_count = _integer(manifest["adversarial_target_count"], "adversarial_target_count")
    if total != benign_count + adversarial_count:
        raise ValueError("evaluated case count does not match the seed manifest")
    categorized_count = sum(len(case_ids) for case_ids in reconciliation_ids.values())
    uncategorized_count = total - categorized_count
    if uncategorized_count != 0:
        raise ValueError("every corpus case must have an oracle reconciliation category")

    report: dict[str, object] = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "base_release_sha": BASE_RELEASE_SHA,
        "scope": {
            "baseline": "reviewed-native-engine-and-current-host-effect-decision",
            "original_oracle": "immutable-original-labels-with-all-native-differences-reported",
            "parser_grammar": "bounded-reviewed-parser-and-classifier-updates-with-explicit-contract-changes",
            "bounded_parser_update_commit": "5a076ded9182f4466b875effffae3b156fba9e04",
            "authority": "offline-native-evidence-not-authenticated-execution-receipts",
        },
        "evaluator_schema_version": evaluator_schema_version,
        "proposal_version": proposal_version,
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
                "native-contract.json": _sha256(NATIVE_CONTRACT_PATH),
            },
        },
        "current_vs_proposed": {
            "lowered_count": lowered_count,
            "action_changed_count": action_changed_count,
            "disposition_changed_count": disposition_changed_count,
            "transition_groups": _group_summaries(transition_ids),
        },
        "native_floor_to_current": {
            "scope": "raw-native-floor-to-current-host-effect-decision",
            "lowered_count": native_floor_lowered_count,
            "transition_groups": _group_summaries(native_floor_ids),
        },
        "native_contract": {
            "equality": True,
            "matched_count": sum(len(ids) for ids in native_contract_ids.values()),
            "unexpected_count": 0,
            "groups": _group_summaries(native_contract_ids),
            "native_rejection_count": sum(len(ids) for ids in native_error_ids.values()),
            "native_rejection_groups": _group_summaries(native_error_ids),
        },
        "oracle_reconciliation": {
            "scope": "comparison-against-the-unchanged-original-oracle",
            "truth_table": {
                "unchanged_meets_oracle": "current equals its native floor and meets the original oracle floor",
                "unchanged_below_oracle": "current equals its native floor but is below the original oracle",
                "strengthened_meets_oracle": "current raises its native floor to the original oracle floor",
                "strengthened_below_oracle": "current raises its native floor but is below the original oracle",
                "strengthened_above_oracle": "current conservatively exceeds the oracle floor",
            },
            "category_groups": _group_summaries(reconciliation_ids),
            "known_gaps": actual_gaps,
            "known_gap_equality": actual_gaps == expected_gaps,
            "below_original_count": below_original_count,
            "above_original_count": above_original_count,
            "categorized_count": categorized_count,
            "uncategorized_count": uncategorized_count,
        },
        "privacy": {
            "case_material": "opaque-case-identifiers-only",
            "commands_included": False,
            "local_paths_included": False,
            "resource_measurements_included": False,
        },
    }
    _validate_manifest_digests(report, manifest)
    active_rss = sum(sorted((shard.rss_mib for shard in shards), reverse=True)[:max_concurrent_workers])
    return report, peak_rss_mib() + active_rss


def _merge_groups(target: defaultdict[str, list[str]], source: Mapping[str, list[str]]) -> None:
    for key, case_ids in source.items():
        target[key].extend(case_ids)


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
    return {source_binding_id(path.relative_to(REPO_ROOT).as_posix()): _sha256(path) for path in paths}


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
    report, rss_mib = _generate_decision_diff_report()
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
                    "rss_mib": rss_mib,
                },
                sort_keys=True,
            )
        )
    else:
        print(payload.decode(), end="")


if __name__ == "__main__":
    _main()
