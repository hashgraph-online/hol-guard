from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
from collections.abc import Iterator
from difflib import SequenceMatcher
from itertools import chain
from pathlib import Path
from typing import Protocol, cast

import pytest

from codex_plugin_scanner.guard.action_lattice import guard_action_severity, is_guard_action
from codex_plugin_scanner.guard.runtime.command_evaluation import evaluate_command
from codex_plugin_scanner.guard.runtime.effect_contract import (
    EffectKind,
    EffectReversibility,
    EffectTargetScope,
    ProofRequirement,
    UncertaintyKind,
)
from tests.guard_command_corpus import (
    FIXTURE_DIR,
    KNOWN_GAPS_PATH,
    MANIFEST_PATH,
    PAIRS_PATH,
    CommandCorpusCase,
    corpus_digest,
    iter_adversarial_corpus,
    iter_benign_corpus,
    load_seed_manifest,
    stable_case_id,
)
from tests.guard_command_corpus_oracle import (
    ADVERSARIAL_ORACLE,
    BENIGN_ORACLE,
    PAIR_ORACLE,
    OracleRecord,
    iter_adversarial_oracle,
    iter_benign_oracle,
)
from tests.guard_command_corpus_runner import linux_peak_rss_mib_from_status, peak_rss_mib

_OPAQUE_ID = re.compile(r"c-[0-9a-f]{24}")
_OWNERS = {f"CDX-06{index}" for index in range(7)}
_WORKFLOW_FAMILIES = {
    "navigation-public-read",
    "source-search-read",
    "build-typecheck-test-lint",
    "workspace-patch-write",
    "git-local",
    "github-remote",
    "package-runner-source",
    "shell-composition",
    "network-container-cloud",
    "credentials-permissions-system-guard-destruction",
}


class _CorpusFactory(Protocol):
    def __call__(self, *, shard_index: int = 0, shard_count: int = 1) -> Iterator[CommandCorpusCase]: ...


class _OracleFactory(Protocol):
    def __call__(self, *, shard_index: int = 0, shard_count: int = 1) -> Iterator[OracleRecord]: ...


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _decode_object(path: Path) -> dict[str, object]:
    decoded = cast(object, json.loads(path.read_text(encoding="utf-8")))
    assert isinstance(decoded, dict)
    return cast(dict[str, object], decoded)


def _oracle_paths() -> tuple[Path, ...]:
    return tuple(sorted(Path(__file__).parent.glob("guard_command_corpus_oracle*.py")))


def _floor_rank(value: object) -> int:
    if value == "monitor":
        return guard_action_severity("warn")
    assert is_guard_action(value)
    return guard_action_severity(value)


@pytest.mark.parametrize(
    ("corpus_factory", "oracle_factory"),
    (
        (iter_benign_corpus, iter_benign_oracle),
        (iter_adversarial_corpus, iter_adversarial_oracle),
    ),
)
def test_deterministic_shards_partition_the_default_corpus(
    corpus_factory: _CorpusFactory,
    oracle_factory: _OracleFactory,
) -> None:
    expected_ids = [case.case_id for case in corpus_factory()]
    observed_ids: list[str] = []
    for shard_index in range(4):
        cases = list(corpus_factory(shard_index=shard_index, shard_count=4))
        oracle = list(oracle_factory(shard_index=shard_index, shard_count=4))
        assert [case.case_id for case in cases] == [record.case_id for record in oracle]
        observed_ids.extend(case.case_id for case in cases)
    assert sorted(observed_ids) == sorted(expected_ids)
    assert len(set(observed_ids)) == len(expected_ids)


def test_invalid_corpus_shards_fail_closed() -> None:
    with pytest.raises(ValueError, match="shard"):
        _ = list(iter_adversarial_corpus(shard_index=1, shard_count=1))
    with pytest.raises(ValueError, match="shard"):
        _ = list(iter_adversarial_oracle(shard_index=-1, shard_count=4))


def _oracle_digest(records: tuple[OracleRecord, ...]) -> str:
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


def test_manifest_binds_generator_oracle_fixtures_counts_and_budgets() -> None:
    manifest = load_seed_manifest()
    generator_path = Path(__file__).with_name("guard_command_corpus.py")
    oracle_paths = _oracle_paths()

    assert manifest["fixed_seed"] == 22020
    assert manifest["permutation_multiplier"] == 7919
    assert manifest["generator_version"] == "2.0.0"
    assert manifest["oracle_version"] == "1.0.0"
    assert manifest["benign_target_count"] == 1000
    assert manifest["adversarial_target_count"] == 50000
    assert manifest["generator_source_sha256"] == _sha256(generator_path)
    assert manifest["oracle_source_sha256"] == {path.name: _sha256(path) for path in oracle_paths}
    assert manifest["pairs_sha256"] == _sha256(PAIRS_PATH)
    assert manifest["known_gaps_sha256"] == _sha256(KNOWN_GAPS_PATH)
    assert manifest["evaluation_budget_seconds"] == 30
    assert manifest["evaluation_rss_budget_mib"] == 512
    assert MANIFEST_PATH.stat().st_size < 24_000


def test_inputs_are_exact_unique_opaque_shuffled_and_label_free() -> None:
    benign = tuple(iter_benign_corpus())
    adversarial = tuple(iter_adversarial_corpus())
    cases = (*benign, *adversarial)

    assert len(benign) == 1000
    assert len(adversarial) == 50000
    assert len({case.case_id for case in cases}) == 51000
    assert len({case.command for case in benign}) == 1000
    assert len({case.command for case in adversarial}) == 50000
    assert all(_OPAQUE_ID.fullmatch(case.case_id) for case in cases)
    assert all(not re.search(r"benign|adversarial|technique|expected|floor", case.case_id) for case in cases)
    assert [case.case_id for case in benign] == sorted(case.case_id for case in benign)
    assert [case.case_id for case in adversarial] != sorted(case.case_id for case in adversarial)


def test_independent_oracle_is_complete_per_seed_and_never_invents_proof() -> None:
    source = "\n".join(path.read_text(encoding="utf-8") for path in _oracle_paths())
    assert "command_evaluation" not in source
    assert "command_extensions" not in source
    assert "command_rules" not in source
    assert "inspect_command" not in source
    assert len(BENIGN_ORACLE) == 40
    assert len(ADVERSARIAL_ORACLE) == 12

    benign = tuple(iter_benign_oracle())
    adversarial = tuple(iter_adversarial_oracle())
    oracle = (*benign, *adversarial)
    assert len(oracle) == 51000
    assert len({record.case_id for record in oracle}) == 51000
    assert {record.workflow_family for record in oracle} == _WORKFLOW_FAMILIES
    assert all(record.effects and record.required_proofs and record.owner.startswith("CDX-06") for record in oracle)
    assert all(not record.provided_proofs for record in oracle)
    assert all(record.minimum_floor not in {"allow", "warn"} for record in oracle)
    assert [case.case_id for case in iter_benign_corpus()] == [record.case_id for record in benign]
    assert [case.case_id for case in iter_adversarial_corpus()] == [record.case_id for record in adversarial]
    effect_values = {value.value for value in EffectKind}
    scope_values = {value.value for value in EffectTargetScope}
    uncertainty_values = {value.value for value in UncertaintyKind}
    proof_values = {value.value for value in ProofRequirement}
    for record in oracle:
        assert set(record.effects) <= effect_values
        assert record.target_scope in scope_values
        assert set(record.uncertainties) <= uncertainty_values
        assert set(record.required_proofs) <= proof_values
        assert record.decision_status in {"decidable", "context-required", "uncertain"}
        assert record.owner in _OWNERS
    reversibility_values = {value.value for value in EffectReversibility}
    for baseline, variant in PAIR_ORACLE.values():
        for facts in (baseline, variant):
            assert set(facts.effects) <= effect_values
            assert facts.target_scope in scope_values
            assert facts.reversibility in reversibility_values
            assert set(facts.uncertainties) <= uncertainty_values
            assert set(facts.required_proofs) <= proof_values
            assert is_guard_action(facts.minimum_floor)


def test_ten_reviewed_pairs_have_one_machine_checked_delta_and_run_through_guard(tmp_path: Path) -> None:
    payload = _decode_object(PAIRS_PATH)
    pairs_value = payload["pairs"]
    assert isinstance(pairs_value, list)
    pairs = cast(list[object], pairs_value)
    assert len(pairs) == 10
    families: set[str] = set()
    pair_case_ids: set[str] = set()

    for value in pairs:
        assert isinstance(value, dict)
        pair = cast(dict[str, object], value)
        family = pair["workflow_family"]
        assert isinstance(family, str)
        families.add(family)
        scope = pair["delta_scope"]
        baseline_command, variant_command = str(pair["baseline_command"]), str(pair["variant_command"])
        if scope == "tokens":
            template = str(pair["shared_template"])
            assert template.replace("{delta}", str(pair["baseline_delta"])) == baseline_command
            assert template.replace("{delta}", str(pair["variant_delta"])) == variant_command
            changes = [
                opcode
                for opcode in SequenceMatcher(
                    a=shlex.split(baseline_command), b=shlex.split(variant_command)
                ).get_opcodes()
                if opcode[0] != "equal"
            ]
            assert len(changes) == 1, pair["pair_id"]
        elif scope == "context":
            assert baseline_command == variant_command
            before = cast(dict[str, object], pair["baseline_context"])
            after = cast(dict[str, object], pair["variant_context"])
            assert len({key for key in before if before[key] != after[key]}) == 1
        else:
            assert scope == "semantic"
            before = cast(dict[str, object], pair["baseline_semantics"])
            after = cast(dict[str, object], pair["variant_semantics"])
            assert len({key for key in before if before[key] != after[key]}) == 1

        baseline_cwd = tmp_path / "workspace"
        variant_cwd = tmp_path / "workspace"
        if scope == "context":
            baseline_context = cast(dict[str, object], pair["baseline_context"])
            variant_context = cast(dict[str, object], pair["variant_context"])
            adapter = pair["context_adapter"]
            if adapter == "cwd":
                baseline_cwd = tmp_path / str(baseline_context["cwd_scope"])
                variant_cwd = tmp_path / str(variant_context["cwd_scope"])
            else:
                assert adapter == "unsupported-known-gap"
                assert baseline_context["nonce_state"] == "fresh"
                assert variant_context["nonce_state"] == "already-consumed"
        baseline_cwd.mkdir(exist_ok=True)
        variant_cwd.mkdir(exist_ok=True)
        pair_id = str(pair["pair_id"])
        pair_case_ids.add(stable_case_id(f"pair:{pair_id}:baseline", 0))
        pair_case_ids.add(stable_case_id(f"pair:{pair_id}:variant", 0))
        baseline_facts, variant_facts = PAIR_ORACLE[pair_id]
        changed = {
            field
            for field in (
                "effects",
                "target_scope",
                "reversibility",
                "uncertainties",
                "required_proofs",
                "minimum_floor",
            )
            if getattr(baseline_facts, field) != getattr(variant_facts, field)
        }
        declared_delta = pair["expected_semantic_delta"]
        assert isinstance(declared_delta, list)
        assert changed == set(cast(list[object], declared_delta))
        assert baseline_facts.minimum_floor == pair["baseline_floor"]
        assert variant_facts.minimum_floor == pair["variant_floor"]
        assert _floor_rank(variant_facts.minimum_floor) >= _floor_rank(baseline_facts.minimum_floor)

        baseline = evaluate_command(baseline_command, cwd=baseline_cwd, home_dir=tmp_path)
        variant = evaluate_command(variant_command, cwd=variant_cwd, home_dir=tmp_path)
        observed_value = pair["observed_floors"]
        assert isinstance(observed_value, list)
        observed = cast(list[object], observed_value)
        assert [baseline.minimum_action, variant.minimum_action] == observed
        assert pair["owner"] in _OWNERS

    assert families == _WORKFLOW_FAMILIES
    assert len(pair_case_ids) == 20


def test_full_guard_evaluation_matches_exact_non_widening_known_gap_baseline() -> None:
    known_payload = _decode_object(KNOWN_GAPS_PATH)
    assert known_payload["schema_version"] == "1.0.0"
    assert known_payload["introduced_in_corpus"] == "1.0.0"
    assert known_payload["expires_by"] == "release/2.2-runtime-gate"
    assert known_payload["status"] == "resolved"
    gaps_value = known_payload["gaps"]
    assert isinstance(gaps_value, list)
    expected: dict[tuple[str, str, str, str], tuple[int, str]] = {}
    for value in cast(list[object], gaps_value):
        assert isinstance(value, dict)
        gap = cast(dict[str, object], value)
        key = (str(gap["owner"]), str(gap["kind"]), str(gap["oracle_floor"]), str(gap["observed_floor"]))
        assert key not in expected
        assert str(gap["gap_id"]).startswith(str(gap["owner"]))
        assert gap["owner"] in _OWNERS
        assert gap["kind"] in {"underclassified", "overclassified"}
        assert is_guard_action(gap["oracle_floor"])
        assert gap["observed_floor"] == "monitor" or is_guard_action(gap["observed_floor"])
        count = int(str(gap["count"]))
        digest = str(gap["case_ids_digest"])
        assert count > 0 and re.fullmatch(r"[0-9a-f]{64}", digest)
        expected[key] = (count, digest)

    runner_path = Path(__file__).with_name("guard_command_corpus_runner.py")
    completed = subprocess.run(
        [sys.executable, str(runner_path)],
        check=True,
        capture_output=True,
        text=True,
        timeout=45,
        cwd=Path.cwd(),
    )
    report_value = cast(object, json.loads(completed.stdout))
    assert isinstance(report_value, dict)
    report = cast(dict[str, object], report_value)
    actual_value = report["actual"]
    assert isinstance(actual_value, dict)
    actual = {
        tuple(key.split("|")): tuple(cast(list[object], value))
        for key, value in cast(dict[str, object], actual_value).items()
        if isinstance(value, list)
    }
    assert actual == expected
    assert isinstance(report["elapsed"], int | float) and report["elapsed"] < 30
    assert isinstance(report["rss_mib"], int | float) and report["rss_mib"] < 512


def test_windows_peak_rss_uses_process_working_set(monkeypatch: pytest.MonkeyPatch) -> None:
    peak_bytes = 128 * 1024 * 1024

    def fake_run(
        command: list[str],
        *,
        check: bool,
        capture_output: bool,
        text: bool,
        timeout: int,
    ) -> subprocess.CompletedProcess[str]:
        assert command[-1] == "(Get-Process -Id 4242).PeakWorkingSet64"
        assert check and capture_output and text and timeout == 10
        return subprocess.CompletedProcess(command, 0, stdout=f"{peak_bytes}\n", stderr="")

    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(os, "getpid", lambda: 4242)
    monkeypatch.setattr(subprocess, "run", fake_run)

    assert peak_rss_mib() == 128.0


def test_linux_peak_rss_uses_fresh_process_high_water_mark() -> None:
    status = "Name:\tpython\nVmPeak:\t1048576 kB\nVmHWM:\t131072 kB\n"
    assert linux_peak_rss_mib_from_status(status) == 128.0


def test_canonical_digests_are_stable_across_process_roots_hash_seed_timezone_and_locale(tmp_path: Path) -> None:
    manifest = load_seed_manifest()
    digests_value = manifest["canonical_digests"]
    assert isinstance(digests_value, dict)
    digests = cast(dict[str, object], digests_value)
    benign = tuple(iter_benign_oracle())
    adversarial = tuple(iter_adversarial_oracle())
    assert corpus_digest(iter_benign_corpus()) == digests["benign"]
    assert corpus_digest(iter_adversarial_corpus()) == digests["adversarial"]
    assert _oracle_digest((*benign, *adversarial)) == digests["oracle"]

    script = (
        "from tests.guard_command_corpus import corpus_digest,iter_adversarial_corpus,iter_benign_corpus;"
        "print(corpus_digest(iter_benign_corpus()));print(corpus_digest(iter_adversarial_corpus()))"
    )
    outputs: list[str] = []
    for hash_seed, timezone, locale in (("1", "UTC", "C"), ("987654", "Pacific/Honolulu", "C.UTF-8")):
        environment = os.environ.copy()
        environment.update(PYTHONHASHSEED=hash_seed, TZ=timezone, LC_ALL=locale, TMPDIR=str(tmp_path))
        completed = subprocess.run(
            [sys.executable, "-c", script],
            check=True,
            capture_output=True,
            text=True,
            env=environment,
            timeout=20,
        )
        outputs.append(completed.stdout)
    assert outputs[0] == outputs[1]


def test_all_corpus_artifacts_and_generated_records_are_secret_and_pii_free() -> None:
    forbidden = (
        "/" + "Users/",
        "/" + "home/",
        "gh" + "p_",
        "gh" + "s_",
        "gl" + "pat-",
        "xo" + "xb-",
        "AK" + "IA",
        "BEGIN " + "PRIVATE KEY",
        "hashgraph-online" + "/points-portal",
    )
    patterns = (
        re.compile(r"\beyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
        re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b", re.I),
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    )
    texts = [path.read_text(encoding="utf-8") for path in FIXTURE_DIR.glob("*") if path.is_file()]
    texts.extend(case.command for case in chain(iter_benign_corpus(), iter_adversarial_corpus()))
    texts.extend(repr(record) for record in chain(iter_benign_oracle(), iter_adversarial_oracle()))
    for text in texts:
        assert all(value not in text for value in forbidden)
        assert all(pattern.search(text) is None for pattern in patterns)
