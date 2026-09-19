"""Bind mutation acceptance to complete reviewed source and tool inventory."""

from __future__ import annotations

import json
import sys
from importlib import metadata
from pathlib import Path

import pytest

from scripts.ci import mutation_gate
from scripts.ci.mutation_targets import TARGETS

ROOT = Path(__file__).resolve().parents[1]
SOURCE_PATH = "src/codex_plugin_scanner/guard/runtime/command_model.py"
SOURCE = (ROOT / SOURCE_PATH).read_bytes()
RAW_CASE = "tests/test_guard_shell_read_syntax_fidelity.py::test_raw_parser_keeps_invalid_execution_prefix"


def _counts(total: int, **overrides: int) -> dict[str, int]:
    counts = {
        "killed": total - 100, "survived": 100, "total": total,
        "no_tests": 0, "skipped": 0, "suspicious": 0, "timeout": 0,
        "segfault": 0, "check_was_interrupted_by_user": 0,
    }
    counts.update(overrides)
    return counts


@pytest.fixture
def inventory_context(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    source = tmp_path / SOURCE_PATH
    source.parent.mkdir(parents=True)
    source.write_bytes(SOURCE)
    summary = tmp_path / "summary.json"
    versions = {"mutmut": "3.7.0", "libcst": "1.9.0"}

    def package_version(name: str) -> str:
        if name not in versions:
            raise metadata.PackageNotFoundError(name)
        return versions[name]

    monkeypatch.setattr(mutation_gate, "ROOT", tmp_path, raising=False)
    monkeypatch.setattr(metadata, "version", package_version)
    monkeypatch.setattr(sys, "argv", ["mutation_gate", "--target", "command-model", "--summary", str(summary)])

    def run(counts: dict[str, int] | None = None) -> int:
        if counts is None:
            counts = _counts(mutation_gate.BASELINES["command-model"].expected_total)
        summary.write_text(json.dumps(counts), encoding="utf-8")
        return mutation_gate.main()

    return run, source, versions


def test_complete_current_mutation_inventory_is_accepted(inventory_context) -> None:
    run, _source, _versions = inventory_context
    assert run(_counts(588, killed=382, survived=206)) == 0


def test_mutation_selection_retains_existing_suites_and_raw_parser_case() -> None:
    assert TARGETS["command-model"].test_selection == (
        "tests/test_guard_command_model.py",
        "tests/test_guard_command_critical_floors.py",
        "tests/test_guard_command_corpus.py",
        RAW_CASE,
    )


def test_matching_reviewed_inventory_remains_accepted(inventory_context) -> None:
    run, _source, _versions = inventory_context
    assert run() == 0


@pytest.mark.parametrize("alteration", ["changed", "missing"])
def test_complete_count_cannot_hide_changed_source(inventory_context, alteration: str) -> None:
    run, source, _versions = inventory_context
    if alteration == "missing":
        source.unlink()
    else:
        source.write_bytes(SOURCE + b"\n# Different source revision\n")
    assert run() == 1


@pytest.mark.parametrize("package, version", [("mutmut", "3.6.0"), ("libcst", "1.8.6"), ("mutmut", None)])
def test_complete_count_cannot_hide_changed_tools(inventory_context, package: str, version: str | None) -> None:
    run, _source, versions = inventory_context
    if version is None:
        del versions[package]
    else:
        versions[package] = version
    assert run() == 1


@pytest.mark.parametrize(
    "status",
    ["skipped", "no_tests", "suspicious", "timeout", "segfault", "check_was_interrupted_by_user"],
)
def test_complete_count_rejects_unevaluated_or_failed_mutants(inventory_context, status: str) -> None:
    run, _source, _versions = inventory_context
    total = mutation_gate.BASELINES["command-model"].expected_total
    assert run(_counts(total, **{status: 1})) == 1


def test_generated_inventory_mismatch_is_rejected(inventory_context) -> None:
    run, _source, _versions = inventory_context
    total = mutation_gate.BASELINES["command-model"].expected_total
    assert run(_counts(total - 1)) == 1


def test_incomplete_evaluated_total_is_rejected(inventory_context) -> None:
    run, _source, _versions = inventory_context
    total = mutation_gate.BASELINES["command-model"].expected_total
    with pytest.raises(ValueError, match="total"):
        run(_counts(total, killed=total - 101))


def test_existing_score_floor_remains_required(inventory_context) -> None:
    run, _source, _versions = inventory_context
    total = mutation_gate.BASELINES["command-model"].expected_total
    assert mutation_gate.BASELINES["command-model"].minimum_score == 64.0
    assert run(_counts(total, killed=total // 2, survived=total - total // 2)) == 1
