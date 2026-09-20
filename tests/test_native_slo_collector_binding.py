from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from scripts import build_native_qualification_artifacts as builder
from scripts.native_slo_collector_binding import FROZEN_CONTRACT_FILES, CollectorBinding, CollectorBindingError


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *args], text=True, stderr=subprocess.PIPE).strip()


def _commit(root: Path) -> str:
    _git(root, "add", ".")
    _git(
        root,
        "-c",
        "user.name=Collector Fixture",
        "-c",
        "user.email=fixture@example.invalid",
        "commit",
        "-qm",
        "fixture",
    )
    return _git(root, "rev-parse", "HEAD")


def _checkout(root: Path) -> str:
    root.mkdir()
    _git(root, "init", "-q")
    for role, name in FROZEN_CONTRACT_FILES.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(role + "\n")
    (root / "uv.lock").write_text('[[package]]\nname = "psutil"\nversion = "7.2.2"\n')
    return _commit(root)


@pytest.fixture
def binding(tmp_path: Path) -> CollectorBinding:
    candidate = tmp_path / "candidate"
    collector = tmp_path / "collector"
    _checkout(candidate)
    sha = _checkout(collector)
    return CollectorBinding(collector, candidate, sha, tmp_path / "evidence")


def test_separate_collector_records_commit_tree_and_unchanged_contract(binding: CollectorBinding) -> None:
    with binding:
        pass
    before = json.loads((binding.output_dir / "collector-before.json").read_text())
    after = json.loads((binding.output_dir / "collector-after.json").read_text())
    assert before["matches_expected"] is True
    assert before["commit"] == binding.expected_sha
    assert before["tree"] == _git(binding.root, "rev-parse", "HEAD^{tree}")
    assert before["frozen_contract_matches"] is True
    assert after["unchanged_during_sampling"] is True
    assert after["paired_failed"] is False
    assert _git(binding.root, "status", "--porcelain") == ""
    assert _git(binding.candidate, "status", "--porcelain") == ""


@pytest.mark.parametrize(
    "change", ["wrong_commit", "tracked", "untracked", "contract", "workload_cases", "driver_alias"]
)
def test_untrusted_or_changed_collector_never_runs(binding: CollectorBinding, change: str) -> None:
    if change == "wrong_commit":
        binding.expected_sha = "0" * 40
    elif change == "tracked":
        (binding.root / FROZEN_CONTRACT_FILES["driver"]).write_text("changed\n")
    elif change == "untracked":
        (binding.root / "scripts/untracked_observer.py").write_text("untracked\n")
    elif change == "contract":
        (binding.root / FROZEN_CONTRACT_FILES["sampling"]).write_text("changed\n")
        binding.expected_sha = _commit(binding.root)
    elif change == "workload_cases":
        (binding.root / FROZEN_CONTRACT_FILES["workload_cases"]).write_text("changed\n")
        binding.expected_sha = _commit(binding.root)
    elif change == "driver_alias":
        driver = binding.root / FROZEN_CONTRACT_FILES["driver"]
        driver.unlink()
        try:
            driver.symlink_to(binding.candidate / FROZEN_CONTRACT_FILES["driver"])
        except OSError:
            pytest.skip("runner cannot create file symlinks")
        binding.expected_sha = _commit(binding.root)
    with pytest.raises(CollectorBindingError), binding:
        pytest.fail("rejected collector cannot execute")
    assert json.loads((binding.output_dir / "collector-before.json").read_text())["matches_expected"] is False


def test_pair_failure_retains_after_binding_and_other_required_checks(
    binding: CollectorBinding, monkeypatch: pytest.MonkeyPatch
) -> None:
    attempted = []

    def run(argv, *, cwd):
        attempted.append((argv[0], cwd))
        if argv[0] == "paired":
            raise subprocess.CalledProcessError(1, argv)
        return ""

    monkeypatch.setattr(builder, "_run", run)
    with pytest.raises(RuntimeError, match="installed qualification failed: paired_sampling"):
        builder._run_required_checks(
            (("paired_sampling", ["paired"]), ("installed_ollama", ["ollama"])),
            cwd=binding.candidate,
            collector=binding,
        )
    assert attempted == [("paired", binding.root), ("ollama", binding.candidate)]
    after = json.loads((binding.output_dir / "collector-after.json").read_text())
    assert after["paired_failed"] is True and after["unchanged_during_sampling"] is True


def test_collector_mutation_is_failure_even_when_process_exits_zero(
    binding: CollectorBinding, monkeypatch: pytest.MonkeyPatch
) -> None:
    attempted = []

    def run(argv, *, cwd):
        attempted.append(argv[0])
        if argv[0] == "paired":
            (cwd / FROZEN_CONTRACT_FILES["driver"]).write_text("mutated during run\n")
        return ""

    monkeypatch.setattr(builder, "_run", run)
    with pytest.raises(RuntimeError, match="paired_sampling"):
        builder._run_required_checks(
            (("paired_sampling", ["paired"]), ("installed_ollama", ["ollama"])),
            cwd=binding.candidate,
            collector=binding,
        )
    assert attempted == ["paired", "ollama"]
    after = json.loads((binding.output_dir / "collector-after.json").read_text())
    assert after["matches_expected"] is False and after["unchanged_during_sampling"] is False


@pytest.mark.parametrize("external", [False, True])
def test_builder_changes_only_paired_collector_preserving_installed_artifacts_and_samples(
    binding: CollectorBinding, monkeypatch: pytest.MonkeyPatch, external: bool
) -> None:
    baseline = binding.root.parent / "baseline"
    _checkout(baseline)
    commands = []

    def build(source, **_kwargs):
        return source / "python", source / "artifact.whl", {"source_sha": _git(source, "rev-parse", "HEAD")}

    def run(argv, *, cwd):
        commands.append((argv, cwd))
        return ""

    monkeypatch.setattr(builder, "_build", build)
    monkeypatch.setattr(builder, "_run", run)
    argv = [
        "builder",
        "--baseline",
        str(baseline),
        "--candidate",
        str(binding.candidate),
        "--target",
        "x86_64-pc-windows-msvc",
        "--platform-tag",
        "win_amd64",
        "--mode",
        "qualification",
        "--output-dir",
        str(binding.output_dir),
    ]
    if external:
        argv.extend(("--collector-root", str(binding.root), "--collector-sha", binding.expected_sha))
    monkeypatch.setattr(sys, "argv", argv)
    assert builder.main() == 0
    paired, cwd = next((args, cwd) for args, cwd in commands if "qualify_guard_native.py" in args[1])
    expected_collector = binding.root if external else binding.candidate
    assert paired[1] == str(expected_collector / "scripts/qualify_guard_native.py")
    assert cwd == expected_collector
    assert paired[paired.index("--baseline-python") + 1] == str(baseline / "python")
    assert paired[paired.index("--candidate-python") + 1] == str(binding.candidate / "python")
    assert paired[paired.index("--baseline-artifact") + 1] == str(baseline / "artifact.whl")
    assert paired[paired.index("--candidate-artifact") + 1] == str(binding.candidate / "artifact.whl")
    assert paired[paired.index("--mode") + 1] == "qualification"
    assert paired[paired.index("--runs") + 1] == "5"
    for args, cwd in commands:
        if args[0] != "uv" and args is not paired:
            assert cwd == binding.candidate
            assert all(str(binding.root) not in item for item in args)
