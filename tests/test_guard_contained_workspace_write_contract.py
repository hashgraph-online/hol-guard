from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime import containment_outputs as outputs_module
from codex_plugin_scanner.guard.runtime.command_evaluation import evaluate_command
from codex_plugin_scanner.guard.runtime.command_workspace_write_candidates import (
    workspace_write_candidate_operation,
)
from codex_plugin_scanner.guard.runtime.containment_contract import (
    ContainmentPolicy,
    ContainmentRequest,
)
from codex_plugin_scanner.guard.runtime.containment_executor import file_sha256
from codex_plugin_scanner.guard.runtime.containment_outputs import (
    OutputBoundaryError,
    capture_declared_outputs,
)
from tests.guard_command_corpus import iter_adversarial_corpus, iter_benign_corpus
from tests.guard_command_corpus_oracle import iter_adversarial_oracle, iter_benign_oracle


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    _ = path.write_text(content, encoding="utf-8")


def test_every_cdx_062_case_retains_exact_review_or_block_floor() -> None:
    benign_count = 0
    operations: set[str] = set()
    for case, oracle in zip(iter_benign_corpus(), iter_benign_oracle(), strict=True):
        evaluation = evaluate_command(case.command, cwd=Path("workspace"), home_dir=Path("home"))
        operation = workspace_write_candidate_operation(evaluation.command)
        if oracle.owner != "CDX-062":
            assert operation is None
            continue
        benign_count += 1
        assert operation is not None
        operations.add(operation)
        assert evaluation.minimum_action == "review"
        assert evaluation.decision_plane.action == "review"
        assert evaluation.decision_plane.proof_routes == frozenset()
    assert benign_count == 100
    assert operations == {"patch-check", "patch-apply", "format-write", "copy-generated"}

    adversarial_count = 0
    for case, oracle in zip(iter_adversarial_corpus(), iter_adversarial_oracle(), strict=True):
        if oracle.owner != "CDX-062":
            continue
        adversarial_count += 1
        evaluation = evaluate_command(case.command, cwd=Path("workspace"), home_dir=Path("home"))
        assert evaluation.minimum_action == "block"
        assert evaluation.decision_plane.action == "block"
        assert evaluation.decision_plane.proof_routes == frozenset()
    assert adversarial_count == 4167


def test_capture_rejects_undeclared_change_and_link(tmp_path: Path) -> None:
    workspace = (tmp_path / "workspace").resolve()
    snapshot = (tmp_path / "snapshot").resolve()
    workspace.mkdir()
    snapshot.mkdir()
    _write(workspace / "source.txt", "old\n")
    _write(snapshot / "source.txt", "changed\n")
    request = ContainmentRequest(
        argv=("/usr/bin/true",),
        cwd=str(workspace),
        environment=(),
        policy=ContainmentPolicy(str(workspace), ()),
        inputs=(),
        launch_digest=hashlib.sha256(b"launch").hexdigest(),
        executable_digest=file_sha256("/usr/bin/true"),
        operation_id="patch-check",
    )
    with pytest.raises(OutputBoundaryError, match="undeclared"):
        _ = capture_declared_outputs(request, snapshot)

    (snapshot / "source.txt").unlink()
    (snapshot / "source.txt").symlink_to(workspace / "source.txt")
    with pytest.raises(OutputBoundaryError, match="symlink"):
        _ = capture_declared_outputs(request, snapshot)


def test_capture_rejects_file_count_over_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = (tmp_path / "workspace").resolve()
    snapshot = (tmp_path / "snapshot").resolve()
    workspace.mkdir()
    snapshot.mkdir()
    _write(snapshot / "first.txt", "first\n")
    _write(snapshot / "second.txt", "second\n")
    monkeypatch.setattr(outputs_module, "_MAX_FILES", 1)
    request = ContainmentRequest(
        argv=("/usr/bin/true",),
        cwd=str(workspace),
        environment=(),
        policy=ContainmentPolicy(str(workspace), ()),
        inputs=(),
        launch_digest=hashlib.sha256(b"launch").hexdigest(),
        executable_digest=file_sha256("/usr/bin/true"),
        operation_id="patch-check",
    )

    with pytest.raises(OutputBoundaryError, match="file budget"):
        _ = capture_declared_outputs(request, snapshot)


def test_output_discovery_stops_at_entry_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeEntry:
        name: str = "file.txt"

        def is_symlink(self) -> bool:
            return False

        def is_dir(self, *, follow_symlinks: bool = True) -> bool:
            del follow_symlinks
            return False

        def is_file(self, *, follow_symlinks: bool = True) -> bool:
            del follow_symlinks
            return True

    class CountingScandir:
        def __init__(self) -> None:
            self.consumed: int = 0

        def __enter__(self) -> CountingScandir:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def __iter__(self) -> CountingScandir:
            return self

        def __next__(self) -> FakeEntry:
            self.consumed += 1
            return FakeEntry()

    snapshot = (tmp_path / "snapshot").resolve()
    workspace = (tmp_path / "workspace").resolve()
    snapshot.mkdir()
    workspace.mkdir()
    entries = CountingScandir()

    def fake_scandir(_path: object) -> CountingScandir:
        return entries

    monkeypatch.setattr(outputs_module, "_MAX_ENTRIES", 1)
    monkeypatch.setattr(os, "scandir", fake_scandir)
    request = ContainmentRequest(
        argv=("/usr/bin/true",),
        cwd=str(workspace),
        environment=(),
        policy=ContainmentPolicy(str(workspace), ()),
        inputs=(),
        launch_digest=hashlib.sha256(b"launch").hexdigest(),
        executable_digest=file_sha256("/usr/bin/true"),
        operation_id="patch-check",
    )

    with pytest.raises(OutputBoundaryError, match="entry budget"):
        _ = capture_declared_outputs(request, snapshot)
    assert entries.consumed == 2
