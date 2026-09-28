from __future__ import annotations

import os
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.evaluation_preflight import EvaluationSetup, setup_evaluation
from codex_plugin_scanner.guard.evaluation_witness import LocalSideEffectWitness
from tests.test_guard_evaluation_preflight import _artifact, _artifact_paths, _fake_host, _profile


def _setup(tmp_path: Path) -> EvaluationSetup:
    executable = _fake_host(tmp_path)
    artifact = _artifact(tmp_path)
    setup = setup_evaluation(
        _profile(tmp_path, executable),
        artifact_paths=_artifact_paths(artifact),
        parent_dir=tmp_path,
        allow_host_execution=True,
    )
    assert setup.report.status == "passed"
    return setup


@pytest.mark.skipif(os.name == "nt", reason="directory descriptor checks require POSIX")
def test_witness_rejects_replaced_workspace_symlink(tmp_path: Path) -> None:
    setup = _setup(tmp_path)
    assert setup.workspace is not None
    outside = tmp_path / "outside"
    outside.mkdir()
    workspace = setup.workspace
    workspace.rmdir()
    workspace.symlink_to(outside, target_is_directory=True)
    try:
        with pytest.raises(ValueError, match="owned evaluation setup"), LocalSideEffectWitness(setup=setup):
            pass
        assert list(outside.iterdir()) == []
    finally:
        workspace.unlink()
        workspace.mkdir(mode=0o700)
        assert setup.cleanup() is True


@pytest.mark.skipif(os.name == "nt", reason="directory descriptor checks require POSIX")
def test_witness_rejects_replaced_workspace_directory(tmp_path: Path) -> None:
    setup = _setup(tmp_path)
    assert setup.workspace is not None
    workspace = setup.workspace
    held = workspace.with_name("held-workspace")
    workspace.rename(held)
    workspace.mkdir(mode=0o700)
    try:
        with pytest.raises(ValueError, match="owned evaluation setup"), LocalSideEffectWitness(setup=setup):
            pass
        assert list(workspace.iterdir()) == []
    finally:
        workspace.rmdir()
        held.rename(workspace)
        assert setup.cleanup() is True


@pytest.mark.skipif(os.name == "nt", reason="directory descriptor checks require POSIX")
def test_witness_rejects_replaced_root_symlink(tmp_path: Path) -> None:
    setup = _setup(tmp_path)
    assert setup.root_path is not None
    outside = tmp_path / "outside"
    outside.mkdir()
    root = setup.root_path
    held = tmp_path / "held-setup"
    root.rename(held)
    root.symlink_to(outside, target_is_directory=True)
    try:
        with pytest.raises(ValueError, match="owned evaluation setup"), LocalSideEffectWitness(setup=setup):
            pass
        assert list(outside.iterdir()) == []
    finally:
        root.unlink()
        held.rename(root)
        assert setup.cleanup() is True


@pytest.mark.skipif(os.name == "nt", reason="synthetic host fixture uses a POSIX shell")
def test_witness_rejects_cleaned_setup(tmp_path: Path) -> None:
    setup = _setup(tmp_path)
    assert setup.cleanup() is True
    with pytest.raises(ValueError, match="owned evaluation setup"), LocalSideEffectWitness(setup=setup):
        pass


@pytest.mark.skipif(os.name == "nt", reason="synthetic host fixture uses a POSIX shell")
def test_witness_rejects_marker_with_trailing_data(tmp_path: Path) -> None:
    setup = _setup(tmp_path)
    assert setup.root_path is not None and setup.marker_token is not None
    marker = setup.root_path / ".hol-guard-evaluation-owned"
    marker.write_text(setup.marker_token + "x", encoding="utf-8")
    with pytest.raises(ValueError, match="owned evaluation setup"), LocalSideEffectWitness(setup=setup):
        pass
    marker.write_text(setup.marker_token, encoding="utf-8")
    assert setup.cleanup() is True


@pytest.mark.skipif(os.name == "nt", reason="directory descriptor checks require POSIX")
def test_witness_exit_tolerates_setup_cleanup(tmp_path: Path) -> None:
    setup = _setup(tmp_path)
    with LocalSideEffectWitness(setup=setup) as witness:
        assert witness.check_file_ready()
        assert setup.cleanup() is True
