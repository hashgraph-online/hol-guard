"""Publication binds reviewed code and exact canonical source bytes."""

from __future__ import annotations

import importlib
import subprocess
from pathlib import Path

import pytest


@pytest.fixture
def checkout(monkeypatch, tmp_path):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts"))
    module = importlib.import_module("extension_delivery_source")
    root = tmp_path / "checkout"
    root.mkdir()

    def git(*args):
        return subprocess.check_output(["git", *args], cwd=root, text=True).strip()

    git("init", "-q", "-b", "main")
    source = root / "contributions/command-sources/command.example.json"
    source.parent.mkdir(parents=True)
    source.write_text('{"reviewed":"source"}\n')
    (root / "pyproject.toml").write_text("[project]\n")
    git("add", "contributions", "pyproject.toml")
    git(
        "-c",
        "commit.gpgsign=false",
        "-c",
        "user.name=github-actions[bot]",
        "-c",
        "user.email=41898282+github-actions[bot]@users.noreply.github.com",
        "commit",
        "-qm",
        "test fixture",
    )
    return module, root, source, git, git("rev-parse", "HEAD")


def test_clean_reviewed_source_passes_and_wrong_commit_fails(checkout):
    module, root, _, _, sha = checkout
    module.verify_sources(root, sha)
    with pytest.raises(ValueError, match="differs from reviewed source"):
        module.verify_sources(root, "0" * 40)


def test_hidden_worktree_change_still_fails_byte_binding(checkout):
    module, root, path, git, sha = checkout
    git("update-index", "--assume-unchanged", str(path.relative_to(root)))
    path.write_text('{"unreviewed":"bytes"}\n')
    assert git("status", "--porcelain") == ""
    with pytest.raises(ValueError, match="differ"):
        module.verify_sources(root, sha)


def test_hidden_deletion_cannot_remove_reviewed_policy_or_revocations(checkout):
    module, root, path, git, sha = checkout
    git("update-index", "--assume-unchanged", str(path.relative_to(root)))
    path.unlink()
    assert git("status", "--porcelain") == ""
    with pytest.raises(ValueError, match="inventory differs"):
        module.verify_sources(root, sha)


@pytest.mark.parametrize(
    "name",
    [
        "scripts/unreviewed.py",
        "pyproject.toml",
        "contributions/command-sources/command.new.json",
        "docs/guard/extensions/README.md",
    ],
)
def test_unreviewed_code_dependency_or_contribution_prevents_publication(checkout, name):
    module, root, _, _, sha = checkout
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("unreviewed\n")
    with pytest.raises(ValueError, match="differ from reviewed source"):
        module.verify_sources(root, sha)
