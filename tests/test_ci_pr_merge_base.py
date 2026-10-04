"""Exercise merge-bound attribution with real histories and strict fixture validation."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest
import yaml

from scripts import prepare_extension_contribution as prepare
from scripts.ci.pr_merge_base import comparison_base

ROOT = Path(__file__).resolve().parents[1]


def write_pair(root: Path, name: str, revision: int, *, fixture_revision: int | None = None) -> None:
    """Write minimal declarative identities; the native compiler owns schema validation."""
    source = {"extension": {"extension_id": f"command.{name}"}, "revision": revision}
    source_path = root / f"contributions/command-sources/command.{name}.json"
    fixture_path = root / f"tests/fixtures/command-source-{name}.v1.json"
    source_path.parent.mkdir(parents=True, exist_ok=True)
    fixture_path.parent.mkdir(parents=True, exist_ok=True)
    source_path.write_text(json.dumps(source), encoding="utf-8")
    embedded = {**source, "revision": revision if fixture_revision is None else fixture_revision}
    fixture_path.write_text(
        json.dumps({"schema": "guard.command-extension-fixtures.v1", "build": {"sources": [embedded]}, "cases": []}),
        encoding="utf-8",
    )


@pytest.fixture
def history(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Construct an old contributor branch and a newer base with unrelated inputs."""
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    monkeypatch.setattr(prepare, "ROOT", checkout)
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)

    def git(*arguments: str) -> str:
        return subprocess.check_output(["git", "-C", str(checkout), *arguments], text=True, timeout=10).strip()

    git("init", "-q", "-b", "main")
    git("config", "user.name", "CI regression")
    git("config", "user.email", "ci@example.invalid")
    git("config", "commit.gpgsign", "false")
    write_pair(checkout, "demo", 1)
    git("add", ".")
    git("commit", "-qm", "baseline")
    old_base = git("rev-parse", "HEAD")
    git("checkout", "-qb", "contributor")
    write_pair(checkout, "demo", 2)
    git("add", ".")
    git("commit", "-qm", "authored source and fixture")
    head = git("rev-parse", "HEAD")
    git("checkout", "-q", "main")
    # An existing unrelated snapshot need not bind the newest canonical source.
    # All native fixture behavior is still tested; attribution must stay PR-specific.
    write_pair(checkout, "unrelated", 2, fixture_revision=1)
    git("add", ".")
    git("commit", "-qm", "newer base inputs")
    current_base = git("rev-parse", "HEAD")
    git("merge", "--no-ff", "-qm", "synthetic PR merge", "contributor")
    return checkout, git, old_base, current_base, head, git("rev-parse", "HEAD")


def test_newer_base_changes_are_not_attributed_to_the_contributor(history) -> None:
    checkout, git, old_base, current_base, head, merge = history
    before = {path: path.read_bytes() for path in checkout.rglob("*.json")}
    base = comparison_base(head, merge, root=checkout)
    assert base == current_base != old_base
    stale_changes = prepare._changed_paths(old_base)
    assert "tests/fixtures/command-source-unrelated.v1.json" in stale_changes
    with pytest.raises(ValueError, match="Changed fixture needs to bind"):
        prepare._validate_changed_source_fixture_pairs(stale_changes, prepare._fixtures(), revision=old_base)
    changes = prepare._changed_paths(base)
    assert changes == {
        "contributions/command-sources/command.demo.json",
        "tests/fixtures/command-source-demo.v1.json",
    }
    fixtures = prepare._fixtures()
    assert prepare._validate_changed_source_fixture_pairs(changes, fixtures, revision=base) == fixtures
    assert all(path.read_bytes() == content for path, content in before.items())
    assert git("rev-parse", "contributor") == head
    assert git("status", "--porcelain") == ""


@pytest.mark.parametrize("tamper", ["fixture", "source", "delete-fixture"])
def test_actual_contributor_binding_failures_are_not_hidden(history, tamper: str) -> None:
    checkout, _, _, _, head, merge = history
    base = comparison_base(head, merge, root=checkout)
    changes = prepare._changed_paths(base)
    if tamper == "fixture":
        write_pair(checkout, "demo", 2, fixture_revision=99)
    elif tamper == "source":
        write_pair(checkout, "demo", 99, fixture_revision=2)
    else:
        (checkout / "tests/fixtures/command-source-demo.v1.json").unlink()
    with pytest.raises(ValueError, match=r"(bind the exact canonical source|matching portable fixture)"):
        prepare._validate_changed_source_fixture_pairs(changes, prepare._fixtures(), revision=base)


@pytest.mark.parametrize("wrong", ["head", "merge", "head-checkout", "base-as-head"])
def test_mismatched_or_non_merge_checkouts_fail_closed(history, wrong: str) -> None:
    checkout, git, old_base, current_base, head, merge = history
    if wrong == "head":
        head = old_base
    elif wrong == "merge":
        merge = old_base
    elif wrong == "base-as-head":
        head = current_base
    else:
        git("checkout", "-q", "contributor")
        merge = head
    with pytest.raises(ValueError, match="expected two-parent PR merge"):
        comparison_base(head, merge, root=checkout)


@pytest.mark.parametrize("invalid", ["main", "--all", "a" * 39, "a" * 40 + "\n", "A" * 40])
def test_ref_names_and_malformed_shas_are_rejected(tmp_path: Path, invalid: str) -> None:
    checkout, head, merge = tmp_path, "a" * 40, "b" * 40
    with pytest.raises(ValueError, match="full GitHub commit SHAs"):
        comparison_base(invalid, merge, root=checkout)
    with pytest.raises(ValueError, match="full GitHub commit SHAs"):
        comparison_base(head, invalid, root=checkout)


def test_builder_binds_the_event_head_and_merge_without_weakening_validation() -> None:
    workflow = yaml.safe_load((ROOT / ".github/workflows/extension-builder-ci.yml").read_text())
    events = workflow.get("on", workflow.get(True))
    assert "pull_request" in events and "pull_request_target" not in events
    assert workflow["permissions"] == {"contents": "read"}
    steps = workflow["jobs"]["authoring"]["steps"]
    checkout = next(step for step in steps if step.get("uses", "").startswith("actions/checkout@"))
    assert checkout["with"] == {"fetch-depth": 0, "persist-credentials": False}
    base = next(step for step in steps if step.get("id") == "contribution-base")
    assert base["env"]["PR_HEAD_SHA"] == "${{ github.event.pull_request.head.sha }}"
    assert base["env"]["PR_MERGE_SHA"] == "${{ github.sha }}"
    assert "builder-evidence/checkout.txt" in base["run"]
    assert "continue-on-error" not in base
    preparation = next(step for step in steps if step.get("name") == "Prepare and verify current extension projections")
    assert preparation["env"]["COMPARISON_BASE"] == "${{ steps.contribution-base.outputs.sha }}"
    assert '--changed-from "$COMPARISON_BASE"' in preparation["run"]
    assert "scripts/prepare_extension_contribution.py --check" in preparation["run"]
    assert "continue-on-error" not in preparation
    assert steps.index(base) < steps.index(preparation)
