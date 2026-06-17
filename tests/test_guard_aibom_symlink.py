from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.aibom_symlink import (
    _MAX_SYMLINK_HOPS,
    _resolve_symlink_chain,
    classify_path_class,
    fingerprint_redacted_path,
    inspect_aibom_source_path,
)
from codex_plugin_scanner.guard.inventory_contract import inventory_snapshot_from_detection
from codex_plugin_scanner.guard.models import GuardArtifact, HarnessDetection


def test_fingerprint_redacted_path_never_emits_raw_home(tmp_path: Path) -> None:
    workspace = tmp_path / "repo"
    workspace.mkdir()
    target = workspace / "skills" / "shared"
    target.mkdir(parents=True)
    home = tmp_path / "home"

    fingerprint = fingerprint_redacted_path(target, home_dir=home, workspace_dir=workspace)
    payload = json.dumps({"fingerprint": fingerprint})

    assert str(tmp_path) not in payload
    assert str(home) not in payload
    assert "workspace" in fingerprint or len(fingerprint) == 64


def test_inspect_valid_symlink_reports_source_hash(tmp_path: Path) -> None:
    workspace = tmp_path / "repo"
    shared = workspace / "shared-root"
    shared.mkdir(parents=True)
    (shared / "SKILL.md").write_text("name: shared\n", encoding="utf-8")
    link = workspace / "skills" / "linked"
    link.parent.mkdir(parents=True)
    link.symlink_to(shared, target_is_directory=True)

    inspection = inspect_aibom_source_path(
        link,
        safe_roots=(workspace,),
        home_dir=tmp_path / "home",
        workspace_dir=workspace,
    )

    assert inspection.link_kind == "symlink"
    assert inspection.validation_state == "valid"
    assert inspection.path_class == "workspace_relative"
    assert inspection.source_fingerprint
    assert inspection.target_content_hash


def test_inspect_broken_symlink_fails_closed(tmp_path: Path) -> None:
    workspace = tmp_path / "repo"
    workspace.mkdir()
    broken = workspace / "broken-link"
    broken.symlink_to(workspace / "missing-target")

    inspection = inspect_aibom_source_path(
        broken,
        safe_roots=(workspace,),
        home_dir=tmp_path / "home",
        workspace_dir=workspace,
    )

    assert inspection.validation_state == "broken"


def test_inspect_symlink_loop_fails_closed(tmp_path: Path) -> None:
    workspace = tmp_path / "repo"
    workspace.mkdir()
    loop_a = workspace / "loop-a"
    loop_b = workspace / "loop-b"
    loop_a.symlink_to(loop_b)
    loop_b.symlink_to(loop_a)

    inspection = inspect_aibom_source_path(
        loop_a,
        safe_roots=(workspace,),
        home_dir=tmp_path / "home",
        workspace_dir=workspace,
    )

    assert inspection.validation_state == "loop"


def test_inspect_escape_symlink_blocked(tmp_path: Path) -> None:
    workspace = tmp_path / "repo"
    workspace.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("outside\n", encoding="utf-8")
    escape = workspace / "escape-link"
    escape.symlink_to(outside)

    inspection = inspect_aibom_source_path(
        escape,
        safe_roots=(workspace,),
        home_dir=tmp_path / "home",
        workspace_dir=workspace,
    )

    assert inspection.validation_state == "escape_blocked"


def test_classify_workspace_relative_path(tmp_path: Path) -> None:
    workspace = tmp_path / "repo"
    workspace.mkdir()
    agents_md = workspace / "AGENTS.md"
    agents_md.write_text("policy\n", encoding="utf-8")

    assert classify_path_class(agents_md, home_dir=tmp_path / "home", workspace_dir=workspace) == "workspace_relative"


def test_inspection_serializes_without_raw_paths(tmp_path: Path) -> None:
    workspace = tmp_path / "repo"
    workspace.mkdir()
    target = workspace / "AGENTS.md"
    target.write_text("policy\n", encoding="utf-8")

    inspection = inspect_aibom_source_path(
        target,
        safe_roots=(workspace,),
        home_dir=tmp_path / "home",
        workspace_dir=workspace,
    )
    encoded = json.dumps(
        {
            "source_fingerprint": inspection.source_fingerprint,
            "path_class": inspection.path_class,
            "validation_state": inspection.validation_state,
            "redaction_summary": inspection.redaction_summary,
        }
    )

    assert str(tmp_path) not in encoded
    assert "policy" not in encoded


def test_inventory_snapshot_attaches_source_of_truth_for_symlink_items(tmp_path: Path) -> None:
    workspace = tmp_path / "repo"
    shared = workspace / "shared-root"
    shared.mkdir(parents=True)
    (shared / "SKILL.md").write_text("name: shared\n", encoding="utf-8")
    link = workspace / "skills" / "linked" / "SKILL.md"
    link.parent.mkdir(parents=True)
    link.symlink_to(shared / "SKILL.md")

    snapshot = inventory_snapshot_from_detection(
        HarnessDetection(
            harness="hermes",
            installed=True,
            command_available=False,
            config_paths=(),
            artifacts=(
                GuardArtifact(
                    artifact_id="hermes:skill:linked",
                    name="linked",
                    harness="hermes",
                    artifact_type="skill",
                    source_scope="project",
                    config_path=str(link),
                ),
            ),
        ),
        generated_at="2026-06-10T00:00:00Z",
        home_dir=tmp_path / "home",
        workspace_dir=workspace,
    )
    item = snapshot.items[0]
    source_of_truth = item.metadata.get("sourceOfTruth")
    assert isinstance(source_of_truth, dict)
    assert source_of_truth.get("validationState") == "valid"
    assert source_of_truth.get("linkKind") == "symlink"


def test_inventory_snapshot_emits_findings_for_broken_symlink_sources(tmp_path: Path) -> None:
    workspace = tmp_path / "repo"
    workspace.mkdir()
    broken = workspace / "broken-link"
    broken.symlink_to(workspace / "missing-target")

    snapshot = inventory_snapshot_from_detection(
        HarnessDetection(
            harness="codex",
            installed=True,
            command_available=False,
            config_paths=(),
            artifacts=(
                GuardArtifact(
                    artifact_id="codex:instruction:broken",
                    name="broken",
                    harness="codex",
                    artifact_type="instruction",
                    source_scope="project",
                    config_path=str(broken),
                ),
            ),
        ),
        generated_at="2026-06-10T00:00:00Z",
        home_dir=tmp_path / "home",
        workspace_dir=workspace,
    )

    assert any(finding.check_id == "aibom.symlink.broken" for finding in snapshot.findings)


def test_resolve_symlink_chain_returns_loop_when_hop_budget_is_exhausted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.aibom_symlink._MAX_SYMLINK_HOPS",
        2,
    )
    calls = {"count": 0}

    def fake_is_symlink(self: Path) -> bool:
        return True

    def fake_readlink(_path: str | Path) -> str:
        calls["count"] += 1
        return f"sibling-{calls['count']}"

    monkeypatch.setattr(Path, "is_symlink", fake_is_symlink)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.aibom_symlink.os.readlink",
        fake_readlink,
    )
    monkeypatch.setattr(Path, "resolve", lambda self: self)

    resolved, state, _ = _resolve_symlink_chain(
        Path("/workspace/entry"),
        safe_roots=(Path("/workspace"),),
        home_dir=Path("/home"),
        workspace_dir=Path("/workspace"),
    )

    assert resolved is None
    assert state == "loop"


def test_max_symlink_hop_budget_is_sixteen() -> None:
    assert _MAX_SYMLINK_HOPS == 16


def test_inspect_oversized_symlink_target_hashes_first_megabyte(tmp_path: Path) -> None:
    workspace = tmp_path / "repo"
    workspace.mkdir()
    home = tmp_path / "home"
    home.mkdir()
    oversized = workspace / "oversized-target.txt"
    oversized.write_bytes(b"x" * (1024 * 1024 + 1))
    link = workspace / "oversized-link"
    link.symlink_to(oversized)

    inspection = inspect_aibom_source_path(
        link,
        safe_roots=(workspace,),
        home_dir=home,
        workspace_dir=workspace,
    )

    assert inspection.validation_state == "valid"
    assert inspection.target_content_hash
