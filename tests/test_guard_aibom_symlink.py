from __future__ import annotations

import json
from pathlib import Path

from codex_plugin_scanner.guard.aibom_symlink import (
    classify_path_class,
    fingerprint_redacted_path,
    inspect_aibom_source_path,
)
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

    assert (
        classify_path_class(agents_md, home_dir=tmp_path / "home", workspace_dir=workspace)
        == "workspace_relative"
    )


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
