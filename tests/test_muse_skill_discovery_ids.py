"""Muse skill discovery issues must sync to Guard Cloud with distinct, path-free IDs."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.muse import MuseHarnessAdapter
from codex_plugin_scanner.guard.inventory_contract import (
    inventory_snapshot_from_detection,
    serialize_inventory_snapshot,
)


def test_skill_discovery_issues_sync_with_distinct_path_free_ids(tmp_path: Path) -> None:
    ctx = HarnessContext(home_dir=tmp_path / "home", workspace_dir=None, guard_home=tmp_path / "guard-home")
    target = ctx.home_dir / "linked-skills" / "review"
    target.mkdir(parents=True)
    (target / "SKILL.md").write_text("# Review\n", encoding="utf-8")
    roots = (ctx.home_dir / ".config" / "muse" / "skills", ctx.home_dir / ".agents" / "skills")
    for root in roots:
        root.mkdir(parents=True)
        try:
            (root / "review").symlink_to(target, target_is_directory=True)
        except (NotImplementedError, OSError) as exc:
            pytest.skip(f"symlink creation unavailable: {exc}")

    result = MuseHarnessAdapter().detect(ctx)
    issues = [a for a in result.artifacts if ":skill-discovery:" in a.artifact_id]
    assert len(issues) == 2
    assert all(str(tmp_path) not in a.artifact_id for a in issues)

    snapshot = serialize_inventory_snapshot(
        inventory_snapshot_from_detection(result, home_dir=ctx.home_dir, generated_at="2026-11-03T00:00:00Z")
    )
    items = snapshot["items"]
    assert isinstance(items, list)
    item_ids = [item["itemId"] for item in items]
    assert len(item_ids) == len(set(item_ids))
    assert "[REDACTED]" not in item_ids
