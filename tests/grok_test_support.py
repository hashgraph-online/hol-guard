"""Shared Grok adapter fixtures."""

import json
from pathlib import Path

from codex_plugin_scanner.guard.adapters.base import HarnessContext


def _ctx(tmp_path: Path, *, workspace: bool = False) -> HarnessContext:
    workspace_dir = tmp_path / "workspace" if workspace else None
    if workspace_dir is not None:
        workspace_dir.mkdir(parents=True, exist_ok=True)
    return HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=workspace_dir,
        guard_home=tmp_path / "guard-home",
    )


def _fixture(name: str) -> dict[str, object]:
    payload = json.loads((Path(__file__).parent / "fixtures" / "grok" / name).read_text(encoding="utf-8"))
    return payload if isinstance(payload, dict) else {}
