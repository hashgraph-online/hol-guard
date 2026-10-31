"""Cursor's per-workspace working files for the benign gate.

Cursor keeps background shell output, spilled tool output and MCP tool
descriptions under ``~/.cursor/projects/<workspace slug>/``, where the slug is
the workspace path with every non-alphanumeric character spelled ``-``. The
gate reads them back from the session workspace and, as negative controls,
from another workspace's directory and from Cursor's MCP auth store.
"""

from __future__ import annotations

import re
from pathlib import Path

OTHER_WORKSPACE_SLUG = "srv-billing-api"
_LEAVES = (
    "terminals/120467.txt",
    "agent-tools/0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d.txt",
    "mcps/docs-server/INSTRUCTIONS.md",
    "mcps/docs-server/tools/search_docs.json",
    "agent-transcripts/5d0c3b9e-7a41-4c1f-9b2e-0f6a8d4c2e71/compaction/INDEX.md",
)


def cursor_project_path(home: Path, workspace: Path) -> Path:
    """The directory Cursor names after ``workspace``."""
    slug = re.sub(r"[^A-Za-z0-9]", "-", str(workspace)).lstrip("-")
    return home / ".cursor" / "projects" / slug


def write_cursor_projects(home: Path, workspace: Path) -> None:
    """Build the session workspace's project directory and another workspace's."""
    for project in (cursor_project_path(home, workspace), home / ".cursor" / "projects" / OTHER_WORKSPACE_SLUG):
        for leaf in _LEAVES:
            path = project / leaf
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"# {path.name}\nSynthetic Cursor output.\n", encoding="utf-8")
        (project / "mcp-auth.json").write_text('{"servers": {}}\n', encoding="utf-8")
    skill = home / ".cursor" / "skills-cursor" / "create-rule" / "SKILL.md"
    skill.parent.mkdir(parents=True, exist_ok=True)
    skill.write_text("# create-rule\nSynthetic Cursor skill.\n", encoding="utf-8")
