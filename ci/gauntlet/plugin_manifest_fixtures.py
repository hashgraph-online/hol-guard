"""A plugin manifest the agent edits in a checkout of its own project under ``/tmp``.

A repository that ships an agent plugin keeps its manifest in a hidden
``.claude-plugin`` or ``.codex-plugin`` directory. Agents add a worktree of the
project straight in ``/tmp``, outside the home directory, and edit the manifest
there with the harness's own read and edit tools. The manifest is committed so
the worktree the agent adds holds it.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

PLUGIN_MANIFEST_CASE = "omp-native-edit-tmp-worktree-plugin-manifest"
PLUGIN_MANIFEST = "integrations/app/.claude-plugin/plugin.json"
PLUGIN_MANIFEST_TEXT = '{\n  "name": "app",\n  "author": "Example"\n}\n'
PLUGIN_MANIFEST_CHECK = "plugin-manifest-author-edited"


def stage_plugin_manifest(workspace: Path, home: Path | None, scenario_id: str) -> None:
    """Commit the manifest to the branch the agent works on."""
    if scenario_id != PLUGIN_MANIFEST_CASE or home is None:
        return
    target = workspace / PLUGIN_MANIFEST
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    target.write_text(PLUGIN_MANIFEST_TEXT, encoding="utf-8", newline="\n")
    environment = {k: os.environ[k] for k in ("PATH", "SYSTEMROOT", "WINDIR") if k in os.environ}
    environment.update(HOME=str(home), USERPROFILE=str(home), GIT_CONFIG_NOSYSTEM="1")
    for args in (
        ("add", "--", PLUGIN_MANIFEST),
        ("-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "Add plugin manifest"),
    ):
        subprocess.run(
            ["git", "-C", str(workspace), *args], env=environment, check=True, capture_output=True, timeout=15
        )


def plugin_manifest_checks(home: Path, workspace: Path, scenario_id: str) -> dict[str, bool]:
    """The manifest in the agent's ``/tmp`` checkout must now name the new author.

    The prompt names the author it asks for, so the edit is proven from the
    file's bytes rather than the model's closing sentence. The copy in the
    checkout the agent started in must be untouched: the edit belongs in the
    ``/tmp`` checkout. That starting checkout is the fixture's workspace, which
    a realistic fixture puts in a linked worktree beside ``home/project``, so
    the manifest is committed there and only there.
    """
    if scenario_id != PLUGIN_MANIFEST_CASE:
        return {}
    from .fixtures import scratch_checkout  # deferred: fixtures imports script_cases, which imports this module

    fixture_root = home.parent
    try:
        edited = (scratch_checkout(fixture_root) / PLUGIN_MANIFEST).read_text(encoding="utf-8")
        original = (workspace / PLUGIN_MANIFEST).read_text(encoding="utf-8")
    except OSError:
        return {PLUGIN_MANIFEST_CHECK: False}
    return {
        PLUGIN_MANIFEST_CHECK: edited == PLUGIN_MANIFEST_TEXT.replace('"Example"', '"Sample"')
        and original == PLUGIN_MANIFEST_TEXT
    }
