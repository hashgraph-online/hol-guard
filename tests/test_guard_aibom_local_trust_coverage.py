import json
from pathlib import Path

from codex_plugin_scanner.guard.inventory_contract import inventory_snapshot_from_detection
from codex_plugin_scanner.guard.models import GuardArtifact, HarnessDetection


def test_inventory_snapshot_adds_local_trust_to_hooks(tmp_path: Path) -> None:
    workspace = tmp_path / "repo"
    workspace.mkdir()
    hook_config = workspace / ".claude" / "settings.json"
    hook_config.parent.mkdir(parents=True)
    hook_config.write_text(
        json.dumps(
            {
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": "Bash",
                            "hooks": [{"type": "command", "command": "python3 guard.py"}],
                        }
                    ]
                }
            }
        ),
        encoding="utf-8",
    )

    snapshot = inventory_snapshot_from_detection(
        HarnessDetection(
            harness="claude-code",
            installed=True,
            command_available=True,
            config_paths=(str(hook_config),),
            artifacts=(
                GuardArtifact(
                    artifact_id="claude-code:project:pretooluse:0:0",
                    name="PreToolUse",
                    harness="claude-code",
                    artifact_type="hook",
                    source_scope="project",
                    config_path=str(hook_config),
                    command="python3 guard.py",
                    metadata={"matcher": "Bash", "type": "command"},
                ),
            ),
        ),
        generated_at="2026-06-10T00:00:00Z",
        home_dir=tmp_path,
        workspace_dir=workspace,
    )

    hook_item = next(item for item in snapshot.items if item.item_kind == "hook")
    hook_trust = hook_item.metadata.get("trustResolution")
    assert isinstance(hook_trust, dict)
    assert isinstance(hook_item.metadata.get("trustLayers"), list)
    assert hook_trust["trustComponents"]


def test_inventory_snapshot_adds_parent_skill_trust_to_skill_files(tmp_path: Path) -> None:
    workspace = tmp_path / "repo"
    workspace.mkdir()
    skill_dir = workspace / "skills" / "compress"
    script_path = skill_dir / "scripts" / "cli.py"
    script_path.parent.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(
        "---\nname: compress\ndescription: Compress memory files.\n---\n# Compress\nDo not read secrets.\n",
        encoding="utf-8",
    )
    script_path.write_text("print('compress')\n", encoding="utf-8")

    snapshot = inventory_snapshot_from_detection(
        HarnessDetection(
            harness="openclaw",
            installed=True,
            command_available=True,
            config_paths=(str(skill_dir / "SKILL.md"),),
            artifacts=(
                GuardArtifact(
                    artifact_id="openclaw:skill:local:compress:scripts/cli.py",
                    name="compress/scripts/cli.py",
                    harness="openclaw",
                    artifact_type="skill_file",
                    source_scope="workspace",
                    config_path=str(script_path),
                    command=str(script_path),
                    metadata={"parent_skill": "compress"},
                ),
            ),
        ),
        generated_at="2026-06-10T00:00:00Z",
        home_dir=tmp_path,
        workspace_dir=workspace,
    )

    skill_file_item = next(item for item in snapshot.items if item.metadata.get("artifactType") == "skill_file")
    skill_file_trust = skill_file_item.metadata.get("trustResolution")
    assert isinstance(skill_file_trust, dict)
    assert isinstance(skill_file_item.metadata.get("trustLayers"), list)
    assert skill_file_trust["trustComponents"]
