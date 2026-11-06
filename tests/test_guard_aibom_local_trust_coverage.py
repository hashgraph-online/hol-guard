import json
from pathlib import Path

from codex_plugin_scanner.guard import aibom_cli as aibom_cli_module
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.aibom_cli import _artifact_rows_from_store
from codex_plugin_scanner.guard.inventory_contract import inventory_snapshot_from_detection
from codex_plugin_scanner.guard.models import GuardArtifact, HarnessDetection


class _FakeInventoryStore:
    def __init__(self, rows: list[dict[str, object]]) -> None:
        self._rows = rows

    def list_inventory(self) -> list[dict[str, object]]:
        return self._rows

    def get_oauth_local_credentials(self, *, allow_primary: bool = False) -> None:
        return None

    def get_or_create_installation_id(self) -> str:
        return "installation-1"

    def get_cloud_workspace_id(self) -> None:
        return None


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


def test_inventory_snapshot_keeps_parent_skill_trust_without_supplementary_skill_files(tmp_path: Path) -> None:
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
                    artifact_id="openclaw:skill:local:compress",
                    name="compress",
                    harness="openclaw",
                    artifact_type="skill",
                    source_scope="workspace",
                    config_path=str(skill_dir / "SKILL.md"),
                    metadata={"skill_dir": str(skill_dir)},
                ),
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

    skill_item = next(item for item in snapshot.items if item.metadata.get("artifactType") == "skill")
    skill_trust = skill_item.metadata.get("trustResolution")
    assert isinstance(skill_trust, dict)
    assert isinstance(skill_item.metadata.get("trustLayers"), list)
    assert skill_trust["trustComponents"]
    assert all(item.metadata.get("artifactType") != "skill_file" for item in snapshot.items)


def test_aibom_export_adds_parent_skill_trust_to_store_only_skill_files(tmp_path: Path) -> None:
    skill_dir = tmp_path / ".agents" / "skills" / "caveman-compress"
    script_path = skill_dir / "scripts" / "cli.py"
    script_path.parent.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(
        "---\nname: caveman-compress\ndescription: Compress memory files.\n---\n# Caveman Compress\n",
        encoding="utf-8",
    )
    script_path.write_text("print('compress')\n", encoding="utf-8")
    store = _FakeInventoryStore(
        [
            {
                "artifact_id": "openclaw:skill:local:caveman-compress:scripts/cli.py",
                "artifact_name": "caveman-compress/scripts/cli.py",
                "artifact_type": "skill_file",
                "config_path": str(script_path),
                "harness": "openclaw",
                "last_policy_action": None,
                "present": True,
                "source_scope": "skill-root:local",
            }
        ]
    )

    rows = _artifact_rows_from_store(
        store,
        (),
        context=HarnessContext(home_dir=tmp_path, workspace_dir=tmp_path, guard_home=tmp_path / ".guard"),
        generated_at="2026-06-10T00:00:00Z",
    )

    trust = rows[0].get("trustResolution")
    assert isinstance(trust, dict)
    assert isinstance(rows[0].get("trustLayers"), list)
    assert trust["trustComponents"]


def test_aibom_export_adds_trust_to_readme_marked_store_only_skill_files(tmp_path: Path) -> None:
    skill_dir = tmp_path / ".agents" / "skills" / "caveman-compress"
    script_path = skill_dir / "scripts" / "cli.py"
    script_path.parent.mkdir(parents=True)
    (skill_dir / "README.md").write_text("# Caveman Compress\n", encoding="utf-8")
    script_path.write_text("print('compress')\n", encoding="utf-8")
    store = _FakeInventoryStore(
        [
            {
                "artifact_id": "openclaw:skill:local:caveman-compress:scripts/cli.py",
                "artifact_name": "caveman-compress/scripts/cli.py",
                "artifact_type": "skill_file",
                "config_path": str(script_path),
                "harness": "openclaw",
                "last_policy_action": None,
                "present": True,
                "source_scope": "skill-root:local",
            }
        ]
    )

    rows = _artifact_rows_from_store(
        store,
        (),
        context=HarnessContext(home_dir=tmp_path, workspace_dir=tmp_path, guard_home=tmp_path / ".guard"),
        generated_at="2026-06-10T00:00:00Z",
    )

    trust = rows[0].get("trustResolution")
    assert isinstance(trust, dict)
    assert isinstance(rows[0].get("trustLayers"), list)


def test_aibom_export_does_not_use_unrelated_skills_ancestor_as_skill_root(tmp_path: Path) -> None:
    utility_root = tmp_path / ".agents" / "skills" / "utilities"
    skill_dir = utility_root / "caveman-compress"
    script_path = skill_dir / "scripts" / "cli.py"
    script_path.parent.mkdir(parents=True)
    (utility_root / "README.md").write_text("# Utilities\n", encoding="utf-8")
    script_path.write_text("print('compress')\n", encoding="utf-8")
    store = _FakeInventoryStore(
        [
            {
                "artifact_id": "openclaw:skill:local:caveman-compress:scripts/cli.py",
                "artifact_name": "caveman-compress/scripts/cli.py",
                "artifact_type": "skill_file",
                "config_path": str(script_path),
                "harness": "openclaw",
                "last_policy_action": None,
                "present": True,
                "source_scope": "skill-root:local",
            }
        ]
    )

    rows = _artifact_rows_from_store(
        store,
        (),
        context=HarnessContext(home_dir=tmp_path, workspace_dir=tmp_path, guard_home=tmp_path / ".guard"),
        generated_at="2026-06-10T00:00:00Z",
    )

    assert rows[0]["present"] is True
    assert "trustResolution" not in rows[0]


def test_aibom_export_marks_missing_store_only_skill_files_not_present(tmp_path: Path) -> None:
    store = _FakeInventoryStore(
        [
            {
                "artifact_id": "openclaw:skill:local:missing:references/example.md",
                "artifact_name": "missing/references/example.md",
                "artifact_type": "skill_file",
                "config_path": str(tmp_path / ".agents" / "skills" / "missing" / "references" / "example.md"),
                "harness": "openclaw",
                "last_policy_action": None,
                "present": True,
                "source_scope": "skill-root:local",
            }
        ]
    )

    rows = _artifact_rows_from_store(
        store,
        (),
        context=HarnessContext(home_dir=tmp_path, workspace_dir=tmp_path, guard_home=tmp_path / ".guard"),
        generated_at="2026-06-10T00:00:00Z",
    )

    assert rows[0]["present"] is False
    assert "trustResolution" not in rows[0]


def test_inventory_json_payload_enriches_store_only_skill_files(tmp_path: Path, monkeypatch) -> None:
    skill_dir = tmp_path / ".agents" / "skills" / "caveman-compress"
    script_path = skill_dir / "scripts" / "cli.py"
    script_path.parent.mkdir(parents=True)
    (skill_dir / "README.md").write_text("# Caveman Compress\n", encoding="utf-8")
    script_path.write_text("print('compress')\n", encoding="utf-8")
    store = _FakeInventoryStore(
        [
            {
                "artifact_id": "openclaw:skill:local:caveman-compress:scripts/cli.py",
                "artifact_name": "caveman-compress/scripts/cli.py",
                "artifact_type": "skill_file",
                "config_path": str(script_path),
                "harness": "openclaw",
                "last_policy_action": None,
                "present": True,
                "source_scope": "skill-root:local",
            }
        ]
    )
    monkeypatch.setattr(aibom_cli_module, "collect_aibom_snapshots", lambda *args, **kwargs: ())

    payload = aibom_cli_module.build_inventory_json_payload(
        store,
        HarnessContext(home_dir=tmp_path, workspace_dir=tmp_path, guard_home=tmp_path / ".guard"),
        generated_at="2026-06-10T00:00:00Z",
    )

    items = payload["items"]
    assert isinstance(items, list)
    item = items[0]
    assert isinstance(item, dict)
    assert item["present"] is True
    assert isinstance(item.get("trustResolution"), dict)
    assert isinstance(item.get("trustLayers"), list)
