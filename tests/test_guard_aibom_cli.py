from __future__ import annotations

import json
from pathlib import Path

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.inventory_contract import inventory_snapshot_from_detection
from codex_plugin_scanner.guard.models import GuardArtifact, HarnessDetection
from codex_plugin_scanner.guard.store import GuardStore


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _build_codex_fixture(home_dir: Path, workspace_dir: Path) -> None:
    _write_text(
        home_dir / ".codex" / "config.toml",
        """
[mcp_servers.global_tools]
command = "python"
args = ["-m", "http.server", "9000"]
""".strip()
        + "\n",
    )
    _write_text(
        workspace_dir / ".codex" / "config.toml",
        """
[mcp_servers.workspace_skill]
command = "node"
args = ["workspace-skill.js"]
""".strip()
        + "\n",
    )


def _seed_inventory(store: GuardStore, artifact: GuardArtifact, *, now: str) -> None:
    store.record_inventory_artifact(
        artifact=artifact,
        artifact_hash="hash-1",
        policy_action="allow",
        changed=False,
        now=now,
        approved=True,
    )


def test_aibom_status_json_includes_layer_and_trust_summary(tmp_path: Path, capsys) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_codex_fixture(home_dir, workspace_dir)
    guard_home = tmp_path / "guard"
    store = GuardStore(guard_home)
    now = "2026-06-10T12:00:00+00:00"
    _seed_inventory(
        store,
        GuardArtifact(
            artifact_id="codex:global:global_tools",
            name="global_tools",
            harness="codex",
            artifact_type="mcp_server",
            source_scope="global",
            config_path=str(home_dir / ".codex" / "config.toml"),
        ),
        now=now,
    )

    rc = main(
        [
            "guard",
            "aibom",
            "status",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--guard-home",
            str(guard_home),
            "--json",
        ]
    )
    output = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert output["layer_summary"]["mcp"] >= 1
    assert "trust_summary" in output
    assert "redaction_report" in output
    assert output["redaction_report"]["rawValuesIncluded"] is False
    assert output["status"] in {"not_connected", "workspace_required", "sync_required", "synced"}


def test_inventory_json_includes_aibom_metadata_extensions(tmp_path: Path, capsys) -> None:
    workspace = tmp_path / "repo"
    shared = workspace / "shared-root"
    shared.mkdir(parents=True)
    (shared / "rule.mdc").write_text("---\ndescription: demo\n---\n", encoding="utf-8")
    rules_dir = workspace / ".cursor" / "rules"
    rules_dir.mkdir(parents=True)
    link = rules_dir / "demo.mdc"
    link.symlink_to(shared / "rule.mdc")
    home_dir = tmp_path / "home"
    guard_home = tmp_path / "guard"
    _build_codex_fixture(home_dir, workspace)
    store = GuardStore(guard_home)
    _seed_inventory(
        store,
        GuardArtifact(
            artifact_id="codex:global:global_tools",
            name="global_tools",
            harness="codex",
            artifact_type="mcp_server",
            source_scope="global",
            config_path=str(home_dir / ".codex" / "config.toml"),
        ),
        now="2026-06-10T12:00:00+00:00",
    )

    rc = main(
        [
            "guard",
            "inventory",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace),
            "--guard-home",
            str(guard_home),
            "--json",
        ]
    )
    encoded = capsys.readouterr().out
    output = json.loads(encoded)

    assert rc == 0
    assert str(tmp_path) not in encoded
    snapshot_metadata = [
        item.get("metadata", {})
        for snapshot in output.get("snapshots", [])
        if isinstance(snapshot, dict)
        for item in snapshot.get("items", [])
        if isinstance(item, dict)
    ]
    assert any(
        isinstance(metadata.get("sourceOfTruth"), dict) or isinstance(metadata.get("sourceLinks"), list)
        for metadata in snapshot_metadata
        if isinstance(metadata, dict)
    )
    assert output["redaction_report"]["rawValuesIncluded"] is False


def test_aibom_symlink_flags_control_source_metadata(tmp_path: Path) -> None:
    workspace = tmp_path / "repo"
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "SKILL.md").write_text("name: outside\n", encoding="utf-8")
    link = workspace / "skills" / "escaped" / "SKILL.md"
    link.parent.mkdir(parents=True)
    link.symlink_to(outside / "SKILL.md")
    detection = HarnessDetection(
        harness="codex",
        installed=True,
        command_available=False,
        config_paths=(),
        artifacts=(
            GuardArtifact(
                artifact_id="codex:skill:escaped",
                name="escaped",
                harness="codex",
                artifact_type="skill",
                source_scope="project",
                config_path=str(link),
            ),
        ),
    )

    with_symlinks = inventory_snapshot_from_detection(
        detection,
        generated_at="2026-06-10T12:00:00+00:00",
        home_dir=tmp_path / "home",
        workspace_dir=workspace,
        include_symlinks=True,
        follow_unsafe_symlinks=False,
    )
    without_symlinks = inventory_snapshot_from_detection(
        detection,
        generated_at="2026-06-10T12:00:00+00:00",
        home_dir=tmp_path / "home",
        workspace_dir=workspace,
        include_symlinks=False,
    )
    follow_unsafe = inventory_snapshot_from_detection(
        detection,
        generated_at="2026-06-10T12:00:00+00:00",
        home_dir=tmp_path / "home",
        workspace_dir=workspace,
        include_symlinks=True,
        follow_unsafe_symlinks=True,
    )

    with_metadata = with_symlinks.items[0].metadata.get("sourceOfTruth")
    without_metadata = without_symlinks.items[0].metadata.get("sourceOfTruth")
    follow_metadata = follow_unsafe.items[0].metadata.get("sourceOfTruth")

    assert isinstance(with_metadata, dict)
    assert with_metadata.get("validationState") == "escape_blocked"
    assert without_metadata is None
    assert isinstance(follow_metadata, dict)
    assert follow_metadata.get("validationState") == "valid"


def test_sync_aibom_snapshots_if_due_skips_recent_sync(tmp_path: Path, monkeypatch) -> None:
    from codex_plugin_scanner.guard.aibom_cli import sync_aibom_snapshots_if_due

    store = GuardStore(tmp_path / "guard")
    monkeypatch.setattr(store, "get_cloud_workspace_id", lambda: "workspace-1")
    now = "2026-06-10T13:00:00+00:00"
    store.set_sync_payload(
        "aibom_sync_summary",
        {"synced": True, "synced_at": "2026-06-10T12:30:00+00:00"},
        "2026-06-10T12:30:00+00:00",
    )

    summary = sync_aibom_snapshots_if_due(store, generated_at=now)

    assert summary.get("skipped") is True
    assert summary.get("reason") == "recently_synced"


def test_sync_aibom_snapshots_if_due_skips_recent_empty_sync(tmp_path: Path, monkeypatch) -> None:
    from codex_plugin_scanner.guard.aibom_cli import sync_aibom_snapshots_if_due

    store = GuardStore(tmp_path / "guard")
    monkeypatch.setattr(store, "get_cloud_workspace_id", lambda: "workspace-1")
    now = "2026-06-10T12:03:00+00:00"
    store.set_sync_payload(
        "aibom_sync_summary",
        {
            "synced": True,
            "synced_at": "2026-06-10T12:00:00+00:00",
            "snapshots": 0,
            "accepted": 0,
        },
        "2026-06-10T12:00:00+00:00",
    )

    summary = sync_aibom_snapshots_if_due(store, generated_at=now)

    assert summary.get("skipped") is True
    assert summary.get("reason") == "recently_synced"


def test_sync_aibom_snapshots_if_due_retries_empty_sync_after_interval(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from codex_plugin_scanner.guard import aibom_cli
    from codex_plugin_scanner.guard.aibom_cli import sync_aibom_snapshots_if_due

    store = GuardStore(tmp_path / "guard")
    monkeypatch.setattr(store, "get_cloud_workspace_id", lambda: "workspace-1")
    calls: list[str] = []

    def _fake_sync(*_args, **_kwargs):
        calls.append("sync")
        return {"synced": True, "synced_at": "2026-06-10T12:06:00+00:00", "snapshots": 1, "accepted": 1}

    monkeypatch.setattr(aibom_cli, "sync_aibom_snapshots", _fake_sync)
    store.set_sync_payload(
        "aibom_sync_summary",
        {
            "synced": True,
            "synced_at": "2026-06-10T12:00:00+00:00",
            "snapshots": 0,
            "accepted": 0,
        },
        "2026-06-10T12:00:00+00:00",
    )

    summary = sync_aibom_snapshots_if_due(store, generated_at="2026-06-10T12:06:00+00:00")

    assert calls == ["sync"]
    assert summary.get("synced") is True


def test_sync_aibom_snapshots_404_backoff_isolated_from_guard_events_summary(
    tmp_path: Path,
    monkeypatch,
) -> None:
    import urllib.error

    from codex_plugin_scanner.guard import aibom_cli
    from codex_plugin_scanner.guard.adapters.base import HarnessContext
    from codex_plugin_scanner.guard.aibom_cli import sync_aibom_snapshots
    from codex_plugin_scanner.guard.inventory_contract import GuardAgentInventorySnapshot
    from codex_plugin_scanner.guard.runtime import runner

    store = GuardStore(tmp_path / "guard")
    monkeypatch.setattr(store, "get_cloud_workspace_id", lambda: "workspace-1")
    store.set_sync_payload(
        "guard_events_v1_summary",
        {"synced_at": "2026-06-10T11:00:00+00:00", "events": 12, "accepted": 12},
        "2026-06-10T11:00:00+00:00",
    )
    snapshot = GuardAgentInventorySnapshot(
        snapshot_id="cursor-proof",
        agent_id="cursor:local",
        agent_type="cursor",
        generated_at="2026-06-10T12:00:00+00:00",
        runtime_version="test",
    )
    monkeypatch.setattr(aibom_cli, "collect_aibom_snapshots", lambda *_args, **_kwargs: (snapshot,))

    def _raise_404(*_args, **_kwargs):
        raise urllib.error.HTTPError(
            url="https://hol.test/api/v1/guard/events",
            code=404,
            msg="Not Found",
            hdrs=None,
            fp=None,
        )

    monkeypatch.setattr(runner, "_urlopen_json_with_timeout_retry", _raise_404)
    monkeypatch.setattr(runner, "_guard_events_sync_url", lambda url: url)
    monkeypatch.setattr(runner, "_guard_sync_request", lambda *_args, **_kwargs: object())

    summary = sync_aibom_snapshots(
        store,
        HarnessContext(home_dir=tmp_path / "home", workspace_dir=tmp_path / "workspace", guard_home=store.guard_home),
        generated_at="2026-06-10T12:00:00+00:00",
        auth_context={
            "sync_url": "https://hol.test/api/v1/guard/events",
            "token": "test-token",
        },
    )

    guard_events_summary = store.get_sync_payload("guard_events_v1_summary")
    aibom_backoff = store.get_sync_payload("aibom_guard_events_backoff")

    assert summary.get("reason") == "guard_events_endpoint_unavailable"
    assert isinstance(guard_events_summary, dict)
    assert guard_events_summary.get("events") == 12
    assert isinstance(aibom_backoff, dict)
    assert aibom_backoff.get("sync_reason") == "guard_events_endpoint_unavailable"


def test_aibom_export_json_includes_redaction_report(tmp_path: Path, capsys) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_codex_fixture(home_dir, workspace_dir)

    rc = main(
        [
            "guard",
            "aibom",
            "export",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--format",
            "json",
            "--json",
        ]
    )
    output = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert "layer_summary" in output
    assert "trust_summary" in output
    assert output["redaction_report"]["rawValuesIncluded"] is False
    assert "snapshots" in output
