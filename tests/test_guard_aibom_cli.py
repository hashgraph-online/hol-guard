from __future__ import annotations

import argparse
import base64
import json
from email.message import Message
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard import aibom_cli
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.cli import commands_dispatch_records as dispatch
from codex_plugin_scanner.guard.inventory_cisco import CiscoInventoryRun
from codex_plugin_scanner.guard.inventory_contract import GuardAgentInventorySnapshot, inventory_snapshot_from_detection
from codex_plugin_scanner.guard.models import GuardArtifact, HarnessDetection
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.version import __version__


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


@pytest.mark.parametrize("content_status", ["accepted", "missing_endpoint"])
def test_sync_uploads_exact_primary_hermes_content_after_legacy_ack(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    content_status: str,
) -> None:
    import urllib.error

    from codex_plugin_scanner.guard.adapters.hermes import HermesHarnessAdapter
    from codex_plugin_scanner.guard.runtime import runner

    home = tmp_path / "home"
    workspace = tmp_path / "workspace"
    skill_body = b"---\nname: deploy\n---\n# Deploy\n"
    instruction_body = b"# Workspace instructions\n"
    skill_dir = home / ".hermes" / "skills" / "dev" / "deploy"
    _write_text(skill_dir / "SKILL.md", skill_body.decode())
    _write_text(skill_dir / "references" / "agent_install_commands.md", "Supplementary notes.\n")
    _write_text(workspace / "AGENTS.md", instruction_body.decode())
    context = HarnessContext(home_dir=home, workspace_dir=workspace, guard_home=tmp_path / "guard")
    store = GuardStore(context.guard_home)
    monkeypatch.setattr(store, "get_cloud_workspace_id", lambda: "workspace-1")
    monkeypatch.setenv("GUARD_AIBOM_TRUST_ATTESTATION_V2", "0")
    monkeypatch.setattr(
        aibom_cli,
        "detect_all",
        lambda _context: (HermesHarnessAdapter().detect(context),),
    )
    requests: list[SimpleNamespace] = []

    def guard_sync_request(_auth_context, *, request_url, method, data, extra_headers):
        request = SimpleNamespace(data=data, full_url=request_url, method=method)
        requests.append(request)
        assert extra_headers is None
        return request

    def respond(*, request, **_kwargs):
        if request.full_url.endswith("/api/v1/guard/events"):
            # Older compatible portals may report aggregate acceptance without statuses.
            return {"accepted": 1, "rejected": 0}
        if content_status == "missing_endpoint":
            raise urllib.error.HTTPError(
                url=request.full_url,
                code=404,
                msg="Not Found",
                hdrs=Message(),
                fp=None,
            )
        payload = json.loads(request.data)
        return {
            "storedCount": len(payload["items"]),
            "hashOnlyCount": 0,
            "failedCount": 0,
        }

    monkeypatch.setattr(runner, "_guard_events_sync_url", lambda url: url)
    monkeypatch.setattr(runner, "_guard_sync_request", guard_sync_request)
    monkeypatch.setattr(runner, "_urlopen_json_with_timeout_retry", respond)

    summary = aibom_cli.sync_aibom_snapshots(
        store,
        context,
        generated_at="2026-07-10T00:00:00+00:00",
        auth_context={"sync_url": "https://hol.test/api/v1/guard/events"},
    )

    assert summary["synced"] is (content_status == "accepted")
    upload_summary = summary["content_upload"]
    assert isinstance(upload_summary, dict)
    assert upload_summary["eligible"] == 2
    content_requests = [request for request in requests if request.full_url.endswith("/content-upload")]
    assert len(content_requests) == 1
    if content_status == "missing_endpoint":
        assert summary["synced"] is False
        assert summary["partial"] is True
        assert summary["reason"] == "content_upload_incomplete"
        assert summary["content_upload_complete"] is False
        assert upload_summary["failed"] == 2
        assert upload_summary["reason"] == "endpoint_unavailable"
        return

    assert summary["content_upload_complete"] is True
    assert upload_summary["uploaded"] == 2
    assert upload_summary["stored"] == 2
    assert upload_summary["hash_only"] == 0
    content_payload = json.loads(content_requests[0].data)
    assert set(content_payload) == {"items"}
    uploaded_bodies = {base64.b64decode(item["bodyBase64"]) for item in content_payload["items"]}
    assert uploaded_bodies == {skill_body, instruction_body}
    assert all(str(item["contentHash"]).startswith("sha256:") for item in content_payload["items"])


def test_aibom_status_json_includes_layer_and_trust_summary(
    tmp_path: Path, capsys, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GUARD_AIBOM_TRUST_ATTESTATION_V2", "0")
    monkeypatch.delenv("GUARD_AIBOM_TRUST_ATTESTATION_PRIVATE_KEY", raising=False)
    monkeypatch.delenv("GUARD_AIBOM_TRUST_ATTESTATION_KEY_ID", raising=False)
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


def test_inventory_json_includes_aibom_metadata_extensions(
    tmp_path: Path, capsys, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GUARD_AIBOM_TRUST_ATTESTATION_V2", "0")
    monkeypatch.delenv("GUARD_AIBOM_TRUST_ATTESTATION_PRIVATE_KEY", raising=False)
    monkeypatch.delenv("GUARD_AIBOM_TRUST_ATTESTATION_KEY_ID", raising=False)
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
        {"synced": True, "synced_at": "2026-06-10T12:55:00+00:00"},
        "2026-06-10T12:55:00+00:00",
    )

    summary = sync_aibom_snapshots_if_due(store, generated_at=now)

    assert summary.get("skipped") is True
    assert summary.get("reason") == "recently_synced"


def test_sync_aibom_snapshots_if_due_rejects_changed_workspace(tmp_path: Path, monkeypatch) -> None:
    from codex_plugin_scanner.guard.aibom_cli import sync_aibom_snapshots_if_due

    store = GuardStore(tmp_path / "guard")
    monkeypatch.setattr(store, "get_cloud_workspace_id", lambda: "workspace-beta")

    summary = sync_aibom_snapshots_if_due(
        store,
        generated_at="2026-06-10T13:00:00+00:00",
        expected_workspace_id="workspace-alpha",
    )

    assert summary == {
        "synced": False,
        "reason": "workspace_changed",
        "error": "Guard Cloud workspace changed before AIBOM inventory sync.",
    }


def test_sync_aibom_snapshots_if_due_binds_current_workspace(tmp_path: Path, monkeypatch) -> None:
    from codex_plugin_scanner.guard import aibom_cli

    store = GuardStore(tmp_path / "guard")
    monkeypatch.setattr(store, "get_cloud_workspace_id", lambda: "workspace-alpha")
    calls: list[dict[str, object]] = []

    def _fake_sync(*_args: object, **kwargs: object) -> dict[str, object]:
        calls.append(kwargs)
        return {"synced": True}

    monkeypatch.setattr(aibom_cli, "sync_aibom_snapshots", _fake_sync)

    summary = aibom_cli.sync_aibom_snapshots_if_due(
        store,
        generated_at="2026-06-10T13:00:00+00:00",
        force=True,
    )

    assert summary == {"synced": True}
    assert calls[0]["expected_workspace_id"] == "workspace-alpha"


def test_sync_aibom_snapshots_if_due_skips_recent_empty_sync(tmp_path: Path, monkeypatch) -> None:
    from codex_plugin_scanner.guard.aibom_cli import sync_aibom_snapshots_if_due

    store = GuardStore(tmp_path / "guard")
    monkeypatch.setattr(store, "get_cloud_workspace_id", lambda: "workspace-1")
    now = "2026-06-10T12:03:00+00:00"
    store.set_sync_payload(
        "aibom_sync_summary",
        {
            "synced": True,
            "synced_at": "2026-06-10T12:02:30+00:00",
            "snapshots": 0,
            "accepted": 0,
        },
        "2026-06-10T12:02:30+00:00",
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


def test_sync_aibom_snapshots_if_due_force_bypasses_recent_sync(
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
        return {"synced": True, "synced_at": "2026-06-10T12:56:00+00:00", "snapshots": 1, "accepted": 1}

    monkeypatch.setattr(aibom_cli, "sync_aibom_snapshots", _fake_sync)
    store.set_sync_payload(
        "aibom_sync_summary",
        {"synced": True, "synced_at": "2026-06-10T12:55:00+00:00"},
        "2026-06-10T12:55:00+00:00",
    )

    summary = sync_aibom_snapshots_if_due(
        store,
        generated_at="2026-06-10T12:56:00+00:00",
        force=True,
    )

    assert calls == ["sync"]
    assert summary.get("synced") is True


def test_inventory_snapshot_event_includes_device_id() -> None:
    snapshot = GuardAgentInventorySnapshot(
        snapshot_id="snapshot-aibom-1",
        agent_id="codex:local",
        agent_type="codex",
        generated_at="2026-06-10T12:00:00+00:00",
        runtime_version="test",
    )

    event = aibom_cli._inventory_snapshot_event(
        snapshot=snapshot,
        workspace_id="workspace-1",
        device_id="device-1",
        generated_at="2026-06-10T12:00:00+00:00",
    )

    assert event["deviceId"] == "device-1"


def test_resolve_trust_attestation_context_defaults_to_v1(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard")
    monkeypatch.setattr(store, "get_cloud_workspace_id", lambda: "workspace-1")
    monkeypatch.setattr(store, "get_or_create_installation_id", lambda: "device-1")
    monkeypatch.delenv("GUARD_AIBOM_TRUST_ATTESTATION_V2", raising=False)
    monkeypatch.setenv("GUARD_AIBOM_TRUST_ATTESTATION_V2", "0")

    context = aibom_cli._resolve_trust_attestation_context(
        store,
        generated_at="2026-06-10T12:00:00+00:00",
    )

    assert context["analyzerId"] is None
    assert context["analyzerSpecVersion"] is None
    assert context["analyzerVersion"] is None
    assert context["policyVersion"] is None
    assert context["workspaceId"] is None
    assert context["deviceId"] is None


def test_resolve_trust_attestation_context_includes_workspace_device_for_v2(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    store = GuardStore(tmp_path / "guard")
    monkeypatch.setattr(store, "get_cloud_workspace_id", lambda: "workspace-1")
    monkeypatch.setattr(store, "get_or_create_installation_id", lambda: "device-1")
    monkeypatch.setenv("GUARD_AIBOM_TRUST_ATTESTATION_V2", "1")

    context = aibom_cli._resolve_trust_attestation_context(
        store,
        generated_at="2026-06-10T12:00:00+00:00",
    )

    assert context["workspaceId"] == "workspace-1"
    assert context["deviceId"] == "device-1"
    assert context["analyzerId"] == "hol-guard"
    assert context["analyzerSpecVersion"] == "guard-aibom-trust-spec.v1"
    assert context["analyzerVersion"] == __version__
    assert context["installationId"] == "device-1"
    assert context["policyVersion"] == "guard-aibom-trust-policy.v1"
    assert context["uploadId"] is None


def test_resolve_trust_attestation_context_uses_workspace_override(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    store = GuardStore(tmp_path / "guard")
    monkeypatch.setattr(store, "get_cloud_workspace_id", lambda: "workspace-beta")
    monkeypatch.setattr(store, "get_or_create_installation_id", lambda: "device-1")
    monkeypatch.setenv("GUARD_AIBOM_TRUST_ATTESTATION_V2", "1")

    context = aibom_cli._resolve_trust_attestation_context(
        store,
        generated_at="2026-06-10T12:00:00+00:00",
        workspace_id="workspace-alpha",
    )

    assert context["workspaceId"] == "workspace-alpha"
    assert context["challengeId"] is None
    assert context["nonce"] is None
    assert context["sequence"] is None
    assert context["expiresAt"] is None


def test_resolve_trust_attestation_context_includes_upload_session_bindings_for_sync(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    store = GuardStore(tmp_path / "guard")
    monkeypatch.setattr(store, "get_cloud_workspace_id", lambda: "workspace-1")
    monkeypatch.setattr(store, "get_or_create_installation_id", lambda: "device-1")
    monkeypatch.setenv("GUARD_AIBOM_TRUST_ATTESTATION_V2", "1")

    context = aibom_cli._resolve_trust_attestation_context(
        store,
        generated_at="2026-06-10T12:00:00+00:00",
        include_upload_session_bindings=True,
    )

    assert context["analyzerId"] == "hol-guard"
    assert context["analyzerSpecVersion"] == "guard-aibom-trust-spec.v1"
    assert context["analyzerVersion"] == __version__
    assert context["policyVersion"] == "guard-aibom-trust-policy.v1"
    assert isinstance(context["uploadId"], str) and context["uploadId"].startswith("guard-aibom-upload-")
    assert isinstance(context["challengeId"], str) and context["challengeId"].startswith("guard-aibom-challenge-")
    assert isinstance(context["nonce"], str) and context["nonce"]
    assert context["sequence"] == 1
    assert context["expiresAt"] == "2026-06-10T12:15:00Z"

    second_context = aibom_cli._resolve_trust_attestation_context(
        store,
        generated_at="2026-06-10T12:05:00+00:00",
        include_upload_session_bindings=True,
    )

    assert second_context["sequence"] == 2


def test_resolve_trust_attestation_context_tolerates_invalid_generated_at_for_sync(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    store = GuardStore(tmp_path / "guard")
    monkeypatch.setattr(store, "get_cloud_workspace_id", lambda: "workspace-1")
    monkeypatch.setattr(store, "get_or_create_installation_id", lambda: "device-1")
    monkeypatch.setenv("GUARD_AIBOM_TRUST_ATTESTATION_V2", "1")

    context = aibom_cli._resolve_trust_attestation_context(
        store,
        generated_at="not-a-timestamp",
        include_upload_session_bindings=True,
    )

    assert context["expiresAt"] is None
    assert context["sequence"] == 1


def test_trust_attestation_v2_enabled_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard.runtime.trust_attestation import trust_attestation_v2_enabled

    monkeypatch.delenv("GUARD_AIBOM_TRUST_ATTESTATION_V2", raising=False)
    assert trust_attestation_v2_enabled() is True


def test_trust_attestation_v2_can_be_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard.runtime.trust_attestation import trust_attestation_v2_enabled

    monkeypatch.setenv("GUARD_AIBOM_TRUST_ATTESTATION_V2", "0")
    assert trust_attestation_v2_enabled() is False


def test_resolve_trust_attestation_context_auto_generates_persistent_key(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from codex_plugin_scanner.guard.runtime.trust_attestation import (
        resolve_trust_attestation_signing_config,
    )

    guard_home = tmp_path / "guard"
    guard_home.mkdir(parents=True, exist_ok=True)
    key_path = guard_home / "trust_attestation_key.pem"
    assert not key_path.exists()

    config = resolve_trust_attestation_signing_config(guard_home=guard_home)
    assert config is not None
    assert key_path.exists()
    assert config.signature_algorithm == "ecdsa-p256-sha256"

    # Second call loads the same key
    config2 = resolve_trust_attestation_signing_config(guard_home=guard_home)
    assert config2 is not None
    assert config2.private_key_pem == config.private_key_pem


def test_env_private_key_overrides_persistent_key(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization

    from codex_plugin_scanner.guard.runtime.trust_attestation import (
        resolve_trust_attestation_signing_config,
    )

    guard_home = tmp_path / "guard"
    guard_home.mkdir(parents=True, exist_ok=True)

    # Generate a separate key for env var
    env_key = ec.generate_private_key(ec.SECP256R1())
    env_key_pem = env_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    monkeypatch.setenv("GUARD_AIBOM_TRUST_ATTESTATION_PRIVATE_KEY", env_key_pem)
    monkeypatch.setenv("GUARD_AIBOM_TRUST_ATTESTATION_KEY_ID", "env-key-1")

    config = resolve_trust_attestation_signing_config(guard_home=guard_home)
    assert config is not None
    assert config.active_key_id == "env-key-1"
    assert config.private_key_pem == env_key_pem.strip()
    # Persistent key file should NOT be created when env var is set
    assert not (guard_home / "trust_attestation_key.pem").exists()


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
            hdrs=Message(),
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


def test_sync_aibom_snapshots_404_reports_only_remaining_batch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import urllib.error

    from codex_plugin_scanner.guard import aibom_cli
    from codex_plugin_scanner.guard.adapters.base import HarnessContext
    from codex_plugin_scanner.guard.aibom_cli import sync_aibom_snapshots
    from codex_plugin_scanner.guard.inventory_contract import GuardAgentInventorySnapshot
    from codex_plugin_scanner.guard.runtime import runner

    store = GuardStore(tmp_path / "guard")
    monkeypatch.setattr(store, "get_cloud_workspace_id", lambda: "workspace-1")
    snapshots = tuple(
        GuardAgentInventorySnapshot(
            snapshot_id=f"snapshot-{index}",
            agent_id=f"agent-{index}",
            agent_type="codex",
            generated_at="2026-06-10T12:00:00+00:00",
            runtime_version="test",
        )
        for index in range(4)
    )
    monkeypatch.setattr(aibom_cli, "collect_aibom_snapshots", lambda *_args, **_kwargs: snapshots)
    responses: list[dict[str, object] | Exception] = [
        {
            "accepted": 3,
            "rejected": 0,
            "statuses": [{"eventId": f"event-{index}", "status": "accepted"} for index in range(3)],
            "syncedAt": "2026-06-10T12:00:01+00:00",
        },
        urllib.error.HTTPError(
            url="https://hol.test/api/v1/guard/events",
            code=404,
            msg="Not Found",
            hdrs=Message(),
            fp=None,
        ),
    ]

    def respond(*_args, **_kwargs):
        response = responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response

    monkeypatch.setattr(runner, "_urlopen_json_with_timeout_retry", respond)
    monkeypatch.setattr(runner, "_guard_events_sync_url", lambda url: url)
    monkeypatch.setattr(runner, "_guard_sync_request", lambda *_args, **_kwargs: object())

    summary = sync_aibom_snapshots(
        store,
        HarnessContext(
            home_dir=tmp_path / "home",
            workspace_dir=tmp_path / "workspace",
            guard_home=store.guard_home,
        ),
        generated_at="2026-06-10T12:00:00+00:00",
        auth_context={
            "sync_url": "https://hol.test/api/v1/guard/events",
            "token": "test-token",
        },
    )

    backoff = store.get_sync_payload("aibom_guard_events_backoff")
    assert summary.get("synced") is False
    assert summary.get("partial") is True
    assert summary.get("accepted") == 3
    assert summary.get("statuses") == [{"eventId": f"event-{index}", "status": "accepted"} for index in range(3)]
    assert isinstance(backoff, dict)
    assert backoff.get("events") == 1
    assert backoff.get("skipped") == 1
    assert backoff.get("accepted") == 3
    assert responses == []


def test_sync_aibom_snapshots_skips_oversized_snapshot_and_syncs_valid_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from codex_plugin_scanner.guard import aibom_cli
    from codex_plugin_scanner.guard.adapters.base import HarnessContext
    from codex_plugin_scanner.guard.aibom_cli import sync_aibom_snapshots
    from codex_plugin_scanner.guard.inventory_contract import GuardAgentInventorySnapshot
    from codex_plugin_scanner.guard.runtime import runner

    store = GuardStore(tmp_path / "guard")
    monkeypatch.setattr(store, "get_cloud_workspace_id", lambda: "workspace-1")
    snapshots = (
        GuardAgentInventorySnapshot(
            snapshot_id="codex:valid",
            agent_id="codex:local",
            agent_type="codex",
            generated_at="2026-06-10T12:00:00+00:00",
            runtime_version="test",
        ),
        GuardAgentInventorySnapshot(
            snapshot_id="hermes:oversized",
            agent_id="hermes:local",
            agent_type="hermes",
            generated_at="2026-06-10T12:00:00+00:00",
            runtime_version="test",
        ),
    )
    monkeypatch.setattr(aibom_cli, "collect_aibom_snapshots", lambda *_args, **_kwargs: snapshots)
    planned_event_ids: dict[str, str] = {}

    def plan_mixed_snapshots(events, **_kwargs):
        planned_event_ids["valid"] = str(events[0]["eventId"])
        planned_event_ids["oversized"] = str(events[1]["eventId"])
        return [[events[0]]], [events[1]]

    monkeypatch.setattr(
        aibom_cli,
        "_batch_inventory_events",
        plan_mixed_snapshots,
    )
    monkeypatch.setattr(runner, "_guard_events_sync_url", lambda url: url)
    monkeypatch.setattr(runner, "_guard_sync_request", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(
        runner,
        "_urlopen_json_with_timeout_retry",
        lambda *_args, **_kwargs: {
            "accepted": 1,
            "rejected": 0,
            "statuses": [{"eventId": planned_event_ids["valid"], "status": "accepted"}],
            "syncedAt": "2026-06-10T12:00:01+00:00",
        },
    )

    summary = sync_aibom_snapshots(
        store,
        HarnessContext(
            home_dir=tmp_path / "home",
            workspace_dir=tmp_path / "workspace",
            guard_home=store.guard_home,
        ),
        generated_at="2026-06-10T12:00:00+00:00",
        auth_context={
            "sync_url": "https://hol.test/api/v1/guard/events",
            "token": "test-token",
        },
    )

    assert summary.get("synced") is True
    assert summary.get("partial") is True
    assert summary.get("reason") == "snapshot_too_large"
    assert summary.get("accepted") == 1
    assert summary.get("rejected") == 1
    assert summary.get("statuses") == [
        {
            "eventId": planned_event_ids["oversized"],
            "status": "rejected",
            "reason": "snapshot_too_large",
        },
        {"eventId": planned_event_ids["valid"], "status": "accepted"},
    ]


def test_sync_aibom_snapshots_preserves_oversized_rejection_when_valid_batch_is_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import urllib.error

    from codex_plugin_scanner.guard import aibom_cli
    from codex_plugin_scanner.guard.adapters.base import HarnessContext
    from codex_plugin_scanner.guard.aibom_cli import sync_aibom_snapshots
    from codex_plugin_scanner.guard.inventory_contract import GuardAgentInventorySnapshot
    from codex_plugin_scanner.guard.runtime import runner

    store = GuardStore(tmp_path / "guard")
    monkeypatch.setattr(store, "get_cloud_workspace_id", lambda: "workspace-1")
    snapshots = (
        GuardAgentInventorySnapshot(
            snapshot_id="codex:valid",
            agent_id="codex:local",
            agent_type="codex",
            generated_at="2026-06-10T12:00:00+00:00",
            runtime_version="test",
        ),
        GuardAgentInventorySnapshot(
            snapshot_id="hermes:oversized",
            agent_id="hermes:local",
            agent_type="hermes",
            generated_at="2026-06-10T12:00:00+00:00",
            runtime_version="test",
        ),
    )
    monkeypatch.setattr(aibom_cli, "collect_aibom_snapshots", lambda *_args, **_kwargs: snapshots)
    planned_event_ids: dict[str, str] = {}

    def plan_mixed_snapshots(events, **_kwargs):
        planned_event_ids["valid"] = str(events[0]["eventId"])
        planned_event_ids["oversized"] = str(events[1]["eventId"])
        return [[events[0]]], [events[1]]

    def reject_valid_batch(*_args, **_kwargs):
        raise urllib.error.HTTPError(
            url="https://hol.test/api/v1/guard/events",
            code=404,
            msg="Not Found",
            hdrs=Message(),
            fp=None,
        )

    monkeypatch.setattr(aibom_cli, "_batch_inventory_events", plan_mixed_snapshots)
    monkeypatch.setattr(runner, "_guard_events_sync_url", lambda url: url)
    monkeypatch.setattr(runner, "_guard_sync_request", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(runner, "_urlopen_json_with_timeout_retry", reject_valid_batch)

    summary = sync_aibom_snapshots(
        store,
        HarnessContext(
            home_dir=tmp_path / "home",
            workspace_dir=tmp_path / "workspace",
            guard_home=store.guard_home,
        ),
        generated_at="2026-06-10T12:00:00+00:00",
        auth_context={
            "sync_url": "https://hol.test/api/v1/guard/events",
            "token": "test-token",
        },
    )

    backoff = store.get_sync_payload("aibom_guard_events_backoff")
    assert summary.get("synced") is False
    assert summary.get("skipped") is True
    assert summary.get("partial") is True
    assert summary.get("accepted") == 0
    assert summary.get("rejected") == 1
    assert summary.get("statuses") == [
        {
            "eventId": planned_event_ids["oversized"],
            "status": "rejected",
            "reason": "snapshot_too_large",
        }
    ]
    assert isinstance(backoff, dict)
    assert backoff.get("events") == 1
    assert backoff.get("skipped") == 1
    assert backoff.get("accepted") == 0


@pytest.mark.parametrize("failure_kind", ("http", "network"))
def test_sync_aibom_snapshots_marks_oversized_rejection_partial_on_transport_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_kind: str,
) -> None:
    import urllib.error

    from codex_plugin_scanner.guard import aibom_cli
    from codex_plugin_scanner.guard.adapters.base import HarnessContext
    from codex_plugin_scanner.guard.aibom_cli import sync_aibom_snapshots
    from codex_plugin_scanner.guard.inventory_contract import GuardAgentInventorySnapshot
    from codex_plugin_scanner.guard.runtime import runner

    store = GuardStore(tmp_path / "guard")
    monkeypatch.setattr(store, "get_cloud_workspace_id", lambda: "workspace-1")
    snapshots = (
        GuardAgentInventorySnapshot(
            snapshot_id="codex:valid",
            agent_id="codex:local",
            agent_type="codex",
            generated_at="2026-06-10T12:00:00+00:00",
            runtime_version="test",
        ),
        GuardAgentInventorySnapshot(
            snapshot_id="hermes:oversized",
            agent_id="hermes:local",
            agent_type="hermes",
            generated_at="2026-06-10T12:00:00+00:00",
            runtime_version="test",
        ),
    )
    monkeypatch.setattr(aibom_cli, "collect_aibom_snapshots", lambda *_args, **_kwargs: snapshots)
    planned_event_ids: dict[str, str] = {}

    def plan_mixed_snapshots(events, **_kwargs):
        planned_event_ids["oversized"] = str(events[1]["eventId"])
        return [[events[0]]], [events[1]]

    def fail_valid_batch(*_args, **_kwargs):
        if failure_kind == "http":
            raise urllib.error.HTTPError(
                url="https://hol.test/api/v1/guard/events",
                code=500,
                msg="Server Error",
                hdrs=Message(),
                fp=None,
            )
        raise OSError("network unavailable")

    monkeypatch.setattr(aibom_cli, "_batch_inventory_events", plan_mixed_snapshots)
    monkeypatch.setattr(runner, "_guard_events_sync_url", lambda url: url)
    monkeypatch.setattr(runner, "_guard_sync_request", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(runner, "_urlopen_json_with_timeout_retry", fail_valid_batch)

    with pytest.raises(RuntimeError):
        sync_aibom_snapshots(
            store,
            HarnessContext(
                home_dir=tmp_path / "home",
                workspace_dir=tmp_path / "workspace",
                guard_home=store.guard_home,
            ),
            generated_at="2026-06-10T12:00:00+00:00",
            auth_context={
                "sync_url": "https://hol.test/api/v1/guard/events",
                "token": "test-token",
            },
        )

    summary = store.get_sync_payload("aibom_sync_summary")
    assert isinstance(summary, dict)
    assert summary.get("synced") is False
    assert summary.get("partial") is True
    assert summary.get("accepted") == 0
    assert summary.get("rejected") == 1
    assert summary.get("statuses") == [
        {
            "eventId": planned_event_ids["oversized"],
            "status": "rejected",
            "reason": "snapshot_too_large",
        }
    ]


def test_collect_aibom_snapshots_passes_cisco_runs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard import aibom_cli
    from codex_plugin_scanner.guard.adapters.base import HarnessContext

    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    skill_path = workspace_dir / ".agents" / "skills" / "demo" / "SKILL.md"
    _write_text(skill_path, "---\ndescription: demo\n---\n")

    detection = HarnessDetection(
        harness="codex",
        installed=True,
        command_available=True,
        config_paths=(str(skill_path),),
        artifacts=(
            GuardArtifact(
                artifact_id="codex:global:skill:.agents/skills:demo",
                name="demo",
                harness="codex",
                artifact_type="skill",
                source_scope="global",
                config_path=str(skill_path),
                metadata={"skill_root": ".agents/skills"},
            ),
        ),
        warnings=(),
    )
    context = HarnessContext(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        guard_home=tmp_path / "guard",
    )
    observed: dict[str, object] = {}
    cisco_runs = (
        CiscoInventoryRun(
            source="cisco-skill-scanner",
            status="enabled",
            message="ok",
            findings=(),
            duration_ms=12,
            metadata={"skillsScanned": 1},
        ),
    )

    monkeypatch.setattr(aibom_cli, "detect_all", lambda _context: [detection])

    def fake_run_cisco_inventory_scans(**kwargs: object) -> tuple[object, ...]:
        observed["cisco_kwargs"] = kwargs
        return cisco_runs

    def fake_inventory_snapshot_from_detection(*args: object, **kwargs: object) -> object:
        observed["snapshot_kwargs"] = kwargs
        return object()

    monkeypatch.setattr(aibom_cli, "run_cisco_inventory_scans", fake_run_cisco_inventory_scans)
    monkeypatch.setattr(
        aibom_cli,
        "inventory_snapshot_from_detection",
        fake_inventory_snapshot_from_detection,
    )

    snapshots = aibom_cli.collect_aibom_snapshots(
        context,
        generated_at="2026-06-10T12:00:00+00:00",
    )

    assert len(snapshots) == 1
    assert observed["cisco_kwargs"] == {
        "harness": "codex",
        "context": context,
        "detection": detection,
        "mcp_mode": "off",
        "skill_mode": "off",
        "timeout_seconds": None,
    }
    snapshot_kwargs = observed["snapshot_kwargs"]
    assert isinstance(snapshot_kwargs, dict)
    assert snapshot_kwargs["cisco_runs"] == cisco_runs


def test_sync_aibom_snapshots_uses_cloud_sync_cisco_defaults(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard import aibom_cli
    from codex_plugin_scanner.guard.adapters.base import HarnessContext
    from codex_plugin_scanner.guard.aibom_cli import sync_aibom_snapshots

    store = GuardStore(tmp_path / "guard")
    monkeypatch.setattr(store, "get_cloud_workspace_id", lambda: "workspace-1")
    context = HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=tmp_path / "workspace",
        guard_home=tmp_path / "guard",
    )
    observed: dict[str, object] = {}

    def fake_collect_aibom_snapshots(*args: object, **kwargs: object) -> tuple[object, ...]:
        observed["collect_kwargs"] = kwargs
        return ()

    monkeypatch.setattr(aibom_cli, "collect_aibom_snapshots", fake_collect_aibom_snapshots)
    monkeypatch.setenv("GUARD_AIBOM_TRUST_ATTESTATION_V2", "0")

    summary = sync_aibom_snapshots(
        store,
        context,
        generated_at="2026-06-10T12:00:00+00:00",
        auth_context={
            "sync_url": "https://hol.test/api/v1/guard/events",
            "token": "test-token",
        },
    )

    assert summary["accepted"] == 0
    collect_kwargs = observed["collect_kwargs"]
    assert isinstance(collect_kwargs, dict)
    options = collect_kwargs["options"]
    assert isinstance(options, aibom_cli.AibomCliOptions)
    assert options.cisco_skill_scan == "auto"
    assert options.cisco_mcp_scan == "auto"
    assert options.cisco_timeout_seconds == 30.0
    trust_attestation_context = collect_kwargs["trust_attestation_context"]
    assert isinstance(trust_attestation_context, dict)
    assert trust_attestation_context["deviceId"] is None
    assert trust_attestation_context["workspaceId"] is None


def test_collect_aibom_snapshots_shares_cisco_timeout_budget_across_detections(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from codex_plugin_scanner.guard import aibom_cli
    from codex_plugin_scanner.guard.adapters.base import HarnessContext

    context = HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=tmp_path / "workspace",
        guard_home=tmp_path / "guard",
    )
    context.home_dir.mkdir(parents=True)
    assert context.workspace_dir is not None
    context.workspace_dir.mkdir(parents=True)
    context.guard_home.mkdir(parents=True)

    detections = [
        SimpleNamespace(installed=True, artifacts=(), harness="codex"),
        SimpleNamespace(installed=True, artifacts=(), harness="openclaw"),
    ]
    observed_timeouts: list[float | None] = []
    monotonic_values = iter([0.0, 4.0, 4.0, 9.0])

    def fake_monotonic() -> float:
        return next(monotonic_values)

    monkeypatch.setattr(aibom_cli, "detect_all", lambda _context: detections)
    monkeypatch.setattr(aibom_cli.time, "monotonic", fake_monotonic)
    monkeypatch.setattr(
        aibom_cli,
        "run_cisco_inventory_scans",
        lambda **kwargs: observed_timeouts.append(kwargs.get("timeout_seconds")) or (),
    )
    monkeypatch.setattr(
        aibom_cli,
        "inventory_snapshot_from_detection",
        lambda *args, **kwargs: {"harness": getattr(args[0], "harness", "unknown"), "kwargs": kwargs},
    )

    snapshots = aibom_cli.collect_aibom_snapshots(
        context,
        generated_at="2026-06-10T12:00:00+00:00",
        options=aibom_cli.AibomCliOptions(cisco_skill_scan="auto", cisco_timeout_seconds=10.0),
    )

    assert len(snapshots) == 2
    assert observed_timeouts == [10.0, 6.0]


def test_guard_aibom_sync_command_uses_cloud_sync_cisco_defaults(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard")
    context = HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=tmp_path / "workspace",
        guard_home=tmp_path / "guard",
    )
    observed: dict[str, object] = {}

    def fake_sync_aibom_snapshots(*args: object, **kwargs: object) -> dict[str, object]:
        observed["kwargs"] = kwargs
        return {"synced": True}

    monkeypatch.setattr(dispatch, "sync_aibom_snapshots", fake_sync_aibom_snapshots)

    exit_code = dispatch._run_guard_aibom_command(
        argparse.Namespace(
            aibom_command="sync",
            include_symlinks=True,
            follow_unsafe_symlinks=False,
            json=True,
        ),
        context=context,
        store=store,
    )

    assert exit_code == 0
    kwargs = observed["kwargs"]
    assert isinstance(kwargs, dict)
    options = kwargs["options"]
    assert isinstance(options, aibom_cli.AibomCliOptions)
    assert options.cisco_skill_scan == "auto"
    assert options.cisco_mcp_scan == "auto"
    assert options.cisco_timeout_seconds == 30.0
    assert options.include_symlinks is True
    assert options.follow_unsafe_symlinks is False


def test_aibom_export_json_includes_redaction_report(tmp_path: Path, capsys, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GUARD_AIBOM_TRUST_ATTESTATION_V2", "0")
    monkeypatch.delenv("GUARD_AIBOM_TRUST_ATTESTATION_PRIVATE_KEY", raising=False)
    monkeypatch.delenv("GUARD_AIBOM_TRUST_ATTESTATION_KEY_ID", raising=False)
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
