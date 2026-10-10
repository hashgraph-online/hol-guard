"""End-to-end approval-boundary regressions for external package archives."""

from __future__ import annotations

import json
import shlex
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_supply_chain_eval
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.local_supply_chain import (
    build_package_protect_payload,
    evaluate_package_request_artifact,
)
from codex_plugin_scanner.guard.models import GuardArtifact, PolicyDecision
from codex_plugin_scanner.guard.runtime.package_intent import (
    build_package_request_artifact,
    parse_package_intent,
)
from codex_plugin_scanner.guard.stable_digest import stable_digest_hex
from codex_plugin_scanner.guard.store import GuardStore
from tests.native_archive_fakes import forbid_download, install_download, install_inspection

pytestmark = pytest.mark.usefixtures("archive_package_intent_native")


def _hook_inputs(
    tmp_path: Path,
) -> tuple[GuardArtifact, GuardConfig, HarnessContext, GuardStore, Path, dict[str, object]]:
    guard_home = tmp_path / "guard-home"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "package.json").write_text('{"name":"archive-boundary"}\n', encoding="utf-8")
    command = "npm install demo@https://packages.example.com/demo.tgz"
    intent = parse_package_intent(command, workspace=workspace)
    assert intent is not None
    artifact = build_package_request_artifact(
        "codex",
        intent,
        config_path=str(workspace / ".codex" / "config.toml"),
        source_scope="project",
    )
    config = GuardConfig(
        guard_home=guard_home,
        workspace=workspace,
        default_action="allow",
        approval_wait_timeout_seconds=0,
    )
    context = HarnessContext(home_dir=tmp_path, workspace_dir=workspace, guard_home=guard_home)
    store = GuardStore(guard_home)
    payload: dict[str, object] = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
        "source_scope": "project",
    }
    return artifact, config, context, store, workspace, payload


def _save_exact_allow(store: GuardStore, *, artifact: GuardArtifact, artifact_hash: str) -> None:
    store.upsert_policy(
        PolicyDecision(
            harness=artifact.harness,
            scope="artifact",
            action="allow",
            artifact_id=artifact.artifact_id,
            artifact_hash=artifact_hash,
            reason="approved exact external archive request",
            source="approval-gate",
            expires_at="2099-07-19T00:00:00Z",
        ),
        "2026-07-19T00:00:00Z",
    )


def _package_artifact(workspace: Path, command: str) -> GuardArtifact:
    intent = parse_package_intent(command, workspace=workspace)
    assert intent is not None
    return build_package_request_artifact(
        "guard-cli",
        intent,
        config_path="hol-guard.toml",
        source_scope="project",
    )


def test_manifest_warning_does_not_suppress_approved_external_archive_inspection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "package.json").write_text(
        json.dumps({"dependencies": {"left-pad": "^1.0.0"}}) + "\n", encoding="utf-8"
    )
    (workspace / "package-lock.json").write_text(
        json.dumps({"lockfileVersion": 3, "packages": {"": {}}}) + "\n", encoding="utf-8"
    )
    source_url = "https://packages.example.com/demo.tgz"
    artifact = _package_artifact(workspace, f"npm install demo@{source_url}")
    scans: list[str] = []
    install_download(monkeypatch, tmp_path, calls=scans)
    install_inspection(monkeypatch)

    result = evaluate_package_request_artifact(
        artifact=artifact,
        store=GuardStore(tmp_path / "guard-home"),
        workspace_dir=workspace,
        external_archive_network_authorized=True,
    )

    assert scans == [source_url]
    assert "external_tarball_source" in {reason["code"] for reason in result.reasons}


def test_mixed_registry_and_external_archive_request_fails_closed_without_network(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "package.json").write_text("{}\n", encoding="utf-8")
    source_url = "https://packages.example.com/demo.tgz"
    artifact = _package_artifact(workspace, f"npm install lodash demo@{source_url}")
    forbid_download(monkeypatch, "mixed request must fail before network inspection")

    result = evaluate_package_request_artifact(
        artifact=artifact,
        store=GuardStore(tmp_path / "guard-home"),
        workspace_dir=workspace,
        external_archive_network_authorized=True,
    )

    assert result.decision == "block"
    assert result.policy_action == "block"
    assert any(reason["code"] == "external_archive_mixed_request_unsupported" for reason in result.reasons)
    assert result.external_archive_source_hashes == (stable_digest_hex(source_url.encode()),)


def test_retained_archive_is_cleaned_if_evidence_persistence_raises(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "package.json").write_text("{}\n", encoding="utf-8")
    source_url = "https://packages.example.com/demo.tgz"
    artifact = _package_artifact(workspace, f"npm install demo@{source_url}")
    blobs = install_download(monkeypatch, tmp_path)
    install_inspection(monkeypatch)

    def persistence_failure(**_kwargs: object) -> None:
        raise RuntimeError("controlled evidence failure")

    monkeypatch.setattr(native_supply_chain_eval, "_persist_evidence", persistence_failure)

    with pytest.raises(RuntimeError, match="controlled evidence failure"):
        evaluate_package_request_artifact(
            artifact=artifact,
            store=GuardStore(tmp_path / "guard-home"),
            workspace_dir=workspace,
            external_archive_network_authorized=True,
            retain_external_archive_blob=True,
        )

    assert blobs and all(path.exists() is False for path in blobs)


def test_external_archive_evaluation_never_discloses_sensitive_url_query(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "package.json").write_text("{}\n", encoding="utf-8")
    secret = "archive-token-must-not-leak"
    artifact = _package_artifact(
        workspace,
        f"npm install demo@https://packages.example.com/demo.tgz?token={secret}",
    )

    result = evaluate_package_request_artifact(
        artifact=artifact,
        store=GuardStore(tmp_path / "guard-home"),
        workspace_dir=workspace,
    )

    assert secret not in repr(result.to_dict())


@pytest.mark.parametrize("explicit_guard_home", (False, True))
def test_external_archive_credentials_stay_private_across_artifact_and_receipt_surfaces(
    tmp_path: Path,
    archive_package_intent_native: Path,
    explicit_guard_home: bool,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "package.json").write_text("{}\n", encoding="utf-8")
    secret = "VERY_SECRET_ARCHIVE_TOKEN"
    password = "VERY_SECRET_PASSWORD"
    source_url = f"https://user:{password}@packages.example.com/demo.tgz?token={secret}"
    command = ["npm", "install", f"demo@{source_url}"]
    intent = parse_package_intent(
        shlex.join(command),
        workspace=workspace,
        guard_home=archive_package_intent_native if explicit_guard_home else None,
    )
    assert intent is not None
    assert intent.command_tokens == tuple(command)
    assert intent.targets[0].raw_spec == command[-1]
    assert intent.targets[0].source_url == source_url
    artifact = build_package_request_artifact(
        "guard-cli",
        intent,
        config_path="hol-guard.toml",
        source_scope="project",
    )

    store = GuardStore(tmp_path / "guard-home")
    evaluation = evaluate_package_request_artifact(
        artifact=artifact,
        store=store,
        workspace_dir=workspace,
    )
    package_payload = build_package_protect_payload(
        command=command,
        store=store,
        workspace_dir=workspace,
        dry_run=True,
        now="2026-07-19T00:00:00Z",
        config=None,
        unsafe_raw_output=False,
        timeout_seconds=30,
    )
    assert package_payload is not None
    payload, _returncode = package_payload
    serialized = json.dumps(
        {
            "artifact": artifact.to_dict(),
            "artifact_metadata": artifact.metadata,
            "intent": intent.to_dict(),
            "evaluation": evaluation.to_dict(),
            "payload": payload,
            "receipts": store.list_receipts(limit=20),
        },
        sort_keys=True,
        default=str,
    )

    assert secret not in serialized
    assert password not in serialized
    assert secret not in repr(artifact)
    assert password not in repr(intent)


@pytest.mark.parametrize("slash_count", (3, 4, 5))
@pytest.mark.parametrize("named", (False, True))
def test_malformed_https_credentials_are_redacted_from_all_public_surfaces(
    slash_count: int,
    named: bool,
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "package.json").write_text("{}\n", encoding="utf-8")
    secret = "MALFORMED_URL_SECRET"
    password = "MALFORMED_URL_PASSWORD"
    source_url = f"https:{'/' * slash_count}user:{password}@packages.example.com/demo.tgz?token={secret}"
    package_spec = f"demo@{source_url}" if named else source_url
    command = ["npm", "install", package_spec]
    intent = parse_package_intent(shlex.join(command), workspace=workspace)
    assert intent is not None
    artifact = build_package_request_artifact(
        "guard-cli",
        intent,
        config_path="hol-guard.toml",
        source_scope="project",
    )
    store = GuardStore(tmp_path / "guard-home")
    package_payload = build_package_protect_payload(
        command=command,
        store=store,
        workspace_dir=workspace,
        dry_run=True,
        now="2026-07-19T00:00:00Z",
        config=None,
        unsafe_raw_output=False,
        timeout_seconds=30,
    )
    assert package_payload is not None
    payload, _returncode = package_payload
    serialized = json.dumps(
        {
            "artifact": artifact.to_dict(),
            "metadata": artifact.metadata,
            "intent": intent.to_dict(),
            "payload": payload,
            "receipts": store.list_receipts(limit=20),
        },
        sort_keys=True,
        default=str,
    )

    assert secret not in serialized
    assert password not in serialized
