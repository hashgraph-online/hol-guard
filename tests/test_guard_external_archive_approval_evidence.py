"""End-to-end approval-boundary regressions for external package archives."""

from __future__ import annotations

import argparse
import hashlib
import json
import shlex
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.cli.commands_hook_runtime_eval import _evaluate_runtime_artifact_hook
from codex_plugin_scanner.guard.cli.commands_hook_runtime_state import RuntimeArtifactHookState
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.local_supply_chain import (
    build_package_protect_payload,
)
from codex_plugin_scanner.guard.models import GuardArtifact, PolicyDecision
from codex_plugin_scanner.guard.runtime import supply_chain_package_eval as evaluator
from codex_plugin_scanner.guard.runtime.package_intent import (
    build_package_request_artifact,
    parse_package_intent,
)
from codex_plugin_scanner.guard.runtime.restricted_archive_download import RestrictedArchiveDownload
from codex_plugin_scanner.guard.store import GuardStore


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


def _evaluate_hook(
    *,
    artifact: GuardArtifact,
    config: GuardConfig,
    context: HarnessContext,
    store: GuardStore,
    workspace: Path,
    payload: dict[str, object],
    trusted_request_override_hash: str | None = None,
) -> int | RuntimeArtifactHookState:
    return _evaluate_runtime_artifact_hook(
        argparse.Namespace(harness="codex", policy_action=None, json=True),
        action_envelope=None,
        config=config,
        context=context,
        data_flow_signals=(),
        guard_home=store.guard_home,
        payload=payload,
        runtime_artifact=artifact,
        runtime_workspace=workspace,
        store=store,
        trusted_request_override_hash=trusted_request_override_hash,
    )


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
    (workspace / "package.json").write_text("{}\n", encoding="utf-8")
    source_url = "https://packages.example.com/demo.tgz"
    artifact = _package_artifact(workspace, f"npm install demo@{source_url}")
    store = GuardStore(tmp_path / "guard-home")
    real_targets = evaluator._evaluation_targets
    scans: list[str] = []

    def unsynced_targets(
        target_artifact: GuardArtifact,
        target_workspace: Path | None,
    ) -> tuple[dict[str, object], ...]:
        return tuple(
            {**target, "manifest_unsynced": True} for target in real_targets(target_artifact, target_workspace)
        )

    def clean_scan(
        scanned_url: str,
        *,
        retain_download: bool = False,
        request_deadline: float | None = None,
    ) -> tuple[dict[str, str], None]:
        del request_deadline, retain_download
        scans.append(scanned_url)
        return (
            {
                "decision": "ask",
                "code": "external_tarball_source",
                "message": "External tarball source requires review.",
                "severity": "medium",
            },
            None,
        )

    monkeypatch.setattr(evaluator, "_evaluation_targets", unsynced_targets)
    monkeypatch.setattr(evaluator, "_scan_external_tarball", clean_scan)

    result = evaluator.evaluate_package_request_artifact(
        artifact=artifact,
        store=store,
        workspace_dir=workspace,
        external_archive_network_authorized=True,
    )

    assert scans == [source_url]
    assert {reason["code"] for reason in result.reasons} >= {
        "external_tarball_source",
        "manifest_lockfile_unsynced",
    }


def test_mixed_registry_and_external_archive_request_fails_closed_without_network(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "package.json").write_text("{}\n", encoding="utf-8")
    source_url = "https://packages.example.com/demo.tgz"
    artifact = _package_artifact(workspace, f"npm install lodash demo@{source_url}")

    def unexpected_scan(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("mixed request must fail before network inspection")

    monkeypatch.setattr(evaluator, "_scan_external_tarball", unexpected_scan)

    result = evaluator.evaluate_package_request_artifact(
        artifact=artifact,
        store=GuardStore(tmp_path / "guard-home"),
        workspace_dir=workspace,
        external_archive_network_authorized=True,
    )

    assert result.decision == "block"
    assert result.policy_action == "block"
    assert any(reason["code"] == "external_archive_mixed_request_unsupported" for reason in result.reasons)
    assert result.external_archive_source_hashes == (evaluator.stable_digest_hex(source_url.encode()),)


def test_retained_archive_is_cleaned_if_evidence_persistence_raises(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "package.json").write_text("{}\n", encoding="utf-8")
    source_url = "https://packages.example.com/demo.tgz"
    artifact = _package_artifact(workspace, f"npm install demo@{source_url}")
    archive_path = tmp_path / "retained.tgz"
    payload = b"inspected bytes"
    archive_path.write_bytes(payload)
    archive_path.chmod(0o400)
    download = RestrictedArchiveDownload(
        path=archive_path,
        sha256=hashlib.sha256(payload).hexdigest(),
        size=len(payload),
        source_url=source_url,
        final_url=source_url,
    )

    monkeypatch.setattr(
        evaluator,
        "_scan_external_tarball",
        lambda *_args, **_kwargs: (
            {
                "decision": "ask",
                "code": "external_tarball_source",
                "message": "External tarball source requires review.",
                "severity": "medium",
            },
            download,
        ),
    )

    def persistence_failure(**_kwargs: object) -> None:
        raise RuntimeError("controlled evidence failure")

    monkeypatch.setattr(evaluator, "_persist_evidence", persistence_failure)

    with pytest.raises(RuntimeError, match="controlled evidence failure"):
        evaluator.evaluate_package_request_artifact(
            artifact=artifact,
            store=GuardStore(tmp_path / "guard-home"),
            workspace_dir=workspace,
            external_archive_network_authorized=True,
            retain_external_archive_blob=True,
        )

    assert archive_path.exists() is False


def test_external_archive_evaluation_never_discloses_sensitive_url_query(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "package.json").write_text("{}\n", encoding="utf-8")
    secret = "archive-token-must-not-leak"
    artifact = _package_artifact(
        workspace,
        f"npm install demo@https://packages.example.com/demo.tgz?token={secret}",
    )

    result = evaluator.evaluate_package_request_artifact(
        artifact=artifact,
        store=GuardStore(tmp_path / "guard-home"),
        workspace_dir=workspace,
    )

    assert secret not in repr(result.to_dict())


def test_external_archive_credentials_stay_private_across_artifact_and_receipt_surfaces(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "package.json").write_text("{}\n", encoding="utf-8")
    secret = "VERY_SECRET_ARCHIVE_TOKEN"
    password = "VERY_SECRET_PASSWORD"
    source_url = f"https://user:{password}@packages.example.com/demo.tgz?token={secret}"
    command = ["npm", "install", f"demo@{source_url}"]
    intent = parse_package_intent(shlex.join(command), workspace=workspace)
    assert intent is not None
    artifact = build_package_request_artifact(
        "guard-cli",
        intent,
        config_path="hol-guard.toml",
        source_scope="project",
    )
    private_targets = artifact.runtime_private_metadata["package_targets"]
    assert isinstance(private_targets, list)
    assert private_targets[0]["source_url"] == source_url

    store = GuardStore(tmp_path / "guard-home")
    evaluation = evaluator.evaluate_package_request_artifact(
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
