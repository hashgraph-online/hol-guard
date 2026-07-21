"""End-to-end approval-boundary regressions for external package archives."""

from __future__ import annotations

import argparse
import hashlib
import json
import shlex
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.cli.commands_hook_runtime_eval import _evaluate_runtime_artifact_hook
from codex_plugin_scanner.guard.cli.commands_hook_runtime_state import RuntimeArtifactHookState
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.local_supply_chain import (
    _bound_external_archive_launch_command,
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


def test_multiple_url_userinfo_segments_are_fully_redacted(tmp_path: Path) -> None:
    source_url = "https://FIRST_SECRET@tenant:SECOND_SECRET@packages.example.com/demo.tgz?token=THIRD_SECRET"
    intent = parse_package_intent(shlex.join(("npm", "install", f"demo@{source_url}")), workspace=tmp_path)
    assert intent is not None
    serialized = json.dumps(intent.to_dict(), sort_keys=True, default=str)

    assert "FIRST_SECRET" not in serialized
    assert "SECOND_SECRET" not in serialized
    assert "THIRD_SECRET" not in serialized


def test_external_archive_private_source_is_preserved_for_authorized_scan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "package.json").write_text("{}\n", encoding="utf-8")
    source_url = "https://packages.example.com/demo.tgz?token=PRIVATE_DOWNLOAD_TOKEN"
    artifact = _package_artifact(workspace, f"npm install demo@{source_url}")
    scanned_sources: list[str] = []

    def clean_scan(
        scanned_url: str,
        *,
        retain_download: bool = False,
        request_deadline: float | None = None,
    ) -> tuple[dict[str, str], None]:
        del request_deadline, retain_download
        scanned_sources.append(scanned_url)
        return (
            {
                "decision": "ask",
                "code": "external_tarball_source",
                "message": "External tarball source requires review.",
                "severity": "medium",
            },
            None,
        )

    monkeypatch.setattr(evaluator, "_scan_external_tarball", clean_scan)
    evaluator.evaluate_package_request_artifact(
        artifact=artifact,
        store=GuardStore(tmp_path / "guard-home"),
        workspace_dir=workspace,
        external_archive_network_authorized=True,
    )

    assert scanned_sources == [source_url]


def test_external_archive_private_source_mutation_fails_closed_before_scan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "package.json").write_text("{}\n", encoding="utf-8")
    artifact = _package_artifact(workspace, "npm install demo@https://packages.example.com/demo.tgz")
    private_targets = artifact.runtime_private_metadata.get("package_targets")
    assert isinstance(private_targets, list)
    private_target = private_targets[0]
    assert isinstance(private_target, dict)
    private_target["source_url"] = "https://changed.example.com/demo.tgz"
    monkeypatch.setattr(
        evaluator,
        "_scan_external_tarball",
        lambda *_args, **_kwargs: pytest.fail("mutated private source reached archive scan"),
    )

    result = evaluator.evaluate_package_request_artifact(
        artifact=artifact,
        store=GuardStore(tmp_path / "guard-home"),
        workspace_dir=workspace,
        external_archive_network_authorized=True,
    )

    assert result.decision == "block"
    assert any(reason["code"] == "external_archive_source_integrity_invalid" for reason in result.reasons)


def test_direct_pip_signed_url_preserves_exact_private_download_and_binding_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    source_url = "https://packages.example.com/demo.whl?token=PRIVATE_PIP_TOKEN"
    command = ["pip", "install", source_url]
    intent = parse_package_intent(shlex.join(command), workspace=workspace)
    assert intent is not None
    assert intent.targets[0].source_url == source_url
    artifact = build_package_request_artifact(
        "guard-cli",
        intent,
        config_path="hol-guard.toml",
        source_scope="project",
    )
    public_targets = artifact.metadata.get("targets")
    assert isinstance(public_targets, list)
    public_target = public_targets[0]
    assert isinstance(public_target, dict)
    assert "PRIVATE_PIP_TOKEN" not in json.dumps(public_target)
    scanned_sources: list[str] = []

    def clean_scan(
        scanned_url: str,
        *,
        retain_download: bool = False,
        request_deadline: float | None = None,
    ) -> tuple[dict[str, str], None]:
        del request_deadline, retain_download
        scanned_sources.append(scanned_url)
        return (
            {
                "decision": "ask",
                "code": "external_tarball_source",
                "message": "External archive source requires review.",
                "severity": "medium",
            },
            None,
        )

    monkeypatch.setattr(evaluator, "_scan_external_tarball", clean_scan)
    evaluator.evaluate_package_request_artifact(
        artifact=artifact,
        store=GuardStore(tmp_path / "guard-home"),
        workspace_dir=workspace,
        external_archive_network_authorized=True,
    )
    assert scanned_sources == [source_url]

    archive_path = tmp_path / "demo.whl"
    archive_payload = b"digest-bound-wheel"
    archive_path.write_bytes(archive_payload)
    archive_path.chmod(0o400)
    download = RestrictedArchiveDownload(
        path=archive_path,
        sha256=hashlib.sha256(archive_payload).hexdigest(),
        size=len(archive_payload),
        source_url=source_url,
        final_url=source_url,
    )
    bound = _bound_external_archive_launch_command(
        command,
        evaluation=SimpleNamespace(external_archive_downloads=(download,)),
    )

    assert bound == ["pip", "install", str(archive_path)]
    download.cleanup()
