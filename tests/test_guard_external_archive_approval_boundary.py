"""End-to-end approval-boundary regressions for external package archives."""

from __future__ import annotations

import argparse
import hashlib
import shlex
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.cli.commands_hook_runtime_eval import _evaluate_runtime_artifact_hook
from codex_plugin_scanner.guard.cli.commands_hook_runtime_state import RuntimeArtifactHookState
from codex_plugin_scanner.guard.config import GuardConfig
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


@pytest.mark.parametrize(
    "source_url",
    (
        "https:packages.example.com/demo.tgz",
        "https:/packages.example.com/demo.tgz",
        "https:///packages.example.com/demo.tgz",
        "https:////packages.example.com/demo.tgz",
        "https://///packages.example.com/demo.tgz",
        "https:\\packages.example.com\\demo.tgz",
        "https:\\\\packages.example.com\\demo.tgz",
    ),
)
@pytest.mark.parametrize("named", (False, True))
def test_npm_url_like_https_specs_are_rejected_before_approval_or_network(
    source_url: str,
    named: bool,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "package.json").write_text("{}\n", encoding="utf-8")
    package_spec = f"demo@{source_url}" if named else source_url
    command = shlex.join(("npm", "install", package_spec))
    intent = parse_package_intent(command, workspace=workspace)
    assert intent is not None
    assert intent.targets[0].source_url == source_url
    assert evaluator._source_url_from_raw_spec(package_spec) == source_url
    artifact = build_package_request_artifact(
        "guard-cli",
        intent,
        config_path="hol-guard.toml",
        source_scope="project",
    )

    monkeypatch.setattr(
        evaluator,
        "_scan_external_tarball",
        lambda *_args, **_kwargs: pytest.fail("non-canonical source reached archive network boundary"),
    )
    result = evaluator.evaluate_package_request_artifact(
        artifact=artifact,
        store=GuardStore(tmp_path / "guard-home"),
        workspace_dir=workspace,
    )

    assert result.decision == "block"
    assert any(reason["code"] == "npm_source_host_missing" for reason in result.reasons)


@pytest.mark.parametrize("named", (False, True))
def test_npm_url_like_source_query_is_removed_from_redacted_command(
    named: bool,
    tmp_path: Path,
) -> None:
    secret = "must-not-be-persisted"
    source_url = f"https:packages.example.com/demo.tgz?token={secret}"
    package_spec = f"demo@{source_url}" if named else source_url
    intent = parse_package_intent(shlex.join(("npm", "install", package_spec)), workspace=tmp_path)

    assert intent is not None
    assert secret not in intent.redacted_command
    assert "<redacted-source>" in intent.redacted_command


@pytest.mark.parametrize("named", (False, True))
@pytest.mark.parametrize(
    "source_url",
    (
        "https://user:password@packages.example.com/demo.tgz",
        "https://packages.example.com/releases/user@channel/demo.tgz",
    ),
)
def test_npm_https_at_sign_is_not_mistaken_for_package_source_separator(
    source_url: str,
    named: bool,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "package.json").write_text("{}\n", encoding="utf-8")
    package_spec = f"demo@{source_url}" if named else source_url
    intent = parse_package_intent(shlex.join(("npm", "install", package_spec)), workspace=workspace)

    assert intent is not None
    assert intent.targets[0].source_url == source_url
    assert evaluator._source_url_from_raw_spec(package_spec) == source_url
    artifact = build_package_request_artifact(
        "guard-cli",
        intent,
        config_path="hol-guard.toml",
        source_scope="project",
    )
    if "user:password@" in source_url:
        monkeypatch.setattr(
            evaluator,
            "_scan_external_tarball",
            lambda *_args, **_kwargs: pytest.fail("credential URL reached archive network boundary"),
        )
        result = evaluator.evaluate_package_request_artifact(
            artifact=artifact,
            store=GuardStore(tmp_path / "guard-home"),
            workspace_dir=workspace,
        )
        assert result.decision == "block"
        assert any(reason["code"] == "npm_source_ambiguous_userinfo" for reason in result.reasons)


def test_external_archive_request_caps_target_count_before_network(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "package.json").write_text("{}\n", encoding="utf-8")
    sources = [f"https://packages{index}.example.com/demo.tgz" for index in range(5)]
    artifact = _package_artifact(workspace, shlex.join(("npm", "install", *sources)))
    monkeypatch.setattr(
        evaluator,
        "_scan_external_tarball",
        lambda *_args, **_kwargs: pytest.fail("over-target request reached archive network boundary"),
    )

    result = evaluator.evaluate_package_request_artifact(
        artifact=artifact,
        store=GuardStore(tmp_path / "guard-home"),
        workspace_dir=workspace,
        external_archive_network_authorized=True,
        retain_external_archive_blob=True,
    )

    assert result.decision == "block"
    assert any(reason["code"] == "external_archive_target_limit" for reason in result.reasons)
    assert len(result.external_archive_source_hashes) == len(sources)


def test_external_archive_request_caps_aggregate_retained_bytes_and_cleans_blobs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "package.json").write_text("{}\n", encoding="utf-8")
    sources = ["https://one.example.com/demo.tgz", "https://two.example.com/demo.tgz"]
    artifact = _package_artifact(workspace, shlex.join(("npm", "install", *sources)))
    paths: list[Path] = []

    def retained_scan(
        source_url: str,
        *,
        retain_download: bool = False,
        request_deadline: float | None = None,
    ) -> tuple[dict[str, str], RestrictedArchiveDownload]:
        assert retain_download is True
        assert request_deadline is not None
        path = tmp_path / f"retained-{len(paths)}.tgz"
        path.write_bytes(b"xx")
        path.chmod(0o400)
        paths.append(path)
        return (
            {
                "decision": "ask",
                "code": "external_tarball_source",
                "message": "External tarball source requires review.",
                "severity": "medium",
            },
            RestrictedArchiveDownload(
                path=path,
                sha256=hashlib.sha256(b"xx").hexdigest(),
                size=2,
                source_url=source_url,
                final_url=source_url,
            ),
        )

    monkeypatch.setattr(evaluator, "_EXTERNAL_ARCHIVE_MAX_AGGREGATE_BYTES", 3)
    monkeypatch.setattr(evaluator, "_scan_external_tarball", retained_scan)

    result = evaluator.evaluate_package_request_artifact(
        artifact=artifact,
        store=GuardStore(tmp_path / "guard-home"),
        workspace_dir=workspace,
        external_archive_network_authorized=True,
        retain_external_archive_blob=True,
    )

    assert result.decision == "block"
    assert any(reason["code"] == "external_archive_aggregate_size_limit" for reason in result.reasons)
    assert len(result.external_archive_source_hashes) == len(sources)
    assert paths and all(path.exists() is False for path in paths)


def test_external_archive_request_deadline_fails_before_next_download(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        evaluator,
        "_download_external_tarball",
        lambda *_args, **_kwargs: pytest.fail("expired request started another download"),
    )

    result, retained = evaluator._scan_external_tarball(
        "https://packages.example.com/demo.tgz",
        request_deadline=evaluator.time.monotonic() - 1,
    )

    assert result is not None
    assert result["code"] == "external_archive_request_timeout"
    assert retained is None


@pytest.mark.parametrize(
    "source_url",
    (
        "https://github.com/acme/demo/releases/download/v1.0.0/demo.tar.gz",
        "https://downloads.example.com/api/archive?id=123",
    ),
)
def test_external_archive_cannot_be_shadowed_or_bypass_restricted_inspection(
    source_url: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "package.json").write_text("{}\n", encoding="utf-8")
    artifact = _package_artifact(workspace, f"npm install demo@{source_url}")
    store = GuardStore(tmp_path / "guard-home")
    scans: list[str] = []

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

    monkeypatch.setattr(evaluator, "_scan_external_tarball", clean_scan)

    initial = evaluator.evaluate_package_request_artifact(
        artifact=artifact,
        store=store,
        workspace_dir=workspace,
    )
    approved_phase = evaluator.evaluate_package_request_artifact(
        artifact=artifact,
        store=store,
        workspace_dir=workspace,
        external_archive_network_authorized=True,
    )

    assert scans == [source_url]
    assert initial.external_archive_source_hashes == (evaluator.stable_digest_hex(source_url.encode()),)
    assert any(reason["code"] == "external_tarball_source" for reason in initial.reasons)
    assert any(reason["code"] == "external_tarball_source" for reason in approved_phase.reasons)
    assert all(reason["code"] != "git_dependency_source" for reason in approved_phase.reasons)
