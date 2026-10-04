"""End-to-end approval-boundary regressions for external package archives."""

from __future__ import annotations

import hashlib
import io
import json
import shlex
import subprocess
import tarfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import local_supply_chain as local_supply_chain_module
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.local_supply_chain import (
    _bound_external_archive_launch_command,
    build_package_protect_payload,
)
from codex_plugin_scanner.guard.models import GuardArtifact, PolicyDecision
from codex_plugin_scanner.guard.proxy.runtime_mcp import _bound_external_archive_mcp_request
from codex_plugin_scanner.guard.runtime import supply_chain_package_eval as evaluator
from codex_plugin_scanner.guard.runtime.supply_chain_package_services import _TARBALL_SCAN_TIMEOUT_SECONDS
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


def test_package_firewall_reuses_one_review_to_inspect_then_launch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    native_hook_force: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "package.json").write_text('{"name":"archive-firewall"}\n', encoding="utf-8")
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake_npm = fake_bin / "npm"
    fake_npm.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    fake_npm.chmod(0o755)
    monkeypatch.setenv("PATH", str(fake_bin))
    store = GuardStore(tmp_path / "guard-home")
    command = ["npm", "install", "demo@https://packages.example.com/demo.tgz"]
    archive_buffer = io.BytesIO()
    package_json = json.dumps({"name": "demo", "version": "1.0.0"}).encode()
    with tarfile.open(fileobj=archive_buffer, mode="w:gz") as archive:
        package_info = tarfile.TarInfo("package/package.json")
        package_info.size = len(package_json)
        archive.addfile(package_info, io.BytesIO(package_json))
    archive_payload = archive_buffer.getvalue()
    archive_path = tmp_path / "approved-demo.tgz"
    archive_path.write_bytes(archive_payload)
    archive_path.chmod(0o400)
    download_calls: list[str] = []

    def downloaded_archive(
        source_url: str,
        *,
        timeout_seconds: float = _TARBALL_SCAN_TIMEOUT_SECONDS,
    ) -> RestrictedArchiveDownload:
        del timeout_seconds
        download_calls.append(source_url)
        return RestrictedArchiveDownload(
            path=archive_path,
            sha256=hashlib.sha256(archive_payload).hexdigest(),
            size=len(archive_payload),
            source_url=source_url,
            final_url=source_url,
        )

    monkeypatch.setattr(evaluator, "_download_external_tarball", downloaded_archive)
    baseline = build_package_protect_payload(
        command=command,
        store=store,
        workspace_dir=workspace,
        dry_run=True,
        now="2026-07-19T00:00:00Z",
        config=None,
        unsafe_raw_output=False,
        timeout_seconds=30,
    )
    assert baseline is not None
    baseline_payload, baseline_rc = baseline
    assert baseline_rc == 2
    assert download_calls == []
    receipt = baseline_payload["receipt"]
    assert isinstance(receipt, dict)
    store.ensure_policy_integrity_ready_for_write(now="2026-07-19T00:00:00Z")
    store.upsert_policy(
        PolicyDecision(
            harness="guard-cli",
            scope="artifact",
            action="allow",
            artifact_id=str(receipt["artifact_id"]),
            artifact_hash=str(receipt["artifact_hash"]),
            source="approval-gate",
        ),
        "2026-07-19T00:00:00Z",
    )
    launches: list[list[str]] = []

    def fake_run(argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        launches.append(argv)
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    monkeypatch.setattr(
        local_supply_chain_module,
        "subprocess",
        SimpleNamespace(run=fake_run, TimeoutExpired=subprocess.TimeoutExpired),
    )

    approved = build_package_protect_payload(
        command=command,
        store=store,
        workspace_dir=workspace,
        dry_run=True,
        allow_saved_approval_execution=True,
        now="2026-07-19T00:01:00Z",
        config=None,
        unsafe_raw_output=False,
        timeout_seconds=30,
    )

    assert approved is not None
    approved_payload, approved_rc = approved
    assert approved_rc == 0
    assert approved_payload["executed"] is True
    assert download_calls == ["https://packages.example.com/demo.tgz"]
    assert len(launches) == 1
    assert launches[0][-3:] == [str(fake_npm), "install", f"demo@{archive_path}"]
    assert archive_path.exists() is False


def test_package_firewall_rejects_archive_blob_changed_after_inspection(tmp_path: Path) -> None:
    source_url = "https://packages.example.com/demo.tgz"
    archive_path = tmp_path / "changed-demo.tgz"
    original_payload = b"inspected archive"
    archive_path.write_bytes(original_payload)
    download = RestrictedArchiveDownload(
        path=archive_path,
        sha256=hashlib.sha256(original_payload).hexdigest(),
        size=len(original_payload),
        source_url=source_url,
        final_url=source_url,
    )
    archive_path.write_bytes(b"substituted archive")
    evaluation = SimpleNamespace(external_archive_downloads=(download,))

    bound = _bound_external_archive_launch_command(
        ["npm", "install", f"demo@{source_url}"],
        evaluation=evaluation,
    )

    assert bound is None


def test_mcp_package_forward_replaces_external_url_with_verified_blob(tmp_path: Path) -> None:
    source_url = "https://packages.example.com/demo.tgz"
    archive_payload = b"verified MCP archive"
    archive_path = tmp_path / "mcp-demo.tgz"
    archive_path.write_bytes(archive_payload)
    archive_path.chmod(0o400)
    download = RestrictedArchiveDownload(
        path=archive_path,
        sha256=hashlib.sha256(archive_payload).hexdigest(),
        size=len(archive_payload),
        source_url=source_url,
        final_url=source_url,
    )
    evaluation = SimpleNamespace(
        external_archive_downloads=(download,),
        reasons=({"code": "external_tarball_source"},),
    )
    original_arguments = {"command": f"npm install demo@{source_url}"}
    params = {
        "name": "shell",
        "arguments": original_arguments,
    }
    message = {"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": params}

    bound = _bound_external_archive_mcp_request(message, params, evaluation=evaluation)

    assert bound is not None
    bound_message, bound_params = bound
    bound_arguments = bound_params["arguments"]
    assert isinstance(bound_arguments, dict)
    assert bound_arguments["command"] == f"npm install demo@{archive_path}"
    assert bound_message["params"] == bound_params
    assert original_arguments["command"] == f"npm install demo@{source_url}"


def test_mcp_package_forward_shell_quotes_digest_bound_path(tmp_path: Path) -> None:
    source_url = "https://packages.example.com/demo.tgz"
    unsafe_root = tmp_path / "archive path;not-a-command"
    unsafe_root.mkdir()
    archive_path = unsafe_root / "demo.tgz"
    archive_payload = b"verified archive with unsafe path characters"
    archive_path.write_bytes(archive_payload)
    archive_path.chmod(0o400)
    download = RestrictedArchiveDownload(
        path=archive_path,
        sha256=hashlib.sha256(archive_payload).hexdigest(),
        size=len(archive_payload),
        source_url=source_url,
        final_url=source_url,
    )
    evaluation = SimpleNamespace(
        external_archive_downloads=(download,),
        external_archive_source_hashes=(hashlib.sha256(source_url.encode()).hexdigest(),),
    )
    params = {"name": "shell", "arguments": {"command": f"npm install demo@{source_url}"}}
    message = {"jsonrpc": "2.0", "id": 8, "method": "tools/call", "params": params}

    bound = _bound_external_archive_mcp_request(message, params, evaluation=evaluation)

    assert bound is not None
    _bound_message, bound_params = bound
    arguments = bound_params["arguments"]
    assert isinstance(arguments, dict)
    command = arguments["command"]
    assert isinstance(command, str)
    assert shlex.split(command) == ["npm", "install", f"demo@{archive_path}"]
