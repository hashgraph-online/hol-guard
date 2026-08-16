"""Tests for release toolchain verification, claim gating, and SBOM generation."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from scripts.write_release_toolchain_sbom import (
    ToolchainVerificationError,
    build_guard_secrets_claim_gate_command,
    resolve_release_commit,
    run_guard_secrets_claim_gate,
    write_release_toolchain_sbom,
)

ROOT = Path(__file__).resolve().parents[1]
_CAPABILITY_PATH = ROOT / "docs/guard/contracts/guard-secrets-capability-evidence.v2.json"


def _fake_uv(path: Path, version: str) -> Path:
    path.write_text(f"#!/bin/sh\nprintf 'uv {version}\\n'\n", encoding="utf-8")
    path.chmod(0o755)
    return path


def _required_capabilities() -> tuple[str, ...]:
    payload = json.loads(_CAPABILITY_PATH.read_text(encoding="utf-8"))
    return tuple(payload["claim_policy"]["required_capabilities"])


def test_release_toolchain_sbom_records_verified_version_and_executable_digest(
    tmp_path: Path,
) -> None:
    executable = _fake_uv(tmp_path / "uv", "0.9.26")
    output = tmp_path / "release-toolchain.cdx.json"
    payload = write_release_toolchain_sbom(
        output=output,
        release_version="3.0.0a1",
        expected_uv_version="0.9.26",
        setup_action_ref="fac544c07dec837d0ccb6301d7b5580bf5edae39",
        uv_executable=executable,
    )
    persisted = json.loads(output.read_text(encoding="utf-8"))
    expected_digest = hashlib.sha256(executable.read_bytes()).hexdigest()
    assert persisted == payload
    assert persisted["bomFormat"] == "CycloneDX"
    assert persisted["metadata"]["component"]["version"] == "3.0.0a1"
    assert persisted["components"][0]["version"] == "0.9.26"
    assert persisted["components"][0]["hashes"] == [{"alg": "SHA-256", "content": expected_digest}]


def test_release_toolchain_sbom_rejects_runtime_version_mismatch(
    tmp_path: Path,
) -> None:
    executable = _fake_uv(tmp_path / "uv", "0.9.27")
    output = tmp_path / "release-toolchain.cdx.json"
    with pytest.raises(ToolchainVerificationError, match="version mismatch"):
        write_release_toolchain_sbom(
            output=output,
            release_version="3.0.0a1",
            expected_uv_version="0.9.26",
            setup_action_ref="fac544c07dec837d0ccb6301d7b5580bf5edae39",
            uv_executable=executable,
        )
    assert not output.exists()


def test_release_toolchain_sbom_records_passed_claim_gate(tmp_path: Path) -> None:
    executable = _fake_uv(tmp_path / "uv", "0.9.26")
    command = (sys.executable, "gate.py", "--release-commit", "a" * 40)
    payload = write_release_toolchain_sbom(
        output=tmp_path / "release-toolchain.cdx.json",
        release_version="preflight",
        expected_uv_version="0.9.26",
        setup_action_ref="fac544c07dec837d0ccb6301d7b5580bf5edae39",
        uv_executable=executable,
        claim_gate_command=command,
        release_commit="a" * 40,
    )
    properties = payload["components"][0]["properties"]
    by_name = {item["name"]: item["value"] for item in properties}
    assert by_name["hol-guard:secrets-claim-gate"] == "passed"
    assert by_name["hol-guard:source-commit"] == "a" * 40
    assert (
        by_name["hol-guard:secrets-claim-gate-command-sha256"]
        == hashlib.sha256("\0".join(command).encode("utf-8")).hexdigest()
    )


def test_claim_gate_command_contains_every_authoritative_input() -> None:
    commit = "a" * 40
    command = build_guard_secrets_claim_gate_command(
        repository_root=ROOT,
        release_commit=commit,
        python_executable="python3",
    )
    assert command[:2] == (
        "python3",
        str(ROOT / "scripts/ci/guard_secrets_release_claim_gate.py"),
    )
    assert command[command.index("--release-commit") + 1] == commit
    assert command[command.index("--manifest") + 1].endswith("guard-secrets-capability-evidence.v2.json")
    assert command[command.index("--product-boundaries") + 1].endswith("guard-secrets-product-boundaries.v2.json")
    assert command[command.index("--source-capabilities") + 1].endswith("guard-secrets-source-capabilities.v2.json")
    assert command[command.index("--reason-codes") + 1].endswith("guard-secrets-reason-codes.v2.json")
    declared = tuple(command[index + 1] for index, value in enumerate(command) if value == "--required-capability")
    assert declared == _required_capabilities()
    assert "--require-parity" not in command


def test_claim_gate_command_includes_parity_flag_only_when_policy_enables_it(
    tmp_path: Path,
) -> None:
    capability = json.loads(_CAPABILITY_PATH.read_text(encoding="utf-8"))
    capability["claim_policy"]["public_parity_claim_enabled"] = True
    target = tmp_path / "docs/guard/contracts"
    target.mkdir(parents=True)
    (target / "guard-secrets-capability-evidence.v2.json").write_text(
        json.dumps(capability),
        encoding="utf-8",
    )
    command = build_guard_secrets_claim_gate_command(
        repository_root=tmp_path,
        release_commit="a" * 40,
    )
    assert "--require-parity" in command


def test_claim_gate_runs_successfully_for_current_disabled_claim_policy() -> None:
    command = run_guard_secrets_claim_gate(
        repository_root=ROOT,
        release_commit="a" * 40,
        python_executable=sys.executable,
    )
    assert "--require-parity" not in command


def test_claim_gate_runs_in_isolated_stdlib_python() -> None:
    command = build_guard_secrets_claim_gate_command(
        repository_root=ROOT,
        release_commit="a" * 40,
        python_executable=sys.executable,
    )
    isolated_command = (command[0], "-I", "-S", *command[1:])
    result = subprocess.run(
        isolated_command,
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


def test_claim_gate_subprocess_does_not_inject_pythonpath() -> None:
    completed = subprocess.CompletedProcess(
        args=(sys.executable,),
        returncode=0,
        stdout="",
        stderr="",
    )
    with patch(
        "scripts.write_release_toolchain_sbom.subprocess.run",
        return_value=completed,
    ) as run:
        run_guard_secrets_claim_gate(
            repository_root=ROOT,
            release_commit="a" * 40,
            python_executable=sys.executable,
        )
    assert "env" not in run.call_args.kwargs


def test_claim_gate_fails_closed_when_product_policy_drifts(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    for relative in (
        "src/codex_plugin_scanner/guard/secrets/contracts_v2.py",
        "scripts/ci/guard_secrets_release_claim_gate.py",
        "docs/guard/contracts/guard-secrets-capability-evidence.v2.json",
        "docs/guard/contracts/guard-secrets-product-boundaries.v2.json",
        "docs/guard/contracts/guard-secrets-source-capabilities.v2.json",
        "docs/guard/contracts/guard-secrets-reason-codes.v2.json",
    ):
        source = ROOT / relative
        destination = repository / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(source.read_bytes())
    product_path = repository / "docs/guard/contracts/guard-secrets-product-boundaries.v2.json"
    product = json.loads(product_path.read_text(encoding="utf-8"))
    product["invariants"] = ["local_detection_unmetered"]
    product_path.write_text(json.dumps(product), encoding="utf-8")
    with pytest.raises(ToolchainVerificationError, match="claim gate failed"):
        run_guard_secrets_claim_gate(
            repository_root=repository,
            release_commit="a" * 40,
            python_executable=sys.executable,
        )


def test_resolve_release_commit_returns_exact_checked_out_sha(tmp_path: Path) -> None:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(
        ["git", "-C", str(tmp_path), "config", "user.email", "ci@example.test"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(tmp_path), "config", "user.name", "CI"],
        check=True,
    )
    (tmp_path / "README.md").write_text("fixture\n", encoding="utf-8")
    subprocess.run(
        ["git", "-C", str(tmp_path), "add", "README.md"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(tmp_path), "commit", "-qm", "fixture"],
        check=True,
    )
    expected = subprocess.run(
        ["git", "-C", str(tmp_path), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    assert resolve_release_commit(tmp_path) == expected


def test_publish_workflow_attests_toolchain_sbom_without_sending_it_to_pypi() -> None:
    workflow = yaml.safe_load((ROOT / ".github/workflows/publish.yml").read_text(encoding="utf-8"))
    jobs = workflow["jobs"]
    build_steps = jobs["build"]["steps"]
    release_steps = jobs["release-alpha"]["steps"]
    preflight_index = next(
        index
        for index, step in enumerate(build_steps)
        if step.get("name") == "Verify release uv before dependency install"
    )
    install_index = next(index for index, step in enumerate(build_steps) if step.get("name") == "Install dependencies")
    assert preflight_index < install_index
    assert "scripts/write_release_toolchain_sbom.py" in build_steps[preflight_index]["run"]
    assert any(step.get("name") == "Upload release toolchain SBOM" for step in build_steps)
    assert any(step.get("name") == "Download release toolchain SBOM" for step in release_steps)
    assert all(
        step.get("name") != "Download release toolchain SBOM"
        for job_name in (
            "publish-testpypi",
            "publish-alpha-testpypi",
            "publish-alpha-pypi",
        )
        for step in jobs[job_name]["steps"]
    )
    provenance_step = next(step for step in release_steps if step.get("id") == "provenance")
    assert "dist/*" in provenance_step["with"]["subject-path"]


def test_publish_workflow_claim_gate_chain_is_fail_closed() -> None:
    script = (ROOT / "scripts/write_release_toolchain_sbom.py").read_text(encoding="utf-8")
    resolve_index = script.index("release_commit = resolve_release_commit(repository_root)")
    gate_index = script.index("claim_gate_command = run_guard_secrets_claim_gate(")
    sbom_index = script.index("write_release_toolchain_sbom(", gate_index)
    assert resolve_index < gate_index < sbom_index
    run_gate_start = script.index("def run_guard_secrets_claim_gate(")
    write_sbom_start = script.index("def write_release_toolchain_sbom(")
    run_gate_source = script[run_gate_start:write_sbom_start]
    assert "if result.returncode != 0:" in run_gate_source
    assert "raise ToolchainVerificationError(" in run_gate_source
    assert "PYTHONPATH" not in run_gate_source
    assert "env=" not in run_gate_source


def test_publish_workflow_limits_ambient_credentials_and_has_no_version_sync() -> None:
    workflow = yaml.safe_load((ROOT / ".github/workflows/publish.yml").read_text(encoding="utf-8"))
    jobs = workflow["jobs"]
    assert workflow["permissions"] == {
        "contents": "read",
        "pull-requests": "read",
    }
    assert "permissions" not in jobs["build"]
    assert "sync-repository-version" not in jobs
    assert "ACTION_REPO_TOKEN" not in (ROOT / ".github/workflows/publish.yml").read_text(encoding="utf-8")
    publish_uv_versions = {
        step["with"]["version"]
        for job in jobs.values()
        for step in job.get("steps", [])
        if str(step.get("uses", "")).startswith("astral-sh/setup-uv@")
    }
    assert publish_uv_versions == {"0.9.26"}
