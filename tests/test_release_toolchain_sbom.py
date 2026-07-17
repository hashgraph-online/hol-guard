"""Tests for release toolchain verification and SBOM generation."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
import yaml

from scripts.write_release_toolchain_sbom import ToolchainVerificationError, write_release_toolchain_sbom

ROOT = Path(__file__).resolve().parents[1]


def _fake_uv(path: Path, version: str) -> Path:
    path.write_text(f"#!/bin/sh\nprintf 'uv {version}\\n'\n", encoding="utf-8")
    path.chmod(0o755)
    return path


def test_release_toolchain_sbom_records_verified_version_and_executable_digest(tmp_path: Path) -> None:
    executable = _fake_uv(tmp_path / "uv", "0.9.26")
    output = tmp_path / "release-toolchain.cdx.json"

    payload = write_release_toolchain_sbom(
        output=output,
        release_version="2.0.1089",
        expected_uv_version="0.9.26",
        setup_action_ref="fac544c07dec837d0ccb6301d7b5580bf5edae39",
        uv_executable=executable,
    )

    persisted = json.loads(output.read_text(encoding="utf-8"))
    expected_digest = hashlib.sha256(executable.read_bytes()).hexdigest()
    assert persisted == payload
    assert persisted["bomFormat"] == "CycloneDX"
    assert persisted["metadata"]["component"]["version"] == "2.0.1089"
    assert persisted["components"][0]["version"] == "0.9.26"
    assert persisted["components"][0]["hashes"] == [{"alg": "SHA-256", "content": expected_digest}]


def test_release_toolchain_sbom_rejects_runtime_version_mismatch(tmp_path: Path) -> None:
    executable = _fake_uv(tmp_path / "uv", "0.9.27")
    output = tmp_path / "release-toolchain.cdx.json"

    with pytest.raises(ToolchainVerificationError, match="version mismatch"):
        write_release_toolchain_sbom(
            output=output,
            release_version="2.0.1089",
            expected_uv_version="0.9.26",
            setup_action_ref="fac544c07dec837d0ccb6301d7b5580bf5edae39",
            uv_executable=executable,
        )

    assert not output.exists()


def test_publish_workflow_attests_toolchain_sbom_without_sending_it_to_pypi() -> None:
    workflow = yaml.safe_load((ROOT / ".github" / "workflows" / "publish.yml").read_text(encoding="utf-8"))
    jobs = workflow["jobs"]
    build_steps = jobs["build"]["steps"]
    release_steps = jobs["release"]["steps"]

    preflight_index = next(
        index
        for index, step in enumerate(build_steps)
        if step.get("name") == "Verify release uv before dependency install"
    )
    install_index = next(index for index, step in enumerate(build_steps) if step.get("name") == "Install dependencies")
    assert preflight_index < install_index
    assert any(step.get("name") == "Upload release toolchain SBOM" for step in build_steps)
    assert any(step.get("name") == "Download release toolchain SBOM" for step in release_steps)
    assert all(
        step.get("name") != "Download release toolchain SBOM"
        for job_name in ("publish-testpypi", "publish-pypi")
        for step in jobs[job_name]["steps"]
    )
    provenance_step = next(step for step in release_steps if step.get("id") == "provenance")
    assert "dist/*" in provenance_step["with"]["subject-path"]


def test_publish_workflow_limits_ambient_credentials_for_build_and_version_sync() -> None:
    workflow = yaml.safe_load((ROOT / ".github" / "workflows" / "publish.yml").read_text(encoding="utf-8"))
    jobs = workflow["jobs"]
    sync_job = jobs["sync-repository-version"]

    assert workflow["permissions"] == {"contents": "read"}
    assert "permissions" not in jobs["build"]
    assert sync_job["permissions"] == {"contents": "read"}
    token_steps = [step.get("name") for step in sync_job["steps"] if "ACTION_REPO_TOKEN" in (step.get("env") or {})]
    assert token_steps == ["Open repository version sync PR"]

    publish_uv_versions = {
        step["with"]["version"]
        for job in jobs.values()
        for step in job.get("steps", [])
        if str(step.get("uses", "")).startswith("astral-sh/setup-uv@")
    }
    assert publish_uv_versions == {"0.9.26"}
