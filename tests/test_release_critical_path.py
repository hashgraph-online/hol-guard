"""Release latency changes must preserve exact inputs and independent publish gates."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import urllib.error
from pathlib import Path

import pytest

from scripts.release import publish_core_inputs
from scripts.release.prepared_native import transfer
from scripts.release.ready_core_releases import ready_tags
from scripts.release.wait_for_core_publication import (
    attested_publication_identity,
    publication_ready,
    registry_ready,
    wait,
)
from tests.release_workflow_helpers import load_workflow

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(
    "workflow,publisher",
    [
        ("desktop-core-alpha-feed.yml", "publish-macos-arm64"),
        ("desktop-core-linux-feed.yml", "publish-linux-x64"),
    ],
)
def test_feed_registry_checks_keep_the_authorized_distribution_filename(workflow, publisher):
    steps = load_workflow(ROOT / ".github/workflows" / workflow)["jobs"][publisher]["steps"]
    authorization = next(step for step in steps if step.get("id") == "source")["run"]
    if "authorize_macos_core_source.sh" in authorization:
        authorization = (ROOT / "scripts/release/authorize_macos_core_source.sh").read_text()
    assert 'ATTESTED_WHEEL_FILENAME=$(basename "$WHEEL")' in authorization
    checks = [step["run"] for step in steps if "wait_for_core_publication.py" in step.get("run", "")]
    assert len(checks) == 2
    assert all('--filename "$ATTESTED_WHEEL_FILENAME"' in check for check in checks)
    assert all('--bundle "$RUNNER_TEMP/core-trust-assets/' in check for check in checks)
    registry = next(step for step in steps if step.get("id") == "registry")
    assert registry["env"]["GH_TOKEN"] == "${{ github.token }}"


@pytest.mark.parametrize("repaired", [False, True])
def test_scheduled_publication_identity_comes_from_verified_wheel_provenance(tmp_path, monkeypatch, repaired):
    wheel = tmp_path / "attested.whl"
    wheel.write_bytes(b"wheel")
    statement = {
        "subject": [{"digest": {"sha256": hashlib.sha256(wheel.read_bytes()).hexdigest()}}],
        "predicate": {
            "buildDefinition": {"resolvedDependencies": [{"digest": {"gitCommit": "c" * 40}}]},
            "runDetails": {
                "metadata": {
                    "invocationId": "https://github.com/hashgraph-online/hol-guard/actions/runs/123/attempts/1"
                }
            },
        },
    }
    bundle = tmp_path / "proof.jsonl"
    bundle.write_text(
        json.dumps({"dsseEnvelope": {"payload": base64.b64encode(json.dumps(statement).encode()).decode()}})
    )
    calls = []

    def verify(*args, **kwargs):
        calls.append(args[0])
        assert kwargs["check"] is True

    monkeypatch.setattr(subprocess, "run", verify)

    def api(command, **kwargs):
        if any("/statuses?" in item for item in command):
            assert "commits/" + "c" * 40 in command[3]
            return "https://github.com/hashgraph-online/hol-guard/actions/runs/456\n" if repaired else ""
        return json.dumps({"head_sha": "a" * 40})

    monkeypatch.setattr(subprocess, "check_output", api)
    assert attested_publication_identity(wheel, bundle, "hashgraph-online/hol-guard", version="3.34.1") == (
        "456" if repaired else "123",
        "a" * 40,
    )
    assert "--signer-workflow" in calls[0]
    wheel.write_bytes(b"wrong wheel")
    with pytest.raises(ValueError, match="bind the attested wheel"):
        attested_publication_identity(wheel, bundle, "hashgraph-online/hol-guard")

    def reject(*args, **kwargs):
        raise subprocess.CalledProcessError(1, args[0])

    monkeypatch.setattr(subprocess, "run", reject)
    with pytest.raises(subprocess.CalledProcessError):
        attested_publication_identity(wheel, bundle, "hashgraph-online/hol-guard")


@pytest.mark.parametrize("renamed", [False, True])
@pytest.mark.parametrize("state", ["missing-platform", "wrong-digest", "wrong-version", "ready"])
def test_registry_readiness_distinguishes_pending_uploads_from_corruption(tmp_path, monkeypatch, state, renamed):
    filename = "hol_guard-3.34.1-py3-none-macosx_11_0_arm64.whl"
    wheel = tmp_path / ("attested-macos-arm64.whl" if renamed else filename)
    wheel.write_bytes(b"attested wheel")
    metadata = {
        "info": {"version": "3.34.0" if state == "wrong-version" else "3.34.1"},
        "urls": [
            {
                "filename": "other-platform.whl" if state == "missing-platform" else filename,
                "digests": {
                    "sha256": "0" * 64 if state == "wrong-digest" else hashlib.sha256(wheel.read_bytes()).hexdigest()
                },
            }
        ],
    }
    monkeypatch.setattr("urllib.request.urlopen", lambda *args, **kwargs: io.BytesIO(json.dumps(metadata).encode()))
    if state in {"wrong-digest", "wrong-version"}:
        with pytest.raises(ValueError, match="mismatch"):
            registry_ready("3.34.1", wheel, filename if renamed else None)
    else:
        assert registry_ready("3.34.1", wheel, filename if renamed else None) is (state == "ready")


@pytest.mark.parametrize(
    "error",
    [urllib.error.URLError("temporary"), subprocess.CalledProcessError(1, ["gh"]), ValueError("failed publication")],
)
def test_publication_wait_retries_network_errors_but_rejects_failed_publication(tmp_path, monkeypatch, error):
    for key, value in {
        "PUBLICATION_RUN_ID": "123",
        "PUBLICATION_SOURCE_SHA": "a" * 40,
        "GITHUB_REPOSITORY": "hashgraph-online/hol-guard",
    }.items():
        monkeypatch.setenv(key, value)
    calls = []

    def ready(*args):
        calls.append(args)
        if len(calls) == 1:
            raise error
        return True

    monkeypatch.setattr("scripts.release.wait_for_core_publication.publication_ready", ready)
    monkeypatch.setattr("scripts.release.wait_for_core_publication.registry_ready", lambda *args: True)
    monkeypatch.setattr("scripts.release.wait_for_core_publication.time.sleep", lambda *args: None)
    if isinstance(error, ValueError):
        with pytest.raises(ValueError, match="failed publication"):
            wait("3.34.1", tmp_path / "wheel", timeout=1)
        assert len(calls) == 1
    else:
        wait("3.34.1", tmp_path / "wheel", timeout=1)
        assert len(calls) == 2


@pytest.mark.parametrize("conclusion,expected", [("success", True), (None, False), ("failure", None)])
def test_legacy_publication_requires_the_entire_attested_run_to_succeed(monkeypatch, conclusion, expected):
    def api(command, **kwargs):
        if "--paginate" in command:
            return ""
        return json.dumps(
            {
                "path": ".github/workflows/publish.yml",
                "event": "workflow_dispatch",
                "head_sha": "a" * 40,
                "conclusion": conclusion,
            }
        )

    monkeypatch.setattr(subprocess, "check_output", api)
    if expected is None:
        with pytest.raises(ValueError, match="failed"):
            publication_ready("hashgraph-online/hol-guard", "123", "a" * 40)
    else:
        assert publication_ready("hashgraph-online/hol-guard", "123", "a" * 40) is expected


def test_precompilation_stamps_a_requested_version_above_the_source_version(tmp_path):
    for name in ("pyproject.toml", "uv.lock", "src/codex_plugin_scanner/version.py", "scripts/sync_repo_version.py"):
        destination = tmp_path / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, destination)
    env = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
    subprocess.run(["git", "init", "--quiet"], cwd=tmp_path, env=env, check=True)
    subprocess.run(["git", "add", "."], cwd=tmp_path, env=env, check=True)
    subprocess.run(
        ["git", "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "--quiet", "-m", "fixture"],
        cwd=tmp_path,
        env=env,
        check=True,
    )
    source_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=tmp_path, env=env, text=True).strip()
    tools = tmp_path / "tools"
    tools.mkdir()
    uv = tools / "uv"
    uv.write_text(
        f"#!{sys.executable}\nimport subprocess,sys\n"
        "index=sys.argv.index('scripts/sync_repo_version.py')\n"
        "subprocess.run([sys.executable,*sys.argv[index:]],check=True)\n"
    )
    uv.chmod(0o755)
    source_version = subprocess.check_output(
        [sys.executable, "scripts/sync_repo_version.py", "--check"], cwd=tmp_path, text=True
    ).strip()
    major, minor, patch = source_version.split(".")
    requested = f"{major}.{minor}.{int(patch) + 1}"
    job = load_workflow(ROOT / ".github/workflows/release-native-prepare.yml")["jobs"]["compile"]
    identity = next(step for step in job["steps"] if step.get("name") == "Bind exact source and version")
    output = tmp_path / "environment"
    subprocess.run(
        ["bash", "-c", identity["run"]],
        cwd=tmp_path,
        check=True,
        env={
            **env,
            "PATH": f"{tools}{os.pathsep}{env['PATH']}",
            "SOURCE_SHA": source_sha,
            "VERSION": requested,
            "GITHUB_ENV": str(output),
        },
    )
    recorded = output.read_text()
    assert f"VERSION={requested}\n" in recorded
    assert f"HOL_GUARD_PACKAGE_VERSION={requested}\n" in recorded
    assert (
        subprocess.check_output(
            [sys.executable, "scripts/sync_repo_version.py", "--check"], cwd=tmp_path, text=True
        ).strip()
        == requested
    )


def native_environment(tmp_path, monkeypatch):
    paths = {}
    for key, name in [("RUNTIME", "runtime"), ("SOURCE_COMPILER", "compiler")]:
        path = tmp_path / name
        path.write_bytes(name.encode())
        monkeypatch.setenv(key, str(path))
        paths[key] = path
    monkeypatch.setenv("SOURCE_SHA", "a" * 40)
    monkeypatch.setenv("VERSION", "3.34.1")
    return paths


def test_prepared_binaries_reject_tampering_before_any_install(tmp_path, monkeypatch):
    paths = native_environment(tmp_path, monkeypatch)
    directory = tmp_path / "packed"
    transfer(directory, install=False)
    paths["RUNTIME"].write_bytes(b"existing")
    (directory / "compiler").write_bytes(b"changed")
    with pytest.raises(ValueError, match="hash mismatch"):
        transfer(directory, install=True)
    assert paths["RUNTIME"].read_bytes() == b"existing"


def test_prepared_binaries_bind_source_and_restore_executable(tmp_path, monkeypatch):
    paths = native_environment(tmp_path, monkeypatch)
    directory = tmp_path / "packed"
    transfer(directory, install=False)
    monkeypatch.setenv("SOURCE_SHA", "b" * 40)
    with pytest.raises(ValueError, match="source/version mismatch"):
        transfer(directory, install=True)
    monkeypatch.setenv("SOURCE_SHA", "a" * 40)
    paths["RUNTIME"].unlink()
    transfer(directory, install=True)
    assert paths["RUNTIME"].read_bytes() == b"runtime"
    assert paths["RUNTIME"].stat().st_mode & 0o111


def test_feed_discovery_skips_unfinished_and_ambiguous_releases(tmp_path):
    inventory = tmp_path / "releases.jsonl"
    wheel = "hol_guard-3.34.0-py3-none-macosx_11_0_arm64.whl"
    bundle = "hol-guard-v3.34.0.intoto.jsonl"
    inventory.write_text(
        "\n".join(
            json.dumps(item)
            for item in [
                {"tag": "v3.34.1", "assets": []},
                {"tag": "v3.34.0", "assets": [wheel, bundle]},
                {"tag": "v3.33.0", "assets": [wheel.replace("3.34.0", "3.33.0")]},
            ]
        )
    )
    assert ready_tags(inventory, "macosx_.*_arm64") == ["v3.34.0"]
    assert ready_tags(inventory, "manylinux_.*_x86_64") == []
    inventory.write_text(json.dumps({"tag": "v3.34.0", "assets": [wheel, bundle, wheel.replace("11_0", "13_0")]}))
    assert ready_tags(inventory, "macosx_.*_arm64") == []


def test_compilation_and_signing_run_beside_packaging_and_registry_verification():
    jobs = load_workflow(ROOT / ".github/workflows/publish.yml")["jobs"]
    assert jobs["precompile-native"]["needs"] == "authorize-release"
    assert jobs["build"]["needs"] == "authorize-release"
    assert jobs["build-native-guard-wheels"]["needs"] == ["build", "precompile-native"]
    assert "publish-main-pypi" not in jobs["publish-main-assets"]["needs"]
    assert jobs["wake-main-core-feeds"]["needs"] == ["build", "publish-main-assets"]
    assert "publish-main-pypi" in jobs["release-main"]["needs"]
    assert "publish-main-assets" in jobs["release-main"]["needs"]
    assert jobs["release-main"]["permissions"]["statuses"] == "write"
    assert "!cancelled()" in jobs["build-native-guard-wheels"]["if"]
    receipt = next(
        step for step in jobs["release-main"]["steps"] if step.get("name", "").startswith("Record completed stable")
    )
    assert 'context="hol-guard / published $VERSION"' in receipt["run"]
    warm = load_workflow(ROOT / ".github/workflows/release-native-prepare.yml")
    assert "pull_request" not in warm[True]
    cache = next(step for step in warm["jobs"]["compile"]["steps"] if "rust-cache@" in step.get("uses", ""))
    assert "github.event_name == 'push'" in cache["with"]["save-if"]
    assert "refs/heads/main" in cache["with"]["save-if"]
    assert jobs["publish-main-assets"]["steps"][0]["with"]["ref"] == "${{ github.sha }}"
    assert "needs.release-main.result == 'success'" in jobs["wake-final-core-feeds"]["if"]
    for name, publisher in [
        ("desktop-core-alpha-feed.yml", "publish-macos-arm64"),
        ("desktop-core-linux-feed.yml", "publish-linux-x64"),
    ]:
        steps = load_workflow(ROOT / ".github/workflows" / name)["jobs"][publisher]["steps"]
        gate = next(
            i
            for i, step in enumerate(steps)
            if step.get("name") == "Require verified registry publication before updater upload"
        )
        readiness = next(i for i, step in enumerate(steps) if step.get("id") == "registry")
        upload = next(i for i, step in enumerate(steps) if step.get("name") == "Publish immutable Core assets")
        signing = next(
            i for i, step in enumerate(steps) if step.get("name") == "Attest complete hardened Core asset set"
        )
        assert signing < gate < upload
        assert readiness < signing
        assert "steps.registry.outputs.registry_ready == 'true'" in steps[signing]["if"]


def test_early_asset_publication_rejects_a_different_tag_before_upload(tmp_path, monkeypatch):
    for key, value in {
        "VERSION": "3.34.1",
        "SOURCE_SHA": "a" * 40,
        "GITHUB_REPOSITORY": "hashgraph-online/hol-guard",
    }.items():
        monkeypatch.setenv(key, value)
    commands = []

    def fake_run(*args):
        commands.append(args)
        return "b" * 40 if args[1] == "rev-parse" else ""

    monkeypatch.setattr(publish_core_inputs, "run", fake_run)
    with pytest.raises(ValueError, match="tag does not match"):
        publish_core_inputs.publish(tmp_path)
    assert all(command[0] == "git" for command in commands)


def test_early_asset_publication_never_overwrites_an_existing_wheel(tmp_path, monkeypatch):
    for key, value in {
        "VERSION": "3.34.1",
        "SOURCE_SHA": "a" * 40,
        "GITHUB_REPOSITORY": "hashgraph-online/hol-guard",
    }.items():
        monkeypatch.setenv(key, value)
    wheel = tmp_path / "hol_guard-3.34.1-py3-none-any.whl"
    wheel.write_bytes(b"expected")
    release = {"draft": False, "prerelease": False, "assets": [{"name": wheel.name}]}
    monkeypatch.setattr(
        publish_core_inputs.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args=[], returncode=0, stdout=json.dumps(release)),
    )
    commands = []

    def fake_run(*args):
        commands.append(args)
        if args[:2] == ("git", "rev-parse"):
            return "a" * 40
        if args[:3] == ("gh", "release", "download"):
            Path(args[-1], wheel.name).write_bytes(b"different")
        return ""

    monkeypatch.setattr(publish_core_inputs, "run", fake_run)
    with pytest.raises(ValueError, match="immutable release asset differs"):
        publish_core_inputs.publish(tmp_path)
    assert not any(command[:3] == ("gh", "release", "upload") for command in commands)


@pytest.mark.parametrize("conclusion,expected", [("success", True), ("null", False), ("failure", None)])
def test_signed_core_waits_for_the_exact_registry_publish_job(monkeypatch, conclusion, expected):
    run = {
        "path": ".github/workflows/publish.yml",
        "event": "workflow_dispatch",
        "head_sha": "a" * 40,
        "conclusion": None,
    }

    def api(args, **kwargs):
        return conclusion + "\n" if "--paginate" in args else json.dumps(run)

    monkeypatch.setattr(subprocess, "check_output", api)
    if expected is None:
        with pytest.raises(ValueError, match="withholding updater"):
            publication_ready("hashgraph-online/hol-guard", "123", "a" * 40)
    else:
        assert publication_ready("hashgraph-online/hol-guard", "123", "a" * 40) is expected
    with pytest.raises(ValueError, match="authorized release dispatch"):
        publication_ready("hashgraph-online/hol-guard", "123", "b" * 40)


def test_no_public_release_is_created_before_manual_registry_success(tmp_path, monkeypatch):
    for key, value in {
        "VERSION": "3.34.1",
        "SOURCE_SHA": "a" * 40,
        "GITHUB_REPOSITORY": "hashgraph-online/hol-guard",
        "GITHUB_OUTPUT": str(tmp_path / "output"),
    }.items():
        monkeypatch.setenv(key, value)
    (tmp_path / "wheel.whl").write_bytes(b"fixture")
    commands = []

    def run(*args):
        commands.append(args)
        return "a" * 40 if args[:2] == ("git", "rev-parse") else ""

    monkeypatch.setattr(publish_core_inputs, "run", run)
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **k: subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="HTTP 404: Not Found"),
    )
    publish_core_inputs.publish(tmp_path)
    assert (tmp_path / "output").read_text() == "core_ready=false\n"
    assert all(command[0] == "git" for command in commands)
