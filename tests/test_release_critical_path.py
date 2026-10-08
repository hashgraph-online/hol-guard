"""Release latency changes must preserve exact inputs and independent publish gates."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from scripts.release import publish_core_inputs
from scripts.release.prepared_native import transfer
from scripts.release.ready_core_releases import ready_tags
from tests.release_workflow_helpers import load_workflow

ROOT = Path(__file__).resolve().parents[1]


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
    warm = load_workflow(ROOT / ".github/workflows/release-native-prepare.yml")
    assert "pull_request" not in warm[True]
    cache = next(step for step in warm["jobs"]["compile"]["steps"] if "rust-cache@" in step.get("uses", ""))
    assert "github.event_name == 'push'" in cache["with"]["save-if"]
    assert "refs/heads/main" in cache["with"]["save-if"]


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
