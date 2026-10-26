"""Registry uploads require published, downloaded, source-bound native assets."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import zipfile
from pathlib import Path

import pytest

from scripts.release import publish_core_inputs as publisher
from scripts.verify_native_runtime_release import EXPECTED_TARGETS, NativeReleaseError
from tests.release_workflow_helpers import load_workflow

SOURCE = "a" * 40


def distributions(directory: Path, version: str) -> None:
    digests = {}
    for platform, target in EXPECTED_TARGETS.items():
        path = directory / f"hol_guard-{version}-py3-none-{platform}.whl"
        runtime = b"native-runtime"
        manifest = dict(
            schema="hol-guard-native-runtime.v1",
            protocol_version=1,
            package_version=version,
            target=target,
            platform_tag=platform,
            source_sha=SOURCE,
            rule_digest="b" * 64,
            runtime_sha256=hashlib.sha256(runtime).hexdigest(),
            runtime_size=len(runtime),
        )
        executable = "hol-guard-runtime.exe" if platform.startswith("win") else "hol-guard-runtime"
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("codex_plugin_scanner/_native/runtime-manifest.json", json.dumps(manifest))
            archive.writestr("codex_plugin_scanner/_native/" + executable, runtime)
        digests[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
    with zipfile.ZipFile(directory / f"hol_guard-{version}-py3-none-any.whl", "w") as archive:
        archive.writestr(
            "codex_plugin_scanner/native-wheels.json",
            json.dumps(
                dict(
                    schema="hol-guard-native-wheels.v1",
                    version=version,
                    wheels=digests,
                )
            ),
        )
    (directory / f"hol_guard-{version}.tar.gz").write_bytes(b"sdist")
    (directory / f"hol-guard-v{version}.intoto.jsonl").write_bytes(b"provenance")


def remote(monkeypatch, directory, version, channel, *, failure=None, existing=False, draft=False):
    for key, value in dict(
        VERSION=version,
        SOURCE_SHA=SOURCE,
        CHANNEL=channel,
        GITHUB_REPOSITORY="hashgraph-online/hol-guard",
        GITHUB_SHA=SOURCE,
        GITHUB_OUTPUT=str(directory.parent / "output"),
    ).items():
        monkeypatch.setenv(key, value)
    assets = {path.name: path.read_bytes() for path in directory.iterdir()} if existing else {}
    state = dict(isDraft=not existing or draft, isPrerelease=channel != "stable")
    commands = []

    def run(*args):
        commands.append(args)
        if args[:2] == ("git", "rev-parse"):
            return SOURCE
        if args[:3] == ("gh", "release", "view"):
            return json.dumps(dict(state, assets=[dict(name=name) for name in assets]))
        if args[:3] == ("gh", "release", "upload"):
            if failure == "upload":
                raise subprocess.CalledProcessError(1, args)
            path = Path(args[4])
            assets[path.name] = path.read_bytes()
        if args[:3] == ("gh", "release", "download"):
            name = args[args.index("--pattern") + 1]
            if failure == "missing" and "win_arm64" in name:
                raise subprocess.CalledProcessError(1, args)
            content = assets[name]
            if failure == "bytes" and "macosx_13" in name:
                content = b"wrong remote bytes"
            Path(args[-1], name).write_bytes(content)
        if args[:3] == ("gh", "attestation", "verify") and failure == "provenance":
            raise subprocess.CalledProcessError(1, args)
        if args[:3] == ("gh", "release", "edit"):
            state["isDraft"] = False
        return ""

    lookup = dict(state, assets=[dict(name=name) for name in assets])
    monkeypatch.setattr(publisher, "run", run)
    monkeypatch.setattr(
        publisher.subprocess,
        "run",
        lambda *a, **k: subprocess.CompletedProcess(
            args=[],
            returncode=0 if existing else 1,
            stdout=json.dumps(lookup),
            stderr="" if existing else "HTTP 404",
        ),
    )
    return commands


@pytest.mark.parametrize("channel,version", [("stable", "3.49.0"), ("alpha", "3.49.0a1"), ("canary", "3.49.0.dev1")])
def test_missing_release_is_published_only_after_all_platform_downloads(tmp_path, monkeypatch, channel, version):
    directory = tmp_path / "dist"
    directory.mkdir()
    distributions(directory, version)
    commands = remote(monkeypatch, directory, version, channel)
    publisher.publish(directory)
    edits = [i for i, command in enumerate(commands) if command[:3] == ("gh", "release", "edit")]
    downloads = [i for i, command in enumerate(commands) if command[:3] == ("gh", "release", "download")]
    assert len(downloads) == 9  # Six native wheels, pure wheel, sdist and provenance.
    assert max(downloads) < edits[0]
    assert (tmp_path / "output").read_text() == "core_ready=true\n"


@pytest.mark.parametrize("draft", [False, True])
def test_existing_release_or_draft_resumes_without_replacing_assets(tmp_path, monkeypatch, draft):
    directory = tmp_path / "dist"
    directory.mkdir()
    distributions(directory, "3.49.0")
    commands = remote(monkeypatch, directory, "3.49.0", "stable", existing=True, draft=draft)
    publisher.publish(directory)
    assert not any(command[:3] in {("gh", "release", "create"), ("gh", "release", "upload")} for command in commands)
    assert (tmp_path / "output").read_text() == "core_ready=true\n"


def test_existing_release_native_digest_collision_blocks_readiness(tmp_path, monkeypatch):
    directory = tmp_path / "dist"
    directory.mkdir()
    distributions(directory, "3.49.0")
    remote(monkeypatch, directory, "3.49.0", "stable", existing=True, failure="bytes")
    with pytest.raises(ValueError, match="immutable release asset differs"):
        publisher.publish(directory)
    assert not (tmp_path / "output").exists()


@pytest.mark.parametrize("failure", ["upload", "missing", "bytes", "provenance"])
def test_remote_failure_never_reports_readiness(tmp_path, monkeypatch, failure):
    directory = tmp_path / "dist"
    directory.mkdir()
    distributions(directory, "3.49.0")
    commands = remote(monkeypatch, directory, "3.49.0", "stable", failure=failure)
    with pytest.raises((ValueError, subprocess.CalledProcessError)):
        publisher.publish(directory)
    assert not (tmp_path / "output").exists()
    assert all(command[:3] != ("gh", "release", "edit") for command in commands)


@pytest.mark.parametrize("failure", ["platform", "source"])
def test_invalid_local_identity_cannot_start_remote_publication(tmp_path, monkeypatch, failure):
    directory = tmp_path / "dist"
    directory.mkdir()
    distributions(directory, "3.49.0")
    commands = remote(monkeypatch, directory, "3.49.0", "stable")
    if failure == "platform":
        next(directory.glob("*win_arm64.whl")).unlink()
    else:
        monkeypatch.setenv("SOURCE_SHA", "c" * 40)
    with pytest.raises(NativeReleaseError):
        publisher.publish(directory)
    assert not commands


def test_all_registry_actions_are_blocked_by_the_remote_asset_gate():
    root = Path(__file__).resolve().parents[1]
    jobs = load_workflow(root / ".github/workflows/publish.yml")["jobs"]
    registry_jobs = {
        name
        for name, job in jobs.items()
        if any("pypa/gh-action-pypi-publish@" in step.get("uses", "") for step in job.get("steps", []))
    }
    assert len(registry_jobs) == 5
    for name in registry_jobs:
        assert "publish-main-assets" in jobs[name]["needs"]
        assert "needs.publish-main-assets.result == 'success'" in jobs[name]["if"]
    assert "publish-installed-bundle-assets" in jobs["assemble-native-guard-distributions"]["needs"]

    # Walk the actual needs graph: no registry path can run before assets or create a cycle.
    def visit(name, ancestors):
        assert name not in ancestors
        needs = jobs[name].get("needs", [])
        for dependency in [needs] if isinstance(needs, str) else needs:
            visit(dependency, ancestors | {name})

    for name in jobs:
        visit(name, set())


@pytest.mark.parametrize("job_name", ["publish-main-assets", "publish-installed-bundle-assets"])
@pytest.mark.parametrize("build_result", ["success", "failure"])
@pytest.mark.parametrize(
    "same_repo,labelled,cancelled,allowed",
    [
        (True, True, False, True),
        (False, True, False, False),
        (True, False, False, False),
        (True, True, True, False),
    ],
)
def test_canary_asset_mutation_requires_explicit_trusted_eligibility(
    job_name, build_result, same_repo, labelled, cancelled, allowed
):
    root = Path(__file__).resolve().parents[1]
    condition = load_workflow(root / ".github/workflows/publish.yml")["jobs"][job_name]["if"]
    # The alpha resolver is skipped for PRs. Override implicit success() for
    # descendants too, while retaining the successful-build and cancellation gates.
    assert condition.startswith("always() && !cancelled() &&")
    values = {
        "always()": True,
        "!cancelled()": not cancelled,
        "needs.build.result": build_result,
        "needs.assemble-native-guard-distributions.result": "success",
        "needs.build.outputs.channel": "canary",
        "needs.reserve-main-tag.result": "skipped",
        "needs.reserve-alpha-tag.result": "skipped",
        "github.event_name": "pull_request",
        "github.event.pull_request.head.repo.full_name": "owner/repo" if same_repo else "fork/repo",
        "github.repository": "owner/repo",
        "vars.PR_CANARY_PUBLISHING_ENABLED": "true",
        "vars.RELEASE_PUBLISHING_ENABLED": "false",
        "github.run_attempt": 1,
        "github.ref": "refs/pull/1/merge",
        "github.event.inputs.release_train": "main",
        "github.event.inputs.release_version": "3.49.0",
        "github.event.inputs.release_channel": "stable",
        "contains(github.event.pull_request.labels.*.name, 'publish-testpypi-canary')": labelled,
    }
    for key in sorted(values, key=len, reverse=True):
        condition = condition.replace(key, repr(values[key]))
    assert eval(condition.replace("&&", " and ").replace("||", " or "), {"__builtins__": {}}) is (
        allowed and build_result == "success"
    )


@pytest.mark.parametrize("release_status", [0, 1])
def test_alpha_cleanup_keeps_release_tags_and_fails_closed_on_lookup_errors(tmp_path, release_status):
    fake_gh = tmp_path / "gh"
    fake_gh.write_text(f'#!/bin/sh\nprintf "%s\\n" "$*" >> "$CALLS"\necho "lookup error" >&2\nexit {release_status}\n')
    fake_gh.chmod(0o700)
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        ["/bin/bash", str(root / "scripts/release_unpublished_alpha_reservation.sh")],
        cwd=tmp_path,
        env={
            "PATH": f"{tmp_path}:/usr/bin:/bin",
            "VERSION": "3.49.0a1",
            "SOURCE_SHA": SOURCE,
            "GITHUB_REPOSITORY": "hashgraph-online/hol-guard",
            "CALLS": str(tmp_path / "calls"),
        },
        capture_output=True,
        text=True,
    )
    assert result.returncode == release_status
    assert (tmp_path / "calls").read_text().splitlines() == [
        "release view alpha/v3.49.0a1 --repo hashgraph-online/hol-guard --json isDraft"
    ]


@pytest.mark.parametrize("channel", ["stable", "alpha"])
@pytest.mark.parametrize("provenance_fails", [False, True])
def test_existing_release_finalization_checks_assets_before_updating_metadata(tmp_path, channel, provenance_fails):
    root = Path(__file__).resolve().parents[1]
    jobs = load_workflow(root / ".github/workflows/publish.yml")["jobs"]
    job = jobs["release-main" if channel == "stable" else "release-alpha"]
    step = next(step for step in job["steps"] if step.get("name", "").startswith("Create discoverable"))
    directory = tmp_path / "dist"
    directory.mkdir()
    distributions(directory, "3.49.0" if channel == "stable" else "3.49.0a1")
    (tmp_path / "release-notes.md").write_text("Final release notes")
    # Execute the actual workflow shell. Only external GitHub/inventory IO is faked;
    # file comparison, existing-release branching, failure propagation and edits run.
    shims = r"""
    git() { case "$1" in rev-parse) echo "$SOURCE_SHA";; ls-remote) echo "$SOURCE_SHA refs/tags/release";; esac; }
    mapfile() { local_files=(dist/*); }
    jq() { cat >/dev/null; }
    python() { return 0; }
    gh() {
      echo "$*" >> "$CALLS"
      if [[ "$1 $2" == "release view" ]]; then
        echo "{\"isDraft\":false,\"isPrerelease\":$PRERELEASE,\"assets\":[]}"
      elif [[ "$1 $2" == "release download" ]]; then
        while [[ "$1" != "--dir" ]]; do shift; done
        cp dist/* "$2/"
      elif [[ "$1 $2" == "attestation verify" ]]; then
        [[ "$PROVENANCE_FAILS" == "false" ]]
      elif [[ "$1 $2" == "release create" ]]; then
        return 91
      fi
    }
    """
    script = tmp_path / "finalize.sh"
    script.write_text("set -euo pipefail\n" + shims + step["run"])
    result = subprocess.run(
        ["/bin/bash", str(script)],
        cwd=tmp_path,
        env=dict(
            os.environ,
            VERSION="3.49.0" if channel == "stable" else "3.49.0a1",
            SOURCE_SHA=SOURCE,
            GITHUB_REPOSITORY="hashgraph-online/hol-guard",
            RUNNER_TEMP=str(tmp_path),
            RELEASE_REPAIR="false",
            WORKFLOW_GH_TOKEN="test",
            CALLS=str(tmp_path / "calls"),
            PRERELEASE="false" if channel == "stable" else "true",
            PROVENANCE_FAILS=str(provenance_fails).lower(),
        ),
        capture_output=True,
        text=True,
    )
    commands = (tmp_path / "calls").read_text().splitlines()
    edits = [command for command in commands if command.startswith("release edit")]
    assert (result.returncode != 0) == provenance_fails, result.stderr
    assert bool(edits) != provenance_fails
    if not provenance_fails:
        assert any("--notes-file" in command for command in edits)
        if channel == "stable":
            assert any("--latest" in command for command in edits)
    assert not any(command.startswith("release create") for command in commands)
