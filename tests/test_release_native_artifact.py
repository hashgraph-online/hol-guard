"""Trusted artifact reuse refuses ambiguous provenance and unsafe archives."""

from __future__ import annotations

import copy
import hashlib
import io
import json
import stat
import urllib.request
import zipfile
from pathlib import Path

import pytest

from scripts.release import native_artifact as native
from scripts.release.prepared_native import transfer
from tests.release_workflow_helpers import load_workflow, native_target_matrix

ROOT = Path(__file__).resolve().parents[1]
TARGET = "x86_64-unknown-linux-musl"
SHA = "a" * 40


@pytest.fixture
def prepared(tmp_path, monkeypatch):
    values = {
        "SOURCE_SHA": SHA,
        "VERSION": "3.55.0",
        "PREPARED_NATIVE_BUILD_ID": "b" * 64,
        "RUST_TARGET": TARGET,
        "FAST_CODEGEN": "false",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REF": "refs/tags/v3.55.0",
        "GITHUB_RUN_ID": "99",
        "GITHUB_SHA": SHA,
        "GITHUB_REPOSITORY_ID": "123",
    }
    for key, value in values.items():
        monkeypatch.setenv(key, value)
    for key, name in (("RUNTIME", "runtime"), ("SOURCE_COMPILER", "compiler")):
        path = tmp_path / name
        path.write_bytes(name.encode())
        monkeypatch.setenv(key, str(path))
    directory = tmp_path / "original"
    transfer(directory, install=False)
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w") as archive:
        for path in directory.iterdir():
            archive.write(path, path.name)
    return directory, data.getvalue()


class FakeAPI:
    repo = "owner/repo"

    def __init__(self, data):
        self.data = data
        self.run = {
            "id": 7,
            "run_attempt": 2,
            "workflow_id": 42,
            "path": native.WORKFLOW,
            "event": "push",
            "head_branch": "main",
            "head_sha": SHA,
            "repository": {"id": 123, "full_name": self.repo},
            "head_repository": {"id": 123},
            # Another target need not finish before this target is reusable.
            "status": "in_progress",
            "conclusion": None,
        }
        self.job = {
            "id": 8,
            "run_id": 7,
            "run_attempt": 2,
            "head_sha": SHA,
            "name": f"Compile release ({TARGET})",
            "status": "completed",
            "conclusion": "success",
            "started_at": "2026-10-22T17:00:00Z",
            "completed_at": "2026-10-22T17:10:00Z",
        }
        self.artifact = {
            "id": 9,
            "name": native.PREFIX + TARGET,
            "expired": False,
            "created_at": "2026-10-22T17:09:00Z",
            "expires_at": "2099-01-01T00:00:00Z",
            "size_in_bytes": len(data),
            "digest": "sha256:" + hashlib.sha256(data).hexdigest(),
            "workflow_run": {
                "id": 7,
                "repository_id": 123,
                "head_repository_id": 123,
                "head_branch": "main",
                "head_sha": SHA,
            },
        }
        self.duplicates = False
        self.inventory = []
        self.unrelated_count = 0
        self.full_inventory_reads = 0

    def get(self, route):
        if route == "actions/workflows/release-native-prepare.yml":
            return {"id": 42, "path": native.WORKFLOW}
        if route.startswith("actions/workflows/42/runs?"):
            assert f"head_sha={SHA}" in route and "event=push&branch=main" in route
            return {"total_count": 1, "workflow_runs": [self.run]}
        if route == "actions/runs/7/attempts/2/jobs?per_page=100":
            return {"total_count": 1, "jobs": [self.job]}
        if route == "actions/runs/7/artifacts?per_page=100":
            artifacts = [self.artifact] * (2 if self.duplicates else 1)
            return {"total_count": len(artifacts), "artifacts": artifacts}
        if route.startswith("actions/artifacts?name="):
            name = route.split("name=", 1)[1].split("&", 1)[0]
            artifacts = [artifact for artifact in self.inventory if artifact["name"] == name]
            return {"total_count": len(artifacts), "artifacts": artifacts[:100]}
        if route.startswith("actions/artifacts?per_page=100&page="):
            self.full_inventory_reads += 1
            page = int(route.rsplit("=", 1)[1])
            return {
                "total_count": len(self.inventory) + self.unrelated_count,
                "artifacts": self.inventory[(page - 1) * 100 : page * 100],
            }
        raise AssertionError(route)

    def read(self, route, limit):
        assert route == "actions/artifacts/9/zip" and limit == native.MAX_ARTIFACT_BYTES
        return self.data


@pytest.mark.parametrize("nested", [False, True])
def test_completed_target_can_restore_while_other_targets_are_running(prepared, tmp_path, capsys, nested):
    _, data = prepared
    destination = tmp_path / "restored"
    api = FakeAPI(data)
    if nested:
        api.job["name"] = f"Prepare native release binaries ({TARGET}) / Compile release ({TARGET})"
    assert native.restore(api, destination)
    assert (destination / "runtime").read_bytes() == b"runtime"
    assert (destination / "compiler").read_bytes() == b"compiler"
    assert capsys.readouterr().out == "Verified prepared artifact from its successful trusted target job\n"


@pytest.mark.parametrize("target", sorted(native.TARGETS))
def test_nested_preparation_name_binds_both_parent_and_child_to_each_exact_target(prepared, monkeypatch, target):
    monkeypatch.setenv("RUST_TARGET", target)
    api = FakeAPI(prepared[1])
    api.job["name"] = f"Prepare native release binaries ({target}) / Compile release ({target})"
    api.artifact["name"] = native.PREFIX + target
    assert native.trusted_artifact(api) == api.artifact


def test_bare_and_nested_job_names_cannot_create_an_ambiguous_producer(prepared, monkeypatch):
    api = FakeAPI(prepared[1])
    original_get = api.get
    nested = {**api.job, "id": 10, "name": f"Prepare native release binaries ({TARGET}) / Compile release ({TARGET})"}

    def get(route):
        if route == "actions/runs/7/attempts/2/jobs?per_page=100":
            return {"total_count": 2, "jobs": [api.job, nested]}
        return original_get(route)

    monkeypatch.setattr(api, "get", get)
    with pytest.raises(ValueError, match="no unique"):
        native.trusted_artifact(api)


@pytest.mark.parametrize(
    ("record", "key", "value"),
    [
        ("run", "event", "pull_request"),
        ("run", "workflow_id", 43),
        ("run", "path", ".github/workflows/other.yml"),
        ("run", "head_branch", "feature"),
        ("run", "head_sha", "c" * 40),
        ("run", "repository", {"id": 123, "full_name": "another/repo"}),
        ("run", "head_repository", {"id": 456}),
        ("job", "name", "Compile release (another-target)"),
        ("job", "name", f"Other producer / Compile release ({TARGET})"),
        ("job", "name", f"Prepare native release binaries (another-target) / Compile release ({TARGET})"),
        ("job", "name", f"Prepare native release binaries ({TARGET}) / Compile release (another-target)"),
        ("job", "name", f"Prepare native release binaries ({TARGET}) / Compile release ({TARGET}) extra"),
        ("job", "run_id", 8),
        ("job", "run_attempt", 1),
        ("job", "head_sha", "c" * 40),
        ("job", "status", "in_progress"),
        ("job", "conclusion", "failure"),
        ("artifact", "expired", True),
        ("artifact", "expires_at", "2000-01-01T00:00:00Z"),
        ("artifact", "created_at", "2026-10-22T16:59:59Z"),
        ("artifact", "created_at", "2026-10-22T17:10:01Z"),
        ("artifact", "size_in_bytes", native.MAX_ARTIFACT_BYTES + 1),
        ("artifact", "digest", ""),
    ],
)
def test_provenance_mismatch_refuses_reuse(prepared, record, key, value):
    api = FakeAPI(prepared[1])
    getattr(api, record)[key] = value
    with pytest.raises(ValueError):
        native.trusted_artifact(api)


@pytest.mark.parametrize("key", ["id", "repository_id", "head_repository_id", "head_branch", "head_sha"])
def test_artifact_run_binding_is_mandatory(prepared, key):
    api = FakeAPI(prepared[1])
    api.artifact["workflow_run"][key] = "wrong"
    with pytest.raises(ValueError):
        native.trusted_artifact(api)


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("VERSION", "3.55.0a1"),
        ("FAST_CODEGEN", "true"),
        ("GITHUB_REF", "refs/heads/main"),
        ("GITHUB_EVENT_NAME", "pull_request"),
        ("GITHUB_SHA", "c" * 40),
        ("GITHUB_REPOSITORY_ID", "456"),
        ("PREPARED_NATIVE_BUILD_ID", ""),
    ],
)
def test_only_exact_stable_tag_consumers_are_eligible(prepared, monkeypatch, key, value):
    monkeypatch.setenv(key, value)
    with pytest.raises(ValueError):
        native.trusted_artifact(FakeAPI(prepared[1]))


def test_duplicate_artifacts_and_corrupt_downloads_are_refused(prepared, tmp_path):
    api = FakeAPI(prepared[1])
    api.duplicates = True
    with pytest.raises(ValueError):
        native.restore(api, tmp_path / "restored")
    api.duplicates = False
    api.data += b"corrupt"
    with pytest.raises(ValueError, match="digest/size"):
        native.restore(api, tmp_path / "restored")
    assert not (tmp_path / "restored").exists()


@pytest.mark.parametrize("mutation", ["sha", "version", "build-id", "runtime", "compiler"])
def test_manifest_and_both_hashes_remain_mandatory(prepared, tmp_path, mutation):
    directory, _ = prepared
    if mutation in ("runtime", "compiler"):
        (directory / mutation).write_bytes(b"changed")
    else:
        manifest = json.loads((directory / "identity.json").read_text())
        manifest[{"sha": "source_sha", "version": "version", "build-id": "build_id"}[mutation]] = "wrong"
        (directory / "identity.json").write_text(json.dumps(manifest))
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w") as archive:
        for path in directory.iterdir():
            archive.write(path, path.name)
    with pytest.raises(ValueError):
        native.restore(FakeAPI(data.getvalue()), tmp_path / "restored")
    assert not (tmp_path / "restored").exists()


@pytest.mark.parametrize("mutation", ["traversal", "nested", "duplicate", "symlink", "huge"])
def test_archive_rejects_unsupported_paths_types_and_expansion(prepared, tmp_path, mutation):
    directory, _ = prepared
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w") as archive:
        for path in directory.iterdir():
            name = path.name
            if name == "runtime" and mutation in ("traversal", "nested"):
                name = "../runtime" if mutation == "traversal" else "nested/runtime"
            entry = zipfile.ZipInfo(name)
            if name == "runtime" and mutation == "symlink":
                entry.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(entry, path.read_bytes())
        if mutation == "duplicate":
            archive.writestr("runtime", b"extra")
    if mutation == "huge":
        # Central-directory uncompressed size field; no large test allocation.
        content = bytearray(data.getvalue())
        offset = content.index(b"PK\x01\x02")
        content[offset + 24 : offset + 28] = native.MAX_ARTIFACT_BYTES.to_bytes(4, "little")
        data = io.BytesIO(content)
    destination = tmp_path / "staged"
    destination.mkdir()
    with pytest.raises(ValueError):
        native.extract(data.getvalue(), destination)


def test_upload_reserves_five_targets_and_obeys_optional_existing_budget(prepared, monkeypatch):
    monkeypatch.setattr(native, "stable_version_change", lambda: True)
    api = FakeAPI(prepared[1])
    assert native.upload_allowed(api, prepared[0])
    api.inventory = [copy.deepcopy(api.artifact)]
    with pytest.raises(ValueError, match="640 MiB"):
        native.upload_allowed(api, prepared[0])
    api.inventory[0]["workflow_run"]["id"] = 99
    assert native.upload_allowed(api, prepared[0])
    api.inventory[0]["workflow_run"]["id"] = 7
    api.inventory[0]["name"] = "other-feature"
    monkeypatch.setenv("RELEASE_NATIVE_ARTIFACT_BUDGET_BYTES", str(native.MAX_WARM_BYTES))
    with pytest.raises(ValueError, match="repository artifact budget"):
        native.upload_allowed(api, prepared[0])


def test_upload_size_ceiling_is_checked_before_any_upload(prepared, monkeypatch):
    monkeypatch.setattr(native, "stable_version_change", lambda: True)
    monkeypatch.setattr(native, "MAX_ARTIFACT_BYTES", 20)
    with pytest.raises(ValueError, match="128 MiB"):
        native.upload_allowed(FakeAPI(prepared[1]), prepared[0])


def test_unrelated_artifact_inventory_does_not_block_feature_budget(prepared, monkeypatch):
    monkeypatch.setattr(native, "stable_version_change", lambda: True)
    monkeypatch.delenv("RELEASE_NATIVE_ARTIFACT_BUDGET_BYTES", raising=False)
    api = FakeAPI(prepared[1])
    api.unrelated_count = 1001
    assert native.upload_allowed(api, prepared[0])
    assert api.full_inventory_reads == 0
    monkeypatch.setenv("RELEASE_NATIVE_ARTIFACT_BUDGET_BYTES", str(2 * native.MAX_WARM_BYTES))
    with pytest.raises(ValueError, match="repository artifact inventory exceeds bound"):
        native.upload_allowed(api, prepared[0])


def test_warm_family_inventory_overflow_still_declines_retention(prepared, monkeypatch):
    monkeypatch.setattr(native, "stable_version_change", lambda: True)
    api = FakeAPI(prepared[1])
    api.inventory = [copy.deepcopy(api.artifact) for _ in range(101)]
    with pytest.raises(ValueError, match="warm artifact family exceeds bounded"):
        native.upload_allowed(api, prepared[0])


def test_known_repo_budget_counts_active_artifacts_and_refuses_incomplete_inventory(prepared, monkeypatch):
    monkeypatch.setattr(native, "stable_version_change", lambda: True)
    api = FakeAPI(prepared[1])
    api.inventory = [copy.deepcopy(api.artifact) for _ in range(3)]
    for index, artifact in enumerate(api.inventory):
        artifact.update(id=index + 10, name="other-feature", size_in_bytes=10)
    api.inventory[1]["expired"] = True
    api.inventory[2]["workflow_run"]["id"] = 99
    monkeypatch.setenv("RELEASE_NATIVE_ARTIFACT_BUDGET_BYTES", str(native.MAX_WARM_BYTES + 10))
    assert native.upload_allowed(api, prepared[0])
    monkeypatch.setenv("RELEASE_NATIVE_ARTIFACT_BUDGET_BYTES", str(native.MAX_WARM_BYTES + 9))
    with pytest.raises(ValueError, match="repository artifact budget"):
        native.upload_allowed(api, prepared[0])
    api.unrelated_count = 1
    with pytest.raises(ValueError, match="inventory is incomplete"):
        native.upload_allowed(api, prepared[0])


@pytest.mark.parametrize("mutation", ["changed-count", "duplicate-id"])
def test_known_repo_budget_refuses_changed_or_duplicate_inventory(prepared, monkeypatch, mutation):
    monkeypatch.setattr(native, "stable_version_change", lambda: True)
    monkeypatch.setenv("RELEASE_NATIVE_ARTIFACT_BUDGET_BYTES", str(2 * native.MAX_WARM_BYTES))
    api = FakeAPI(prepared[1])
    api.inventory = [copy.deepcopy(api.artifact) for _ in range(101)]
    for index, artifact in enumerate(api.inventory):
        artifact.update(id=index + 10, name="other-feature")
    original_get = api.get

    def unstable_get(route):
        result = original_get(route)
        if route == "actions/artifacts?per_page=100&page=2":
            if mutation == "changed-count":
                result["total_count"] += 1
            else:
                result["artifacts"][0]["id"] = 10
        return result

    monkeypatch.setattr(api, "get", unstable_get)
    with pytest.raises(ValueError, match=r"inventory.*changed during admission"):
        native.upload_allowed(api, prepared[0])


@pytest.mark.parametrize(
    ("previous", "current", "eligible"),
    [("3.54.0", "3.55.0", True), ("3.55.0", "3.55.0", False), ("3.54.0", "3.54.0", False)],
)
def test_retention_requires_native_first_parent_manifest_version_change(
    prepared, tmp_path, monkeypatch, previous, current, eligible
):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("GITHUB_EVENT_NAME", "push")
    monkeypatch.setenv("GITHUB_REF", "refs/heads/main")
    (tmp_path / "pyproject.toml").write_text(f'[project]\nversion = "{current}"\n')
    calls = []

    def git_output(command, *, text):
        calls.append(command)
        assert text is True
        if command == ["git", "rev-parse", "HEAD"]:
            return SHA + "\n"
        assert command == ["git", "show", "HEAD^1:pyproject.toml"]
        return f'[project]\nversion = "{previous}"\n'

    monkeypatch.setattr(native.subprocess, "check_output", git_output)
    assert native.stable_version_change() is eligible
    assert len(calls) == 2


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("GITHUB_EVENT_NAME", "pull_request"),
        ("GITHUB_REF", "refs/heads/topic"),
        ("FAST_CODEGEN", "true"),
        ("VERSION", "3.55.0a1"),
    ],
)
def test_non_main_or_non_stable_retention_is_inert(prepared, monkeypatch, key, value):
    monkeypatch.setenv("GITHUB_EVENT_NAME", "push")
    monkeypatch.setenv("GITHUB_REF", "refs/heads/main")
    monkeypatch.setenv(key, value)
    monkeypatch.setattr(native.subprocess, "check_output", lambda *a, **k: pytest.fail("unexpected git read"))
    assert native.stable_version_change() is False


def test_main_cli_network_failure_is_explicit_compile_fallback(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(native, "API", lambda: (_ for _ in ()).throw(OSError("network")))
    monkeypatch.setattr("sys.argv", ["native_artifact", "restore"])
    output = tmp_path / "output"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    native.main()
    assert output.read_text() == "accepted=false\n"
    assert "normal compilation" in capsys.readouterr().out


def test_signed_download_redirect_never_forwards_api_authorization():
    request = urllib.request.Request("https://api.github.com/artifact", headers={"Authorization": "Bearer test"})
    redirect = native.SafeRedirect().redirect_request(
        request, None, 302, "Found", {}, "https://artifact.example/download"
    )
    assert not redirect.has_header("Authorization")
    with pytest.raises(ValueError, match="HTTPS"):
        native.SafeRedirect().redirect_request(request, None, 302, "Found", {}, "http://artifact.example/download")


def test_workflow_keeps_cache_artifact_and_compile_verification_gates():
    workflow = load_workflow(ROOT / ".github/workflows/release-native-prepare.yml")
    targets = {entry["target"] for entry in native_target_matrix(workflow["jobs"]["compile"])[""]}
    assert targets == native.TARGETS
    assert len(targets) * native.MAX_ARTIFACT_BYTES == native.MAX_WARM_BYTES
    steps = {step.get("name"): step for step in workflow["jobs"]["compile"]["steps"]}
    assert workflow["permissions"]["actions"] == "read"
    assert list(steps).index("Verify release enrollment root") < list(steps).index(
        "Restore retained trusted preparation"
    )
    assert "steps.native-artifact.outputs.accepted == 'true'" in steps["Verify restored native release inputs"]["if"]
    assert "self-test --json" in steps["Verify restored native release inputs"]["run"]
    for name in ("Install pinned Rust target", "Compile canonical release inputs", "Cache trusted release compilation"):
        assert "steps.native-artifact.outputs.accepted != 'true'" in steps[name]["if"]
    upload = steps["Retain stable version-change binaries"]
    assert upload["continue-on-error"] is True
    assert upload["with"]["retention-days"] == 1
    assert upload["with"]["compression-level"] == 0
    assert "native-retention.outputs.accepted == 'true'" in upload["if"]
    for name in (
        "Verify release enrollment root",
        "Verify restored native release inputs",
        "Compile canonical release inputs",
        "Upload exact-run binaries",
    ):
        assert steps[name].get("continue-on-error", False) is False
