"""Immutable directory snapshots reject altered assets and unsafe archives."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import stat
import sys
import zipfile
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "extension_artifact_bundle", ROOT / "scripts/extension_artifact_bundle.py"
)
bundle = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = bundle
spec.loader.exec_module(bundle)
spec = importlib.util.spec_from_file_location(
    "publish_extension_snapshot", ROOT / "scripts/publish_extension_snapshot.py"
)
publisher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publisher)
SHA = "a" * 40


@pytest.fixture
def snapshot(tmp_path, monkeypatch):
    root = tmp_path / "source"
    root.mkdir()
    for name in bundle.FILES:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps({key: "b" * 64 for key in ("catalog_digest", "program_digest", "implementation_digest")})
        )
    for name in bundle.DIRECTORIES:
        directory = root / name
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "command.example.json").write_text('{"id":"command.example"}')
    monkeypatch.setattr(bundle.subprocess, "check_output", lambda *args, **kwargs: SHA + "\n")
    output = tmp_path / "snapshot"
    bundle.create_bundle(root, output, SHA)
    return root, output


def test_snapshot_is_deterministic_and_source_bound(snapshot, tmp_path):
    root, output = snapshot
    second = tmp_path / "second"
    bundle.create_bundle(root, second, SHA)
    assert (output / bundle.ARCHIVE).read_bytes() == (second / bundle.ARCHIVE).read_bytes()
    assert (output / bundle.MANIFEST).read_bytes() == (second / bundle.MANIFEST).read_bytes()
    with pytest.raises(ValueError, match="identity"):
        bundle.verify_bundle(output, "c" * 40)
    with pytest.raises(ValueError, match="checkout"):
        bundle.create_bundle(root, second, "c" * 40)


@pytest.mark.parametrize("asset", [bundle.ARCHIVE, bundle.MANIFEST])
def test_altered_snapshot_is_rejected(snapshot, asset):
    _, output = snapshot
    if asset == bundle.ARCHIVE:
        with (output / asset).open("ab") as stream:
            stream.write(b"changed")
    else:
        manifest = json.loads((output / asset).read_bytes())
        manifest["files"][bundle.FILES[0]]["sha256"] = "0" * 64
        (output / asset).write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="digest"):
        bundle.verify_bundle(output, SHA)


def test_linked_source_is_rejected(snapshot):
    root, _ = snapshot
    path = root / bundle.FILES[-1]
    path.unlink()
    path.symlink_to(root / bundle.FILES[0])
    with pytest.raises(ValueError, match="symlink"):
        bundle.selected_files(root)


def test_archive_traversal_is_rejected_even_with_matching_digests(snapshot):
    _, output = snapshot
    name = "../escape.json"
    data = b"{}"
    with zipfile.ZipFile(output / bundle.ARCHIVE, "w") as archive:
        info = zipfile.ZipInfo(name)
        info.external_attr = (stat.S_IFREG | 0o644) << 16
        archive.writestr(info, data)
    manifest = json.loads((output / bundle.MANIFEST).read_bytes())
    manifest["files"] = {name: {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}}
    manifest["archive_sha256"] = hashlib.sha256((output / bundle.ARCHIVE).read_bytes()).hexdigest()
    (output / bundle.MANIFEST).write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="path"):
        bundle.verify_bundle(output, SHA)


class PublisherRemote:
    def __init__(self, output):
        self.output = output
        self.release = None
        self.calls = []
        self.uploads = []
        self.downloads = []
        self.created = False
        self.published = False
        self.tag_exists = False
        self.api_error = self.ref_error = self.commit_error = None
        self.commit_sha = SHA
        self.bad_download = False

    def set_release(self, draft, names):
        self.release = {"id": 123, "tag_name": "extension-artifacts-" + SHA,
                        "draft": draft, "target_commitish": SHA, "prerelease": True,
                        "assets": [{"id": 100 + i, "name": name} for i, name in enumerate(names)]}
        self.tag_exists = True

    def github(self, *args):
        self.calls.append(args)
        assert args[0] == "api"
        endpoint = args[1]
        if self.api_error:
            raise RuntimeError(self.api_error)
        method = args[args.index("--method") + 1] if "--method" in args else "GET"
        if method == "POST":
            assert endpoint == f"repos/{publisher.REPOSITORY}/releases"
            assert "draft=true" in args and "make_latest=false" in args
            assert "target_commitish=" + SHA in args
            self.set_release(True, [])
            self.tag_exists = False
            self.created = True
            return json.dumps(self.release)
        if method == "PATCH":
            assert endpoint.endswith("/releases/123")
            assert "draft=false" in args and "make_latest=false" in args
            assert set(self.downloads) == {bundle.ARCHIVE, bundle.MANIFEST}
            self.release["draft"] = False
            self.published = self.tag_exists = True
            return json.dumps(self.release)
        if "/git/ref/tags/" in endpoint:
            if self.ref_error or not self.tag_exists:
                raise RuntimeError(self.ref_error or "HTTP 404")
            return json.dumps({"object": {"sha": SHA, "type": "commit"}})
        if "/commits/" in endpoint:
            if self.commit_error or not self.tag_exists:
                raise RuntimeError(self.commit_error or "No commit found for SHA (HTTP 422)")
            return json.dumps({"sha": self.commit_sha})
        if "/releases/tags/" in endpoint:
            if self.release is None or self.release["draft"]:
                raise RuntimeError("HTTP 404")
            return json.dumps(self.release)
        assert "--paginate" in args
        # A newly created draft remains invisible to both tag and list queries.
        return json.dumps([[self.release]] if self.release and not self.created else [[]])

    def upload(self, release_id, path):
        assert release_id == 123 and self.release["draft"]
        assert path.name not in {a["name"] for a in self.release["assets"]}
        self.uploads.append(path.name)
        asset = {"id": 100 + len(self.release["assets"]), "name": path.name}
        self.release["assets"].append(asset)
        return asset

    def download(self, asset, destination):
        assert asset["id"] > 0
        self.downloads.append(asset["name"])
        destination.write_bytes(
            b"wrong existing asset" if self.bad_download else (self.output / asset["name"]).read_bytes()
        )


@pytest.fixture
def remote(snapshot, monkeypatch):
    state = PublisherRemote(snapshot[1])
    monkeypatch.setattr(publisher, "github", state.github)
    monkeypatch.setattr(publisher, "upload_asset", state.upload)
    monkeypatch.setattr(publisher, "download_asset", state.download)
    return state


@pytest.mark.parametrize("draft", [True, False])
def test_existing_matching_snapshot_is_verified_without_overwrite(snapshot, remote, draft):
    remote.set_release(draft, [bundle.ARCHIVE, bundle.MANIFEST])
    publisher.publish(snapshot[1], SHA)
    assert not remote.created and not remote.uploads
    assert set(remote.downloads) == {bundle.ARCHIVE, bundle.MANIFEST}
    assert remote.published is draft


@pytest.mark.parametrize("matching", [True, False])
def test_partial_draft_can_resume_but_mismatching_assets_cannot_be_replaced(snapshot, remote, matching):
    remote.set_release(True, [bundle.ARCHIVE])
    remote.bad_download = not matching
    if matching:
        publisher.publish(snapshot[1], SHA)
        assert remote.uploads == [bundle.MANIFEST]
        assert remote.published and len(remote.downloads) == 2
    else:
        with pytest.raises(ValueError, match="refusing to overwrite"):
            publisher.publish(snapshot[1], SHA)
        assert not remote.uploads and not remote.published


def test_new_snapshot_uses_create_response_until_downloaded_assets_verify(snapshot, remote):
    publisher.publish(snapshot[1], SHA)
    assert remote.created and remote.published
    assert set(remote.uploads) == {bundle.ARCHIVE, bundle.MANIFEST}
    assert len([c for c in remote.calls if "/commits/" in c[1]]) == 1
    created = next(i for i, c in enumerate(remote.calls) if "POST" in c)
    assert not any("/releases/tags/" in c[1] or "--paginate" in c for c in remote.calls[created + 1:])


def test_corrupt_new_upload_keeps_verified_draft_unpublished(snapshot, remote):
    remote.bad_download = True
    with pytest.raises(ValueError, match="uploaded snapshot differs"):
        publisher.publish(snapshot[1], SHA)
    assert remote.created and remote.uploads and remote.downloads
    assert remote.release["draft"] is True and not remote.published


@pytest.mark.parametrize("draft,status", [(False, 404), (True, 403), (True, 503)])
def test_tag_lookup_failures_are_only_tolerated_for_missing_draft_tags(snapshot, remote, draft, status):
    remote.set_release(draft, [])
    remote.ref_error = f"HTTP {status}"
    with pytest.raises(RuntimeError, match=str(status)):
        publisher.publish(snapshot[1], SHA)
    assert not remote.uploads and not remote.downloads and not remote.published


@pytest.mark.parametrize("commit_result", ["HTTP 404", "HTTP 503", "different-sha"])
def test_existing_draft_tag_must_resolve_to_its_verified_source(snapshot, remote, commit_result):
    remote.set_release(True, [])
    if commit_result.startswith("HTTP"):
        remote.commit_error = commit_result
    else:
        remote.commit_sha = "b" * 40
    error = RuntimeError if commit_result.startswith("HTTP") else ValueError
    with pytest.raises(error):
        publisher.publish(snapshot[1], SHA)
    assert not remote.uploads and not remote.downloads and not remote.published


def test_api_outage_does_not_create_a_replacement_release(snapshot, remote):
    remote.api_error = "HTTP 503"
    with pytest.raises(RuntimeError, match="503"):
        publisher.publish(snapshot[1], SHA)
    assert len(remote.calls) == 1 and not remote.created


def test_duplicate_release_assets_are_rejected_before_io(snapshot, remote):
    remote.set_release(True, [bundle.ARCHIVE, bundle.ARCHIVE])
    with pytest.raises(ValueError, match="duplicate"):
        publisher.publish(snapshot[1], SHA)
    assert not remote.downloads and not remote.uploads


@pytest.mark.parametrize("identity", [None, True, -1, "123"])
def test_release_identity_must_be_a_positive_integer(identity):
    with pytest.raises(ValueError, match="identity"):
        publisher.github_id(identity)


def test_upload_targets_fixed_host_without_redirecting_credentials(tmp_path, monkeypatch):
    import io
    path = tmp_path / bundle.ARCHIVE
    path.write_bytes(b"verified bytes")
    monkeypatch.setenv("GH_TOKEN", "synthetic-test-token")
    calls = []

    class Opener:
        def open(self, request, timeout):
            calls.append(request)
            assert request.full_url == f"https://uploads.github.com/repos/{publisher.REPOSITORY}/releases/123/assets?name={bundle.ARCHIVE}"
            assert request.get_header("Authorization") == "Bearer synthetic-test-token"
            assert request.data == b"verified bytes" and timeout == 120
            return io.BytesIO(json.dumps({"id": 456, "name": path.name}).encode())

    def opener(handler):
        assert isinstance(handler, publisher.RejectRedirects)
        assert handler.redirect_request(None, None, 302, "", {}, "https://other.example") is None
        return Opener()

    monkeypatch.setattr(publisher.urllib.request, "build_opener", opener)
    assert publisher.upload_asset(123, path)["id"] == 456
    assert len(calls) == 1


def test_asset_download_preserves_binary_bytes_and_uses_numeric_id(tmp_path, monkeypatch):
    output = tmp_path / "download.zip"

    def run(args, **kwargs):
        assert args == [
            "gh", "api", f"repos/{publisher.REPOSITORY}/releases/assets/456",
            "--header", "Accept: application/octet-stream",
        ]
        assert kwargs["timeout"] == 120
        kwargs["stdout"].write(b"binary\xff\x00")
        return publisher.subprocess.CompletedProcess(args, 0, stderr=b"")

    monkeypatch.setattr(publisher.subprocess, "run", run)
    publisher.download_asset({"id": 456}, output)
    assert output.read_bytes() == b"binary\xff\x00"
    with pytest.raises(FileExistsError):
        publisher.download_asset({"id": 456}, output)


def test_publication_is_postmerge_and_never_writes_a_branch():
    workflow = yaml.safe_load((ROOT / ".github/workflows/extension-artifact-regen.yml").read_text())
    events = workflow.get("on", workflow.get(True))
    assert set(events) == {"push", "workflow_dispatch"}
    assert events["push"]["branches"] == ["main"]
    assert workflow["concurrency"]["cancel-in-progress"] is False
    commands = "\n".join(step.get("run", "") for step in workflow["jobs"]["regen"]["steps"])
    assert "git push" not in commands and "gh pr create" not in commands
    assert "scripts/publish_extension_snapshot.py" in commands


def test_legacy_directory_changes_are_accepted_by_existing_path_gate():
    workflow = (ROOT / ".github/workflows/generated-artifacts-guard.yml").read_text()
    assert "owned+='|^docs/guard/extensions/" not in workflow
    assert "native-command-program|command-catalog" in workflow
