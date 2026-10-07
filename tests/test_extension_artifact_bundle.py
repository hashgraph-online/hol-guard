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


@pytest.mark.parametrize("draft", [True, False])
def test_existing_matching_snapshot_is_verified_without_overwrite(snapshot, monkeypatch, draft):
    _, output = snapshot
    calls = []

    def github(*args):
        calls.append(args)
        if args[0] == "api":
            if "/commits/" in args[1]:
                return json.dumps({"sha": SHA})
            if draft and "/releases/tags/" in args[1]:
                raise RuntimeError("HTTP 404")
            release = {
                "tag_name": "extension-artifacts-" + SHA,
                "draft": draft,
                "target_commitish": SHA,
                "prerelease": True,
                "assets": [{"name": n} for n in (bundle.ARCHIVE, bundle.MANIFEST)],
            }
            return json.dumps([[release]] if "--paginate" in args else release)
        if args[1] == "download":
            name = args[args.index("--pattern") + 1]
            destination = Path(args[args.index("--dir") + 1])
            (destination / name).write_bytes((output / name).read_bytes())
        return ""

    monkeypatch.setattr(publisher, "github", github)
    publisher.publish(output, SHA)
    assert not any("upload" in call or "create" in call for call in calls)
    assert any("edit" in call for call in calls) is draft


@pytest.mark.parametrize("matching", [True, False])
def test_partial_draft_can_resume_but_mismatching_assets_cannot_be_replaced(snapshot, monkeypatch, matching):
    _, output = snapshot
    calls = []

    def github(*args):
        calls.append(args)
        if args[0] == "api":
            return (
                json.dumps({"sha": SHA})
                if "/commits/" in args[1]
                else json.dumps(
                    {"draft": True, "target_commitish": SHA, "prerelease": True, "assets": [{"name": bundle.ARCHIVE}]}
                )
            )
        if args[1] == "download":
            destination = Path(args[args.index("--dir") + 1])
            name = args[args.index("--pattern") + 1]
            (destination / name).write_bytes((output / name).read_bytes() if matching else b"wrong existing asset")
        return ""

    monkeypatch.setattr(publisher, "github", github)
    if matching:
        publisher.publish(output, SHA)
        uploads = [call for call in calls if "upload" in call]
        assert len(uploads) == 1 and str(output / bundle.MANIFEST) in uploads[0]
        assert any("edit" in call for call in calls)
        assert len([call for call in calls if "download" in call]) == 2
    else:
        with pytest.raises(ValueError, match="refusing to overwrite"):
            publisher.publish(output, SHA)
        assert not any("upload" in call or "edit" in call for call in calls)


def test_new_snapshot_stays_draft_until_downloaded_assets_verify(snapshot, monkeypatch):
    _, output = snapshot
    calls = []
    created = False
    published = False

    def github(*args):
        nonlocal created, published
        calls.append(args)
        if args[0] == "api":
            if "/git/ref/tags/" in args[1] and not published:
                raise RuntimeError("HTTP 404")
            if "/commits/" in args[1]:
                if not published:
                    raise RuntimeError("No commit found for SHA (HTTP 422)")
                return json.dumps({"sha": SHA})
            if not created:
                if "/releases/tags/" in args[1]:
                    raise RuntimeError("HTTP 404")
                return json.dumps([[]])
            if "/releases/tags/" in args[1]:
                raise RuntimeError("HTTP 404")
            return json.dumps(
                [
                    [
                        {
                            "tag_name": "extension-artifacts-" + SHA,
                            "draft": True,
                            "prerelease": True,
                            "target_commitish": SHA,
                            "assets": [],
                        }
                    ]
                ]
            )
        if args[1] == "create":
            assert "--draft" in args and "--latest=false" in args
            created = True
        if args[1] == "download":
            name = args[args.index("--pattern") + 1]
            (Path(args[args.index("--dir") + 1]) / name).write_bytes((output / name).read_bytes())
        if args[1] == "edit":
            assert len([c for c in calls if "download" in c]) == 2
            published = True
        return ""

    monkeypatch.setattr(publisher, "github", github)
    publisher.publish(output, SHA)
    assert published
    assert not any("--clobber" in call for call in calls)
    assert len([call for call in calls if call[0] == "api" and "/commits/" in call[1]]) == 1


@pytest.mark.parametrize("draft,status", [(False, 404), (True, 403), (True, 503)])
def test_tag_lookup_failures_are_only_tolerated_for_missing_draft_tags(snapshot, monkeypatch, draft, status):
    _, output = snapshot
    calls = []

    def github(*args):
        calls.append(args)
        if "/git/ref/tags/" in args[1]:
            raise RuntimeError(f"HTTP {status}")
        return json.dumps({"draft": draft, "target_commitish": SHA, "prerelease": True, "assets": []})

    monkeypatch.setattr(publisher, "github", github)
    with pytest.raises(RuntimeError, match=str(status)):
        publisher.publish(output, SHA)
    assert not any(call[0] == "release" for call in calls)


@pytest.mark.parametrize("commit_result", ["HTTP 404", "HTTP 503", "different-sha"])
def test_existing_draft_tag_must_resolve_to_its_verified_source(snapshot, monkeypatch, commit_result):
    _, output = snapshot
    calls = []

    def github(*args):
        calls.append(args)
        if "/git/ref/tags/" in args[1]:
            return json.dumps({"object": {"sha": SHA, "type": "commit"}})
        if "/commits/" in args[1]:
            if commit_result.startswith("HTTP"):
                raise RuntimeError(commit_result)
            return json.dumps({"sha": "b" * 40})
        return json.dumps({"draft": True, "target_commitish": SHA, "prerelease": True, "assets": []})

    monkeypatch.setattr(publisher, "github", github)
    error = RuntimeError if commit_result.startswith("HTTP") else ValueError
    with pytest.raises(error):
        publisher.publish(output, SHA)
    assert not any(call[0] == "release" for call in calls)


def test_api_outage_does_not_create_a_replacement_release(snapshot, monkeypatch):
    _, output = snapshot
    calls = []

    def github(*args):
        calls.append(args)
        raise RuntimeError("HTTP 503")

    monkeypatch.setattr(publisher, "github", github)
    with pytest.raises(RuntimeError, match="503"):
        publisher.publish(output, SHA)
    assert len(calls) == 1


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
