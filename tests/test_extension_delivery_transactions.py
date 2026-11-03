"""Failure boundaries leave publication pointers and legacy protections intact."""

from __future__ import annotations

import hashlib
import importlib
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


@pytest.fixture
def modules(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts"))
    return SimpleNamespace(
        **{
            name: importlib.import_module(name)
            for name in (
                "publish_extension_delivery",
                "extension_delivery_github",
                "extension_delivery_selector",
                "extension_delivery_legacy",
                "build_native_command_program",
            )
        }
    )


@pytest.mark.parametrize("failure", [None, "data", "legacy", "root"])
def test_only_complete_publication_advances_pointer(modules, monkeypatch, tmp_path, failure):
    publisher = modules.publish_extension_delivery
    from extension_delivery_assets import AssetPlan
    from extension_delivery_objects import encoded

    source, publication = "1" * 40, "12.1"
    plan = AssetPlan(tmp_path / "assets", source, publication_id=publication)
    target = plan.asset(b"public metadata", "object")
    row = plan.pending[0]
    (tmp_path / "asset-plan.jsonl").write_bytes(encoded(row) + b"\n")
    data = b"prepared root bytes"
    (tmp_path / "extension-distribution.v2.json").write_bytes(data)
    (tmp_path / "extension-distribution.intoto.jsonl").write_bytes(b"unit proof")
    root = {"publication_id": publication, "legacy": {"status": "unsupported-oversize", "code": "program-bytes"}}
    legacy_directory = tmp_path / "legacy"
    legacy_directory.mkdir()
    marker = modules.extension_delivery_legacy.unavailable_marker(source, "program-bytes")
    (legacy_directory / "extension-artifacts.unavailable.v1.json").write_text(json.dumps(marker))
    (legacy_directory / "extension-artifacts.intoto.jsonl").write_bytes(b"unit legacy proof")
    verified = SimpleNamespace(manifest=lambda: root, digest=hashlib.sha256(data).hexdigest())
    events = []

    def verify(*args, **kwargs):
        events.append("authenticate")
        assert args == (data, b"unit proof") and kwargs["expected_source_sha"] == source
        return verified

    def upload(tag, *args, **kwargs):
        if tag.startswith("extension-data-"):
            # A data release must ship the signed root that binds its assets,
            # and that bundle must be re-verified when the release already
            # carries one from an interrupted attempt.
            paths, expected = args[1:3]
            proof = "extension-distribution.intoto.jsonl"
            assert paths["extension-distribution.v2.json"].read_bytes() == data
            assert paths[proof].read_bytes() == b"unit proof"
            assert expected[proof]["sha256"] == hashlib.sha256(b"unit proof").hexdigest()
            assert kwargs["verify_existing_provenance"] is not None
        kind = (
            "root"
            if tag.startswith("extension-distribution-")
            else "legacy"
            if tag.startswith("extension-artifacts-")
            else "data"
        )
        events.append(kind)
        if failure == kind:
            raise ValueError("interrupted " + kind)

    monkeypatch.setattr(publisher, "verify_distribution", verify)
    monkeypatch.setattr(publisher, "_verify_attested_digest", lambda *args: events.append("legacy_auth"))
    monkeypatch.setattr(publisher, "verify_sources", lambda *args, **kwargs: events.append("source"))
    monkeypatch.setattr(
        publisher,
        "publication_inventory",
        lambda *args: {
            (target["tag"], target["asset"]): {
                "kind": "container",
                "location": row["location"],
                "members": {
                    target["member"]: {"sha256": hashlib.sha256(b"public metadata").hexdigest(), "length": 15},
                },
            }
        },
    )
    monkeypatch.setattr(publisher.provider, "verify_repository", lambda: events.append("repository"))
    monkeypatch.setattr(publisher.provider, "publish_assets", upload)
    monkeypatch.setattr(publisher, "select", lambda value: events.append("selected") or True)
    if failure is not None:
        with pytest.raises(ValueError, match="interrupted"):
            publisher.publish(tmp_path, source, publication)
        assert "selected" not in events
    else:
        result = publisher.publish(tmp_path, source, publication)
        assert result == {
            "selected": True,
            "source_sha": source,
            "publication_id": publication,
            "root_sha256": hashlib.sha256(data).hexdigest(),
        }
        assert events == ["authenticate", "source", "repository", "data", "legacy_auth", "legacy", "root", "selected"]


def test_bad_provenance_causes_no_public_mutation(modules, monkeypatch, tmp_path):
    publisher = modules.publish_extension_delivery
    (tmp_path / "extension-distribution.v2.json").write_bytes(b"root")
    (tmp_path / "extension-distribution.intoto.jsonl").write_bytes(b"invalid")

    def reject(*args, **kwargs):
        raise ValueError("untrusted publisher")

    monkeypatch.setattr(publisher, "verify_distribution", reject)
    monkeypatch.setattr(
        publisher.provider, "verify_repository", lambda: pytest.fail("invalid provenance reached remote publication")
    )
    with pytest.raises(ValueError, match="untrusted publisher"):
        publisher.publish(tmp_path, "1" * 40, "12.1")


def test_pointer_commit_contains_only_fixed_public_selection_metadata(modules, monkeypatch):
    selector = modules.extension_delivery_selector
    payloads = []

    def github(*args, input_data=None):
        payloads.append(json.loads(input_data))
        return json.dumps({"sha": "2" * 40})

    monkeypatch.setattr(selector, "github", github)
    value = {
        "schema": "guard.extension-distribution-selector.v2",
        "source_sha": "1" * 40,
        "publication_id": "12.1",
        "root_sha256": "3" * 64,
    }
    assert selector.pointer_commit("4" * 40, value) == "2" * 40
    assert payloads[0]["tree"] == [
        {
            "path": "extension-distribution-current.json",
            "mode": "100644",
            "type": "blob",
            "content": json.dumps(value, sort_keys=True, separators=(",", ":")),
        }
    ]
    assert payloads[1]["parents"] == ["4" * 40]
    assert payloads[1]["author"]["email"].endswith("@users.noreply.github.com")


def test_release_download_stops_at_its_bound(modules, monkeypatch, tmp_path):
    provider = modules.extension_delivery_github
    real_popen = subprocess.Popen
    processes = []

    def popen(command, **kwargs):
        assert command[:2] == ["gh", "api"]
        process = real_popen([sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'x' * 1000000)"], **kwargs)
        processes.append(process)
        return process

    monkeypatch.setattr(provider.subprocess, "Popen", popen)
    path = tmp_path / "bounded"
    with pytest.raises(ValueError, match="exceeds byte limit"):
        provider.download_asset({"id": 1}, path, 100)
    assert path.stat().st_size == 101
    assert all(process.poll() is not None for process in processes)


def test_legacy_oversize_is_explicit_and_other_admission_failures_remain_fatal(modules, monkeypatch, tmp_path):
    legacy = modules.extension_delivery_legacy
    compiler = modules.build_native_command_program
    assert legacy.preflight(tmp_path, {"extensions": 513}) == "extension-count"
    monkeypatch.setattr(legacy, "preflight", lambda *args: None)

    def reject(*args):
        raise compiler.NativeCompilationError("native_command_program_bounds_invalid", "invalid admission")

    monkeypatch.setattr(compiler, "main", reject)
    with pytest.raises(compiler.NativeCompilationError, match="invalid admission"):
        legacy.prepare(tmp_path, tmp_path, tmp_path, {}, Path("compiler"), "1" * 40, resolve_claimants=False)


def test_oversized_legacy_catalog_publishes_an_explicit_source_bound_marker(modules, tmp_path):
    legacy = modules.extension_delivery_legacy
    source = "1" * 40
    result = legacy.prepare(
        tmp_path, tmp_path, tmp_path, {"extensions": 513}, Path("compiler"), source, resolve_claimants=False
    )
    marker = json.loads((tmp_path / "legacy" / legacy.UNAVAILABLE).read_bytes())
    assert result == {"status": "unsupported-oversize", "code": "extension-count"}
    assert marker == legacy.unavailable_marker(source, "extension-count")
    assert not (tmp_path / "legacy/extension-artifacts.zip").exists()


def test_changed_staging_file_cannot_upload_unbound_bytes(modules, monkeypatch, tmp_path):
    from publish_extension_snapshot import upload_asset

    monkeypatch.setenv("GH_TOKEN", "unit-test-token")
    path = tmp_path / "reviewed.json"
    expected = {"sha256": hashlib.sha256(b"reviewed").hexdigest(), "length": len(b"reviewed")}
    path.write_bytes(b"modified")
    monkeypatch.setattr(modules.extension_delivery_github, "pace_write", lambda: None)
    with pytest.raises(ValueError, match="changed before upload"):
        upload_asset(1, path, expected=expected)
