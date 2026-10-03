"""Local transform snapshots never grant unrelated process execution."""

import json

import pytest

from codex_plugin_scanner.guard.runtime import restricted_esbuild as module
from codex_plugin_scanner.guard.runtime.restricted_pytest_model import RestrictedPytestError


def fixture(tmp_path, monkeypatch):
    monkeypatch.setattr(module.sys, "platform", "darwin")
    monkeypatch.setattr(module.platform, "machine", lambda: "arm64")
    package = tmp_path / "node_modules/esbuild"
    package.mkdir(parents=True)
    (package / "package.json").write_text(json.dumps({"name": "esbuild", "version": "0.25.4"}))
    image = tmp_path / "node_modules/@esbuild/darwin-arm64/bin/esbuild"
    image.parent.mkdir(parents=True)
    image.write_bytes(b"\xcf\xfa\xed\xfe" + b"fixture")
    image.chmod(0o700)
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    return image, private


def test_local_native_image_is_snapshotted(tmp_path, monkeypatch):
    source, private = fixture(tmp_path, monkeypatch)
    original, image, version = module.snapshot_esbuild(tmp_path, private)
    assert original == source
    assert image.parent == private
    assert version == "0.25.4"
    assert image.read_bytes() == source.read_bytes()
    source.write_bytes(b"changed")
    assert image.read_bytes() != source.read_bytes()


@pytest.mark.parametrize("unsafe", ["script", "writable", "external", "version", "nonregular"])
def test_invalid_or_external_transform_image_is_rejected(tmp_path, monkeypatch, unsafe):
    source, private = fixture(tmp_path, monkeypatch)
    if unsafe == "script":
        source.write_bytes(b"#!/bin/sh\n")
    elif unsafe == "writable":
        source.chmod(0o777)
    elif unsafe == "external":
        external = tmp_path / "outside"
        source.rename(external)
        source.symlink_to(external)
    elif unsafe == "version":
        (tmp_path / "node_modules/esbuild/package.json").write_text('{"name":"esbuild","version":"--evil"}')
    else:
        source.unlink()
        source.mkdir()
    with pytest.raises(RestrictedPytestError):
        module.snapshot_esbuild(tmp_path, private)


def test_missing_dependency_does_not_download_or_grant_an_image(tmp_path):
    assert module.snapshot_esbuild(tmp_path, tmp_path) is None
