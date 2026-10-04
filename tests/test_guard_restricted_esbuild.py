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
    prepared_snapshot = module.snapshot_esbuild(tmp_path, private)
    assert prepared_snapshot is not None
    original, image, version = prepared_snapshot
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


@pytest.mark.parametrize("private_parent_name", ["private", "private with spaces", "private's with spaces"])
def test_runner_keeps_authorized_image_outside_writable_ancestors(tmp_path, monkeypatch, private_parent_name):
    import shlex
    import tempfile
    from pathlib import Path

    from codex_plugin_scanner.guard.runtime import restricted_vitest as vitest
    from codex_plugin_scanner.guard.runtime.restricted_pytest_model import RestrictedPytestPlan

    source, _ = fixture(tmp_path, monkeypatch)
    temporary_parent = tmp_path.parent / (tmp_path.name + "-" + private_parent_name)
    temporary_parent.mkdir(mode=0o700)
    monkeypatch.setattr(tempfile, "tempdir", str(temporary_parent))
    plan = RestrictedPytestPlan(
        profile_version="vitest-readonly-v1",
        backend="macos-seatbelt",
        backend_executable=Path("/usr/bin/sandbox-exec"),
        workspace=tmp_path,
        cwd=tmp_path,
        command=("/usr/bin/node", "vitest.mjs", "run"),
        executable=Path("/usr/bin/node"),
        allowed_executables=(Path("/usr/bin/node"),),
        denied_capabilities=(),
    )
    checked, launched = [], []

    def launch(argv, *, env, **kwargs):
        image = Path(env["ESBUILD_BINARY_PATH"])
        scratch = Path(env["HOME"]).parent
        assert shlex.split(env["NODE_OPTIONS"])[-2:] == ["--require", str(scratch / "localhost-resolution.cjs")]
        assert image.is_file()
        assert not image.is_relative_to(scratch)
        assert not image.is_relative_to(tmp_path)
        assert image.read_bytes() == source.read_bytes()
        profile = argv[2]
        writes = next(line for line in profile.splitlines() if line.startswith("(allow file-write*"))
        assert f'(subpath "{scratch}")' in writes
        assert str(image.parent) not in writes
        assert f'(literal "{image}")' in profile
        assert any(str(image) in line for line in profile.splitlines() if line.startswith("(deny file-write*"))
        launched.append(image)
        return 0

    monkeypatch.setattr(vitest, "_run_backend_process", launch)
    assert vitest.run_restricted_node_plan(plan, env={}, authorize_capability=checked.append) == 0
    assert checked == [(str(source), "--service=0.25.4", "--ping")]
    assert len(launched) == 1
    assert not launched[0].exists()
    assert not launched[0].parent.exists()
