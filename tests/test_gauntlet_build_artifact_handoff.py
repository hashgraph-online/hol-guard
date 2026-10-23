"""The passive ARM artifact adapter keeps one verified native compiler pin."""

import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace
import zipfile

from ci.gauntlet.control_plane import build_artifact


def test_native_wheel_assembly_receives_the_verified_compiler(tmp_path, monkeypatch):
    source = "a" * 40
    version = "3.50.0"
    rule_digest = "b" * 64
    native = b"verified native runtime fixture"
    runtime = tmp_path / "rust/target/release/hol-guard-runtime"
    runtime.parent.mkdir(parents=True)
    runtime.write_bytes(native)
    pure = tmp_path / "gauntlet-pure/hol_guard-3.50.0-py3-none-any.whl"
    pure.parent.mkdir()
    pure.write_bytes(b"pure wheel fixture")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOL_GUARD_BUILD_SHA", source)
    monkeypatch.setenv("HOL_GUARD_BUILD_SOURCE_COMPILER", "/outside/stale/compiler")
    monkeypatch.setattr(build_artifact.os, "geteuid", lambda: 501)
    monkeypatch.setattr(build_artifact.os, "uname", lambda: SimpleNamespace(machine="aarch64"))

    def output(argv, *, text):
        assert text is True
        if argv[:2] == ["git", "rev-parse"]:
            return source + "\n"
        if argv[1:3] == ["scripts/sync_repo_version.py", "--check"]:
            return version + "\n"
        if argv[1:] == ["export-built"]:
            return json.dumps({"implementation_digest": "c" * 64,
                               "program": {"program_digest": "d" * 64}})
        if argv[1:] == ["capabilities", "--json"]:
            return json.dumps({"build_sha": source, "runtime_version": version,
                               "rule_digest": rule_digest})
        raise AssertionError(argv)

    def run(argv, *, env, check):
        assert check is True
        assert env["HOL_GUARD_PACKAGE_VERSION"] == version
        if argv[0] == str(build_artifact.sys.executable):
            assert env["HOL_GUARD_BUILD_SOURCE_COMPILER"] == str(runtime)
        return SimpleNamespace(returncode=0)

    def build_native_wheel(**arguments):
        assert os.environ["HOL_GUARD_BUILD_SOURCE_COMPILER"] == str(runtime)
        assert arguments["runtime"] == runtime
        assert arguments["source_sha"] == source
        wheel = tmp_path / "gauntlet-artifact/hol_guard-3.50.0-py3-none-linux_aarch64.whl"
        wheel.parent.mkdir()
        with zipfile.ZipFile(wheel, "w") as archive:
            archive.writestr("codex_plugin_scanner/_native/runtime-manifest.json", json.dumps({
                "source_sha": source, "runtime_sha256": hashlib.sha256(native).hexdigest()
            }))
        return wheel

    module = SimpleNamespace(build_native_wheel=build_native_wheel)
    spec = SimpleNamespace(name="native_wheel_builder_fixture",
                           loader=SimpleNamespace(exec_module=lambda value: None))
    monkeypatch.setattr(build_artifact.subprocess, "check_output", output)
    monkeypatch.setattr(build_artifact.subprocess, "run", run)
    monkeypatch.setattr(build_artifact.importlib.util, "spec_from_file_location", lambda *args: spec)
    monkeypatch.setattr(build_artifact.importlib.util, "module_from_spec", lambda value: module)
    try:
        build_artifact.main()
    finally:
        build_artifact.sys.modules.pop(spec.name, None)

    assert os.environ["HOL_GUARD_BUILD_SOURCE_COMPILER"] == "/outside/stale/compiler"
    record = json.loads((tmp_path / "gauntlet-artifact/artifact.json").read_text())
    assert record["source_sha"] == source
    assert record["native_sha256"] == hashlib.sha256(native).hexdigest()
