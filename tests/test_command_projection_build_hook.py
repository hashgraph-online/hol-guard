"""Package builds must stage native projections without mutable runtime discovery."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import types
from pathlib import Path

import pytest
import yaml


@pytest.fixture
def hook(monkeypatch, tmp_path):
    # Hatchling is an isolated build dependency, not a runtime/test dependency.
    # Supply its interface to test our hook without installing a second backend.
    """Load the build hook with an isolated package root and controlled subprocesses."""
    interface = types.ModuleType("hatchling.builders.hooks.plugin.interface")
    interface.BuildHookInterface = object
    monkeypatch.setitem(sys.modules, interface.__name__, interface)
    path = Path(__file__).parents[1] / "scripts/build_command_projection_hook.py"
    spec = importlib.util.spec_from_file_location("command_projection_build_hook", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    archive = types.ModuleType("archive_test_support")
    archive.MANIFEST = "contracts/extensions/command-projection-build.v1.json"
    archive.write_projection_manifest = lambda root: None
    archive.verify_projection_manifest = lambda root: None
    monkeypatch.setattr(module, "_archive_support", lambda: archive)
    instance = module.CommandProjectionBuildHook()
    instance.archive_test_support = archive
    instance.root = str(tmp_path)
    instance.target_name = "wheel"
    monkeypatch.delenv("HOL_GUARD_BUILD_SOURCE_COMPILER", raising=False)
    return instance


def test_editable_setup_does_not_require_outputs_or_rust(hook, monkeypatch):
    """Editable dependency setup must neither invoke Rust nor require generated files."""

    def unexpected(*args, **kwargs):
        """Fail immediately if this compiler-free path attempts a subprocess."""
        pytest.fail("editable dependency setup must not invoke the compiler")

    monkeypatch.setattr(subprocess, "run", unexpected)
    data = {"force_include": {}}
    hook.initialize("editable", data)
    assert data["force_include"] == {}


@pytest.mark.parametrize("target", ["wheel", "sdist"])
def test_package_build_stages_and_verifies_before_registering_absent_outputs(hook, monkeypatch, target):
    """Package resources become eligible for inclusion only after generation and verification."""
    hook.target_name = target
    data = {"force_include": {}}
    calls = []

    def generate(command, **kwargs):
        """Simulate generated files and record the required verification sequence."""
        assert kwargs == {"cwd": Path(hook.root), "check": True}
        assert not data["force_include"]
        calls.append(command)

    monkeypatch.setattr(subprocess, "run", generate)
    hook.initialize("standard", data)
    assert len(calls) == 2
    assert calls[1] == [*calls[0], "--check"]
    assert "--projections-only" in calls[0]
    prefix = "contracts/extensions" if target == "sdist" else "codex_plugin_scanner/guard/contracts/data/extensions"
    expected = {
        f"{prefix}/command-catalog.v1.json",
        f"{prefix}/native-command-program.v1.json",
    }
    if target == "sdist":
        expected.add(hook.archive_test_support.MANIFEST)
    assert set(data["force_include"].values()) == expected


@pytest.mark.parametrize("failing_call", [1, 2])
def test_compilation_or_identity_failure_aborts_packaging(hook, monkeypatch, failing_call):
    """A failed compiler or identity check must leave package inclusions unset."""
    data = {"force_include": {}}
    calls = []

    def fail(command, **kwargs):
        """Simulate a failed native build without registering package outputs."""
        calls.append(command)
        if len(calls) == failing_call:
            raise subprocess.CalledProcessError(1, command)

    monkeypatch.setattr(subprocess, "run", fail)
    with pytest.raises(subprocess.CalledProcessError):
        hook.initialize("standard", data)
    assert not data["force_include"]


def test_pinned_compiler_is_used_for_generation_and_strict_check(hook, monkeypatch):
    """Both compiler invocations must honor the configured executable."""
    compiler = str(Path(hook.root) / "compiler")
    monkeypatch.setenv("HOL_GUARD_BUILD_SOURCE_COMPILER", compiler)
    calls = []
    monkeypatch.setattr(subprocess, "run", lambda command, **kwargs: calls.append(command))
    hook.initialize("standard", {"force_include": {}})
    assert all(command[command.index("--compiler") + 1] == compiler for command in calls)


def test_frozen_source_archive_uses_verified_projections_without_rust(hook, monkeypatch):
    """An unchanged archive validates bundled projections without spawning a compiler."""
    (Path(hook.root) / "PKG-INFO").write_text("Metadata-Version: 2.4\n")
    verified = []
    hook.archive_test_support.verify_projection_manifest = verified.append

    def unexpected(*args, **kwargs):
        """Fail immediately if this compiler-free path attempts a subprocess."""
        pytest.fail("an unchanged source archive must not invoke Cargo")

    monkeypatch.setattr(subprocess, "run", unexpected)
    hook.initialize("standard", {"force_include": {}})
    assert verified == [Path(hook.root)]


def test_changed_source_archive_aborts_before_registering_outputs(hook, monkeypatch):
    """Reject a modified archive before its generated files can enter a wheel."""
    (Path(hook.root) / "PKG-INFO").write_text("Metadata-Version: 2.4\n")

    def reject(root):
        """Simulate archive fingerprint rejection before output registration."""
        raise ValueError("changed build inputs")

    hook.archive_test_support.verify_projection_manifest = reject
    data = {"force_include": {}}
    with pytest.raises(ValueError, match="changed build inputs"):
        hook.initialize("standard", data)
    assert not data["force_include"]


def test_generated_path_gate_permits_removal_but_rejects_reintroduction():
    """The generated-path gate permits deletion, not renewed tracking of build outputs."""
    root = Path(__file__).parents[1]
    workflow = yaml.safe_load((root / ".github/workflows/generated-artifacts-guard.yml").read_text())
    run = workflow["jobs"]["regen-owned-paths"]["steps"][0]["run"]
    query = run.split("--jq '", 1)[1].split("'", 1)[0]
    paths = [
        f"{prefix}/{name}.v1.json"
        for prefix in ("contracts/extensions", "src/codex_plugin_scanner/guard/contracts/data/extensions")
        for name in ("command-catalog", "native-command-program")
    ]
    files = [{"filename": path, "status": status} for path in paths for status in ("removed", "added", "modified")]
    other = "src/codex_plugin_scanner/guard/contracts/data/extensions/trust-class-map.v1.json"
    files.append({"filename": other, "status": "removed"})
    result = subprocess.run(["jq", "-r", query], input=json.dumps(files), text=True, capture_output=True, check=True)
    assert result.stdout.splitlines() == [path for path in paths for _ in range(2)] + [other]
