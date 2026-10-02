"""Build-owned data must be complete, source-bound and invisible to contributors."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from scripts import build_guard_resources as resources
from scripts.ci.check_build_owned_paths import tracked_derived_paths


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    """A small source inventory exercises cache binding without invoking Cargo."""
    files = {
        "pyproject.toml": "[project]\nname='fixture'\n",
        "hatch_build.py": "# fixture\n",
        "scripts/build_guard_resources.py": "# fixture\n",
        "scripts/build_native_command_program.py": "# fixture\n",
        "rust/Cargo.toml": "[workspace]\n",
        "rust/Cargo.lock": "version = 4\n",
        "rust/crates/example/Cargo.toml": "[package]\nname='example'\n",
        "rust/crates/example/src/lib.rs": "pub fn example() {}\n",
        "rust/build_support/identity.rs": "// identity\n",
        "contributions/command-sources/command.example.json": '{"extension":{"extension_id":"command.example"}}\n',
        "contributions/mcp-servers/mcp.example.json": '{"id":"mcp.example"}\n',
        "contracts/extensions/trust-class-map.v1.json": '{"classes":{"external":["command.example"]}}\n',
        "contracts/extensions/contribution.v2.schema.json": '{"schema":"fixture"}\n',
        "contracts/mcp-servers/contribution.v1.schema.json": '{"schema":"fixture"}\n',
    }
    for relative, text in files.items():
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return tmp_path


def _cache(root: Path) -> dict:
    """Write only fake derived bytes, leaving authored fixture inputs untouched."""
    output = {}
    for relative in resources.expected_outputs(root):
        content = (json.dumps({"generated": relative}) + "\n").encode()
        resources._atomic_write(root, root / relative, content)
        output[relative] = hashlib.sha256(content).hexdigest()
    manifest = {"schema": resources.SCHEMA, "input_digest": resources.input_digest(root), "outputs": output}
    resources._atomic_write(root, root / resources.STATE, json.dumps(manifest).encode())
    return manifest


def test_complete_same_input_resources_are_reusable(tree: Path) -> None:
    """Source identity and every independently enumerated output must agree."""
    expected = _cache(tree)
    assert resources.current_manifest(tree) == expected
    assert "contributions/extensions/command.example.json" in expected["outputs"]
    assert str(resources.PACKAGE / "mcp_servers/contributions/mcp.example.json") in expected["outputs"]


@pytest.mark.parametrize(
    "relative",
    [
        "contributions/command-sources/command.example.json",
        "contributions/mcp-servers/mcp.example.json",
        "contracts/extensions/trust-class-map.v1.json",
        "rust/crates/example/src/lib.rs",
        "rust/Cargo.lock",
        "hatch_build.py",
        "scripts/build_native_command_program.py",
    ],
)
def test_changed_authored_input_invalidates_outputs(tree: Path, relative: str) -> None:
    """Unrelated Git metadata cannot keep artifacts valid after an input edit."""
    _cache(tree)
    path = tree / relative
    path.write_bytes(path.read_bytes() + b"\n")
    assert resources.current_manifest(tree) is None


@pytest.mark.parametrize("operation", ["add", "remove"])
def test_source_inventory_changes_invalidate_outputs(tree: Path, operation: str) -> None:
    """Adding or deleting a source requires a new complete compiled inventory."""
    _cache(tree)
    if operation == "add":
        (tree / "contributions/command-sources/command.second.json").write_text(
            '{"extension":{"extension_id":"command.second"}}'
        )
    else:
        (tree / "contributions/command-sources/command.example.json").unlink()
    assert resources.current_manifest(tree) is None


@pytest.mark.parametrize("operation", ["missing", "modified", "omitted-from-manifest", "extra-in-manifest"])
def test_output_corruption_never_reuses_a_cache(tree: Path, operation: str) -> None:
    """Checksums alone cannot excuse omitted extensions or missing output files."""
    manifest = _cache(tree)
    path = tree / "contributions/extensions/command.example.json"
    if operation == "missing":
        path.unlink()
    elif operation == "modified":
        path.write_text('{"wrong":"output"}')
    else:
        if operation == "omitted-from-manifest":
            del manifest["outputs"][path.relative_to(tree).as_posix()]
        else:
            manifest["outputs"]["../outside"] = "0" * 64
        (tree / resources.STATE).write_text(json.dumps(manifest))
    assert resources.current_manifest(tree) is None


def test_duplicate_manifest_keys_are_rejected(tree: Path) -> None:
    """A parser must not discard conflicting output bindings."""
    _cache(tree)
    (tree / resources.STATE).write_text('{"schema":"a","schema":"b"}')
    assert resources.current_manifest(tree) is None


def test_source_hash_uses_relative_paths_and_normalized_newlines(tree: Path, tmp_path: Path) -> None:
    """Equivalent checkouts on Windows and Unix identify the same build inputs."""
    other = tmp_path / "other-checkout"
    other.mkdir()
    for path in resources.input_paths(tree):
        relative = path.relative_to(tree)
        destination = other / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(path.read_bytes().replace(b"\n", b"\r\n"))
    assert resources.input_digest(tree) == resources.input_digest(other)


def test_linked_input_is_rejected(tree: Path) -> None:
    """A source cannot borrow mutable bytes from outside the checkout."""
    path = tree / "contributions/command-sources/command.example.json"
    outside = tree / "outside.json"
    outside.write_bytes(path.read_bytes())
    path.unlink()
    try:
        path.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("host does not permit symlink creation")
    with pytest.raises(ValueError, match="symlink"):
        resources.input_digest(tree)


def test_linked_output_directory_is_rejected(tree: Path) -> None:
    """Staging must not write through a package resource symlink."""
    destination = tree / "package-output"
    destination.mkdir()
    link = tree / "linked"
    try:
        link.symlink_to(destination, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("host does not permit symlink creation")
    with pytest.raises(ValueError, match="symlink"):
        resources._atomic_write(tree, link / "artifact.json", b"{}")
    assert not list(destination.iterdir())


def test_valid_cache_does_not_build_again(tree: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Downstream shards reuse only validated same-input producer output."""
    expected = _cache(tree)

    def unexpected(*args, **kwargs):
        pytest.fail("a complete same-input cache must not compile in each shard")

    monkeypatch.setattr(resources, "_build_compiler", unexpected)
    monkeypatch.setattr(resources, "_stage", unexpected)
    assert resources.prepare(tree) == expected


def test_input_change_during_staging_cannot_publish_a_manifest(tree: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A concurrent edit cannot be mislabeled as a completed same-input build."""
    compiler = tree / "compiler"
    compiler.write_text("fixture")

    def changed(root: Path, _compiler: Path) -> list[Path]:
        (root / "hatch_build.py").write_text("changed while building")
        return []

    monkeypatch.setattr(resources, "_stage", changed)
    with pytest.raises(RuntimeError, match="changed during"):
        resources.prepare(tree, compiler=compiler)
    assert not (tree / resources.STATE).exists()


@pytest.mark.parametrize(
    "path",
    [
        "contracts/extensions/native-command-program.v1.json",
        "contracts/extensions/command-catalog.v1.json",
        "contributions/extensions/command.new.json",
        "src/codex_plugin_scanner/guard/contracts/data/extensions/contributions/command.new.json",
        "docs/guard/extensions/catalog.v2.json",
        "tests/fixtures/guard-command-corpus/decision-diff-report.json",
        "build/guard-resources/manifest.json",
    ],
)
def test_derived_files_are_not_source_inputs(path: str) -> None:
    """No branch prefix or author exemption can reintroduce generated commits."""
    assert tracked_derived_paths([path]) == [path]


@pytest.mark.parametrize(
    "path",
    [
        "contributions/command-sources/command.new.json",
        "contributions/mcp-servers/mcp.new.json",
        "contracts/extensions/trust-class-map.v1.json",
        "contracts/extensions/contribution.v2.schema.json",
        "contracts/managed-controls/v1/extension-projection-digest-vector.json",
        "tests/fixtures/guard-command-corpus/native-contract.json",
        "tests/fixtures/guard-command-corpus/seed-manifest.json",
        "tests/fixtures/command-source-new.v1.json",
        "tests/test_guard_extension_trust.py",
    ],
)
def test_authored_expectations_stay_reviewable(path: str) -> None:
    """Authored security and cryptographic expectations are not build-owned."""
    assert tracked_derived_paths([path]) == []


def test_native_build_discovers_the_workspace_toolchain(tree: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Rustup must see rust/rust-toolchain.toml, not an unrelated global default."""
    import subprocess

    observed = []
    expected = tree / "rust/target/debug/guard-command-source"
    monkeypatch.setattr(resources.shutil, "which", lambda _: "/usr/bin/cargo")

    def execute(command, **kwargs):
        observed.append((command, kwargs))
        record = {
            "reason": "compiler-artifact",
            "target": {"name": "guard-command-source"},
            "executable": str(expected),
        }
        return subprocess.CompletedProcess(command, 0, stdout=json.dumps(record) + "\n")

    monkeypatch.setattr(resources.subprocess, "run", execute)
    assert resources._build_compiler(tree) == expected
    assert observed[0][1]["cwd"] == tree / "rust"
    assert "--locked" in observed[0][0]
    assert "--message-format=json" in observed[0][0]


def test_implementation_order_is_identical_on_windows_and_posix() -> None:
    """Case-folded Windows Path ordering must not alter the implementation hash."""
    from pathlib import PurePosixPath, PureWindowsPath

    from scripts.build_native_command_program import implementation_path_key

    relative = [
        "crates/example/build.rs",
        "crates/example/Cargo.toml",
        "Cargo.lock",
        "crates/example/src/Z.rs",
        "crates/example/src/a.rs",
    ]
    observed = []
    for kind, base in ((PurePosixPath, "/checkout/rust"), (PureWindowsPath, "C:/checkout/rust")):
        root = kind(base)
        paths = [root / name for name in relative]
        ordered = sorted(paths, key=lambda path: implementation_path_key(path, root))
        observed.append([implementation_path_key(path, root) for path in ordered])
    assert observed[0] == observed[1] == sorted(relative)
