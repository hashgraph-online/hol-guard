"""Prove partition reuse without ignoring dependencies, fixtures or shared source."""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts.ci.rust_test_archive_inputs import Inputs, fingerprint


def write(root: Path, name: str, value: str = "input") -> Path:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value)
    return path


@pytest.fixture
def workspace(tmp_path):
    write(
        tmp_path,
        "rust/Cargo.toml",
        '[workspace]\nmembers=["crates/command","crates/runtime","crates/helper"]\n'
        '[workspace.dependencies]\nhelper={path="crates/helper"}\n',
    )
    for directory, name in (("command", "guard-command"), ("runtime", "hol-guard-runtime"), ("helper", "helper")):
        manifest = f'[package]\nname="{name}"\nversion="0.1.0"\n'
        if directory == "command":
            manifest += "[dependencies]\nhelper={workspace=true}\n"
        elif directory == "runtime":
            manifest += '[dependencies]\ncommand={path="../command"}\n'
        write(tmp_path, f"rust/crates/{directory}/Cargo.toml", manifest)
        write(tmp_path, f"rust/crates/{directory}/src/lib.rs", "pub fn example() {}")
    write(tmp_path, "rust/Cargo.lock")
    write(tmp_path, "rust/rust-toolchain.toml")
    write(tmp_path, ".github/workflows/ci.yml")
    return tmp_path


def keys(root):
    return {partition: fingerprint(root, partition) for partition in ("core", "command", "runtime")}


def test_runtime_edit_keeps_command_and_core_test_builds(workspace):
    before = keys(workspace)
    write(workspace, "rust/crates/runtime/src/lib.rs", "pub fn changed() {}")
    after = keys(workspace)
    assert after["command"] == before["command"]
    assert after["core"] == before["core"]
    assert after["runtime"] != before["runtime"]


def test_transitive_workspace_dependency_invalidates_every_consumer(workspace):
    before = keys(workspace)
    write(workspace, "rust/crates/helper/src/lib.rs", "pub fn changed() {}")
    assert all(keys(workspace)[group] != original for group, original in before.items())


def test_build_script_component_inputs_invalidate_only_their_consumers(workspace):
    manifest = workspace / "rust/crates/helper/Cargo.toml"
    manifest.write_text(manifest.read_text().replace('name="helper"', 'name="guard-rule-contract"'))
    write(workspace, "rust/crates/helper/component-inputs.tsv", "runtime-edge\t../runtime/src/edge.rs\n")
    edge = write(workspace, "rust/crates/runtime/src/edge.rs", "original edge")
    before = keys(workspace)
    edge.write_text("changed edge")
    assert all(keys(workspace)[group] != original for group, original in before.items())
    before = keys(workspace)
    write(workspace, "rust/crates/runtime/src/runtime_cli.rs", "unrelated CLI change")
    after = keys(workspace)
    assert after["core"] == before["core"]
    assert after["command"] == before["command"]
    assert after["runtime"] != before["runtime"]


@pytest.mark.parametrize("rows", ["edge\t\n", "edge\t../runtime/src/edge.rs\nedge\t../runtime/src/lib.rs\n"])
def test_invalid_component_input_declarations_fail_closed(workspace, rows):
    manifest = workspace / "rust/crates/helper/Cargo.toml"
    manifest.write_text(manifest.read_text().replace('name="helper"', 'name="guard-rule-contract"'))
    write(workspace, "rust/crates/helper/component-inputs.tsv", rows)
    with pytest.raises(ValueError, match="component input"):
        fingerprint(workspace, "core")


@pytest.mark.parametrize(
    "kind", ["dependencies", "build-dependencies", "dev-dependencies", "target.'cfg(windows)'.dependencies"]
)
def test_every_local_dependency_kind_is_bound(workspace, kind):
    write(workspace, "rust/crates/excluded/Cargo.toml", '[package]\nname="excluded"\nversion="0.1.0"\n')
    source = write(workspace, "rust/crates/excluded/src/lib.rs", "pub fn example() {}")
    manifest = workspace / "rust/crates/command/Cargo.toml"
    with manifest.open("a") as output:
        if kind != "dependencies":
            output.write(f"\n[{kind}]\n")
        output.write('excluded={path="../excluded"}\n')
    before = fingerprint(workspace, "command")
    source.write_text("pub fn changed() {}")
    assert fingerprint(workspace, "command") != before


def test_external_library_root_and_module_paths_retain_shared_sources(workspace):
    write(workspace, "rust/crates/excluded/Cargo.toml", '[package]\nname="excluded"\nversion="0.1.0"\n')
    shared = write(workspace, "rust/crates/excluded/src/lib.rs", "pub fn example() {}")
    root = write(workspace, "rust/crates/command/src/lib.rs", '#[path="../../excluded/src/lib.rs"]\nmod shared;')
    before = fingerprint(workspace, "command")
    shared.write_text("pub fn changed() {}")
    assert fingerprint(workspace, "command") != before
    root.write_text("// external library root")
    manifest = workspace / "rust/crates/command/Cargo.toml"
    with manifest.open("a") as output:
        output.write('\n[lib]\npath="../excluded/src/lib.rs"\n')
    assert shared in Inputs(workspace).collect("command")


@pytest.mark.parametrize(
    "syntax",
    [
        'const DATA:&str=include_str! ( "../../../../data/input.json" );',
        'const DATA:&str=include_str!(r#"../../../../data/input.json"#);',
        'const DATA:&[u8]=include_bytes!(r"../../../../data/input.json");',
        '#[\npath = r#"../../../../data/input.json"#\n]\nmod shared;',
        'include!("../../../../data/input.json");',
    ],
)
def test_raw_literals_whitespace_and_include_macros_still_bind_external_files(workspace, syntax):
    write(workspace, "rust/crates/command/src/lib.rs", syntax)
    source = write(workspace, "data/input.json", "original")
    before = fingerprint(workspace, "command")
    source.write_text("changed")
    assert fingerprint(workspace, "command") != before


@pytest.mark.parametrize(
    "name", ["Cargo.lock", "rust-toolchain.toml", "build_support/shared.rs", "crates/runtime/Cargo.toml"]
)
def test_workspace_build_metadata_stays_global(workspace, name):
    before = keys(workspace)
    path = workspace / "rust" / name
    if name.endswith("Cargo.toml"):
        path.write_text(path.read_text() + "\n# changed metadata\n")
    else:
        write(workspace, "rust/" + name, "changed")
    assert all(keys(workspace)[group] != original for group, original in before.items())


@pytest.mark.parametrize("name", [".github/workflows/rust-test-cache-warm.yml", "scripts/ci/archive_rust_tests.sh"])
def test_archive_recipe_or_retired_producer_changes_invalidate_every_archive(workspace, name):
    before = keys(workspace)
    write(workspace, name, "changed build recipe")
    assert all(keys(workspace)[group] != original for group, original in before.items())


def test_retiring_the_warmer_invalidates_its_archives_and_keeps_absence_bound(workspace):
    name = ".github/workflows/rust-test-cache-warm.yml"
    producer = write(workspace, name, "previous producer recipe")
    before = keys(workspace)
    producer.unlink()
    after = keys(workspace)
    assert all(after[group] != original for group, original in before.items())
    for partition in before:
        assert producer in Inputs(workspace).collect(partition)
    write(workspace, name, "previous producer recipe")
    assert keys(workspace) == before


@pytest.mark.parametrize(
    "name",
    [
        "contributions/command-sources/item.json",
        "contracts/trust.json",
        "tests/fixtures/case.json",
        "scripts/tool.py",
        ".github/workflows/ci.yml",
    ],
)
def test_existing_external_input_roots_stay_global(workspace, name):
    before = keys(workspace)
    write(workspace, name, "changed")
    assert all(keys(workspace)[group] != original for group, original in before.items())


def test_added_sources_and_external_literal_fixtures_change_the_key(workspace):
    before = fingerprint(workspace, "command")
    write(workspace, "rust/crates/command/src/new.rs", "pub fn new() {}")
    assert fingerprint(workspace, "command") != before
    write(workspace, "rust/crates/command/src/lib.rs", 'const DATA:&str=include_str!("../../../../data/fixture.json");')
    before = fingerprint(workspace, "command")
    write(workspace, "data/fixture.json", "changed")
    assert fingerprint(workspace, "command") != before


def test_generated_bytecode_and_cargo_outputs_do_not_change_identity(workspace):
    before = keys(workspace)
    write(workspace, "scripts/__pycache__/tool.pyc")
    write(workspace, "rust/target/output")
    assert keys(workspace) == before


def test_authored_target_named_fixture_is_not_treated_as_cargo_output(workspace):
    before = fingerprint(workspace, "command")
    write(workspace, "rust/crates/command/tests/fixtures/target/important.json", "authored")
    assert fingerprint(workspace, "command") != before


def test_missing_include_and_executable_mode_have_distinct_identities(workspace):
    write(workspace, "rust/crates/command/src/lib.rs", 'const DATA:&str=include_str!("script.sh");')
    missing = fingerprint(workspace, "command")
    script = write(workspace, "rust/crates/command/src/script.sh", "")
    regular = fingerprint(workspace, "command")
    assert regular != missing
    old_mode = script.stat().st_mode & 0o111
    script.chmod(0o755)
    mode_changed = (script.stat().st_mode & 0o111) != old_mode
    assert (fingerprint(workspace, "command") != regular) == mode_changed


def test_symlinked_package_input_is_rejected(workspace):
    target = write(workspace, "outside.txt")
    link = workspace / "rust/crates/command/src/link.rs"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("host cannot create symlinks")
    with pytest.raises(ValueError, match="symlink"):
        fingerprint(workspace, "command")
