"""Runtime compilation reuse must not reuse test results or partial input matches."""

import re
from pathlib import Path

import yaml

from scripts.ci.rust_test_archive_inputs import EXTERNAL_ROOTS, Inputs

ROOT = Path(__file__).resolve().parents[1]


def test_runtime_archive_is_exact_input_only_and_saved_by_one_trusted_writer():
    action = yaml.safe_load((ROOT / ".github/actions/restore-runtime-tests/action.yml").read_text())
    stages = action["runs"]["steps"]
    restore = next(step for step in stages if step.get("id") == "archive")
    assert stages[0]["run"] == "python3 scripts/refresh_extension_artifacts.py --trust-only"
    assert "restore-keys" not in restore["with"]
    key = restore["with"]["key"]
    for binding in (
        "runner.arch",
        "outputs.image",
        "outputs.compiler-env",
        "CARGO_PROFILE_RELEASE_LTO",
        "CARGO_PROFILE_RELEASE_CODEGEN_UNITS",
        "runtime-test-archive-v3-",
        "steps.inputs.outputs.digest",
    ):
        assert binding in key
    identify = next(step for step in stages if step.get("id") == "inputs")
    assert identify["env"]["ARCHIVE_PARTITION"] == "${{ inputs.partition }}"
    assert 'rust_test_archive_inputs --partition "$ARCHIVE_PARTITION"' in identify["run"]

    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
    steps = workflow["jobs"]["native-workspace"]["steps"]
    configure = next(step for step in steps if step.get("name") == "Configure the checked test profile")
    restore_call = next(step for step in steps if step.get("id") == "runtime-archive")
    archive = next(step for step in steps if step.get("name") == "Archive the complete runtime test build")
    validate = next(step for step in steps if step.get("name") == "Validate the locked Rust workspace")
    save = next(step for step in steps if step.get("name") == "Save successful runtime test compilation")
    assert steps.index(configure) < steps.index(restore_call) < steps.index(archive)
    assert steps.index(archive) < steps.index(validate) < steps.index(save)
    assert archive["run"] == 'bash scripts/ci/archive_rust_tests.sh "$CARGO_CHECK"'
    assert archive["env"]["CARGO_CHECK"] == "${{ matrix.check }}"
    assert restore_call["if"] == "matrix.check != 'clippy'"
    assert restore_call["with"]["partition"] == (
        "${{ matrix.check == 'test-command' && 'command' || (matrix.check == 'test-core' && 'core' || 'runtime') }}"
    )
    assert save["if"] == (
        "matrix.check != 'clippy' && "
        "steps.runtime-archive.outputs.cache-hit != 'true' && "
        "github.event_name == 'push' && github.ref == 'refs/heads/main'"
    )
    assert archive["if"] == save["if"]
    assert save["with"]["key"] == "${{ steps.runtime-archive.outputs.cache-primary-key }}"
    assert save["with"]["path"] == restore["with"]["path"]


def test_literal_rust_includes_are_covered_by_the_archive_key():
    authored = set().union(*(Inputs(ROOT).collect(partition) for partition in ("core", "command", "runtime")))
    includes = re.compile(r'include_(?:str|bytes)!\(\s*"([^"\n]+)"\s*\)', re.MULTILINE)
    checked = 0
    for source in (ROOT / "rust").rglob("*.rs"):
        if "target" in source.relative_to(ROOT).parts:
            continue
        for included in includes.findall(source.read_text()):
            path = (source.parent / included).resolve()
            assert path in authored, path.relative_to(ROOT)
            checked += 1
    assert checked > 100  # Exercise the compiled fixture graph, not an empty match.


def test_generated_files_are_excluded_without_excluding_authored_fixtures():
    paths = {path.relative_to(ROOT).as_posix() for path in Inputs(ROOT).collect("runtime")}
    assert not any("__pycache__" in Path(path).parts or path.startswith("rust/target/") for path in paths)
    assert {"contributions", "contracts", "spec", "tests/fixtures", "scripts", ".cargo"}.issubset(EXTERNAL_ROOTS)
    for path in (
        "scripts/ci/native_cache_environment.py",
        "rust/rust-toolchain.toml",
        "rust/crates/guard-runtime/src/lib.rs",
        "rust/crates/guard-runtime/src/main.rs",
    ):
        assert path in paths, path


def test_core_archive_covers_every_rule_contract_component():
    inputs = Inputs(ROOT).collect("core")
    package = ROOT / "rust/crates/guard-rule-contract"
    manifest = package / "component-inputs.tsv"
    assert manifest in inputs
    for line in manifest.read_text().splitlines():
        name, relative = line.split("\t")
        if name == "native-command-program-artifact":
            assert relative == "@packaged-program"  # Resolved from the packaged program.
            continue
        assert (package / relative).resolve() in inputs, relative
    build = (package / "build.rs").read_text()
    assert 'include_str!("component-inputs.tsv")' in build
    assert "rerun-if-changed=component-inputs.tsv" in build
