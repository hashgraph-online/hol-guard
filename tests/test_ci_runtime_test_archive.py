"""Runtime compilation reuse must not reuse test results or partial input matches."""

import fnmatch
import re
from pathlib import Path

import yaml

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
        "rust/**",
        "contributions/**",
        "contracts/**",
        "spec/**",
        "tests/fixtures/**",
        "src/codex_plugin_scanner/guard/contracts/**",
        ".cargo/**",
        ".github/actions/setup-rust/**",
        ".github/actions/restore-runtime-tests/**",
        ".github/workflows/ci.yml",
        "scripts/**",
        "!**/__pycache__/**",
        "!rust/target/**",
    ):
        assert binding in key

    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
    steps = workflow["jobs"]["native-workspace"]["steps"]
    configure = next(step for step in steps if step.get("name") == "Configure the checked test profile")
    restore_call = next(step for step in steps if step.get("id") == "runtime-archive")
    archive = next(step for step in steps if step.get("name") == "Archive the complete runtime test build")
    validate = next(step for step in steps if step.get("name") == "Validate the locked Rust workspace")
    save = next(step for step in steps if step.get("name") == "Save successful runtime test compilation")
    assert steps.index(configure) < steps.index(restore_call) < steps.index(archive)
    assert steps.index(archive) < steps.index(validate) < steps.index(save)
    assert "--locked --workspace --exclude guard-command --exclude hol-guard-runtime --all-targets" in archive["run"]
    assert "--locked --package guard-command --all-targets" in archive["run"]
    assert "--locked --package hol-guard-runtime --all-targets" in archive["run"]
    assert "--partition" not in archive["run"]  # Cache every runtime target, not one hash half.
    assert restore_call["if"] == "matrix.check != 'clippy'"
    assert restore_call["with"]["partition"] == (
        "${{ matrix.check == 'test-command' && 'command' || (matrix.check == 'test-core' && 'core' || 'runtime') }}"
    )
    assert save["if"] == (
        "matrix.check != 'clippy' && "
        "matrix.check != 'test-runtime-2' && "
        "steps.runtime-archive.outputs.cache-hit != 'true' && "
        "github.event_name == 'push' && github.ref == 'refs/heads/main'"
    )
    assert archive["if"] == save["if"]
    assert save["with"]["key"] == "${{ steps.runtime-archive.outputs.cache-primary-key }}"
    assert save["with"]["path"] == restore["with"]["path"]


def test_literal_rust_includes_are_covered_by_the_archive_key():
    action = yaml.safe_load((ROOT / ".github/actions/restore-runtime-tests/action.yml").read_text())
    restore = next(step for step in action["runs"]["steps"] if step.get("id") == "archive")
    patterns = re.findall(r"'([^']+)'", restore["with"]["key"])
    authored = [pattern for pattern in patterns if not pattern.startswith("!")]
    generated = [pattern[1:] for pattern in patterns if pattern.startswith("!")]
    includes = re.compile(r'include_(?:str|bytes)!\(\s*"([^"\n]+)"\s*\)', re.MULTILINE)
    checked = 0
    for source in (ROOT / "rust").rglob("*.rs"):
        if "target" in source.relative_to(ROOT).parts:
            continue
        for included in includes.findall(source.read_text()):
            path = (source.parent / included).resolve().relative_to(ROOT).as_posix()
            assert any(fnmatch.fnmatchcase(path, pattern) for pattern in authored), path
            assert not any(fnmatch.fnmatchcase(path, pattern) for pattern in generated), path
            checked += 1
    assert checked > 100  # Exercise the compiled fixture graph, not an empty match.


def test_generated_files_are_excluded_without_excluding_authored_fixtures():
    action = yaml.safe_load((ROOT / ".github/actions/restore-runtime-tests/action.yml").read_text())
    restore = next(step for step in action["runs"]["steps"] if step.get("id") == "archive")
    patterns = re.findall(r"'([^']+)'", restore["with"]["key"])
    assert patterns[-2:] == ["!**/__pycache__/**", "!rust/target/**"]

    def included(path):
        return any(fnmatch.fnmatchcase(path, pattern) for pattern in patterns[:-2]) and not any(
            fnmatch.fnmatchcase(path, pattern[1:]) for pattern in patterns[-2:]
        )

    assert not included("scripts/ci/__pycache__/native_cache_environment.cpython-312.pyc")
    assert not included("src/codex_plugin_scanner/guard/contracts/__pycache__/loaders.cpython-312.pyc")
    assert not included("rust/target/debug/deps/runtime-generated-output")
    for path in (
        "scripts/ci/native_cache_environment.py",
        "rust/rust-toolchain.toml",
        "rust/crates/guard-runtime/src/main.rs",
        "rust/crates/guard-runtime/testdata/case.json",
        "tests/fixtures/authority/vectors.json",
        "spec/guard-policy/v1alpha1/schema.json",
    ):
        assert included(path), path
