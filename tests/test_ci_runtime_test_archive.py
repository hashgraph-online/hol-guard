"""Runtime compilation reuse must not reuse test results or partial input matches."""

import fnmatch
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_runtime_archive_is_exact_input_only_and_saved_by_one_trusted_writer():
    action = yaml.safe_load(
        (ROOT / ".github/actions/restore-runtime-tests/action.yml").read_text()
    )
    stages = action["runs"]["steps"]
    restore = next(step for step in stages if step.get("id") == "archive")
    assert stages[0]["run"] == "python3 scripts/refresh_extension_artifacts.py --trust-only"
    assert "restore-keys" not in restore["with"]
    key = restore["with"]["key"]
    for binding in (
        "runner.arch", "outputs.image", "outputs.compiler-env",
        "CARGO_PROFILE_RELEASE_LTO", "CARGO_PROFILE_RELEASE_CODEGEN_UNITS",
        "rust/**", "contributions/**", "contracts/**", "spec/**", "tests/fixtures/**",
        "src/codex_plugin_scanner/guard/contracts/**", ".cargo/**",
        ".github/actions/setup-rust/**", ".github/actions/restore-runtime-tests/**",
        ".github/workflows/ci.yml", "scripts/**",
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
    assert "--locked --package hol-guard-runtime --all-targets" in archive["run"]
    assert "--partition" not in archive["run"]  # Cache every runtime target, not one hash half.
    assert restore_call["if"] == "startsWith(matrix.check, 'test-runtime-')"
    assert save["if"] == (
        "matrix.check == 'test-runtime-1' && "
        "steps.runtime-archive.outputs.cache-hit != 'true' && "
        "github.event_name == 'push' && github.ref == 'refs/heads/main'"
    )
    assert archive["if"] == save["if"]
    assert save["with"]["key"] == "${{ steps.runtime-archive.outputs.cache-primary-key }}"
    assert save["with"]["path"] == restore["with"]["path"]


def test_literal_rust_includes_are_covered_by_the_archive_key():
    action = yaml.safe_load(
        (ROOT / ".github/actions/restore-runtime-tests/action.yml").read_text()
    )
    restore = next(step for step in action["runs"]["steps"] if step.get("id") == "archive")
    patterns = re.findall(r"'([^']+)'", restore["with"]["key"])
    includes = re.compile(r'include_(?:str|bytes)!\(\s*"([^"\n]+)"\s*\)', re.MULTILINE)
    checked = 0
    for source in (ROOT / "rust").rglob("*.rs"):
        if "target" in source.relative_to(ROOT).parts:
            continue
        for included in includes.findall(source.read_text()):
            path = (source.parent / included).resolve().relative_to(ROOT).as_posix()
            assert any(fnmatch.fnmatchcase(path, pattern) for pattern in patterns), path
            checked += 1
    assert checked > 100  # Exercise the compiled fixture graph, not an empty match.
