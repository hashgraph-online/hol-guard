"""Runtime compilation reuse must not reuse test results or partial input matches."""

import os
import re
import subprocess
from pathlib import Path

import pytest
import yaml

from scripts.ci.rust_test_archive_inputs import EXTERNAL_ROOTS, Inputs

ROOT = Path(__file__).resolve().parents[1]


def test_test_compilation_html_is_uploaded_only_for_non_clippy_archive_misses():
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
    steps = workflow["jobs"]["native-workspace"]["steps"]
    uploads = [step for step in steps if step.get("name") == "Retain Rust test compilation timings"]
    assert len(uploads) == 1
    upload = uploads[0]
    assert upload["if"] == ("always() && matrix.check != 'clippy' && steps.runtime-archive.outputs.cache-hit != 'true'")
    assert upload["uses"] == "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
    assert upload["with"] == {
        "name": "rust-test-compilation-timings-${{ matrix.check }}-${{ github.run_attempt }}",
        "path": "rust/target/cargo-timings/cargo-timing.html",
        "if-no-files-found": "ignore",
        "retention-days": 1,
    }


@pytest.mark.parametrize("check", ["test-core", "test-command", "test-runtime-1", "test-runtime-2"])
@pytest.mark.parametrize(
    "event,ref,hit,timed",
    [
        ("pull_request", "refs/pull/1/merge", False, True),
        ("push", "refs/heads/main", False, False),
        ("schedule", "refs/heads/main", False, True),
        ("workflow_dispatch", "refs/heads/main", False, True),
        ("push", "refs/heads/release/3.2", False, True),
        ("pull_request", "refs/pull/1/merge", True, False),
        ("push", "refs/heads/main", True, False),
    ],
)
def test_validation_times_existing_miss_builds_and_preserves_main_archive_html(tmp_path, check, event, ref, hit, timed):
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
    step = next(
        step
        for step in workflow["jobs"]["native-workspace"]["steps"]
        if step.get("name") == "Validate the locked Rust workspace"
    )
    binaries = tmp_path / "bin"
    binaries.mkdir()
    report = tmp_path / "cargo-timing.html"
    report.write_text("archive report")
    for name, source in {
        "python3": '#!/bin/bash\n[[ "$*" == scripts/ci/install_nextest.py ]] || exit 90\nprintf "%s\\n" "$FAKE_BIN"\n',
        "cargo": (
            '#!/bin/bash\nprintf "%s\\n" "$@" > "$ARGS"\n'
            'for argument in "$@"; do\n'
            '  if [[ "$argument" == --timings ]]; then printf "run report" > "$TIMINGS"; fi\n'
            "done\n"
        ),
    }.items():
        path = binaries / name
        path.write_text(source)
        path.chmod(0o755)
    result = subprocess.run(
        ["bash", "-c", step["run"]],
        env={
            **os.environ,
            "PATH": f"{binaries}:{os.environ['PATH']}",
            "FAKE_BIN": str(binaries),
            "RUNNER_TEMP": str(tmp_path),
            "GITHUB_WORKSPACE": str(tmp_path),
            "ARGS": str(tmp_path / "args"),
            "TIMINGS": str(report),
            "CARGO_CHECK": check,
            "GITHUB_EVENT_NAME": event,
            "GITHUB_REF": ref,
            "RUNTIME_ARCHIVE_HIT": str(hit).lower(),
        },
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    arguments = (tmp_path / "args").read_text().splitlines()
    assert arguments[:2] == ["nextest", "run"]
    assert arguments.count("--timings") == int(timed)
    assert not any(argument.startswith("--timings=") for argument in arguments)
    assert report.read_text() == ("run report" if timed else "archive report")
    assert arguments[-5:] == ["--test-threads", "4", "--retries", "0", "--no-fail-fast"]
    assert arguments[arguments.index("--profile") + 1] == "ci"
    if check.startswith("test-runtime-"):
        assert arguments[arguments.index("--partition") + 1] == f"hash:{check[-1]}/2"
    else:
        assert "--partition" not in arguments
    if hit:
        assert "--manifest-path" not in arguments and "--all-targets" not in arguments
        assert arguments[arguments.index("--archive-file") + 1] == str(tmp_path / "runtime-test-archive.tar.zst")
        assert arguments[arguments.index("--workspace-remap") + 1] == str(tmp_path / "rust")
    else:
        assert "--archive-file" not in arguments and "--all-targets" in arguments
        assert "--locked" in arguments
        if check == "test-core":
            assert "--workspace" in arguments
            assert [arguments[i + 1] for i, value in enumerate(arguments) if value == "--exclude"] == [
                "guard-command",
                "hol-guard-runtime",
            ]
        else:
            expected = "guard-command" if check == "test-command" else "hol-guard-runtime"
            assert arguments[arguments.index("--package") + 1] == expected


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
