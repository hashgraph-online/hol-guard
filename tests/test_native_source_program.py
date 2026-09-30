"""Exercise the real native compiler without importing Python matcher implementations."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import runpy
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PROGRAM_DOMAIN = b"hol-guard.native-command-program.v1\0"
NODE_DOMAIN = b"hol-guard.native-command-matcher.v1\0"


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


@pytest.fixture(scope="module")
def compiler() -> Path:
    configured = os.environ.get("HOL_GUARD_NATIVE_TEST_SOURCE_COMPILER")
    if configured is not None:
        executable = Path(configured)
        if not configured or not executable.is_file() or not os.access(executable, os.X_OK):
            pytest.fail(
                f"HOL_GUARD_NATIVE_TEST_SOURCE_COMPILER must name an existing executable compiler: {configured!r}"
            )
        return executable.resolve()
    subprocess.run(
        [
            "cargo",
            "+1.88.0",
            "build",
            "--locked",
            "--manifest-path",
            str(ROOT / "rust/Cargo.toml"),
            "-p",
            "guard-command",
            "--bin",
            "guard-command-source",
        ],
        cwd=ROOT,
        check=True,
        timeout=600,
    )
    return ROOT / "rust/target/debug/guard-command-source"


def invoke(compiler: Path, request: object) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run([str(compiler), "compile"], input=canonical(request), capture_output=True, timeout=60)


def compile_request(compiler: Path, request: object) -> dict:
    result = invoke(compiler, request)
    assert result.returncode == 0, result.stderr.decode(errors="replace") + result.stdout.decode(errors="replace")
    return json.loads(result.stdout)


@pytest.fixture(scope="module")
def build() -> dict:
    generator = runpy.run_path(str(ROOT / "scripts/build_native_command_program.py"))
    return generator["build_request"]()


@pytest.fixture(scope="module")
def compiled(compiler: Path, build: dict) -> dict:
    return compile_request(compiler, build)


@pytest.fixture
def example(compiler: Path, build: dict) -> dict:
    source = json.loads((ROOT / "rust/crates/guard-command/tests/fixtures/command-source-example.v1.json").read_bytes())
    request = copy.deepcopy(build)
    request["sources"].insert(0, source)
    compile_request(compiler, request)
    return request


def test_checked_in_program_matches_native_authoring(compiler: Path, compiled: dict) -> None:
    checked_in = json.loads((ROOT / "contracts/extensions/native-command-program.v1.json").read_bytes())
    assert checked_in == compiled["program"]
    result = subprocess.run(
        [str(compiler), "evaluate-batch"],
        input=canonical(
            {
                "schema": "guard.command-extension-evaluation-batch.v1",
                "cases": [{"id": "embedded-program-identity", "command": "pwd"}],
            }
        ),
        capture_output=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr.decode(errors="replace") + result.stdout.decode(errors="replace")
    embedded = json.loads(result.stdout)
    assert embedded["schema"] == "guard.command-extension-evaluation-batch-results.v1"
    assert embedded["ok"] is True
    assert embedded["target_commands_executed"] == 0
    assert embedded["program_digest"] == checked_in["program_digest"], (
        "Native source compiler embeds a stale command program; rebuild it after generating the checked-in program"
    )
    assert embedded["catalog_digest"] == checked_in["catalog_digest"]
    assert [case["id"] for case in embedded["cases"]] == ["embedded-program-identity"]
    binding = embedded["cases"][0]["payload"]["command_extensions"]["binding"]
    assert binding["program_digest"] == checked_in["program_digest"]
    assert binding["catalog_digest"] == checked_in["catalog_digest"]


def test_full_catalog_identity_coverage_and_node_closure(compiler: Path, build: dict, compiled: dict) -> None:
    assert compiled == compile_request(compiler, build)
    program = compiled["program"]
    payload = dict(program)
    digest = payload.pop("program_digest")
    assert hashlib.sha256(PROGRAM_DOMAIN + canonical(payload)).hexdigest() == digest
    assert len(canonical(program)) <= 4 * 1024 * 1024
    metadata_rules = {rule["rule_id"]: rule for extension in compiled["catalog"] for rule in extension["rules"]}
    rules = {rule["rule_id"]: rule for rule in program["rules"]}
    coverage = {rule["rule_id"]: rule for rule in program["coverage"]}
    assert rules.keys() == coverage.keys() == metadata_rules.keys()
    for identity, rule in rules.items():
        assert [item["variant_id"] for item in rule["safe_variants"]] == [
            item["variant_id"] for item in coverage[identity]["safe_variants"]
        ]
        assert coverage[identity]["native_execution"] == "requires-runtime-admission"
    nodes = program["nodes"]
    for node_id, node in nodes.items():
        assert hashlib.sha256(NODE_DOMAIN + canonical(node)).hexdigest() == node_id
        for value in node["children"].values():
            assert all(reference in nodes for reference in (value if isinstance(value, list) else [value]))


def test_python_callbacks_are_rejected_without_execution(compiler: Path, example: dict, tmp_path: Path) -> None:
    marker = tmp_path / "executed"
    example["sources"][0]["extension"]["rules"][0]["matcher"] = {
        "op": "python.v1",
        "config": {"code": f"open({str(marker)!r}, 'w').write('executed')"},
    }
    assert invoke(compiler, example).returncode != 0
    assert not marker.exists()


def test_unknown_operation_is_rejected(compiler: Path, example: dict) -> None:
    example["sources"][0]["extension"]["rules"][0]["matcher"]["op"] = "unreviewed.v1"
    assert invoke(compiler, example).returncode != 0


def test_full_executable_and_path_set_contracts_survive_lowering(compiler: Path, example: dict) -> None:
    config = {
        "executables": ["ollama", "ollama.exe"],
        "subcommands": ["push"],
        "required_flags": ["--help"],
        "forbidden_flags": ["--unsafe"],
        "allow_leading_options": True,
        "leading_options_with_values": ["--config"],
        "interspersed_options_with_values": ["--server"],
        "interspersed_flags": ["--verbose"],
        "options_with_values": ["--format"],
        "inverse_flag_pairs": [["--read-only", "--no-read-only"]],
        "required_option_values": [["--format", ["json", "yaml"]]],
        "required_flags_in_all_arguments": True,
        "fail_secure_unknown_options": True,
    }
    rule = example["sources"][0]["extension"]["rules"][0]
    rule["matcher"] = {"op": "executable.v1", "config": config}
    program = compile_request(compiler, example)["program"]
    assert any(node["op"] == "executable.v1" and node["config"] == config for node in program["nodes"].values())
    path_config = {"executables": ["cloud"], "paths": [["a", "b"], ["a"]]}
    rule["matcher"] = {"op": "executable-path-set.v1", "config": path_config}
    program = compile_request(compiler, example)["program"]
    assert any(
        node["op"] == "executable-path-set.v1" and node["config"] == path_config for node in program["nodes"].values()
    )


def test_depth_and_configuration_limits(compiler: Path, example: dict) -> None:
    rule = example["sources"][0]["extension"]["rules"][0]
    matcher = rule["matcher"]
    for _ in range(34):
        matcher = {"op": "any.v1", "config": {}, "matchers": [matcher]}
    rule["matcher"] = matcher
    assert invoke(compiler, example).returncode != 0
    rule["matcher"] = {"op": "arguments.v1", "config": {"executables": ["x" * 4097]}}
    assert invoke(compiler, example).returncode != 0


def test_native_input_byte_budget(compiler: Path, example: dict) -> None:
    result = subprocess.run(
        [str(compiler), "compile"], input=canonical(example) + b" " * (4 * 1024 * 1024), capture_output=True, timeout=60
    )
    assert result.returncode != 0


def test_native_matcher_node_budget(compiler: Path, example: dict) -> None:
    groups = [
        {
            "op": "any.v1",
            "config": {},
            "matchers": [
                {
                    "op": "arguments.v1",
                    "config": {"executables": [f"fixture-{group}-{index}"], "required_arguments": ["destroy"]},
                }
                for index in range(1024)
            ],
        }
        for group in range(17)
    ]
    example["sources"][0]["extension"]["rules"][0]["matcher"] = {
        "op": "any.v1",
        "config": {},
        "matchers": groups,
    }
    assert len(canonical(example)) < 4 * 1024 * 1024
    result = invoke(compiler, example)
    assert result.returncode != 0
    assert json.loads(result.stdout)["code"] == "command_source_matcher_budget_exceeded"


def test_reordered_catalog_inputs_keep_identity(compiler: Path, build: dict, compiled: dict) -> None:
    reordered = copy.deepcopy(build)
    reordered["sources"].reverse()
    reordered["mcp_sources"].reverse()
    assert compile_request(compiler, reordered) == compiled
