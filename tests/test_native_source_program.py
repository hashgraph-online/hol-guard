"""Exercise the real native compiler without importing Python matcher implementations."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import runpy
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.extension_control_limits import MAX_NATIVE_COMMAND_PROGRAM_BYTES
from scripts import native_directory_inventory

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
    # Legacy compiler contracts use the bounded resident selection. Complete
    # product coverage below walks native packs instead of one aggregate.
    return generator["build_request"](core_only=True)


@pytest.fixture(scope="module")
def canonical_packs(compiler: Path):
    with native_directory_inventory.compiled_inventory(compiler) as (_, reader, release):
        yield reader, release


@pytest.fixture(scope="module")
def compiled(compiler: Path, build: dict) -> dict:
    return compile_request(compiler, build)


def test_extension_directory_renders_all_canonical_sources(canonical_packs, monkeypatch: pytest.MonkeyPatch) -> None:
    """Pending sources must render even when the committed directory awaits regeneration."""
    from codex_plugin_scanner.guard.runtime.generated_command_catalog_loader import _extension
    from scripts.native_directory_inventory import catalog_rows

    reader, release = canonical_packs
    catalog = [row for _, _, row in catalog_rows(reader, release)]
    spec = importlib.util.spec_from_file_location(
        "render_pending_extension_directory", ROOT / "scripts/render_command_extension_directory.py"
    )
    assert spec is not None and spec.loader is not None
    renderer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(renderer)
    monkeypatch.setattr(renderer, "native_extensions", lambda: tuple(_extension(row) for row in catalog))
    current = (ROOT / "docs/guard/extensions/README.md").read_text(encoding="utf-8")
    rendered = renderer.render_document(current)
    assert renderer.render_document(rendered) == rendered
    # Canonical trust classes are required schema fields; missing metadata must fail.
    for extension in catalog:
        identity = extension["extension_id"]
        description = renderer._escape_cell(extension["description"])
        assert rendered.count(f"`{identity}`") == 1
        assert f"| `{identity}` | {description} | {len(extension['rules'])} |" in rendered
        if extension["trust_class"] == "external":
            assert f"| `{identity}` | {description} | {len(extension['rules'])} | External opt-in |" in rendered
    # Exactly one marker pair is part of the directory contract.
    assert rendered.count(renderer.START_MARKER) == rendered.count(renderer.END_MARKER) == 1
    assert rendered.split(renderer.START_MARKER, 1)[0] == current.split(renderer.START_MARKER, 1)[0]
    assert rendered.split(renderer.END_MARKER, 1)[1] == current.split(renderer.END_MARKER, 1)[1]


@pytest.fixture
def example(compiler: Path, build: dict) -> dict:
    source = json.loads((ROOT / "rust/crates/guard-command/tests/fixtures/command-source-example.v1.json").read_bytes())
    request = copy.deepcopy(build)
    request["sources"].insert(0, source)
    compile_request(compiler, request)
    return request


def test_checked_in_program_matches_native_authoring(compiler: Path, canonical_packs) -> None:
    """Bind the resident artifact and embedded compiler to the reviewed core selection."""
    generator = runpy.run_path(str(ROOT / "scripts/build_native_command_program.py"))
    core = compile_request(compiler, generator["build_request"](core_only=True))
    core_ids = {entry["extension_id"] for entry in generator["core_entries"]()}
    assert {entry["extension_id"] for entry in core["catalog"]} == core_ids
    from scripts.native_directory_inventory import catalog_rows

    reader, release = canonical_packs
    assert core_ids <= {identity for identity, _, _ in catalog_rows(reader, release)}
    checked_in = json.loads((ROOT / "contracts/extensions/native-command-program.v1.json").read_bytes())
    assert checked_in == core["program"], (
        "Stage current projections before testing: python scripts/ci/verify_native_command_program.py "
        "--compiler rust/target/release/guard-command-source"
    )
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


def test_full_catalog_identity_coverage_and_node_closure(
    compiler: Path, build: dict, compiled: dict, canonical_packs
) -> None:
    assert compiled == compile_request(compiler, build)
    from scripts.native_directory_inventory import catalog_rows

    reader, release = canonical_packs
    identities = set()
    for identity, manifest, row in catalog_rows(reader, release):
        identities.add(identity)
        program = reader.json(manifest["program"])
        program["nodes"] = {key: reader.json(reference) for key, reference in program["nodes"].items()}
        assert_program_closure({"program": program, "catalog": [row]})
    expected = {path.stem for path in (ROOT / "contributions/command-sources").glob("command.*.json")}
    expected.update(
        "command.mcp-" + path.stem.removeprefix("mcp.")
        for path in (ROOT / "contributions/mcp-servers").glob("mcp.*.json")
    )
    assert identities == expected
    assert len(identities) == release["extensions"]
    assert_program_closure(compiled)


def assert_program_closure(compiled: dict) -> None:
    program = compiled["program"]
    payload = dict(program)
    digest = payload.pop("program_digest")
    assert hashlib.sha256(PROGRAM_DOMAIN + canonical(payload)).hexdigest() == digest
    assert len(canonical(program)) <= MAX_NATIVE_COMMAND_PROGRAM_BYTES
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


def test_native_input_above_legacy_budget_is_accepted(compiler: Path, build: dict) -> None:
    payload = canonical(build)
    legacy_limit = 4 * 1024 * 1024
    current_limit = 8 * 1024 * 1024
    if len(payload) <= legacy_limit:
        payload += b" " * (legacy_limit + 1 - len(payload))
    assert legacy_limit < len(payload) <= current_limit

    result = subprocess.run([str(compiler), "compile"], input=payload, capture_output=True, timeout=60)
    assert result.returncode == 0, result.stderr.decode(errors="replace") + result.stdout.decode(errors="replace")


def test_native_input_byte_budget(compiler: Path, example: dict) -> None:
    expanded = subprocess.run(
        [str(compiler), "compile"], input=canonical(example) + b" " * (4 * 1024 * 1024), capture_output=True, timeout=60
    )
    assert expanded.returncode == 0
    for padding_mib in (8, 9):
        result = subprocess.run(
            [str(compiler), "compile"],
            input=canonical(example) + b" " * (padding_mib * 1024 * 1024),
            capture_output=True,
            timeout=60,
        )
        assert result.returncode != 0


def test_native_matcher_node_budget(compiler: Path, example: dict) -> None:
    # Exercise the matcher budget independently of the growing product catalog.
    example = copy.deepcopy(example)
    example["sources"] = example["sources"][:1]
    example["mcp_sources"] = []
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

    result = invoke(compiler, example)
    assert result.returncode != 0
    assert json.loads(result.stdout)["code"] == "command_source_matcher_budget_exceeded"


def test_reordered_catalog_inputs_keep_identity(compiler: Path, build: dict, compiled: dict) -> None:
    reordered = copy.deepcopy(build)
    reordered["sources"].reverse()
    reordered["mcp_sources"].reverse()
    assert compile_request(compiler, reordered) == compiled


def test_native_directory_preparation_above_legacy_limit(compiler: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Real native packs and public metadata remain complete at the 513th source."""
    # The script imports its siblings by bare name, as it does when run directly.
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    import prepare_extension_directory as directory

    from codex_plugin_scanner.guard.extension_builder.errors import BuilderError
    from scripts.native_directory_inventory import catalog_rows, compiled_inventory

    template = (ROOT / "rust/crates/guard-command/tests/fixtures/command-source-example.v1.json").read_text()
    # Stay under this checkout so the local build marker binds its actual Git
    # revision. These synthetic sources never enter the checkout's inventory.
    with tempfile.TemporaryDirectory(prefix=".directory-scale-", dir=ROOT) as scratch:
        root = Path(scratch)
        # Preserve the real compatibility inventory and global relationships.
        # Added sources exercise growth without replacing any canonical input.
        for relative in (
            "contributions/command-sources",
            "contributions/mcp-servers",
            "contributions/extensions",
            "contributions/extension-listings",
            "contracts/extensions/trust",
        ):
            shutil.copytree(ROOT / relative, root / relative)
        (root / "docs/guard/extensions").mkdir(parents=True)
        identities = {path.stem for path in (root / "contributions/command-sources").glob("command.*.json")}
        identities.update(
            "command.mcp-" + path.stem.removeprefix("mcp.")
            for path in (root / "contributions/mcp-servers").glob("mcp.*.json")
        )
        additions = {f"command.scale-{index:04}" for index in range(513 - len(identities))}
        identities.update(additions)
        for identity in sorted(additions):
            source = template.replace("command.example-cli", identity)
            (root / "contributions/command-sources" / f"{identity}.json").write_text(source)
            (root / "contracts/extensions/trust" / f"{identity}.v1.json").write_bytes(
                canonical(
                    {
                        "schemaVersion": "guard.extension-trust-binding.v1",
                        "extension": identity,
                        "trustClass": "external",
                    }
                )
            )
        with compiled_inventory(compiler, root=root) as (_, reader, release):
            assert release["extensions"] == len(identities)
            for identity, manifest, _ in catalog_rows(reader, release):
                descriptors = reader.json(manifest["descriptors"])
                if identity in additions:
                    assert len(descriptors) == 1 and descriptors[0]["id"] == identity
                for descriptor in descriptors:
                    path = root / "contributions/extensions" / f"{descriptor['id']}.json"
                    path.write_bytes(canonical(descriptor))
        markdown = root / "docs/guard/extensions/README.md"
        markdown.write_text(f"intro\n{directory.markdown.START_MARKER}\nold\n{directory.markdown.END_MARKER}\nend\n")
        expected = {"extensions": 513, "legacy": "extension-count"}
        assert directory.prepare(compiler, root=root) == expected
        assert directory.prepare(compiler, root=root, check=True) == expected
        assert all(markdown.read_text().count(f"`{identity}`") == 1 for identity in identities)
        marker = root / "docs/guard/extensions" / directory.UNAVAILABLE
        source_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
        assert json.loads(marker.read_bytes()) == directory.unavailable_marker(source_sha, "extension-count")
        before = marker.read_bytes()
        marker.write_bytes(before.replace(b"extension-count", b"directory-bytes"))
        with pytest.raises(ValueError, match="marker differs"):
            directory.prepare(compiler, root=root, check=True)
        marker.write_bytes(before)
        descriptor = root / "contributions/extensions/command.scale-0000.json"
        original = descriptor.read_bytes()
        descriptor.unlink()
        with pytest.raises((BuilderError, OSError, ValueError)):
            directory.prepare(compiler, root=root, check=True)
        descriptor.write_bytes(original)
        listing = root / "contributions/extension-listings/command.scale-0000.json"
        listing.parent.mkdir(exist_ok=True)
        listing.write_text('{"schemaVersion":"invalid"}')
        with pytest.raises((BuilderError, ValueError)):
            directory.prepare(compiler, root=root, check=True)
