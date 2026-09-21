"""Public schema parity and portable source emission at the documented field limits."""

from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.extension_builder.discover import discover
from codex_plugin_scanner.guard.extension_builder.io import canonical_json
from codex_plugin_scanner.guard.extension_builder.kit import build_kit, write_kit
from codex_plugin_scanner.guard.extension_builder.models import make_discovery, make_operation
from codex_plugin_scanner.guard.extension_builder.python_literals import LiteralCall, emit, inline
from codex_plugin_scanner.guard.extension_builder.review import default_review, load_review
from codex_plugin_scanner.guard.extension_builder.schemas import DISCOVERY_JSON_SCHEMA, REVIEW_JSON_SCHEMA
from tests.extension_builder_support import REPOSITORY, make_kit, metadata


@pytest.mark.parametrize("kind,schema", [("discovery", DISCOVERY_JSON_SCHEMA), ("review", REVIEW_JSON_SCHEMA)])
def test_public_schemas_match_the_bundled_runtime_contract(kind: str, schema: object) -> None:
    path = REPOSITORY / "contracts/extensions" / f"authoring-{kind}.v1.schema.json"
    assert path.read_text(encoding="utf-8") == canonical_json(schema)


@pytest.mark.parametrize("kind,filename", [("cli", "cli-surface.json"), ("mcp", "mcp-tools.json")])
def test_documented_exports_produce_valid_kits(tmp_path: Path, kind: str, filename: str) -> None:
    source = REPOSITORY / "docs/guard/extension-builder/examples" / filename
    discovery = discover(kind, source, metadata(kind))
    kit = build_kit(discovery, default_review(discovery))
    write_kit(kit, tmp_path / "kit")
    assert kit.summary()["reviewedOperations"] == 0


@pytest.mark.parametrize(
    "value",
    [None, "", "plain", 'quote" slash\\ apostrophe\'', "line\nbreak", "界" * 128, "\U0001f680" * 128,
     (), ("a",), ("x" * 64,) * 8, (("first", "second"), ("third", "fourth"))],
)
def test_literal_emission_preserves_values_without_version_dependent_formatters(value: object) -> None:
    source = "\n".join(emit(value, prefix="VALUE = "))
    tree = ast.parse(source, feature_version=(3, 10))
    assert isinstance(tree.body[0], ast.Assign)
    assert ast.literal_eval(tree.body[0].value) == value
    assert all(len(line) <= 120 for line in source.splitlines())


def test_literal_emitter_rejects_arbitrary_constructor_names() -> None:
    with pytest.raises(ValueError, match="Unsupported"):
        inline(LiteralCall("__import__", "os"))


def test_maximum_field_lengths_produce_linted_portable_native_source(tmp_path: Path) -> None:
    target = replace(metadata(), name="界" * 128, homepage="https://example.test/" + "x" * 480)
    path = tuple(chr(97 + index) * 64 for index in range(8))
    flags = tuple("--" + f"flag{index}".ljust(62, "x") for index in range(128))
    operation = make_operation("cli", path=path, flags=flags, evidence={})
    discovery = make_discovery(target, "cli", "0" * 64, (operation,), ("metadata-is-not-semantics",))
    review = default_review(discovery).to_dict()
    entry = review["entries"][operation.operation_id]
    entry.update({
        "reviewed": True,
        "rationale": "Reviewed the bounded synthetic fixture.",
        "evidenceUrl": target.homepage,
        "riskClasses": ["execution", "destructive_shell", "network_egress", "local_secret_read"],
        "saferAlternative": "界" * 256,
    })
    kit = build_kit(discovery, load_review(review, discovery))
    output = tmp_path / "kit"
    write_kit(kit, output)
    for filename, content in kit.files:
        if filename.endswith(".py"):
            ast.parse(content, feature_version=(3, 10))
            assert all(len(line) <= 120 for line in content.splitlines()), filename
    for command in ("check", "format"):
        arguments = [sys.executable, "-m", "ruff", command, "--config", str(REPOSITORY / "pyproject.toml")]
        if command == "format":
            arguments.append("--check")
        result = subprocess.run(
            [*arguments, str(output / "artifacts")], capture_output=True, text=True, timeout=20, check=False,
        )
        assert result.returncode == 0, result.stdout + result.stderr


def test_snapshot_replay_is_identical_across_python_hash_seeds(tmp_path: Path) -> None:
    kit = make_kit(tmp_path, reviewed=True)
    original = tmp_path / "original"
    write_kit(kit, original)
    manifest = (original / "manifest.json").read_bytes()
    for seed in ("1", "731"):
        output = tmp_path / f"seed-{seed}"
        environment = os.environ.copy()
        environment["PYTHONHASHSEED"] = seed
        for name in list(environment):
            if name.startswith(("COV_CORE_", "COVERAGE_")):
                environment.pop(name)
        command = [sys.executable, "-c", "import sys; from codex_plugin_scanner.cli import main; sys.exit(main(sys.argv[1:]))",
                   "guard", "extensions", "generate", "--from", "snapshot", "--input", str(original / "discovery.json"),
                   "--review", str(original / "review.json"), "--output", str(output), "--json"]
        result = subprocess.run(command, env=environment, capture_output=True, text=True, timeout=30, check=False)
        assert result.returncode == 0, result.stdout + result.stderr
        assert json.loads(result.stdout)["generated"] is True
        assert (output / "manifest.json").read_bytes() == manifest
