"""Synthetic, nonexecuting authoring fixtures shared by the builder test suites."""

from __future__ import annotations

import copy
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Literal

import pytest

from codex_plugin_scanner.guard.extension_builder import kit as kit_module
from codex_plugin_scanner.guard.extension_builder import native_source_compiler
from codex_plugin_scanner.guard.extension_builder.discover import discover
from codex_plugin_scanner.guard.extension_builder.io import canonical_json
from codex_plugin_scanner.guard.extension_builder.kit import Kit, build_kit
from codex_plugin_scanner.guard.extension_builder.models import Discovery, Metadata
from codex_plugin_scanner.guard.extension_builder.repository_edits import (
    PYPROJECT_PATH,
    STAGING_PATH,
)
from codex_plugin_scanner.guard.extension_builder.review import default_review, load_review

REPOSITORY = Path(__file__).resolve().parents[1]


def invoke_source_cli(compiler, request, operation="compile"):
    return subprocess.run(
        [str(compiler), operation],
        input=json.dumps(request, sort_keys=True, separators=(",", ":")).encode(),
        capture_output=True,
        timeout=120,
        check=False,
    )


@pytest.fixture(scope="module")
def native_authoring_index(tmp_path_factory):
    import base64
    import io

    from codex_plugin_scanner.guard.catalog_delivery.metadata_objects import ObjectStore, encoded
    from tests.delivery_scripts import script

    entries = script("extension_delivery_objects").entries

    compiler = REPOSITORY / "rust/target/debug/guard-command-source"
    if not compiler.is_file():
        pytest.skip("build the actual native source CLI before running authoring integration")
    built = json.loads(subprocess.check_output([str(compiler), "export-built"], timeout=60))
    trust = json.loads(subprocess.check_output([str(compiler), "export-trust"], timeout=60))
    source = json.loads(
        (REPOSITORY / "rust/crates/guard-command/tests/fixtures/command-source-example.v1.json").read_bytes()
    )
    dependency = json.loads(json.dumps(source).replace("command.example-cli", "command.dependency"))
    buffer = io.BytesIO()
    with pytest.MonkeyPatch.context() as patch:
        patch.syspath_prepend(str(REPOSITORY / "scripts"))
        from build_native_command_packs import input_stream

        count = input_stream(REPOSITORY, buffer)
    canonical = buffer.getvalue()
    header_length = int.from_bytes(canonical[5:9], "big")

    def frame(value):
        data = encoded(value)
        return len(data).to_bytes(4, "big") + data

    pack_trust = copy.deepcopy(trust)
    pack_trust["classes"] = {"external": ["command.dependency"], "first-party": [], "trusted-library": []}
    stream = b"HGPS\x01" + frame({"schema": "guard.command-pack-source-stream.v1", "count": count + 1})
    stream += canonical[9 + header_length :] + frame({"kind": "command", "trust": pack_trust}) + frame(dependency)
    response = subprocess.run([str(compiler), "compile-packs"], input=stream, capture_output=True, timeout=60)
    response.check_returncode()
    store = ObjectStore(tmp_path_factory.mktemp("authoring-index-pack").resolve())
    rows = [json.loads(line) for line in response.stdout.splitlines()]
    for row in rows:
        if row["kind"] == "object":
            store.put(base64.b64decode(row["data"]))
    release = next(row for row in rows if row["kind"] == "root")
    manifest = store.json(dict(entries(store, release["index"], count + 1))["command.dependency"])
    program = store.json(manifest["program"])
    program["nodes"] = {identity: store.json(reference) for identity, reference in program["nodes"].items()}
    selected = {"catalog": store.json(manifest["catalog"]), "program": program}
    candidate = copy.deepcopy(source)
    candidate["extension"]["dependencies"] = ["command.dependency"]
    candidate["extension"]["permissions"][0]["dependencies"] = ["command.dependency.permission.destroy"]
    request = {"schema": "guard.command-extension-build.v1", "base": "packaged", "sources": [candidate], "trust": trust}
    return compiler, built, selected, request


def authoring_index_inventory(native, count):
    _, built, selected, _ = native
    catalog = copy.deepcopy(built["catalog"] + selected["catalog"])
    template = json.dumps(selected["catalog"][0])
    for index in range(count - len(catalog)):
        catalog.append(json.loads(template.replace("command.dependency", f"command.zzinactive{index:05d}")))
    return catalog


def use_installed_native_source_compiler(monkeypatch: Any, directory: Path) -> None:
    """Enter a synthetic installation without retaining checkout overrides."""
    monkeypatch.setattr(native_source_compiler, "_NATIVE_PACKAGE", directory)
    monkeypatch.delenv("HOL_GUARD_NATIVE_SOURCE_COMPILER", raising=False)
    monkeypatch.delenv("HOL_GUARD_NATIVE_TEST_SOURCE_COMPILER", raising=False)


def use_built_native_source_compiler(monkeypatch: Any) -> Path | None:
    """Route builder unit tests through the explicitly built native compiler.

    Returns the compiler for callers that must also expose it to unpatched
    native operations such as destination admission, or None when installed.
    """

    if os.environ.get("HOL_GUARD_TEST_USE_INSTALLED") == "1":
        assert Path(native_source_compiler.__file__).is_relative_to(Path(sys.prefix))
        return None  # Exercise the installed factory rather than a checkout compiler.
    candidates = [
        *(
            [Path(os.environ["HOL_GUARD_BUILD_SOURCE_COMPILER"])]
            if os.environ.get("HOL_GUARD_BUILD_SOURCE_COMPILER")
            else []
        ),
        REPOSITORY / "rust/target/release/guard-command-source",
        REPOSITORY / "rust/target/release/guard-command-source.exe",
        REPOSITORY / "rust/target/debug/guard-command-source",
        REPOSITORY / "rust/target/debug/guard-command-source.exe",
    ]
    compiler = next((candidate for candidate in candidates if candidate.is_file()), candidates[0])
    assert compiler.is_file(), "build guard-command-source before running builder orchestration tests"
    setter = monkeypatch.setattr
    setter(
        kit_module,
        "compile_source",
        lambda request: native_source_compiler.compile_source(request, compiler=compiler),
    )
    setter(
        kit_module,
        "run_source_compiler",
        lambda operation, request: native_source_compiler.run_source_compiler(operation, request, compiler=compiler),
    )
    return compiler


def metadata(kind: Literal["cli", "mcp"] = "cli", *, slug: str = "builder-demo") -> Metadata:
    return Metadata(
        kind=kind,
        slug=slug,
        name="Builder Demo",
        publisher_id="community.example",
        publisher_name="Example Maintainer",
        homepage="https://example.test/builder-demo",
        upstream_version="2.4.0",
        executable=slug if kind == "cli" else "",
        launcher="npx" if kind == "mcp" else "",
        package=f"@example/{slug}" if kind == "mcp" else "",
    )


def cli_document() -> dict[str, object]:
    return {
        "schemaVersion": "guard.cli-surface.v1",
        "flags": ["--help", "--version"],
        "optionsWithValues": ["--profile"],
        "commands": [
            {"path": []},
            {"path": ["items", "list"], "flags": ["--json"]},
            {"path": ["items", "delete"], "flags": ["--force"]},
        ],
    }


def mcp_document() -> dict[str, object]:
    return {
        "tools": [
            {"name": "read_item", "inputSchema": {"type": "object"}, "annotations": {"readOnlyHint": True}},
            {"name": "delete_item", "inputSchema": {"type": "object"}, "annotations": {"destructiveHint": True}},
        ]
    }


def make_discovery(tmp_path: Path, kind: Literal["cli", "mcp"] = "cli") -> Discovery:
    source = tmp_path / f"{kind}-source.json"
    source.write_text(canonical_json(cli_document() if kind == "cli" else mcp_document()), encoding="utf-8")
    return discover("cli" if kind == "cli" else "mcp", source, metadata(kind))


def make_kit(tmp_path: Path, kind: Literal["cli", "mcp"] = "cli", *, reviewed: bool = False) -> Kit:
    discovery = make_discovery(tmp_path, kind)
    review = default_review(discovery)
    if reviewed:
        payload = review.to_dict()
        entries = payload["entries"]
        assert isinstance(entries, dict)
        for operation in discovery.operations:
            entry = entries[operation.operation_id]
            assert isinstance(entry, dict)
            entry.update(
                {
                    "reviewed": True,
                    "rationale": "Reviewed against the synthetic fixture implementation.",
                    "evidenceUrl": discovery.metadata.homepage,
                }
            )
            if kind == "cli" and operation.path == ("items", "list"):
                entry["safeArgv"] = [["items", "list", "--json"]]
            if kind == "cli" and operation.path == ("items", "delete"):
                entry["state"] = "block"
            if kind == "mcp":
                entry["state"] = "allow" if operation.name == "read_item" else "block"
        review = load_review(payload, discovery)
    return build_kit(discovery, review)


def repository_fixture(tmp_path: Path) -> Path:
    root = tmp_path / "repository"
    for name in (
        PYPROJECT_PATH,
        STAGING_PATH,
    ):
        destination = root / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(REPOSITORY / name, destination)
    for family in ("extensions", "mcp-servers"):
        shutil.copytree(REPOSITORY / "contributions" / family, root / "contributions" / family)
    # Authored trust bindings are the source of truth for the builder's
    # aggregate projection; a real checkout always has them.
    shutil.copytree(REPOSITORY / "contracts/extensions/trust", root / "contracts/extensions/trust")
    return root


def file_snapshot(root: Path) -> dict[str, bytes]:
    return {path.relative_to(root).as_posix(): path.read_bytes() for path in root.rglob("*") if path.is_file()}
