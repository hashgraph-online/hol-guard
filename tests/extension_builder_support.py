"""Synthetic, nonexecuting authoring fixtures shared by the builder test suites."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Literal

from codex_plugin_scanner.guard.extension_builder.discover import discover
from codex_plugin_scanner.guard.extension_builder.io import canonical_json
from codex_plugin_scanner.guard.extension_builder.kit import Kit, build_kit
from codex_plugin_scanner.guard.extension_builder.models import Discovery, Metadata
from codex_plugin_scanner.guard.extension_builder.repository_edits import (
    CATALOG_PATH,
    PYPROJECT_PATH,
    STAGING_PATH,
    TRUST_PATH,
)
from codex_plugin_scanner.guard.extension_builder.review import default_review, load_review

REPOSITORY = Path(__file__).resolve().parents[1]


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
        TRUST_PATH,
        STAGING_PATH,
        CATALOG_PATH,
        "src/codex_plugin_scanner/guard/runtime/command_reviewed_literal_matcher.py",
    ):
        destination = root / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(REPOSITORY / name, destination)
    for family in ("extensions", "mcp-servers"):
        shutil.copytree(REPOSITORY / "contributions" / family, root / "contributions" / family)
    return root


def file_snapshot(root: Path) -> dict[str, bytes]:
    return {path.relative_to(root).as_posix(): path.read_bytes() for path in root.rglob("*") if path.is_file()}
