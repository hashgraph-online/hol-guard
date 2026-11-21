"""Oversized legacy output must not hide invalid canonical public metadata."""

from __future__ import annotations

import importlib
import json
import sys
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import native_directory_inventory

# The script imports its siblings by bare name, as it does when run directly.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
try:
    preparation = importlib.import_module("prepare_extension_directory")
finally:
    sys.path.remove(str(Path(__file__).resolve().parents[1] / "scripts"))


@pytest.fixture
def inventory(tmp_path, monkeypatch):
    assert preparation.ROOT == native_directory_inventory.ROOT
    directory = tmp_path / "docs/guard/extensions"
    directory.mkdir(parents=True)
    markdown = preparation.markdown
    (directory / "README.md").write_text(f"intro\n{markdown.START_MARKER}\nold\n{markdown.END_MARKER}\nend\n")
    rows = []
    sources = tmp_path / "contributions/extensions"
    sources.mkdir(parents=True)
    for index in range(513):
        identity = f"command.scale-{index:04}"
        (sources / f"{identity}.json").write_text("{}")
        rows.append((identity, {}, {"extension_id": identity}))

    @contextmanager
    def compiled(*args, **kwargs):
        yield tmp_path, None, {"extensions": len(rows)}

    monkeypatch.setattr(preparation, "compiled_inventory", compiled)
    monkeypatch.setattr(preparation, "catalog_rows", lambda *args: iter(rows))
    calls = []

    def public_entry(root, catalog):
        identity = catalog[0]["extension_id"]
        calls.append(identity)
        return {"id": identity, "runtimeExtensionId": identity}

    monkeypatch.setattr(preparation, "public_entry", public_entry)
    import codex_plugin_scanner.guard.runtime.generated_command_catalog_loader as loader

    monkeypatch.setattr(
        loader,
        "_extension",
        lambda row: SimpleNamespace(
            extension_id=row["extension_id"],
            description="Scale fixture",
            required=False,
            delegated_protection=None,
            trust_class="external",
            rules=(),
        ),
    )
    monkeypatch.setattr(preparation.subprocess, "check_output", lambda *a, **k: "1" * 40 + "\n")
    monkeypatch.setattr(
        preparation.legacy, "render_directories", lambda *a: pytest.fail("oversize must not call legacy export")
    )
    return tmp_path, rows, calls


def test_oversized_inventory_validates_every_entry_and_checks_explicit_marker(inventory):
    root, rows, calls = inventory
    result = preparation.prepare(root=root)
    assert result == {"extensions": 513, "legacy": "extension-count"}
    assert calls == [identity for identity, _, _ in rows]
    marker = root / "docs/guard/extensions" / preparation.UNAVAILABLE
    assert json.loads(marker.read_text()) == preparation.unavailable_marker("1" * 40, "extension-count")
    markdown = (marker.parent / "README.md").read_text()
    assert all(markdown.count(f"`{identity}`") == 1 for identity, _, _ in rows)
    assert markdown.startswith("intro\n") and markdown.endswith("\nend\n")
    assert preparation.prepare(root=root, check=True) == result
    marker.write_text(marker.read_text().replace("extension-count", "directory-bytes"))
    with pytest.raises(ValueError, match="marker differs"):
        preparation.prepare(root=root, check=True)


def test_oversize_does_not_mask_invalid_entry(inventory, monkeypatch):
    root, _, _ = inventory

    def invalid(*args):
        raise ValueError("invalid canonical listing")

    monkeypatch.setattr(preparation, "public_entry", invalid)
    with pytest.raises(ValueError, match="invalid canonical listing"):
        preparation.prepare(root=root)
    assert not (root / "docs/guard/extensions" / preparation.UNAVAILABLE).exists()


def test_oversize_does_not_mask_orphaned_public_source(inventory):
    root, _, _ = inventory
    (root / "contributions/extensions/command.orphan.json").write_text("{}")
    with pytest.raises(ValueError, match="sources differ"):
        preparation.prepare(root=root)


def test_legacy_source_count_bound_remains_explicit(tmp_path, monkeypatch):
    parent = tmp_path / "contributions/extensions"
    parent.mkdir(parents=True)
    for index in range(513):
        identity = f"command.scale-{index:04}"
        (parent / f"{identity}.json").write_text(json.dumps({"id": identity}))
    # Validation semantics are covered separately; this isolates the unchanged
    # aggregate limit from native compilation or product inventory size.
    monkeypatch.setattr(preparation.legacy, "validate_contribution", lambda *a, **k: None)
    with pytest.raises(ValueError, match="source count exceeds its budget"):
        preparation.legacy._sources(tmp_path)
