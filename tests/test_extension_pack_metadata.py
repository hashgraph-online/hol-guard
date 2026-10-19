"""Control-plane metadata indexing; this test creates no runtime authority."""

from __future__ import annotations

import json
import re

import pytest

from codex_plugin_scanner.guard.catalog_delivery.preparation import PreparedCommandPacks
from codex_plugin_scanner.guard.native_command_control_binding import NativeCommandProgramMetadata
from codex_plugin_scanner.guard.runtime.generated_command_catalog import GeneratedCommandCatalog
from codex_plugin_scanner.guard.runtime.generated_command_catalog_loader import _extension


def test_prepared_metadata_index_keeps_legacy_count_cap_and_supports_independent_packs(
    monkeypatch, authored_command_catalog
):
    template = json.dumps(authored_command_catalog.get("command.agentbridge").to_dict())
    rows = [json.loads(re.sub("agentbridge", f"metadata-scale-{index}", template, flags=re.I)) for index in range(600)]
    extensions = tuple(_extension(row) for row in rows)
    with pytest.raises(ValueError, match="catalog extension limit"):
        GeneratedCommandCatalog(extensions)
    # Synthetic prepared-token fixture for the metadata index only. Production
    # tokens require verified publication and actual native cache admission.
    prepared = object.__new__(PreparedCommandPacks)
    fields = {
        "registry_ids": frozenset(row["extension_id"] for row in rows),
        "metadata": NativeCommandProgramMetadata("1" * 64, "2" * 64, "3" * 64),
        "source_sha": "4" * 40,
        "engine": "5" * 64,
        "candidate_executables": (),
    }
    for name, value in fields.items():
        object.__setattr__(prepared, name, value)
    monkeypatch.setattr(PreparedCommandPacks, "registry_catalogs", lambda _: iter(rows))
    registry = GeneratedCommandCatalog.from_prepared_packs(prepared)
    assert len(registry.extensions) == 600
    assert registry.catalog_digest == prepared.metadata.catalog_digest
    assert registry.program_digest == prepared.metadata.program_digest
    assert registry.implementation_digest == prepared.engine
    assert registry.get("command.metadata-scale-599") is not None
    with pytest.raises(ValueError, match="prepared authenticated"):
        GeneratedCommandCatalog.from_prepared_packs(rows)
