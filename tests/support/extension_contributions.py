"""Independent descriptor fixtures for schema, packaging and directory tests."""

from __future__ import annotations

from codex_plugin_scanner.guard.runtime.extension_trust import trust_class_for


def command_descriptor_fixture(extension_id: str) -> dict[str, object]:
    """Construct test metadata without depending on a generated checkout file."""
    trust = trust_class_for(extension_id)
    return {
        "schemaVersion": "guard.extension-contribution.v2",
        "id": extension_id,
        "name": f"Fixture for {extension_id}",
        "description": "Synthetic contribution metadata for isolated contract tests.",
        "version": "1.0.0",
        "generated": True,
        "trustClass": trust,
        "activation": "opt-in" if trust == "external" else "default-on",
        "publisher": {"id": "test.fixture", "displayName": "Test fixture"},
        "icon": {"kind": "none"},
        "license": "MIT",
        "homepage": None,
        "referenceUrls": [],
        "ecosystemIds": [],
        "executables": [],
        "actionClasses": [],
        "riskClasses": [],
        "saferAlternatives": [],
        "nativeSource": {
            "schemaVersion": "guard.command-extension-source.v1",
            "path": f"contributions/command-sources/{extension_id}.json",
            "digest": "0" * 64,
        },
    }
