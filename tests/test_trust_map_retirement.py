"""A repository aggregate must never substitute for reviewed trust inputs."""

import json

import pytest

from codex_plugin_scanner.guard.runtime import extension_contribution, extension_trust


@pytest.mark.parametrize("reader", [extension_trust._load_map, extension_contribution._trust_classes])
def test_source_runtime_rejects_a_legacy_map_without_canonical_trust(tmp_path, monkeypatch, reader):
    legacy = tmp_path / "contracts/extensions/trust-class-map.v1.json"
    legacy.parent.mkdir(parents=True)
    legacy.write_text(
        json.dumps(
            {
                "schemaVersion": "guard.extension-trust-class-map.v1",
                "classes": {"first-party": ["command.unreviewed"], "trusted-library": [], "external": []},
            }
        )
    )
    module_path = tmp_path / "src/codex_plugin_scanner/guard/runtime/extension_trust.py"
    monkeypatch.setattr(extension_trust, "__file__", str(module_path))
    monkeypatch.setattr(extension_contribution, "__file__", str(module_path.with_name("extension_contribution.py")))
    monkeypatch.delattr(extension_trust.sys, "frozen", raising=False)

    def missing_package(_name):
        raise ModuleNotFoundError("no packaged trust")

    monkeypatch.setattr(extension_trust.resources, "files", missing_package)
    monkeypatch.setattr(extension_contribution, "frozen_package_data", lambda *_args: None)
    extension_contribution._trust_classes.cache_clear()
    try:
        with pytest.raises(FileNotFoundError, match="authored trust bindings or a packaged"):
            reader()
    finally:
        extension_contribution._trust_classes.cache_clear()
