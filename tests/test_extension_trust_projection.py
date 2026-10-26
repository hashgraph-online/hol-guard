"""Offline migration tools load authored trust data without an installed package."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.extension_trust_projection import repository_trust_map


def test_missing_and_empty_binding_directories_are_rejected(tmp_path):
    """An absent inventory must not become an empty trust map."""
    with pytest.raises(ValueError, match="authored trust bindings are missing"):
        repository_trust_map(tmp_path)
    (tmp_path / "contracts/extensions/trust").mkdir(parents=True)
    with pytest.raises(ValueError, match="authored trust bindings are missing"):
        repository_trust_map(tmp_path)


def test_standalone_parser_loads_only_trusted_tooling_code(tmp_path):
    """Uninstalled tooling accepts inspected bindings without importing inspected Python."""
    binding = tmp_path / "contracts/extensions/trust/command.example.v1.json"
    binding.parent.mkdir(parents=True)
    binding.write_text(
        json.dumps(
            {
                "schemaVersion": "guard.extension-trust-binding.v1",
                "extension": "command.example",
                "trustClass": "external",
            }
        )
    )
    (tmp_path / "src").mkdir()
    (tmp_path / "src/codex_plugin_scanner.py").write_text("raise RuntimeError('untrusted Python imported')")
    root = Path(__file__).parents[1]
    command = (
        "import json,sys; from pathlib import Path; sys.path.insert(0,sys.argv[1]); "
        "from scripts.extension_trust_projection import repository_trust_map; "
        "print(json.dumps(repository_trust_map(Path(sys.argv[2]))))"
    )
    result = subprocess.run(
        [sys.executable, "-S", "-c", command, str(root), str(tmp_path)],
        cwd=tmp_path,
        text=True,
        capture_output=True,
        check=True,
    )
    assert json.loads(result.stdout)["classes"]["external"] == ["command.example"]
