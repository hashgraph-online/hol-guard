"""Resident selection remains independent of an expanding optional inventory."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def generator(root=ROOT):
    spec = importlib.util.spec_from_file_location(
        "core_projection_test", ROOT / "scripts/build_native_command_program.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.ROOT = root
    return module


def test_core_projection_ignores_more_than_512_optional_inputs(tmp_path):
    directory = tmp_path / "contributions/command-sources"
    directory.mkdir(parents=True)
    trust = tmp_path / "contracts/extensions/trust"
    trust.mkdir(parents=True)
    core_source = ROOT / "contributions/command-sources/command.git.json"
    (directory / core_source.name).write_bytes(core_source.read_bytes())
    binding = "command.git.v1.json"
    (trust / binding).write_bytes((ROOT / "contracts/extensions/trust" / binding).read_bytes())
    manifest = {
        "schema": "guard.core-defaults.v1",
        "entries": [
            {
                "extension_id": "command.git",
                "source": "contributions/command-sources/command.git.json",
                "trust": f"contracts/extensions/trust/{binding}",
            }
        ],
    }
    (trust.parent / "core-defaults.v1.json").write_text(json.dumps(manifest))
    module = generator(tmp_path)
    before = module.build_request(core_only=True)
    for index in range(600):
        (directory / f"command.optional{index}.json").write_bytes(b"invalid optional data is not a core input")
    assert module.build_request(core_only=True) == before
    with pytest.raises(ValueError, match="extension count budget"):
        module.build_request()
    with module.source_stream(core_only=True) as (stream, _, paths):
        assert len(paths) == 1
        assert stream.read(5) == b"HGCS\x01"


def test_external_cannot_enter_default_manifest(tmp_path):
    directory = tmp_path / "contracts/extensions/trust"
    directory.mkdir(parents=True)
    (directory / "command.example.v1.json").write_text(
        json.dumps({"extension": "command.example", "trustClass": "external"})
    )
    (directory.parent / "core-defaults.v1.json").write_text(
        json.dumps(
            {
                "schema": "guard.core-defaults.v1",
                "entries": [
                    {
                        "extension_id": "command.example",
                        "source": "contributions/command-sources/command.example.json",
                        "trust": "contracts/extensions/trust/command.example.v1.json",
                    }
                ],
            }
        )
    )
    with pytest.raises(ValueError, match="nonexternal"):
        generator(tmp_path).core_entries()
