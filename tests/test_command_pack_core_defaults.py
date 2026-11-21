"""Reviewed core evidence is transported unchanged to native release admission."""

from __future__ import annotations

import importlib
import json
from pathlib import Path

import pytest


@pytest.mark.parametrize("value", [{}, {"schema": "unknown", "entries": []}])
def test_core_evidence_is_not_interpreted_by_python(tmp_path, monkeypatch, value):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts"))
    builder = importlib.import_module("build_command_pack_bundle")
    assert builder.core_defaults_evidence(tmp_path) == {}
    manifest = tmp_path / "contracts/extensions/core-defaults.v1.json"
    manifest.parent.mkdir(parents=True)
    manifest.write_text(json.dumps(value))
    assert builder.core_defaults_evidence(tmp_path) == {"core_defaults": value}
