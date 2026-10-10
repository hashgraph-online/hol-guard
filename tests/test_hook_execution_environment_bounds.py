"""Lookup metadata cannot crash the outer hook serializer."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.hook_execution_environment import collect_hook_execution_environment
from codex_plugin_scanner.guard.native_hook_edge import _encode_hook_envelope


def encode(root: Path) -> bytes | None:
    return _encode_hook_envelope(
        payload={"tool_name": "read", "tool_input": {"path": "ordinary.txt"}},
        harness="omp",
        event="PreToolUse",
        guard_home=root,
        home_dir=root,
        cwd=root,
        source_ref_external_allowed=False,
        deadline_budget_ms=1000,
        snapshot={"generation": 1},
        execution_context_supported=True,
    )


def test_unicode_format_characters_in_names_are_not_silently_dropped(tmp_path, monkeypatch):
    name = "GUARD_NAME_\u200d_\u00a0"
    monkeypatch.setenv(name, "fixture")
    assert name in collect_hook_execution_environment()["environment_names"]
    encoded = encode(tmp_path)
    assert encoded is not None
    assert name in json.loads(encoded)["source"]["execution_environment"]["environment_names"]


@pytest.mark.skipif(os.name == "nt", reason="POSIX environment surrogateescape behavior")
def test_unencodable_environment_fails_closed_without_raising(tmp_path, monkeypatch):
    monkeypatch.setenv("GUARD_NAME_\udcff", "fixture")
    assert encode(tmp_path) is None


def test_large_lookup_context_is_preserved_for_native_operation_specific_limits(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", "p" * (32 * 1024 + 1))
    encoded = encode(tmp_path)
    assert encoded is not None
    context = json.loads(encoded)["source"]["execution_environment"]
    assert context["path"] == "p" * (32 * 1024 + 1)
    assert len(context["environment_digest"]) == 64
