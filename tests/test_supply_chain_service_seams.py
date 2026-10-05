"""The extracted package services must retain all evaluator monkeypatch seams."""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace

from codex_plugin_scanner.guard.runtime import supply_chain_package_eval as evaluator
from codex_plugin_scanner.guard.runtime import supply_chain_package_services as services


def test_every_dynamic_evaluator_seam_is_available():
    tree = ast.parse(Path(services.__file__).read_text())
    names = {
        node.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Name)
        and node.value.func.id == "_pe"
    }
    assert names
    assert not sorted(name for name in names if not hasattr(evaluator, name))


def test_every_moved_service_keeps_its_evaluator_export():
    tree = ast.parse(Path(services.__file__).read_text())
    names = [node.name for node in tree.body if isinstance(node, ast.FunctionDef) and node.name != "_pe"]
    assert len(names) == 14
    for name in names:
        assert getattr(evaluator, name) is getattr(services, name), name


def test_request_payload_uses_the_evaluator_lockfile_seam(monkeypatch):
    calls = []
    artifact = SimpleNamespace(metadata={}, harness="claude-code")

    def lockfile(workspace, current):
        calls.append((workspace, current))
        return {"dependencyCount": 2, "fileName": "package-lock.json", "manifestHash": None}

    monkeypatch.setattr(evaluator, "_lockfile_context", lockfile)
    payload = evaluator._build_request_payload(
        artifact=artifact, targets=(), workspace_dir=None, workspace_fingerprint="fingerprint", policy_version="1"
    )
    assert calls == [(None, artifact)]
    assert payload["lockfileContext"] == {"dependencyCount": 2, "fileName": "package-lock.json"}
    assert payload["policyVersion"] == "1"


def test_workspace_fingerprint_retains_parser_version_dependency():
    result = evaluator._workspace_fingerprint(
        "workspace", workspace_dir=None, artifact=SimpleNamespace(metadata={}), bundle_meta=None
    )
    assert len(result) == 64
    assert evaluator.LOCKFILE_PARSER_VERSION
