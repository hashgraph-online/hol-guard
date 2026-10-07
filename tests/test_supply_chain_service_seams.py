"""The extracted package services must retain all evaluator monkeypatch seams."""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace

from codex_plugin_scanner.guard.runtime import supply_chain_package_eval as evaluator
from codex_plugin_scanner.guard.runtime import supply_chain_package_services as services


def test_evaluator_service_dependencies_are_available():
    tree = ast.parse(Path(evaluator.__file__).read_text())
    names = {
        node.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "package_services"
    }
    assert names
    assert not sorted(name for name in names if not hasattr(services, name))


def test_moved_service_helpers_are_owned_by_the_services_module():
    for name in ("_build_request_payload", "_lockfile_context", "_workspace_fingerprint"):
        assert callable(getattr(services, name)), name


def test_request_payload_uses_the_services_lockfile_seam(monkeypatch):
    calls = []
    artifact = SimpleNamespace(metadata={}, harness="claude-code")

    def lockfile(workspace, current, *, parse_text_result):
        calls.append((workspace, current, parse_text_result))
        return {"dependencyCount": 2, "fileName": "package-lock.json", "manifestHash": None}

    def parser(_filename, _text):
        return None

    monkeypatch.setattr(services, "_lockfile_context", lockfile)
    payload = services._build_request_payload(
        artifact=artifact,
        targets=(),
        workspace_dir=None,
        workspace_fingerprint="fingerprint",
        policy_version="1",
        parse_text_result=parser,
    )
    assert calls == [(None, artifact, parser)]
    assert payload["lockfileContext"] == {"dependencyCount": 2, "fileName": "package-lock.json"}
    assert payload["policyVersion"] == "1"


def test_workspace_fingerprint_retains_parser_version_dependency():
    result = services._workspace_fingerprint(
        "workspace", workspace_dir=None, artifact=SimpleNamespace(metadata={}), bundle_meta=None
    )
    assert len(result) == 64
    assert services.LOCKFILE_PARSER_VERSION
