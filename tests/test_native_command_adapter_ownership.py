"""Bind command projection adapters to the existing policy control owner."""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts.ci import rust_authority_ownership_gate as gate

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(
    "module_name",
    [
        pytest.param("native_command_expression.py", id="command-expression"),
        pytest.param("native_command_row_association.py", id="row-association"),
        pytest.param("native_policy_authority_compile.py", id="mapped-control"),
    ],
)
def test_command_adapter_has_policy_control_owner(
    module_name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(ROOT)
    path = f"src/codex_plugin_scanner/guard/{module_name}"
    current = gate.load_manifest(gate.MANIFEST)
    protected, _owners = gate._manifest_patterns(current)
    # Enumerate the real tracked inventory first. Isolate one path only so one
    # missing mapping cannot mask the other regression or the mapped control.
    assert path in gate._repository_matches(protected)
    monkeypatch.setattr(gate, "_repository_matches", lambda _patterns: (path,))

    manifest = gate._manifest()

    nodes = manifest["nodes"]
    assert isinstance(nodes, list)
    owners = [
        node
        for node in nodes
        if isinstance(node, dict)
        and isinstance(node.get("paths"), list)
        and any(gate._matches(path, pattern) for pattern in node["paths"])
    ]
    assert len(owners) == 1
    assert owners[0]["id"] == "policy_and_approval_control"
    assert owners[0]["class"] == "python_control"
