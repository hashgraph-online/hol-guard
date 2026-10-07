"""Shared CLI/MCP source installation with native local approval, no providers."""

import io
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_business_source_store as owner
from codex_plugin_scanner.guard.approval_gate import ApprovalGateInput, update_settings
from codex_plugin_scanner.guard.business_policy_document_import import compile_document_for_import
from codex_plugin_scanner.guard.cli import commands_dispatch_policy_document as command
from codex_plugin_scanner.guard.mcp import policy_tools
from codex_plugin_scanner.guard.mcp.policy_errors import PolicyToolError
from codex_plugin_scanner.guard.native_policy_snapshot_constants import NativePolicySnapshotError
from codex_plugin_scanner.guard.policy_document import policy_document_digest
from codex_plugin_scanner.guard.policy_document_io import write_private_policy_text
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_native_business_document_compile import document
from tests.test_native_business_source_store import _grant, _install, _key


def _stage(store, candidate, monkeypatch, *, expected=None):
    monkeypatch.setenv("HOL_GUARD_POLICY_YAML_IMPORT", "1")
    monkeypatch.setenv("HOL_GUARD_MCP_POLICY_WRITE", "1")
    return json.loads(
        policy_tools.execute_create_policy(
            store,
            {
                "policyYaml": json.dumps(candidate.to_mapping()),
                "mode": "replace",
                "candidateDigest": policy_document_digest(candidate),
                "expectedCurrentDigest": expected,
                "idempotencyKey": "source-fixture-" + str(candidate.metadata.revision),
            },
        )
    )


def test_cli_import_uses_exact_source_owner_and_reports_business_rules(tmp_path: Path, native_mcp_probe, monkeypatch):
    store = GuardStore(tmp_path / "cli-home")
    native_mcp_probe(store.guard_home)
    password = "synthetic-business-cli-password"
    update_settings(store.guard_home, {"enabled": True, "new_password": password, "confirm_password": password})
    candidate = document(0)
    path = tmp_path / "source.yaml"
    write_private_policy_text(path, json.dumps(candidate.to_mapping()))
    monkeypatch.setenv("HOL_GUARD_POLICY_YAML_IMPORT", "1")
    monkeypatch.setattr(
        command,
        "prompt_for_approval_gate",
        lambda *args, **kwargs: ApprovalGateInput(password=password, use_cooldown=False),
    )
    stream = io.StringIO()
    result = command._run_guard_policy_document_command(
        SimpleNamespace(policy_command="import", file=str(path), mode="replace", dry_run=False, json=True),
        store=store,
        output_stream=stream,
    )
    assert result == 0, stream.getvalue()
    output = json.loads(stream.getvalue())
    assert output["inserted"] == 1 and output["additions"] == [candidate.rules[0].id]
    source = owner.read_installed_business_source(store, _key(store))
    assert source.source_digest == policy_document_digest(candidate)
    assert password not in stream.getvalue() and "Source fixture" not in stream.getvalue()


def test_mcp_request_status_and_source_witness_commit_together(tmp_path: Path, native_mcp_probe, monkeypatch):
    store = GuardStore(tmp_path / "mcp-home")
    native_mcp_probe(store.guard_home)
    candidate = document()
    pending = _stage(store, candidate, monkeypatch)
    assert pending["status"] == "pending"
    result = policy_tools.apply_pending_policy_request(
        store, pending["requestId"], approval_gate_grant=_grant(store, candidate)
    )
    assert result["status"] == "applied" and result["inserted"] == 1
    source = owner.read_installed_business_source(store, _key(store))
    assert source.source_digest == policy_document_digest(candidate)
    current = json.loads(
        policy_tools.execute_validate_policy(
            store, {"policyYaml": json.dumps(candidate.to_mapping()), "mode": "replace"}
        )
    )
    assert current["currentDigest"] == source.source_digest


def test_stale_mcp_source_is_refused_before_closing_the_newer_policy(tmp_path: Path, native_mcp_probe, monkeypatch):
    store = GuardStore(tmp_path / "stale-home")
    native_mcp_probe(store.guard_home)
    first = _install(store, document(1), _grant(store, document(1)))
    candidate = document(3)
    pending = _stage(store, candidate, monkeypatch, expected=first.source.source_digest)
    candidate_grant = _grant(store, candidate, initialize=False)
    newer_grant = _grant(store, document(2), initialize=False)
    read_current = policy_tools._build_current_document
    changed = []

    def change_after_outer_check(current_store):
        prior = read_current(current_store)
        if not changed:
            changed.append(_install(store, document(2), newer_grant))
        return prior

    monkeypatch.setattr(policy_tools, "_build_current_document", change_after_outer_check)
    with pytest.raises(PolicyToolError, match="Current policy digest has changed"):
        policy_tools.apply_pending_policy_request(store, pending["requestId"], approval_gate_grant=candidate_grant)
    assert owner.read_installed_business_source(store, _key(store)) == changed[0].source


def test_business_import_requires_explicit_native_approval(tmp_path: Path, native_mcp_probe):
    store = GuardStore(tmp_path / "no-grant-home")
    native_mcp_probe(store.guard_home)
    candidate = document()
    with pytest.raises(NativePolicySnapshotError, match="native_business_source_approval_required"):
        store.import_policy_document(
            candidate,
            compile_document_for_import(candidate),
            mode="replace",
            now="2026-10-06T00:00:00Z",
            approval_gate_grant=None,
        )
    assert not (store.guard_home / "native-runtime" / owner.ANCHOR_FILE_NAME).exists()


def test_cli_business_inspection_uses_source_and_redacts_provenance(tmp_path, native_mcp_probe):
    from codex_plugin_scanner.guard.policy_document_yaml import parse_policy_document_yaml

    store = GuardStore(tmp_path / "inspection-home")
    native_mcp_probe(store.guard_home)
    candidate = document()
    _install(store, candidate, _grant(store, candidate))
    path = tmp_path / "source.yaml"
    write_private_policy_text(path, json.dumps(candidate.to_mapping()))
    for name in ("diff", "explain", "show", "export"):
        output = io.StringIO()
        assert (
            command._run_guard_policy_document_command(
                SimpleNamespace(policy_command=name, file=str(path), json=True, include_provenance=False),
                store=store,
                output_stream=output,
            )
            == 0
        ), output.getvalue()
        result = json.loads(output.getvalue())
        if name == "explain":
            assert result["rules"] == 1 and result["actions"] == {"review": 1}
            assert result["scopes"] == {"business": 1} and result["compiled_rows"] == 0
        elif name in {"show", "export"}:
            exported = parse_policy_document_yaml(result["yaml"])
            assert exported.rules[0].match == candidate.rules[0].match
            assert exported.rules[0].provenance.source == "local"
            assert exported.rules[0].provenance.created_at == "1970-01-01T00:00:00Z"
            assert result["provenance_redacted"] is True


def test_business_view_excludes_private_free_text_and_extensions():
    from codex_plugin_scanner.guard.business_policy_document_view import without_provenance
    from codex_plugin_scanner.guard.policy_document import GuardPolicyDocument
    from codex_plugin_scanner.guard.policy_document_yaml import parse_policy_document_yaml

    value = document().to_mapping()
    marker = "private-free-text-never-export"
    value["metadata"]["name"] = marker
    value["metadata"]["labels"] = {"owner": marker}
    value["metadata"]["x-owner"] = marker
    value["x-owner"] = marker
    value["spec"]["x-owner"] = marker
    value["spec"]["defaults"]["x-owner"] = marker
    rule = value["spec"]["rules"][0]
    rule["description"] = marker
    rule["x-hol-local"] = {"owner": marker, "workspace": marker}
    rule["provenance"]["createdBy"] = marker
    rule["match"]["x-owner"] = marker
    rule["lifetime"]["x-owner"] = marker
    view = without_provenance(GuardPolicyDocument.from_mapping(value))
    encoded = json.dumps(view.to_mapping())
    assert marker not in encoded
    assert parse_policy_document_yaml(encoded).rules[0].match == document().rules[0].match


def test_legacy_replacement_plan_cannot_hide_installed_business_rules(tmp_path, native_mcp_probe):
    from codex_plugin_scanner.guard.business_policy_document_import import plan_document_for_import
    from codex_plugin_scanner.guard.policy_document_yaml import parse_policy_document_yaml

    store = GuardStore(tmp_path / "planning-home")
    native_mcp_probe(store.guard_home)
    candidate = document()
    _install(store, candidate, _grant(store, candidate))
    value = candidate.to_mapping()
    value["spec"]["rules"] = []
    empty = parse_policy_document_yaml(json.dumps(value))
    with pytest.raises(NativePolicySnapshotError, match="native_business_policy_removal_requires_authority"):
        plan_document_for_import(store, empty, (), "replace")
