"""Real portable file/store roundtrips and retry boundaries (isolated E2)."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.policy_document import GuardPolicyDocument
from codex_plugin_scanner.guard.policy_document_io import (
    PolicyCompilationError,
    build_policy_document_from_rows,
    compile_policy_document,
    load_trusted_policy_document,
    write_private_policy_text,
)
from codex_plugin_scanner.guard.policy_document_yaml import format_policy_document_yaml
from codex_plugin_scanner.guard.store import GuardStore

NOW = "2026-09-17T12:00:00Z"


def rule(rule_id: str, effect: str, artifacts: list[str], **match: object) -> dict[str, object]:
    return {
        "id": rule_id,
        "enabled": True,
        "effect": effect,
        "match": {"artifacts": artifacts, **match},
        "lifetime": {"mode": "until", "expiresAt": "2030-01-01T00:00:00Z"},
        "provenance": {"source": "review-decision", "createdAt": NOW},
        "x-hol-local": {"scope": "artifact", "artifactHash": "sha256:portable"},
    }


def document(*rules: dict[str, object], document_id: str = "portable") -> GuardPolicyDocument:
    return GuardPolicyDocument.from_mapping(
        {
            "apiVersion": "guard.hashgraphonline.com/v1alpha1",
            "kind": "GuardPolicy",
            "metadata": {"id": document_id, "name": "Portable policy", "revision": 1},
            "spec": {"defaults": {"mode": "prompt"}, "rules": list(rules)},
        }
    )


def import_document(store: GuardStore, value: GuardPolicyDocument, mode: str = "merge"):
    return store.import_policy_document(
        value,
        compile_policy_document(value),
        mode=mode,
        now=NOW,
        approval_gate_grant=None,
    )


def decision(store: GuardStore, artifact: str, *, harness: str = "codex", now: str = NOW):
    return store.resolve_policy_decision_lookup(
        harness,
        artifact,
        artifact_hash="sha256:portable",
        now=now,
    )["decision"]


def test_fanned_out_rule_roundtrips_through_real_file_and_store(tmp_path: Path) -> None:
    source = GuardStore(tmp_path / "source")
    value = document(rule("allow-tools", "allow", ["skill:one", "skill:two"], harnesses=["codex", "cursor"]))
    import_document(source, value)
    exported = build_policy_document_from_rows(source.list_policy_decisions(), include_provenance=True)
    path = tmp_path / "portable.yaml"
    write_private_policy_text(path, format_policy_document_yaml(exported))
    parsed = load_trusted_policy_document(path)
    assert [entry.id for entry in parsed.rules] == ["allow-tools"]
    destination = GuardStore(tmp_path / "destination")
    import_document(destination, parsed)
    for harness in ("codex", "cursor", "other"):
        for artifact in ("skill:one", "skill:two", "skill:other"):
            before = decision(source, artifact, harness=harness)
            after = decision(destination, artifact, harness=harness)
            assert (before or {}).get("action") == (after or {}).get("action")
    assert len(destination.list_policy_decisions()) == 4


def test_effect_expiry_source_and_supported_extension_survive_roundtrip(tmp_path: Path) -> None:
    source = GuardStore(tmp_path / "source")
    value = document(*(rule(effect, effect, [f"skill:{effect}"]) for effect in ("allow", "block", "review", "ignore")))
    import_document(source, value)
    exported = build_policy_document_from_rows(source.list_policy_decisions(), include_provenance=True)
    path = tmp_path / "effects.yaml"
    write_private_policy_text(path, format_policy_document_yaml(exported))
    destination = GuardStore(tmp_path / "destination")
    import_document(destination, load_trusted_policy_document(path))
    for effect in ("allow", "block", "review"):
        row = decision(destination, f"skill:{effect}")
        assert row is not None and row["action"] == effect
        stored = next(item for item in destination.list_policy_decisions() if item["artifact_id"] == f"skill:{effect}")
        assert stored["policy_rule_id"] == effect
        assert row["artifact_hash"] == "sha256:portable"
        assert row["source"] == "policy-yaml-import"
        assert decision(destination, f"skill:{effect}", now="2031-01-01T00:00:00Z") is None
    assert decision(source, "skill:ignore") is None
    assert decision(destination, "skill:ignore") is None


def test_redacted_export_never_removes_a_workspace_restriction(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard")
    scoped = rule("scoped", "allow", ["skill:scoped"], workspaces=["/private/project"])
    scoped["x-hol-local"]["scope"] = "workspace"
    import_document(store, document(scoped))
    with pytest.raises(PolicyCompilationError, match="sensitive_local_policy_requires_provenance"):
        build_policy_document_from_rows(store.list_policy_decisions())
    assert (
        store.resolve_policy_decision_lookup("codex", "skill:scoped", workspace="/elsewhere", now=NOW)["decision"]
        is None
    )


@pytest.mark.parametrize("mode", ["merge", "replace"])
def test_identical_retry_preserves_single_grant_per_selector(tmp_path: Path, mode: str) -> None:
    store = GuardStore(tmp_path / "guard")
    value = document(rule("same", "allow", ["skill:one", "skill:two"]))
    for _ in range(3):
        import_document(store, value, mode)
        rows = store.list_policy_decisions()
        assert len(rows) == 2
        assert {row["policy_rule_id"] for row in rows} == {"same"}
        assert all(decision(store, artifact)["action"] == "allow" for artifact in ("skill:one", "skill:two"))


@pytest.mark.parametrize("second_document", ["first", "other"])
def test_merge_rejects_rule_identity_reuse_with_a_different_target(tmp_path: Path, second_document: str) -> None:
    store = GuardStore(tmp_path / "guard")
    import_document(store, document(rule("same", "allow", ["skill:first"]), document_id="first"))
    before = store.list_policy_decisions()
    incoming = document(rule("same", "allow", ["skill:second"]), document_id=second_document)
    with pytest.raises(ValueError, match="policy_rule_identity_conflict"):
        import_document(store, incoming)
    assert store.list_policy_decisions() == before
    assert decision(store, "skill:second") is None


def test_reordered_rules_do_not_change_effective_precedence(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard")
    rules = [rule("broad", "allow", ["skill:target"]), rule("narrow", "block", ["skill:target"], harnesses=["codex"])]
    outcomes = []
    for ordered in (rules, list(reversed(rules)), rules):
        import_document(store, document(*ordered), "replace")
        outcomes.append(decision(store, "skill:target")["action"])
        assert decision(store, "skill:target", harness="cursor")["action"] == "allow"
    assert len(set(outcomes)) == 1


def test_local_scope_override_cannot_erase_workspace_constraint() -> None:
    value = document(rule("scoped", "allow", ["skill:scoped"], workspaces=["/private/project"]))
    with pytest.raises(PolicyCompilationError, match="unsupported_policy_scope_projection"):
        compile_policy_document(value)


def test_artifact_and_workspace_match_retains_both_without_a_scope_override(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard")
    scoped = rule("scoped", "allow", ["skill:scoped"], workspaces=["/private/project"])
    scoped["x-hol-local"].pop("scope")
    import_document(store, document(scoped))
    for workspace, expected in (("/private/project", "allow"), ("/elsewhere", None)):
        row = store.resolve_policy_decision_lookup(
            "codex",
            "skill:scoped",
            artifact_hash="sha256:portable",
            workspace=workspace,
            now=NOW,
        )["decision"]
        assert (row or {}).get("action") == expected


def test_retry_after_transaction_failure_creates_no_partial_or_duplicate_grant(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard")
    value = document(rule("first", "allow", ["skill:first"]), rule("second", "review", ["skill:second"]))
    with store._connect() as connection:
        connection.execute("""create trigger reject_second before insert on policy_decisions
            when new.policy_rule_id = 'second' begin select raise(abort, 'interrupted import'); end""")
    with pytest.raises(sqlite3.IntegrityError, match="interrupted import"):
        import_document(store, value)
    assert store.list_policy_decisions() == []
    with store._connect() as connection:
        connection.execute("drop trigger reject_second")
    import_document(store, value)
    import_document(store, value)
    assert len(store.list_policy_decisions()) == 2
    assert decision(store, "skill:first")["action"] == "allow"
    assert decision(store, "skill:second")["action"] == "review"


def test_document_extensions_survive_file_roundtrip_before_local_projection(tmp_path: Path) -> None:
    value = document(rule("one", "allow", ["skill:one"]))
    mapping = value.to_mapping()
    mapping["x-context"] = {"case": "portable", "enabled": True}
    value = GuardPolicyDocument.from_mapping(mapping)
    path = tmp_path / "extensions.yaml"
    write_private_policy_text(path, format_policy_document_yaml(value))
    assert json.dumps(load_trusted_policy_document(path).to_mapping(), sort_keys=True) == json.dumps(
        value.to_mapping(), sort_keys=True
    )


def test_sparse_export_cannot_create_missing_selector_combinations(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "source")
    value = document(rule("many", "allow", ["skill:one", "skill:two"], harnesses=["codex", "cursor"]))
    import_document(store, value)
    remaining = store.list_policy_decisions()[:3]
    with pytest.raises(PolicyCompilationError, match="policy_rule_export_sparse_selectors"):
        build_policy_document_from_rows(remaining, include_provenance=True)


def test_same_selector_from_another_document_is_an_identity_conflict(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard")
    import_document(store, document(rule("same", "allow", ["skill:one"]), document_id="first"))
    incoming = document(rule("same", "allow", ["skill:one"]), document_id="second")
    with pytest.raises(PolicyCompilationError, match="policy_rule_identity_conflict"):
        store.plan_policy_document_import(compile_policy_document(incoming), mode="merge", document=incoming)
    with pytest.raises(PolicyCompilationError, match="policy_rule_identity_conflict"):
        import_document(store, incoming)
    assert len(store.list_policy_decisions()) == 1


def test_export_does_not_merge_identical_ids_from_different_documents(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard")
    import_document(store, document(rule("same", "allow", ["skill:one"]), document_id="first"))
    row = store.list_policy_decisions()[0]
    legacy_conflict = {**row, "policy_document_id": "other", "artifact_id": "skill:two"}
    with pytest.raises(PolicyCompilationError, match="policy_rule_identity_conflict"):
        build_policy_document_from_rows([row, legacy_conflict], include_provenance=True)


def test_cli_conflict_is_structured_and_leaves_grants_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    from codex_plugin_scanner.cli import main

    store = GuardStore(tmp_path / "guard")
    import_document(store, document(rule("same", "allow", ["skill:first"])))
    before = store.list_policy_decisions()
    path = tmp_path / "incoming.yaml"
    write_private_policy_text(path, format_policy_document_yaml(document(rule("same", "allow", ["skill:second"]))))
    monkeypatch.setenv("HOL_GUARD_POLICY_YAML_IMPORT", "1")
    result = main(["guard", "policy", "import", str(path), "--merge", "--home", str(store.guard_home), "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert result == 4
    assert payload["error"] == "policy_rule_identity_conflict"
    assert store.list_policy_decisions() == before


def test_mcp_validation_reports_identity_conflict_with_public_copy(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.mcp.policy_errors import PolicyToolError
    from codex_plugin_scanner.guard.mcp.policy_tools import execute_validate_policy

    store = GuardStore(tmp_path / "guard")
    import_document(store, document(rule("same", "allow", ["skill:first"])))
    incoming = format_policy_document_yaml(document(rule("same", "allow", ["skill:second"])))
    with pytest.raises(PolicyToolError) as error:
        execute_validate_policy(store, {"policyYaml": incoming})
    assert error.value.code == "policy_write_conflict"
    assert "skill:first" not in error.value.message
    assert "skill:second" not in error.value.message
