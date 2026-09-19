"""Portable policy regression checks for wildcard rows and preview identity."""

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.policy_document_io import (
    PolicyCompilationError,
    build_policy_document_from_rows,
    compile_policy_document,
    load_trusted_policy_document,
    write_private_policy_text,
)
from codex_plugin_scanner.guard.policy_document_yaml import format_policy_document_yaml
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_portable_policy_semantics import decision, document, import_document, rule


def test_wildcard_and_explicit_harnesses_roundtrip_without_changing_grants(tmp_path: Path) -> None:
    source = GuardStore(tmp_path / "source")
    value = document(rule("mixed", "allow", ["skill:one", "skill:two"], harnesses=["*", "codex"]))
    import_document(source, value)
    exported = build_policy_document_from_rows(source.list_policy_decisions(), include_provenance=True)
    path = tmp_path / "portable.yaml"
    write_private_policy_text(path, format_policy_document_yaml(exported))
    destination = GuardStore(tmp_path / "destination")
    import_document(destination, load_trusted_policy_document(path))
    assert len(destination.list_policy_decisions()) == 4
    for harness in ("codex", "cursor", "other"):
        for artifact in ("skill:one", "skill:two", "skill:other"):
            before = decision(source, artifact, harness=harness)
            after = decision(destination, artifact, harness=harness)
            assert (before or {}).get("action") == (after or {}).get("action")


def test_preview_without_document_cannot_hide_cross_document_identity_conflict(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard")
    import_document(store, document(rule("same", "allow", ["skill:one"]), document_id="first"))
    incoming = document(rule("same", "allow", ["skill:one"]), document_id="second")
    before = store.list_policy_decisions()
    with pytest.raises(PolicyCompilationError, match="policy_import_document_required"):
        store.plan_policy_document_import(compile_policy_document(incoming), mode="merge")
    with pytest.raises(PolicyCompilationError, match="policy_rule_identity_conflict"):
        store.plan_policy_document_import(compile_policy_document(incoming), mode="merge", document=incoming)
    with pytest.raises(PolicyCompilationError, match="policy_rule_identity_conflict"):
        import_document(store, incoming)
    assert store.list_policy_decisions() == before


def test_wildcard_export_still_rejects_missing_selector_combinations(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "source")
    value = document(rule("mixed", "allow", ["skill:one", "skill:two"], harnesses=["*", "codex"]))
    import_document(store, value)
    with pytest.raises(PolicyCompilationError, match="policy_rule_export_sparse_selectors"):
        build_policy_document_from_rows(store.list_policy_decisions()[:3], include_provenance=True)
