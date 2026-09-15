from __future__ import annotations

from datetime import UTC, datetime

import pytest

from codex_plugin_scanner.guarded_repository_evidence import (
    CLAIM,
    build_guarded_repository_evidence,
    guarded_repository_evidence_json,
    guarded_repository_evidence_sha256,
)


def _evidence():
    return build_guarded_repository_evidence(
        repository="hashgraph-online/example",
        commit_sha="a" * 40,
        workflow_run_id="123456",
        scanner_version="3.0.0a1",
        scanner_profile="strict-security",
        score=93,
        grade="A",
        max_severity="medium",
        findings_total=2,
        sarif_sha256="b" * 64,
        visibility="public",
        generated_at=datetime(2026, 8, 9, 20, 0, tzinfo=UTC),
    )


def test_evidence_is_deterministic_and_sanitized() -> None:
    evidence = _evidence()
    rendered = guarded_repository_evidence_json(evidence)

    assert (
        guarded_repository_evidence_sha256(evidence)
        == "b730be19205f36f9a8fdcad6d2f65b8c1fb746790338a53f255fa88c8fb01f0c"
    )
    assert evidence.claim == CLAIM
    assert evidence.runtime_coverage_claimed is False
    assert evidence.sensitive_content_included is False
    for forbidden in ("raw_sarif", "finding", "file_path", "source_code", "prompt", "command", "credential", "token"):
        assert f'"{forbidden}"' not in rendered


def test_evidence_rejects_invalid_identity_and_bounds() -> None:
    with pytest.raises(ValueError, match="repository"):
        build_guarded_repository_evidence(
            repository="invalid",
            commit_sha="a" * 40,
            workflow_run_id="123",
            scanner_version="3.0.0a1",
            scanner_profile="strict-security",
            score=93,
            grade="A",
            max_severity="medium",
            findings_total=2,
            sarif_sha256="b" * 64,
            visibility="private",
        )
    with pytest.raises(ValueError, match="score"):
        build_guarded_repository_evidence(
            repository="hashgraph-online/example",
            commit_sha="a" * 40,
            workflow_run_id="123",
            scanner_version="3.0.0a1",
            scanner_profile="strict-security",
            score=101,
            grade="A",
            max_severity="medium",
            findings_total=2,
            sarif_sha256="b" * 64,
            visibility="private",
        )
