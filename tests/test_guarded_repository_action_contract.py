from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ACTION = ROOT / "guarded-repository" / "action.yml"
WORKFLOW = ROOT / ".github" / "workflows" / "guarded-repository.yml"
# v3.58.0 descends from the v3.0.1 secret-word-boundary fix (09c6f67c).
GUARDED_REPOSITORY_ACTION_SHA = "3a28326dad8c9eebfdc4eb61066db8c4f479f469"
GUARDED_ACTION_USE = re.compile(r"(?m)^[ \t]*(?:-[ \t]+)?uses:[ \t]*hashgraph-online/hol-guard/guarded-repository@(\S+)")


def test_composite_action_defaults_portal_registration_off() -> None:
    text = ACTION.read_text(encoding="utf-8")

    assert "register_verification:" in text
    assert 'default: "false"' in text
    assert "uses: actions/attest@508db95dd578ae2727ebd6217d5ba78e4fbda05d" in text
    assert "subject-path: ${{ steps.evidence.outputs.evidence_path }}" in text
    assert "ACTIONS_ID_TOKEN_REQUEST_URL" in text
    assert "ACTIONS_ID_TOKEN_REQUEST_TOKEN" in text
    assert 'default: "https://hol.org/api/guard/repository-attestations"' in text


def test_reusable_workflow_is_least_privilege_and_trusted() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")

    assert "workflow_call:" in text
    assert "contents: read" in text
    assert "id-token: write" in text
    assert "attestations: write" in text
    assert "artifact-metadata: write" in text
    assert "security-events: write" in text
    assert "contents: write" not in text
    assert "pull-requests: write" not in text
    assert "issues: write" not in text
    assert "packages: write" not in text
    assert "register_verification: true" in text
    assert "verification_endpoint: https://hol.org/api/guard/repository-attestations" in text
    matches = GUARDED_ACTION_USE.findall(text)
    assert len(matches) == 1


def test_reusable_workflow_pins_action_with_secret_word_boundary_fix() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    matches = GUARDED_ACTION_USE.findall(text)
    assert matches == [GUARDED_REPOSITORY_ACTION_SHA]


def test_reusable_workflow_checkout_does_not_persist_credentials() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")

    assert "uses: actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10" in text
    assert "persist-credentials: false" in text
