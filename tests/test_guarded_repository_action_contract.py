from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ACTION = ROOT / "guarded-repository" / "action.yml"
WORKFLOW = ROOT / ".github" / "workflows" / "guarded-repository.yml"


def test_composite_action_defaults_portal_registration_off() -> None:
    text = ACTION.read_text(encoding="utf-8")

    assert 'register_verification:' in text
    assert 'default: "false"' in text
    assert 'uses: actions/attest@508db95dd578ae2727ebd6217d5ba78e4fbda05d' in text
    assert 'subject-path: ${{ steps.evidence.outputs.evidence_path }}' in text
    assert 'ACTIONS_ID_TOKEN_REQUEST_URL' in text
    assert 'ACTIONS_ID_TOKEN_REQUEST_TOKEN' in text
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
    match = re.search(r"uses: hashgraph-online/hol-guard/guarded-repository@([a-f0-9]{40})", text)
    assert match is not None


def test_reusable_workflow_checkout_does_not_persist_credentials() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")

    assert "uses: actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10" in text
    assert "persist-credentials: false" in text
