"""An approved package install resumes on the resident's own verdict."""

from __future__ import annotations

from pathlib import Path

import pytest

import codex_plugin_scanner.guard.local_supply_chain as local_supply_chain_module
from codex_plugin_scanner.guard.approvals import apply_approval_resolution
from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.store import GuardStore
from tests.manifest_install_fixtures import (
    _build_review_package_payload,
    _fake_policy_integrity_keyring,  # noqa: F401 -- registers the module autouse fixture
    _native_package_intent,  # noqa: F401 -- registers the module autouse fixture
    _package_policy_config,
    _review_package_evaluation,
)

_REQUEST_ID = "7f1f3a0c9b7f4c5e8a2d6b4c1e9f0a33"


def _approve_the_paused_install(
    *, store: GuardStore, workspace_dir: Path, receipt: dict[str, object], now: str
) -> None:
    """Resolve the request the way the terminal prompt and the CLI both do."""

    store.add_approval_request(
        GuardApprovalRequest(
            request_id=_REQUEST_ID,
            harness="guard-cli",
            artifact_id=str(receipt["artifact_id"]),
            artifact_name="npm install guard-proof",
            artifact_hash=str(receipt["artifact_hash"]),
            policy_action="review",
            recommended_scope="artifact",
            changed_fields=("package_request",),
            source_scope="project",
            config_path=str(workspace_dir / "package.json"),
            workspace=str(workspace_dir),
            artifact_type="package_request",
            launch_target="npm install guard-proof",
            review_command=f"hol-guard approvals approve {_REQUEST_ID}",
            approval_url=f"http://127.0.0.1/pending/{_REQUEST_ID}",
        ),
        now,
    )
    apply_approval_resolution(
        store=store,
        request_id=_REQUEST_ID,
        action="allow",
        scope="artifact",
        workspace=str(workspace_dir),
        reason="approved at the terminal",
        now=now,
        # "Allow once" at the prompt: the shim never asks for a remembered rule.
        persist_policy=None,
    )


def test_an_allow_once_at_the_prompt_lets_the_resident_clear_the_install(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        local_supply_chain_module,
        "evaluate_package_request_artifact",
        lambda **_kwargs: _review_package_evaluation(),
    )
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    store = GuardStore(tmp_path / "guard-home")
    config = _package_policy_config(guard_home=store.guard_home, workspace_dir=workspace_dir)

    paused_payload, paused_rc = _build_review_package_payload(
        store=store, workspace_dir=workspace_dir, config=config, now="2026-07-17T00:00:00Z"
    )
    assert paused_rc == 2
    receipt = paused_payload["receipt"]
    assert isinstance(receipt, dict)

    _approve_the_paused_install(
        store=store, workspace_dir=workspace_dir, receipt=receipt, now="2026-07-17T00:00:30Z"
    )

    resumed_payload, resumed_rc = _build_review_package_payload(
        store=store, workspace_dir=workspace_dir, config=config, now="2026-07-17T00:01:00Z"
    )

    # The resident re-reads the approval it was given and allows the install
    # itself, so nothing downstream has to rewrite a review into an allow.
    assert resumed_rc == 0
    assert resumed_payload["verdict"]["action"] == "allow"
    assert resumed_payload["verdict"]["blocking"] is False


def test_an_unapproved_install_stays_paused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        local_supply_chain_module,
        "evaluate_package_request_artifact",
        lambda **_kwargs: _review_package_evaluation(),
    )
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    store = GuardStore(tmp_path / "guard-home")
    config = _package_policy_config(guard_home=store.guard_home, workspace_dir=workspace_dir)

    _build_review_package_payload(
        store=store, workspace_dir=workspace_dir, config=config, now="2026-07-17T00:00:00Z"
    )
    repeated_payload, repeated_rc = _build_review_package_payload(
        store=store, workspace_dir=workspace_dir, config=config, now="2026-07-17T00:01:00Z"
    )

    assert repeated_rc == 2
    assert repeated_payload["verdict"]["action"] == "review"
