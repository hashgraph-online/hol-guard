from __future__ import annotations

from datetime import datetime, timezone
from typing import cast

import pytest

from codex_plugin_scanner.guard.native_command_model import _canonical_command_from_native
from codex_plugin_scanner.guard.runtime.command_evaluation import CompositeCommandEvaluation, evaluate_command
from codex_plugin_scanner.guard.runtime.command_model import parse_shell_command
from codex_plugin_scanner.guard.runtime.effect_decision import FinalDisposition, PositiveProof
from codex_plugin_scanner.guard.runtime.github_workflow_authorization import (
    GITHUB_MAINTENANCE_ACTION_CLASS,
    GitHubWorkflowAuthorization,
)
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_workflow_capability_common import WORKFLOW_CAPABILITY_STORE_CLOCK
from codex_plugin_scanner.guard.workflow_capabilities import (
    format_utc_timestamp,
)
from tests.github_workflow_test_support import THREAD_COMMAND, digest
from tests.native_command_test_support import real_native_review_fixture

_KEY = b"w" * 32
_KEY_ID = "guard-policy-integrity-key:github-workflow-test"
_ISSUED = datetime(2026, 7, 20, 12, tzinfo=timezone.utc)
_COMMAND = THREAD_COMMAND


def _evaluate_native(
    command: str,
    *,
    compatibility_action_class: str,
    workflow_authorization: GitHubWorkflowAuthorization,
    compatibility_reason: str | None = None,
    controls: tuple[tuple[str, str, str], ...] = (),
    managed_controls: tuple[tuple[str, str, str], ...] = (),
) -> CompositeCommandEvaluation:
    fixture = real_native_review_fixture(command, controls=controls, managed_controls=managed_controls)
    canonical = _canonical_command_from_native(command, fixture.payload["command_model"])
    assert canonical is not None
    return evaluate_command(
        command,
        canonical_command=canonical,
        native_extension_evidence=fixture.payload,
        extension_control_snapshot=fixture.snapshot,
        compatibility_action_class=compatibility_action_class,
        compatibility_reason=compatibility_reason,
        workflow_authorization=workflow_authorization,
    )


@pytest.fixture(autouse=True)
def fixed_authority(monkeypatch: pytest.MonkeyPatch) -> None:
    def secret_material(_store: GuardStore, *, create: bool) -> tuple[bytes | None, str | None]:
        del create
        return _KEY, _KEY_ID

    def fixed_now() -> str:
        return format_utc_timestamp(_ISSUED)

    monkeypatch.setattr(GuardStore, "_policy_integrity_secret_material", secret_material)
    monkeypatch.setattr(WORKFLOW_CAPABILITY_STORE_CLOCK, "now", fixed_now)


def test_public_constructor_and_uninitialized_object_cannot_invent_proof_or_relax_native_uncertainty() -> None:
    with pytest.raises(TypeError, match="atomic Guard claim"):
        _ = GitHubWorkflowAuthorization(
            authority_token=object(),
            command_identity=parse_shell_command(_COMMAND).security_identity,
            proof=cast(PositiveProof, object()),
            receipt_sha256=digest("forged"),
        )
    forged = object.__new__(GitHubWorkflowAuthorization)

    evaluation = _evaluate_native(
        _COMMAND,
        compatibility_action_class=GITHUB_MAINTENANCE_ACTION_CLASS,
        workflow_authorization=forged,
    )

    assert evaluation.decision_plane.action == "review"
    assert evaluation.decision_plane.disposition is FinalDisposition.REVIEW
