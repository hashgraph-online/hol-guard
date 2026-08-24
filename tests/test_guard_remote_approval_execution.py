from __future__ import annotations

from codex_plugin_scanner.guard.runtime.remote_approval_execution import remote_resume_confirmed


def test_explicit_no_transport_is_resolved_without_resume_confirmation() -> None:
    metadata: dict[str, object] = {
        "continuationCapability": "retry-only",
        "resumeStatus": "manual_retry_required",
        "harnessResume": {
            "capability": "retry-only",
            "status": "manual_retry_required",
            "supported": False,
        },
    }

    assert remote_resume_confirmed(metadata, "allow") is True


def test_supported_transport_retry_failure_remains_unconfirmed() -> None:
    metadata: dict[str, object] = {
        "continuationCapability": "session-resume",
        "resumeStatus": "manual_retry_required",
        "codexResume": {
            "capability": "session-resume",
            "status": "manual_retry_required",
            "supported": True,
        },
    }

    assert remote_resume_confirmed(metadata, "allow") is False


def test_missing_support_proof_remains_unconfirmed() -> None:
    metadata: dict[str, object] = {
        "resumeStatus": "manual_retry_required",
        "harnessResume": {"status": "manual_retry_required"},
    }

    assert remote_resume_confirmed(metadata, "allow") is False
