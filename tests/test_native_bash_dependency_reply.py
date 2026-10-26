"""Assessment inputs cannot replace native consent or execution assurance."""

from __future__ import annotations

import copy

import pytest

from codex_plugin_scanner.guard.native_bash_protocol import ARTIFACT_ID, NativeBashError
from codex_plugin_scanner.guard.native_bash_reply import validate_prepared


def prepared():
    return {
        "artifact_id": ARTIFACT_ID,
        "artifact_hash": "guard-approval-context:v1:fixture",
        "assessment": [],
        "consent_required": True,
        "review": {"decision": {}, "receipt": {}},
        "subject": {
            "schema": "guard.bash-subject.v1",
            "execution_assurance": "macos-readonly-root-framed-outputs-v1",
            "context": {"host": "omp-input-rewrite-v1"},
            "package_bindings": [{"state": "declared"}],
        },
    }


def artifact():
    return {
        "artifact_id": f"omp:project:package-request:{'a' * 64}",
        "artifact_type": "package_request",
        "harness": "omp",
        "metadata": {"assessment_only": True, "captured_subject_sha256": "a" * 64},
    }


def test_legacy_preparation_without_dependency_input_remains_supported():
    payload = prepared()
    assert validate_prepared(payload) is payload


def test_dependency_input_cannot_replace_the_native_consent_flag_or_grant():
    payload = prepared()
    payload["dependency_artifact"] = artifact()
    result = validate_prepared(payload)
    assert result["consent_required"] is True
    assert result["artifact_id"] == ARTIFACT_ID
    assert result["artifact_hash"] == "guard-approval-context:v1:fixture"


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.update(dependency_artifact=None),
        lambda value: value.update(dependency_artifact=[]),
        lambda value: value["dependency_artifact"].update(artifact_type="tool_action_request"),
        lambda value: value["dependency_artifact"].update(metadata=[]),
        lambda value: value["dependency_artifact"]["metadata"].update(assessment_only=False),
        lambda value: value["dependency_artifact"]["metadata"].update(assessment_only=1),
        lambda value: value["dependency_artifact"]["metadata"].update(captured_subject_sha256="not-a-digest"),
        lambda value: value["dependency_artifact"].update(artifact_id=f"omp:project:package-request:{'b' * 64}"),
        lambda value: value["dependency_artifact"].update(harness="unknown"),
        lambda value: value["dependency_artifact"].update(
            harness="pi", artifact_id=f"pi:project:package-request:{'a' * 64}"
        ),
        lambda value: value["subject"].update(package_bindings=[]),
        lambda value: value.update(consent_required=0),
        lambda value: value.update(artifact_id=f"omp:project:package-request:{'a' * 64}"),
    ],
)
def test_malformed_dependency_data_cannot_masquerade_as_prepared_execution(mutation):
    payload = prepared()
    payload["dependency_artifact"] = copy.deepcopy(artifact())
    mutation(payload)
    with pytest.raises(NativeBashError):
        validate_prepared(payload)
