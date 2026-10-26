"""Transport contract for the native skill workflow-preflight owner.

The manifest grammar and the requirement state machine belong to
``guard_command::skill_dependency_manifest`` and are covered there. These
cases prove Python frames what it read, binds the answer, and fails closed --
and that the verdicts a skill's authority depends on survive the round trip.
"""

from __future__ import annotations

import json

import pytest

from codex_plugin_scanner.guard import native_skill_workflow_preflight as module
from codex_plugin_scanner.guard.native_skill_workflow_preflight import (
    NativeSkillWorkflowPreflightError,
    native_skill_dependencies,
    native_skill_preflight,
)


def _manifest(tools):
    return {
        "metadata": {
            "hol-guard.dependencies": json.dumps(
                {
                    "schema_version": "guard.skill-dependencies.v1",
                    "tools": tools,
                }
            )
        }
    }


def _force_available(monkeypatch: pytest.MonkeyPatch) -> None:
    class Features:
        features = frozenset({module._FEATURE, module._RESIDENT_PROTOCOL_FEATURE})

    class Identity:
        path = "/bin/true"
        sha256 = "0" * 64

    class Status:
        mode = "force"
        available = True
        compatible = True
        identity = Identity()
        capabilities = Features()

    monkeypatch.setattr(module, "_native_runtime_status_memo", lambda: Status())
    monkeypatch.setattr(module, "ensure_resident_prerequisite", lambda _home: True)
    monkeypatch.setattr(module, "native_record_resident_failure", lambda *a, **k: None)


@pytest.mark.parametrize(
    "tools",
    [
        [{"connection_id": "local-cli.fixture", "tool_name": "*"}],
        [{"connection_id": "*", "tool_name": "read"}],
        [{"connection_id": "local-cli.fixture", "tool_name": "read", "auto_allow": True}],
        [{"connection_id": "local-cli.fixture", "tool_name": "read"}] * 2,
        [{"connection_id": "local-cli.fixture", "tool_name": "read"}] * 51,
    ],
)
def test_guard_manifest_rejects_implicit_and_duplicate_authority(tools):
    assert native_skill_dependencies(_manifest(tools)) == {
        "source": "guard-extension",
        "status": "invalid",
        "tools": [],
    }


def test_manifest_duplicate_json_keys_and_nonfinite_fail_closed():
    for raw in (
        '{"schema_version":"guard.skill-dependencies.v1","tools":[],"tools":[]}',
        '{"schema_version":"guard.skill-dependencies.v1","tools":NaN}',
    ):
        result = native_skill_dependencies({"metadata": {"hol-guard.dependencies": raw}})
        assert result["status"] == "invalid"
    assert native_skill_dependencies({"allowed-tools": "*"})["status"] == "absent"


def test_a_declaration_that_is_not_text_has_no_manifest_to_read():
    # Shaping only: a non-string value never reaches the wire as a manifest,
    # which is the same verdict the resident reaches for text it cannot parse.
    assert module._manifest_text({"metadata": {"hol-guard.dependencies": {"tools": []}}}) == (True, None)
    assert module._manifest_text({"metadata": {"hol-guard.dependencies": "\ud800"}}) == (True, None)
    assert module._manifest_text({"metadata": None}) == (False, None)
    assert native_skill_dependencies({"metadata": {"hol-guard.dependencies": 5}})["status"] == "invalid"


def test_preflight_connections_denies_unknown_tools_and_wrappers_stay_separate():
    names = ["read", "denied", "unknown", "mcp__codex_apps__composio__composio_execute_tool"]
    dependencies = native_skill_dependencies(
        _manifest(
            [{"connection_id": "local-cli.fixture", "tool_name": name} for name in names]
            + [{"connection_id": "local-cli.missing", "tool_name": "read"}]
        )
    )
    item = {
        "cli_id": "local-cli.fixture",
        "identity_hash": "a" * 64,
        "state": "allowed",
        "stale": False,
        "commands": [
            {"usage": name, "state": "block" if name == "denied" else "allow"} for name in names if name != "unknown"
        ],
    }
    original = json.dumps(item)
    plan = native_skill_preflight(dependencies, [item], revision=7)
    assert [requirement["state"] for requirement in plan["requirements"]] == [
        "saved-allow",
        "deny",
        "unresolved",
        "ask",
        "unresolved",
    ]
    assert plan["permissions_granted"] is False
    assert plan["requirements_complete"] is False
    assert plan["runtime_checks_required"] is True
    assert plan["dependency_source"] == "guard-extension"
    assert plan["authority_revision"] == 7
    assert json.dumps(item) == original
    # An identical tool label on another connection cannot satisfy this plan.
    assert all(
        requirement["state"] == "unresolved"
        for requirement in native_skill_preflight(
            dependencies,
            [{**item, "cli_id": "local-cli.other"}],
            revision=7,
        )["requirements"]
    )


def test_unavailable_native_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    class Status:
        mode = "off"
        available = False
        compatible = False
        identity = None
        capabilities = None

    monkeypatch.setattr(module, "_native_runtime_status_memo", lambda: Status())
    with pytest.raises(NativeSkillWorkflowPreflightError, match="unavailable"):
        native_skill_dependencies(_manifest([]))
    with pytest.raises(NativeSkillWorkflowPreflightError, match="unavailable"):
        native_skill_preflight({}, [], revision=1)


def test_client_exceptions_become_typed_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    _force_available(monkeypatch)
    for error in (RuntimeError("thread"), OSError("pipe"), TimeoutError("slow")):

        def client(error: Exception = error, **_kwargs: object) -> bytes:
            raise error

        monkeypatch.setattr(module, "native_resident_client_request", client)
        with pytest.raises(NativeSkillWorkflowPreflightError, match="resident_unavailable"):
            native_skill_dependencies(_manifest([]))


def test_mismatched_binding_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    _force_available(monkeypatch)
    monkeypatch.setattr(
        module,
        "native_resident_client_request",
        lambda **_: (
            b'{"schema":"guard-skill-workflow-preflight-result.v1","request_id":"x","request_sha256":"y",'
            b'"status":"ok","code":"ok","payload":{"status":"declared"}}'
        ),
    )
    with pytest.raises(NativeSkillWorkflowPreflightError, match="result_invalid"):
        native_skill_dependencies(_manifest([]))


def test_a_bound_answer_is_returned_unchanged(monkeypatch: pytest.MonkeyPatch) -> None:
    _force_available(monkeypatch)
    successes: list[object] = []
    monkeypatch.setattr(module, "native_record_resident_success", lambda *a, **k: successes.append(a))

    def client(*, payload: bytes, **_kwargs: object) -> bytes:
        envelope = json.loads(payload)
        assert envelope["operation"] == "skill_workflow_preflight"
        request = envelope["request"]
        assert request["subop"] == "preflight"
        assert request["dependencies"] is None
        assert request["preflight"]["authority_revision"] == 3
        return json.dumps(
            {
                "schema": module._RESULT_SCHEMA,
                "request_id": request["request_id"],
                "request_sha256": "sha256:" + module._canonical_request_sha256(request),
                "status": "ok",
                "code": "ok",
                "payload": {"requirements": []},
            }
        ).encode()

    monkeypatch.setattr(module, "native_resident_client_request", client)
    assert native_skill_preflight({}, [], revision=3) == {"requirements": []}
    assert successes
