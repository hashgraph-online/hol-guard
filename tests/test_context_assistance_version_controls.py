from __future__ import annotations

import argparse
import io
import json
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_context_assistance as native
from codex_plugin_scanner.guard.cli import commands_router
from codex_plugin_scanner.guard.cli.commands_parser import add_guard_parser, add_guard_root_parser
from codex_plugin_scanner.guard.daemon import context_assistance_http as http
from codex_plugin_scanner.guard.daemon import context_assistance_versions_http as version_http


def state():
    return {
        "schema": "guard-context-assistance-status.v2",
        "availability": "off",
        "requested_enabled": False,
        "effective_enabled": False,
        "preferences": {},
        "effective_preferences": {},
        "restriction": None,
        "verification_permitted": True,
        "generation": "9007199254740993",
        "diagnostic": None,
        "runtime": None,
        "last_check": None,
        "qualification": None,
        "capabilities": {"shared_agents": True, "private_persistence": True},
        "installation_options": None,
        "job": None,
        "upgrade": None,
    }


def test_version_transport_negotiates_native_contract_and_preserves_exact_generation(monkeypatch, tmp_path):
    captured = {}
    result = {"schema": "guard-cigar-versions-result.v1", "result": {"jobs": []}}

    def decide(query, home, fields, validate, **kwargs):
        captured.update(query=query, home=home, fields=fields, **kwargs)
        answer = {"kind": "versions", "state": state(), "data": result}
        validate(answer)
        return answer

    monkeypatch.setattr(native, "_decide", decide)
    payload = {
        "action": "prepare_switch",
        "job_id": "one",
        "target_runtime_id": "runtime",
        "expected_generation": "9007199254740993",
    }
    answer = native.versions(guard_home=tmp_path, payload=payload)
    assert captured["query"] == {"kind": "versions", "guard_home": str(tmp_path), "input": payload}
    assert captured["operation"].feature == "context-assistance-versions-v1"
    assert captured["operation"].timeout_seconds == 8.0
    assert captured["operation"].shared_resident_health is False
    assert captured["max_request_bytes"] == 64 * 1024
    assert answer == {**result, "state": state()}


@pytest.mark.parametrize(
    "data",
    [
        {"result": {}},
        {"schema": "guard-cigar-versions-result.v0", "result": {}},
        {
            "schema": "guard-cigar-versions-result.v1",
            "result": [],
        },
        {"schema": "guard-cigar-versions-result.v1", "result": {}, "granted": True},
    ],
)
def test_version_transport_refuses_unknown_or_malformed_results(monkeypatch, tmp_path, data):
    def decide(query, home, fields, validate, **kwargs):
        answer = {"state": state(), "data": data}
        validate(answer)
        return answer

    monkeypatch.setattr(native, "_decide", decide)
    with pytest.raises(native.ContextAssistanceError):
        native.versions(guard_home=tmp_path, payload={"action": "jobs"})


@pytest.mark.parametrize("nested", [False, True])
@pytest.mark.parametrize(
    "argv,payload",
    [
        (["versions"], {"action": "releases"}),
        (
            ["commit", "off-selection", "--generation", "7"],
            {"action": "commit", "job_id": "off-selection", "expected_generation": "7", "reconnect": False},
        ),
        (["preferences"], {"action": "preferences"}),
        (["catalog-refresh", "check-one"], {"action": "refresh_catalog", "job_id": "check-one"}),
        (["jobs"], {"action": "jobs"}),
        (
            ["install", "build", "--interpreter-id", "python", "--job-id", "install-one"],
            {"action": "install", "build_id": "build", "interpreter_id": "python", "job_id": "install-one"},
        ),
        (
            ["switch", "runtime", "--job-id", "switch-one", "--generation", "9007199254740993"],
            {
                "action": "prepare_switch",
                "target_runtime_id": "runtime",
                "job_id": "switch-one",
                "expected_generation": "9007199254740993",
            },
        ),
        (
            ["rollback", "--job-id", "back", "--generation", "7"],
            {"action": "prepare_rollback", "job_id": "back", "expected_generation": "7"},
        ),
        (
            ["commit", "switch-one", "--generation", "9007199254740993", "--acknowledge-reconnect"],
            {"action": "commit", "job_id": "switch-one", "expected_generation": "9007199254740993", "reconnect": True},
        ),
        (
            ["recover", "switch-one", "--generation", "7"],
            {"action": "recover", "job_id": "switch-one", "expected_generation": "7"},
        ),
    ],
)
def test_root_and_nested_version_cli_forward_native_actions(monkeypatch, tmp_path, nested, argv, payload):
    parser = argparse.ArgumentParser()
    if nested:
        add_guard_parser(parser.add_subparsers(dest="command"))
    else:
        add_guard_root_parser(parser)
    calls = []
    answer = {"schema": "guard-cigar-versions-result.v1", "state": state(), "result": {"jobs": []}}
    monkeypatch.setattr(native, "versions", lambda **kw: calls.append(kw) or answer)

    def forbidden(*a, **kw):
        raise AssertionError("Version framing must not create the general Guard store or run a host installer")

    monkeypatch.setattr(commands_router, "GuardStore", forbidden)
    args = parser.parse_args(
        (["guard"] if nested else []) + ["context", "--guard-home", str(tmp_path), "--json", *argv]
    )
    output = io.StringIO()
    assert commands_router.run_guard_command(args, output_stream=output) == 0
    assert calls == [{"guard_home": tmp_path, "payload": payload}]
    assert json.loads(output.getvalue()) == answer


@pytest.mark.parametrize(
    "argv",
    [
        ["commit", "one"],
        ["switch", "target", "--job-id", "one"],
        ["install", "build", "--job-id", "one", "--python", "/untrusted/python"],
    ],
)
def test_cli_requires_exact_generations_and_native_ids(argv):
    parser = argparse.ArgumentParser()
    add_guard_root_parser(parser)
    with pytest.raises(SystemExit) as e:
        parser.parse_args(["context", *argv])
    assert e.value.code == 2


def handler(tmp_path, *, authorized=True):
    responses = []
    return SimpleNamespace(
        server=SimpleNamespace(store=SimpleNamespace(guard_home=tmp_path)),
        _header_token_is_valid=lambda **kw: authorized,
        _write_json=lambda body, **kw: responses.append((body, kw)),
        _write_approval_gate_error=lambda e: responses.append(e.code),
    ), responses


def test_http_requires_operator_auth_before_gate_or_native_dispatch(monkeypatch, tmp_path):
    h, responses = handler(tmp_path, authorized=False)

    def forbidden(*a, **kw):
        raise AssertionError("Unauthorized route reached native/gate")

    monkeypatch.setattr(version_http, "versions", forbidden)
    monkeypatch.setattr(version_http, "require_high_risk", forbidden)
    http.respond(h, "versions", {"input": {"action": "prepare_switch"}})
    assert responses == [({"error": "unauthorized"}, {"status": 401})]


@pytest.mark.parametrize("reconnect", [True, False])
def test_http_version_mutations_use_existing_gate_and_strip_proof(monkeypatch, tmp_path, reconnect):
    h, responses = handler(tmp_path)
    calls = []
    grant = object()
    monkeypatch.setattr(version_http, "require_high_risk", lambda *a, **kw: calls.append("gate") or grant)
    monkeypatch.setattr(version_http, "require_settings_write", lambda *a, **kw: calls.append(("write", kw)))
    monkeypatch.setattr(version_http, "versions", lambda **kw: calls.append(("native", kw)) or {"result": {}})
    body = {"action": "commit", "job_id": "one", "expected_generation": "9007199254740993", "reconnect": reconnect}
    http.respond(h, "versions", {"input": body, "approval_password": "unit-only-proof"})
    assert calls == [
        "gate",
        ("write", {"approval_gate_grant": grant}),
        ("native", {"guard_home": tmp_path, "payload": body}),
    ]
    assert "unit-only-proof" not in repr(calls)
    assert responses == [({"result": {}}, {"extra_headers": {"Cache-Control": "no-store"}})]


def test_http_gate_refusal_cannot_reach_native_and_cancel_needs_no_new_proof(monkeypatch, tmp_path):
    h, responses = handler(tmp_path)
    calls = []

    def refuse(*a, **kw):
        raise version_http.ApprovalGateError("approval_required", "Unit proof required", status=403)

    monkeypatch.setattr(version_http, "require_high_risk", refuse)
    monkeypatch.setattr(version_http, "versions", lambda **kw: calls.append(kw) or {"result": {}})
    http.respond(h, "versions", {"input": {"action": "install"}})
    assert responses == ["approval_required"] and calls == []
    http.respond(h, "versions", {"input": {"action": "cancel", "job_id": "one"}})
    assert calls == [{"guard_home": tmp_path, "payload": {"action": "cancel", "job_id": "one"}}]


def test_get_routes_cannot_smuggle_mutating_actions(monkeypatch, tmp_path):
    h, _responses = handler(tmp_path)
    calls = []
    monkeypatch.setattr(version_http, "versions", lambda **kw: calls.append(kw) or {"result": {}})

    def forbidden(*a, **kw):
        raise AssertionError("Metadata reads need no new approval")

    monkeypatch.setattr(version_http, "require_high_risk", forbidden)
    for path, kind in version_http.READ_PATHS.items():
        assert http.READ_PATHS[path] == kind
        http.respond(h, kind, {"input": {"action": "commit", "reconnect": True}})
    assert [x["payload"] for x in calls] == [
        {"action": "releases"},
        {"action": "jobs"},
        {"action": "interpreters"},
        {"action": "catalog"},
    ]


@pytest.mark.parametrize("body", [None, [], {}, {"action": []}, {"action": True}])
def test_http_malformed_actions_fail_before_gate(monkeypatch, tmp_path, body):
    h, responses = handler(tmp_path)

    def forbidden(*a, **kw):
        raise AssertionError("Malformed framing reached gate/native")

    monkeypatch.setattr(version_http, "require_high_risk", forbidden)
    monkeypatch.setattr(version_http, "versions", forbidden)
    http.respond(h, "versions", {"input": body})
    assert responses == [({"error": "invalid_context_input"}, {"status": 400})]


@pytest.mark.parametrize("disabled", [True, False])
def test_ready_job_render_uses_native_serving_transition_metadata(disabled):
    from codex_plugin_scanner.guard.cli.context_assistance_versions_commands import render

    output = io.StringIO()
    render(
        {
            "state": state(),
            "result": {
                "job_id": "selection",
                "operation": "switch",
                "phase": "ready",
                "code": "ready_disabled" if disabled else "ready",
                "can_commit": True,
                "keeps_disabled": disabled,
                "reconnect_required": not disabled,
            },
        },
        output,
    )
    text = output.getvalue()
    if disabled:
        assert "CIGAR stays off; enable it separately" in text
        assert "Committing reconnects" not in text
    else:
        assert "Committing reconnects applications and requires fresh source grants." in text


def test_settings_switch_refusal_is_actionable_validation_in_the_existing_client(monkeypatch, tmp_path):
    from codex_plugin_scanner.guard import native_guard_config

    message = "Prepare and commit a CIGAR switch before selecting a different installation."
    monkeypatch.setattr(native_guard_config, "_runtime_identity", lambda *args: (tmp_path / "unused-native", "unused"))
    monkeypatch.setattr(
        native_guard_config,
        "_run",
        lambda *args: {"ok": False, "error": "native_context_assistance_switch_required", "invalid": message},
    )
    with pytest.raises(ValueError, match="Prepare and commit a CIGAR switch") as raised:
        native_guard_config.update_native_guard_config(tmp_path, "settings", {}, managed=None)
    assert type(raised.value) is ValueError
    assert str(raised.value) == message
    assert not (tmp_path / "config.toml").exists()
