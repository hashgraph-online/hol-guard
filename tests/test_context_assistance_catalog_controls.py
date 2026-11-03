from __future__ import annotations

import argparse
import io
import json
from types import SimpleNamespace

from codex_plugin_scanner.guard import native_context_assistance as native
from codex_plugin_scanner.guard.cli import commands_router
from codex_plugin_scanner.guard.cli.commands_parser import add_guard_root_parser
from codex_plugin_scanner.guard.daemon import context_assistance_versions_http as http


def test_catalog_cli_reads_bounded_stdin_and_forwards_only_signed_bytes(monkeypatch, tmp_path):
    parser = argparse.ArgumentParser()
    add_guard_root_parser(parser)
    args = parser.parse_args(["context", "catalog-import", "--guard-home", str(tmp_path), "--json"])
    calls = []
    answer = {"schema": "guard-cigar-versions-result.v1", "state": {}, "result": {"activation_granted": False}}
    monkeypatch.setattr(native, "versions", lambda **kw: calls.append(kw) or answer)
    monkeypatch.setattr("sys.stdin", io.StringIO("signed-catalog-fixture"))
    output = io.StringIO()
    assert commands_router.run_guard_command(args, output_stream=output) == 0
    assert calls == [
        {"guard_home": tmp_path, "payload": {"action": "import_catalog", "signed_catalog": "signed-catalog-fixture"}}
    ]
    assert json.loads(output.getvalue()) == answer


def test_catalog_cli_oversize_is_a_framing_refusal_before_native_dispatch(monkeypatch, tmp_path):
    parser = argparse.ArgumentParser()
    add_guard_root_parser(parser)
    args = parser.parse_args(["context", "catalog-import", "--guard-home", str(tmp_path), "--json"])

    def forbidden(**kw):
        raise AssertionError("Oversized catalog reached native transport")

    monkeypatch.setattr(native, "versions", forbidden)
    monkeypatch.setattr("sys.stdin", io.StringIO("x" * (1024 * 1024 + 1)))
    output = io.StringIO()
    assert commands_router.run_guard_command(args, output_stream=output) == 1
    assert json.loads(output.getvalue())["code"] == "native_context_assistance_cigar_catalog_too_large"


def test_signed_catalog_uses_its_own_transport_budget_without_changing_other_version_requests(monkeypatch, tmp_path):
    calls = []

    def decide(query, home, fields, validate, **kw):
        calls.append((query, kw["max_request_bytes"]))
        return {"data": {"schema": "guard-cigar-versions-result.v1", "result": {}}, "state": {}}

    monkeypatch.setattr(native, "_decide", decide)
    signed = "x" * (128 * 1024)
    native.versions(guard_home=tmp_path, payload={"action": "import_catalog", "signed_catalog": signed})
    native.versions(guard_home=tmp_path, payload={"action": "catalog"})
    assert [x[1] for x in calls] == [4 * 1024 * 1024, 64 * 1024]
    assert calls[0][0]["input"]["signed_catalog"] == signed


def test_catalog_http_uses_settings_gate_strips_proof_and_keeps_read_routes_fixed(monkeypatch, tmp_path):
    calls = []
    grant = object()
    handler = SimpleNamespace(
        server=SimpleNamespace(store=SimpleNamespace(guard_home=tmp_path)),
        _header_token_is_valid=lambda **kw: True,
        _write_json=lambda *a, **kw: None,
    )
    monkeypatch.setattr(http, "require_high_risk", lambda *a, **kw: calls.append("gate") or grant)
    monkeypatch.setattr(http, "require_settings_write", lambda *a, **kw: calls.append(("settings", kw)))
    monkeypatch.setattr(http, "versions", lambda **kw: calls.append(("native", kw)) or {})
    body = {"action": "import_catalog", "signed_catalog": "signed-catalog-fixture"}
    http.respond(handler, "versions", {"input": body, "approval_password": "unit-only-proof"})
    assert calls == [
        "gate",
        ("settings", {"approval_gate_grant": grant}),
        ("native", {"guard_home": tmp_path, "payload": body}),
    ]
    assert "unit-only-proof" not in repr(calls)
    calls.clear()
    http.respond(handler, "versions_catalog", {"input": body})
    assert calls == [("native", {"guard_home": tmp_path, "payload": {"action": "catalog"}})]


def test_http_body_budget_is_scoped_and_supports_the_complete_signed_envelope():
    from email.message import Message

    from codex_plugin_scanner.guard.daemon.server import _GuardDaemonHandler

    body = json.dumps({"input": {"action": "import_catalog", "signed_catalog": "x" * (1024 * 1024)}}).encode()
    headers = Message()
    headers["Content-Type"] = "application/json"
    headers["Content-Length"] = str(len(body))
    calls = []
    handler = SimpleNamespace(
        headers=headers,
        path="/v1/context-assistance/versions?read=1",
        _MAX_BODY_BYTES=1_000_000,
        _read_request_body=lambda size: calls.append(size) or (body, None),
    )
    payload, error = _GuardDaemonHandler._load_request_body(handler)
    assert error is None and len(payload["input"]["signed_catalog"]) == 1024 * 1024
    assert calls == [len(body)]
    for path in ("/v1/settings", "/v1/hooks/codex/pre", "/v1/context-assistance/workspace"):
        handler.path = path
        assert _GuardDaemonHandler._load_request_body(handler) == ({}, "request_body_too_large")
    handler.path = "/v1/context-assistance/versions"
    headers.replace_header("Content-Length", str(4 * 1024 * 1024 + 1))
    assert _GuardDaemonHandler._load_request_body(handler) == ({}, "request_body_too_large")
    assert calls == [len(body)]


def test_catalog_lifecycle_conflict_is_an_http_conflict(monkeypatch, tmp_path):
    responses = []
    handler = SimpleNamespace(
        server=SimpleNamespace(store=SimpleNamespace(guard_home=tmp_path)),
        _header_token_is_valid=lambda **kw: True,
        _write_json=lambda data, **kw: responses.append((data, kw)),
    )
    monkeypatch.setattr(http, "require_high_risk", lambda *a, **kw: object())
    monkeypatch.setattr(http, "require_settings_write", lambda *a, **kw: None)

    def busy(**kw):
        raise native.ContextAssistanceError("native_context_assistance_install_busy")

    monkeypatch.setattr(http, "versions", busy)
    http.respond(handler, "versions", {"input": {"action": "import_catalog", "signed_catalog": "unit"}})
    assert responses[0][1]["status"] == 409


def test_remote_refresh_remains_behind_the_settings_gate_and_uses_existing_job_controls(monkeypatch, tmp_path):
    calls = []
    grant = object()
    handler = SimpleNamespace(
        server=SimpleNamespace(store=SimpleNamespace(guard_home=tmp_path)),
        _header_token_is_valid=lambda **kw: True,
        _write_json=lambda *a, **kw: None,
    )
    monkeypatch.setattr(http, "require_high_risk", lambda *a, **kw: calls.append("gate") or grant)
    monkeypatch.setattr(http, "require_settings_write", lambda *a, **kw: calls.append(("settings", kw)))
    monkeypatch.setattr(http, "versions", lambda **kw: calls.append(("native", kw)) or {})
    body = {"action": "refresh_catalog", "job_id": "check-one"}
    http.respond(handler, "versions", {"input": body, "approval_password": "unit-only-proof"})
    assert calls == [
        "gate",
        ("settings", {"approval_gate_grant": grant}),
        ("native", {"guard_home": tmp_path, "payload": body}),
    ]
    calls.clear()
    http.respond(handler, "versions", {"input": {"action": "cancel", "job_id": "check-one"}})
    assert calls == [("native", {"guard_home": tmp_path, "payload": {"action": "cancel", "job_id": "check-one"}})]
