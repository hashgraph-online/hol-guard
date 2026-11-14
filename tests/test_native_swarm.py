"""Swarm's HTTP layer only frames the resident request and renders its result."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_resident_decision as decisions
from codex_plugin_scanner.guard import native_swarm as api
from codex_plugin_scanner.guard.daemon import swarm_http as http


def test_browser_payload_cannot_override_home_or_route(monkeypatch, tmp_path: Path):
    captured = {}
    monkeypatch.setattr(api, "_resolve_digest_home", lambda _: tmp_path)
    monkeypatch.setenv("PATH", "/tool-bin")

    def decide(operation, transport, query, home, validate):
        captured.update(query=query, home=home, operation=operation)
        return {"agent": {"id": "run-1"}}

    monkeypatch.setattr(api, "resident_decide", decide)
    payload = {"guard_home": "/foreign", "cli_path": "/foreign-bin", "action": "snapshot", "executable": "/bin/sh"}
    assert api.execute("launch", payload, guard_home=tmp_path) == {"agent": {"id": "run-1"}}
    assert captured["query"] == {
        "guard_home": str(tmp_path),
        "cli_path": "/tool-bin",
        "input": {"action": "launch", "launch": payload},
    }
    assert captured["operation"].feature == "swarm-v1"
    api.execute("events", {"run_id": "run-1", "action": "launch"}, guard_home=tmp_path)
    assert captured["query"]["input"] == {"action": "events", "run_id": "run-1"}


@pytest.mark.parametrize(
    "code,status",
    [
        ("swarm_stale", 409),
        ("swarm_request_conflict", 409),
        ("swarm_workspace_invalid", 400),
        ("native_swarm_unavailable", 503),
        ("swarm_unavailable", 503),
        ("swarm_worker_unavailable", 503),
    ],
)
def test_http_preserves_rejections_and_uncertain_transport_errors(monkeypatch, tmp_path: Path, code, status):
    replies = []
    handler = SimpleNamespace(
        server=SimpleNamespace(store=SimpleNamespace(guard_home=tmp_path)),
        _write_json=lambda body, **kwargs: replies.append((body, kwargs)),
    )

    def fail(*args, **kwargs):
        raise api.SwarmError(code)

    monkeypatch.setattr(http, "execute", fail)
    http.respond(handler, "launch", {})
    assert replies == [({"error": code}, {"status": status, "extra_headers": {"Cache-Control": "no-store"}})]


def test_snapshot_is_not_cached_and_native_failure_does_not_invent_agents(monkeypatch, tmp_path: Path):
    replies = []
    handler = SimpleNamespace(
        server=SimpleNamespace(store=SimpleNamespace(guard_home=tmp_path)),
        _write_json=lambda body, **kwargs: replies.append((body, kwargs)),
    )
    monkeypatch.setattr(http, "execute", lambda *args, **kwargs: {"schema": "guard-swarm-snapshot.v1", "agents": []})
    http.respond(handler)
    assert replies[0][1]["extra_headers"] == {"Cache-Control": "no-store"}

    def fail(*args, **kwargs):
        raise OSError("private diagnostic")

    monkeypatch.setattr(http, "execute", fail)
    http.respond(handler)
    assert replies[-1] == ({"error": "swarm_unavailable"}, {"status": 503})


@pytest.mark.parametrize("code", ["ok", "swarm_stale", "swarm_workspace_invalid", "unbound"])
def test_real_reply_validation_preserves_native_errors_and_accepts_swarm_shape(monkeypatch, tmp_path, code):
    monkeypatch.setattr(api, "_resolve_digest_home", lambda _: tmp_path)
    monkeypatch.setattr(decisions, "_resolve_digest_home", lambda _: tmp_path)
    monkeypatch.setattr(decisions, "ensure_resident_prerequisite", lambda _: True)
    monkeypatch.setattr(decisions, "native_runtime_status", lambda: SimpleNamespace(identity=None))

    def transport(**kwargs):
        request = kwargs["request"]
        assert kwargs["required_feature"] == "swarm-v1"
        assert kwargs["max_request_bytes"] == 32768
        return {
            "schema": "guard-swarm-result.v1",
            "request_id": request["request_id"],
            "request_sha256": "invalid"
            if code == "unbound"
            else "sha256:" + decisions._canonical_request_sha256(request),
            "status": "ok" if code in {"ok", "unbound"} else "error",
            "code": "ok" if code == "unbound" else code,
            "payload": {"snapshot": {"schema": "guard-swarm-snapshot.v1", "agents": []}},
        }

    monkeypatch.setattr(api, "_resident_request", transport)
    if code == "ok":
        assert api.execute("snapshot", {}, guard_home=tmp_path)["agents"] == []
    else:
        with pytest.raises(api.SwarmError) as error:
            api.execute("snapshot", {}, guard_home=tmp_path)
        assert error.value.code == ("swarm_unavailable" if code == "unbound" else code)
