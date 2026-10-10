"""Daemon route, origin and session policy is answered by the native runtime.

The vectors were recorded from the retired Python handler methods (see
``scripts/record_daemon_route_vectors.py``) and are shared with the Rust crate,
so a divergence here means the resident or the transport changed behaviour.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_daemon_route as route
from codex_plugin_scanner.guard import native_resident_decision as shared
from codex_plugin_scanner.guard.approval_scope_support import APPROVAL_SCOPE_CONTRACT_VERSION_PREFIX
from codex_plugin_scanner.guard.daemon import server as daemon_server
from codex_plugin_scanner.guard.daemon.server import _HEADLESS_APP_ACTIONS, _GuardDaemonHandler

pytestmark = pytest.mark.native_route_unpinned

_DOCUMENT = json.loads(
    (
        Path(__file__).parent.parent
        / "rust"
        / "crates"
        / "guard-runtime"
        / "tests"
        / "fixtures"
        / "daemon_route_vectors.json"
    ).read_text(encoding="utf-8")
)
_VECTORS = _DOCUMENT["vectors"]
_FAR_FUTURE = 1e18


class _Headers:
    def __init__(self, values: dict[str, str | None]) -> None:
        self._values = values

    def get(self, name: str, default: object = None) -> object:
        value = self._values.get(name)
        return default if value is None else value


def _handler(home: Path, command: str, path: str, headers: dict[str, str | None], nonces: list[str] | None = None):
    handler = object.__new__(_GuardDaemonHandler)
    handler.command = command
    handler.path = path
    handler.headers = _Headers(headers)  # type: ignore[assignment]
    handler.server = SimpleNamespace(  # type: ignore[assignment]
        store=SimpleNamespace(guard_home=home),
        package_firewall_session_nonces=dict.fromkeys(nonces or [], _FAR_FUTURE),
        package_firewall_session_nonces_lock=threading.Lock(),
    )
    return handler


def _by_kind(kind: str) -> list[dict[str, object]]:
    return [vector for vector in _VECTORS if vector["query"]["kind"] == kind]


def test_vectors_were_recorded_from_the_base_commit_and_cover_every_kind() -> None:
    assert len(_VECTORS) > 1500
    assert len(_DOCUMENT["base_commit"]) == 40
    for kind in ("route", "origin", "strict_loopback", "session_authorize", "resolve_request"):
        assert len(_by_kind(kind)) >= 20, kind
    expected_allowed = {vector["expected"]["allowed"] for vector in _by_kind("session_authorize")}
    assert expected_allowed == {True, False}


def test_route_facts_match_recorded_vectors(native_approval_reuse_runtime: Path) -> None:
    mismatches = []
    for vector in _by_kind("route"):
        raw = vector["raw"]
        facts = route.native_route_facts(raw["method"], raw["path"], guard_home=native_approval_reuse_runtime)
        answer = {
            "requires_header_token": facts.requires_header_token,
            "session_path": facts.session_path,
            "route_class": facts.route_class,
        }
        if answer != vector["expected"]:
            mismatches.append(vector["name"])
    assert mismatches == []


def test_origin_decisions_match_recorded_vectors(native_approval_reuse_runtime: Path) -> None:
    mismatches = []
    for vector in _by_kind("origin"):
        raw = vector["raw"]
        handler = _handler(native_approval_reuse_runtime, "GET", raw["path"], {"Origin": raw["origin"]})
        answer = {
            "allowed": handler._origin_is_allowed_for_request(raw["path"]),
            "hosted_origin": handler._is_hosted_dashboard_origin(),
        }
        if answer != vector["expected"]:
            mismatches.append(vector["name"])
    assert mismatches == []


def test_unnormalizable_origins_are_refused_without_a_native_answer(tmp_path: Path) -> None:
    gate = _DOCUMENT["python_gate"]
    assert len(gate) >= 20
    for vector in gate:
        raw = vector["raw"]
        handler = _handler(tmp_path, "GET", raw["path"], {"Origin": raw["origin"]})
        assert handler._origin_is_allowed_for_request(raw["path"]) is False, vector["name"]
        assert handler._is_hosted_dashboard_origin() is False, vector["name"]


def test_strict_loopback_matches_recorded_vectors(native_approval_reuse_runtime: Path) -> None:
    mismatches = []
    for vector in _by_kind("strict_loopback"):
        handler = _handler(native_approval_reuse_runtime, "POST", "/", {})
        if handler._strict_loopback_origin(vector["raw"]["value"]) != vector["expected"]["origin"]:
            mismatches.append(vector["name"])
    assert mismatches == []


def test_session_authorization_matches_recorded_vectors_including_nonce_replay(
    native_approval_reuse_runtime: Path,
) -> None:
    mismatches = []
    for vector in _by_kind("session_authorize"):
        raw, expected = vector["raw"], vector["expected"]
        headers = {"Origin": raw["origin_header"], "X-Guard-Dashboard-Nonce": raw["nonce_header"]}
        handler = _handler(native_approval_reuse_runtime, raw["method"], raw["path"], headers)
        allowed = handler._dashboard_session_claims_authorize_request(raw["claims"], payload=raw["payload"])
        consumed = sorted(handler.server.package_firewall_session_nonces)  # type: ignore[attr-defined]
        replay = _handler(
            native_approval_reuse_runtime, raw["method"], raw["path"], headers, [name for name in consumed]
        )
        replayed = replay._dashboard_session_claims_authorize_request(raw["claims"], payload=raw["payload"])
        got = {
            "allowed": allowed,
            "consume_nonce": consumed[0] if consumed else None,
            "replay_allowed": replayed,
        }
        if got != expected:
            mismatches.append(vector["name"])
    assert mismatches == []


def test_resolve_request_matches_recorded_vectors(native_approval_reuse_runtime: Path) -> None:
    mismatches = []
    for vector in _by_kind("resolve_request"):
        raw = vector["raw"]
        outcome = route.native_resolve_request(raw["path"], raw["payload"], guard_home=native_approval_reuse_runtime)
        answer = {
            "outcome": outcome.outcome,
            "request_id": outcome.request_id,
            "action": outcome.action,
            "scope": outcome.scope,
            "scope_contract_version": outcome.scope_contract_version,
            "scope_contract_digest": outcome.scope_contract_digest,
        }
        if answer != vector["expected"]:
            mismatches.append(vector["name"])
    assert mismatches == []


def test_route_constants_stay_in_step_with_the_resident_tables(native_approval_reuse_runtime: Path) -> None:
    for name in _HEADLESS_APP_ACTIONS:
        facts = route.native_route_facts("POST", f"/v1/apps/{name}", guard_home=native_approval_reuse_runtime)
        assert facts.requires_header_token, name
        assert facts.session_path, name
    version = f"{APPROVAL_SCOPE_CONTRACT_VERSION_PREFIX}7"
    payload = {"action": "allow", "scope": "artifact", "scope_contract_version": version}
    resolved = route.native_resolve_request(
        "/v1/requests/r1/approve", payload, guard_home=native_approval_reuse_runtime
    )
    assert resolved.outcome == "resolved"
    assert resolved.scope_contract_version == version
    bare = {**payload, "scope_contract_version": APPROVAL_SCOPE_CONTRACT_VERSION_PREFIX}
    invalid = route.native_resolve_request("/v1/requests/r1/approve", bare, guard_home=native_approval_reuse_runtime)
    assert invalid.outcome == "invalid_scope_contract_version"


# --- transport failure paths: no authoritative answer means deny ----------------------------


def _good(request: dict[str, object], body: dict[str, object], **overrides: object) -> dict[str, object]:
    reply: dict[str, object] = {
        "schema": "guard-daemon-route-result.v1",
        "request_id": request["request_id"],
        "request_sha256": "sha256:" + shared._canonical_request_sha256(request),
        "status": "ok",
        "code": "ok",
        "payload": body,
    }
    reply.update(overrides)
    return reply


def _resident(monkeypatch: pytest.MonkeyPatch, reply) -> None:
    monkeypatch.setattr(shared, "_resolve_digest_home", lambda _home: Path("/tmp/daemon-route-home"))
    monkeypatch.setattr(shared, "ensure_resident_prerequisite", lambda _home: True)
    monkeypatch.setattr(shared, "record_resident", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(route, "_resident_request", lambda *, request, **_kwargs: reply(request))


_ROUTE_PAYLOAD = {"kind": "route", "requires_header_token": True, "session_path": False, "route_class": "none"}


def test_bound_answer_is_returned(monkeypatch: pytest.MonkeyPatch) -> None:
    _resident(monkeypatch, lambda request: _good(request, dict(_ROUTE_PAYLOAD)))
    facts = route.native_route_facts("POST", "/v1/hooks/codex/pre")
    assert facts == route.RouteFacts(True, False, "none")


@pytest.mark.parametrize(
    "mutate",
    [
        lambda request: None,
        lambda request: _good(request, dict(_ROUTE_PAYLOAD), request_id="someone-else"),
        lambda request: _good(request, dict(_ROUTE_PAYLOAD), request_sha256="sha256:" + "0" * 64),
        lambda request: _good(request, dict(_ROUTE_PAYLOAD), schema="guard-daemon-route-result.v0"),
        lambda request: _good(request, dict(_ROUTE_PAYLOAD), status="denied"),
        lambda request: _good(request, dict(_ROUTE_PAYLOAD), code="other"),
        lambda request: _good(request, {**_ROUTE_PAYLOAD, "kind": "origin"}),
        lambda request: _good(request, {**_ROUTE_PAYLOAD, "extra": 1}),
        lambda request: _good(request, {**_ROUTE_PAYLOAD, "requires_header_token": 1}),
        lambda request: _good(request, {**_ROUTE_PAYLOAD, "route_class": "admin"}),
        lambda request: _good(request, {k: v for k, v in _ROUTE_PAYLOAD.items() if k != "session_path"}),
        lambda request: _good(request, dict(_ROUTE_PAYLOAD), payload=None),
        lambda request: _good(request, dict(_ROUTE_PAYLOAD), status="error", code="native_daemon_route_too_large"),
    ],
)
def test_unbound_or_malformed_answers_raise(monkeypatch: pytest.MonkeyPatch, mutate) -> None:
    _resident(monkeypatch, mutate)
    with pytest.raises(route.NativeDaemonRouteError):
        route.native_route_facts("POST", "/v1/runtime")


def test_unavailable_resident_raises_without_a_request(monkeypatch: pytest.MonkeyPatch) -> None:
    _resident(monkeypatch, lambda request: pytest.fail("resident must not be asked"))
    monkeypatch.setattr(shared, "ensure_resident_prerequisite", lambda _home: False)
    with pytest.raises(route.NativeDaemonRouteError) as caught:
        route.native_route_facts("POST", "/v1/runtime")
    assert caught.value.code == "native_daemon_route_unavailable"


_ORIGIN_PAYLOAD = {"kind": "origin", "allowed": True, "hosted_origin": False}


def test_verdicts_are_never_reused_after_the_resident_becomes_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    def answer(request: dict[str, object]) -> dict[str, object]:
        kind = request["query"]["kind"]  # type: ignore[index]
        return _good(request, dict(_ROUTE_PAYLOAD if kind == "route" else _ORIGIN_PAYLOAD))

    _resident(monkeypatch, answer)
    assert route.native_route_facts("POST", "/v1/runtime") == route.RouteFacts(True, False, "none")
    assert route.native_origin_decision("http://127.0.0.1:4781", "/v1/runtime").allowed is True
    # Identical repeat calls still reach the resident, so losing it must fail them closed.
    monkeypatch.setattr(shared, "ensure_resident_prerequisite", lambda _home: False)
    with pytest.raises(route.NativeDaemonRouteError):
        route.native_route_facts("POST", "/v1/runtime")
    with pytest.raises(route.NativeDaemonRouteError):
        route.native_origin_decision("http://127.0.0.1:4781", "/v1/runtime")


def test_native_off_after_a_native_answer_fails_closed(
    monkeypatch: pytest.MonkeyPatch, native_approval_reuse_runtime: Path
) -> None:
    home = native_approval_reuse_runtime
    assert route.native_route_facts("POST", "/v1/hooks/codex/pre", guard_home=home).requires_header_token
    assert route.native_origin_decision("https://hol.org", "/v1/runtime", guard_home=home) is not None
    monkeypatch.setenv("HOL_GUARD_NATIVE", "off")
    with pytest.raises(route.NativeDaemonRouteError):
        route.native_route_facts("POST", "/v1/hooks/codex/pre", guard_home=home)
    with pytest.raises(route.NativeDaemonRouteError):
        route.native_origin_decision("https://hol.org", "/v1/runtime", guard_home=home)


def test_resolve_replies_with_an_unknown_outcome_are_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = {
        "kind": "resolve_request",
        "outcome": "approved_without_scope",
        "request_id": None,
        "action": None,
        "scope": None,
        "scope_contract_version": None,
        "scope_contract_digest": None,
    }
    _resident(monkeypatch, lambda request: _good(request, payload))
    with pytest.raises(route.NativeDaemonRouteError):
        route.native_resolve_request("/v1/requests/r1/approve", {})


def _failing(*_args: object, **_kwargs: object) -> None:
    raise route.NativeDaemonRouteError("native_daemon_route_unavailable")


def test_handler_denies_when_the_resident_cannot_answer(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    for name in (
        "native_origin_decision",
        "native_route_facts",
        "native_session_authorize",
        "native_strict_loopback_origin",
    ):
        monkeypatch.setattr(daemon_server, name, _failing)
    handler = _handler(tmp_path, "POST", "/v1/runtime", {"Origin": "http://127.0.0.1:4781"})
    assert handler._origin_is_allowed_for_request("/v1/runtime") is False
    # Without an answer the origin is treated as hosted, which withholds local-only extras.
    assert handler._is_hosted_dashboard_origin() is True
    assert handler._path_supports_dashboard_session("/v1/runtime") is False
    assert handler._strict_loopback_origin("http://127.0.0.1:4781") is None
    assert handler._dashboard_session_claims_authorize_request({"surface": "dashboard"}, payload=None) is False
