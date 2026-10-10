"""Brokered network egress for resident package evaluation.

The resident cannot dial out, so Python performs the exchanges it asks for under
the managed network policy. These tests pin that policy: a managed host that
disallows public registries must never reach them, and an unmanaged host behind
an environment proxy must keep working. The resident side is covered by the
Rust crate; here the resident is replaced by a scripted fake.
"""

from __future__ import annotations

import http.server
import socket
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import ClassVar

import pytest

from codex_plugin_scanner.guard import native_supply_chain_egress as egress
from codex_plugin_scanner.guard import native_supply_chain_eval as transport
from codex_plugin_scanner.guard.mdm import network_transport
from codex_plugin_scanner.guard.mdm.contracts import ManagedNetworkPolicy
from codex_plugin_scanner.guard.native_context import _canonical_request_sha256
from codex_plugin_scanner.guard.native_package_authority import _RESULT_SCHEMA
from codex_plugin_scanner.guard.runtime.restricted_archive_contract import RestrictedArchiveFailure


def _need(url: str, *, klass: str = "registry", **overrides: object) -> dict[str, object]:
    need: dict[str, object] = {
        "class": klass,
        "method": "GET",
        "url": url,
        "headers": {"Accept": "application/json"},
        "body_sha256": "",
        "occurrence": 1,
        "timeout_seconds": 2.0,
        "max_redirects": 0,
        "max_response_bytes": 1024 * 1024,
        "delay_seconds": 0.0,
    }
    need.update(overrides)
    return need


def _managed(monkeypatch: pytest.MonkeyPatch, *, allow_public_registries: bool) -> None:
    state = SimpleNamespace(
        policy=SimpleNamespace(network=ManagedNetworkPolicy(allow_public_registries=allow_public_registries))
    )
    monkeypatch.setattr(network_transport, "load_managed_policy", lambda: state)


def _unmanaged(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(network_transport, "load_managed_policy", lambda: SimpleNamespace(policy=None))


def _forbid_network(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    reached: list[str] = []

    def refuse(*args: object, **kwargs: object) -> object:
        reached.append(repr(args[:1]))
        raise AssertionError("the network must not be reached")

    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr("urllib.request.urlopen", refuse)
    monkeypatch.setattr("urllib.request.OpenerDirector.open", refuse)
    return reached


@pytest.mark.parametrize(
    "url",
    ["https://registry.npmjs.org/left-pad", "https://pypi.org/pypi/requests/json", "https://files.pythonhosted.org/x"],
)
def test_managed_host_without_public_registries_never_reaches_them(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, url: str
) -> None:
    _managed(monkeypatch, allow_public_registries=False)
    reached = _forbid_network(monkeypatch)
    exchanger = egress.EgressExchanger(tmp_path)
    exchanger.fulfil({"needs": [_need(url)]})
    outcome = exchanger.supplied[0]["outcome"]
    assert outcome == {"kind": "blocked", "code": "managed_public_registry_disabled"}
    assert reached == []


def test_managed_host_without_public_registries_refuses_the_archive_download(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _managed(monkeypatch, allow_public_registries=False)
    reached = _forbid_network(monkeypatch)
    monkeypatch.setattr(
        egress,
        "download_restricted_archive",
        lambda *_a, **_k: pytest.fail("the archive must not be fetched"),
    )
    exchanger = egress.EgressExchanger(tmp_path)
    exchanger.fulfil({"needs": [_need("https://files.pythonhosted.org/a.tgz", klass="archive")]})
    outcome = exchanger.supplied[0]["outcome"]
    assert isinstance(outcome, dict)
    assert outcome["kind"] == "archive_failure"
    assert outcome["code"] == "managed_public_registry_disabled"
    assert reached == []


class _Proxy(http.server.BaseHTTPRequestHandler):
    seen: ClassVar[list[str]] = []

    def do_GET(self) -> None:
        _Proxy.seen.append(self.path)
        body = b'{"versions":{"1.0.0":{}}}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: object) -> None:
        return


def test_unmanaged_host_behind_an_environment_proxy_still_works(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _unmanaged(monkeypatch)
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Proxy)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    _Proxy.seen.clear()
    for name in ("no_proxy", "NO_PROXY", "https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY"):
        monkeypatch.delenv(name, raising=False)
    proxy = f"http://127.0.0.1:{server.server_address[1]}"
    monkeypatch.setenv("http_proxy", proxy)
    monkeypatch.setenv("HTTP_PROXY", proxy)
    try:
        exchanger = egress.EgressExchanger(tmp_path)
        exchanger.fulfil({"needs": [_need("http://registry.example.test/left-pad")]})
    finally:
        server.shutdown()
        server.server_close()
    outcome = exchanger.supplied[0]["outcome"]
    assert outcome == {
        "kind": "response",
        "status": 200,
        "headers": outcome["headers"],  # type: ignore[index]
        "body": '{"versions":{"1.0.0":{}}}',
    }
    # The request went to the proxy in absolute form, not straight to the host.
    assert _Proxy.seen == ["http://registry.example.test/left-pad"]


def test_unreachable_host_is_an_error_outcome_not_an_exception(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _unmanaged(monkeypatch)
    for name in ("http_proxy", "HTTP_PROXY", "no_proxy", "NO_PROXY"):
        monkeypatch.delenv(name, raising=False)
    exchanger = egress.EgressExchanger(tmp_path)
    exchanger.fulfil({"needs": [_need("http://127.0.0.1:1/x", timeout_seconds=1.0)]})
    assert exchanger.supplied[0]["outcome"]["kind"] in {"error", "timeout"}  # type: ignore[index]


def test_large_bodies_are_spooled_with_private_file_and_small_ones_inline(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _unmanaged(monkeypatch)
    big = b"x" * (egress.INLINE_BODY_MAX_BYTES + 1)
    exchanger = egress.EgressExchanger(tmp_path)
    small_outcome = exchanger._response_outcome(200, [("A", "b")], b"{}", 1024)
    big_outcome = exchanger._response_outcome(200, [], big, 1 << 20)
    assert small_outcome["body"] == "{}"
    assert "body" not in big_outcome
    name = big_outcome["body_file"]
    assert isinstance(name, str)
    spooled = tmp_path / name
    assert spooled.read_bytes() == big
    assert spooled.stat().st_mode & 0o777 == 0o600
    over = exchanger._response_outcome(200, [], b"yy", 1)
    assert over == {"kind": "error", "message": "response too large"}


def test_inline_budget_keeps_the_request_under_the_transport_cap(tmp_path: Path) -> None:
    exchanger = egress.EgressExchanger(tmp_path)
    body = b"z" * egress.INLINE_BODY_MAX_BYTES
    outcomes = [exchanger._response_outcome(200, [], body, 1 << 20) for _ in range(8)]
    inline = sum(len(str(o.get("body", ""))) for o in outcomes)
    assert inline <= egress.INLINE_BUDGET_BYTES
    assert any("body_file" in o for o in outcomes)


@pytest.mark.parametrize(
    "payload",
    [
        None,
        {},
        {"needs": []},
        {"needs": [_need("https://x/", klass="other")]},
        {"needs": [_need("https://x/", method="DELETE")]},
        {"needs": [_need("https://x/", timeout_seconds=0)]},
        {"needs": [_need("https://x/", max_response_bytes=10**12)]},
        {"needs": [_need("https://x/")] * 17},
        {"needs": [{**_need("https://x/"), "extra": 1}]},
        {"needs": [_need("https://x/", headers={"a": 1})]},
    ],
)
def test_malformed_needs_are_rejected(payload: object, tmp_path: Path) -> None:
    with pytest.raises(egress.EgressProtocolError):
        egress.EgressExchanger(tmp_path).fulfil(payload)


def test_non_http_scheme_is_blocked(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _unmanaged(monkeypatch)
    exchanger = egress.EgressExchanger(tmp_path)
    exchanger.fulfil({"needs": [_need("file:///etc/passwd")]})
    assert exchanger.supplied[0]["outcome"] == {"kind": "blocked", "code": "egress_scheme_not_allowed"}


def test_archive_failure_from_the_restricted_downloader_is_carried_back(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _unmanaged(monkeypatch)
    monkeypatch.setattr(
        egress,
        "download_restricted_archive",
        lambda *_a, **_k: RestrictedArchiveFailure(code="external_archive_http_error", message="nope"),
    )
    exchanger = egress.EgressExchanger(tmp_path)
    exchanger.fulfil({"needs": [_need("https://example.com/a.tgz", klass="archive", max_redirects=3)]})
    assert exchanger.supplied[0]["outcome"] == {
        "kind": "archive_failure",
        "code": "external_archive_http_error",
        "message": "nope",
    }


class _Artifact:
    artifact_id = "package:npm:left-pad"
    runtime_private_metadata: ClassVar[dict[str, object]] = {}

    def to_dict(self) -> dict[str, object]:
        return {"artifact_id": self.artifact_id}


def _ok_payload() -> dict[str, object]:
    return {
        "decision": "allow",
        "policy_action": "allow",
        "enforcement": "free_local",
        "entitlement_state": "free",
        "cache_status": "miss",
        "package_intent_hash": "sha256:" + "0" * 64,
        "policy_version": "p",
        "reasons": [],
        "packages": [],
        "risk_summary": "ok",
        "user_copy": {"title": "Allowed", "summary": "ok", "harness_message": "ok"},
    }


def _script(monkeypatch: pytest.MonkeyPatch, answers: list[tuple[str, object]]) -> list[dict[str, object]]:
    requests: list[dict[str, object]] = []
    monkeypatch.setattr(transport, "ensure_resident_prerequisite", lambda _home: True)

    def resident(**kwargs: object) -> object:
        request = kwargs["request"]
        assert isinstance(request, dict)
        requests.append(dict(request))
        code, payload = answers[min(len(requests), len(answers)) - 1]
        return {
            "schema": _RESULT_SCHEMA,
            "request_id": request["request_id"],
            "request_sha256": "sha256:" + _canonical_request_sha256(request),
            "status": "ok",
            "code": code,
            "payload": payload,
        }

    monkeypatch.setattr(transport, "_resident_request", resident)
    return requests


def _payload_for(tmp_path: Path):
    return transport.native_supply_chain_eval_payload(
        artifact=_Artifact(),  # type: ignore[arg-type]
        store_path=tmp_path / "guard.db",
        guard_home=tmp_path,
        workspace_dir=None,
        now=None,
        external_archive_network_authorized=False,
    )


def test_rounds_replay_the_request_with_the_supplied_outcomes(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _unmanaged(monkeypatch)
    url = "https://registry.npmjs.org/left-pad"
    performed: list[str] = []

    def fake_urlopen(request: object, **_kwargs: object) -> object:
        performed.append(request.full_url)  # type: ignore[attr-defined]
        raise network_transport.ManagedNetworkError("managed_public_registry_disabled")

    monkeypatch.setattr(egress, "managed_urlopen", fake_urlopen)
    requests = _script(
        monkeypatch,
        [(egress.EGRESS_REQUIRED_CODE, {"needs": [_need(url)]}), ("ok", _ok_payload())],
    )
    assert _payload_for(tmp_path)["decision"] == "allow"
    assert performed == [url]
    assert len(requests) == 2
    assert "egress_supplied" not in requests[0]
    second = requests[1]
    assert second["egress_supplied"] == [
        {
            "class": "registry",
            "method": "GET",
            "url": url,
            "body_sha256": "",
            "occurrence": 1,
            "outcome": {"kind": "blocked", "code": "managed_public_registry_disabled"},
        }
    ]
    assert isinstance(second["egress_spool_dir"], str)
    assert not Path(str(second["egress_spool_dir"])).exists(), "the spool directory is removed afterwards"
    assert isinstance(second["now"], str)


def test_every_round_uses_one_fixed_clock(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _unmanaged(monkeypatch)
    monkeypatch.setattr(
        egress,
        "managed_urlopen",
        lambda *_a, **_k: (_ for _ in ()).throw(network_transport.ManagedNetworkError("x")),
    )
    needs = {"needs": [_need("https://registry.npmjs.org/a")]}
    more = {"needs": [_need("https://registry.npmjs.org/b")]}
    requests = _script(
        monkeypatch,
        [(egress.EGRESS_REQUIRED_CODE, needs), (egress.EGRESS_REQUIRED_CODE, more), ("ok", _ok_payload())],
    )
    _payload_for(tmp_path)
    assert len(requests) == 3
    assert requests[1]["now"] == requests[2]["now"]
    assert len(requests[2]["egress_supplied"]) == 2  # type: ignore[arg-type]


def test_a_resident_that_never_settles_is_a_bounded_block(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _unmanaged(monkeypatch)
    monkeypatch.setattr(
        egress,
        "managed_urlopen",
        lambda *_a, **_k: (_ for _ in ()).throw(network_transport.ManagedNetworkError("x")),
    )
    failures: list[object] = []
    monkeypatch.setattr(transport, "_record_unbound_answer", lambda home: failures.append(home))
    requests = _script(
        monkeypatch,
        [(egress.EGRESS_REQUIRED_CODE, {"needs": [_need("https://registry.npmjs.org/a", occurrence=1)]})],
    )
    with pytest.raises(transport.NativeSupplyChainEvalError):
        _payload_for(tmp_path)
    assert len(requests) <= transport._MAX_ROUNDS + 1
    assert len(failures) == 1


def test_malformed_egress_answer_records_one_failure_and_blocks(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    failures: list[object] = []
    monkeypatch.setattr(transport, "_record_unbound_answer", lambda home: failures.append(home))
    _script(monkeypatch, [(egress.EGRESS_REQUIRED_CODE, {"needs": [{"class": "registry"}]})])
    with pytest.raises(transport.NativeSupplyChainEvalError):
        _payload_for(tmp_path)
    assert len(failures) == 1
