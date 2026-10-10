"""Brokered network egress for resident package evaluation.

The resident cannot dial out, so Python performs the exchanges it asks for under
the managed network policy. These tests pin that policy: a managed host that
disallows public registries must never reach them, and an unmanaged host behind
an environment proxy must keep working. The resident side is covered by the
Rust crate; here the resident is replaced by a scripted fake.
"""

from __future__ import annotations

import http.server
import io
import json
import socket
import threading
import urllib.error
from pathlib import Path
from types import SimpleNamespace
from typing import ClassVar

import pytest

from codex_plugin_scanner.guard import native_supply_chain_archive as archive_module
from codex_plugin_scanner.guard import native_supply_chain_egress as egress
from codex_plugin_scanner.guard import native_supply_chain_eval as transport
from codex_plugin_scanner.guard.mdm import network_transport
from codex_plugin_scanner.guard.mdm.contracts import ManagedNetworkPolicy
from codex_plugin_scanner.guard.native_context import _canonical_request_sha256
from codex_plugin_scanner.guard.native_package_authority import _RESULT_SCHEMA
from codex_plugin_scanner.guard.runtime.restricted_archive_contract import RestrictedArchiveFailure


def _exchanger(tmp_path: Path) -> egress.EgressExchanger:
    return egress.EgressExchanger(
        tmp_path, archive_module.ArchiveFulfilment(guard_home=tmp_path, scratch_dir=tmp_path, retain=False)
    )


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
    exchanger = _exchanger(tmp_path)
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
        archive_module,
        "download_restricted_archive",
        lambda *_a, **_k: pytest.fail("the archive must not be fetched"),
    )
    exchanger = _exchanger(tmp_path)
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
        exchanger = _exchanger(tmp_path)
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
    exchanger = _exchanger(tmp_path)
    exchanger.fulfil({"needs": [_need("http://127.0.0.1:1/x", timeout_seconds=1.0)]})
    assert exchanger.supplied[0]["outcome"]["kind"] in {"error", "timeout"}  # type: ignore[index]


def test_large_bodies_are_spooled_with_private_file_and_small_ones_inline(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _unmanaged(monkeypatch)
    big = b"x" * (egress.INLINE_BODY_MAX_BYTES + 1)
    exchanger = _exchanger(tmp_path)
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
    exchanger = _exchanger(tmp_path)
    body = b"z" * egress.INLINE_BODY_MAX_BYTES
    outcomes = [exchanger._response_outcome(200, [], body, 1 << 20) for _ in range(8)]
    inline = sum(len(str(o.get("body", ""))) for o in outcomes)
    assert inline <= egress.INLINE_BUDGET_BYTES
    assert any("body_file" in o for o in outcomes)


def test_a_command_with_many_ranged_packages_is_not_capped_at_sixty_four_exchanges(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _unmanaged(monkeypatch)
    exchanger = _exchanger(tmp_path)
    monkeypatch.setattr(exchanger, "_answer", lambda need: {"url": need["url"], "outcome": {"kind": "timeout"}})
    for start in range(0, 100, egress.MAX_NEEDS):
        exchanger.fulfil({"needs": [_need(f"https://registry.npmjs.org/p{n}") for n in range(start, start + 16)]})
    assert len(exchanger.supplied) == 112
    # The cap is real, not absent: the resident refuses more than it can replay.
    while len(exchanger.supplied) < egress.MAX_SUPPLIED:
        exchanger.supplied.append({})
    with pytest.raises(egress.EgressProtocolError):
        exchanger.fulfil({"needs": [_need("https://registry.npmjs.org/one-too-many")]})


def test_a_full_set_of_replayed_registry_outcomes_fits_the_request_cap(tmp_path: Path) -> None:
    exchanger = _exchanger(tmp_path)
    headers = [(f"X-Registry-Header-{index}", "v" * 40) for index in range(12)]
    body = b"{" + b" " * (egress.INLINE_BODY_MAX_BYTES + 1) + b"}"
    for index in range(egress.MAX_SUPPLIED):
        outcome = exchanger._response_outcome(200, headers, body, 1 << 20)
        exchanger.supplied.append(
            {
                "class": "registry",
                "method": "GET",
                "url": f"https://registry.npmjs.org/some-scoped-package-name-{index}",
                "body_sha256": "",
                "occurrence": 1,
                "outcome": outcome,
            }
        )
    encoded = len(json.dumps({"egress_supplied": exchanger.supplied}).encode("utf-8"))
    # A full replay overflows the generic package-authority cap, so the eval op raises its own;
    # it must still leave headroom under the native 6 MiB frame cap.
    assert encoded > 256 * 1024
    assert encoded + 512 * 1024 < transport._EVAL_MAX_REQUEST_BYTES
    assert transport._EVAL_MAX_REQUEST_BYTES < 6 * 1024 * 1024


class _Trickle:
    """A body that never stalls a single read but never finishes either."""

    def __init__(self, clock: list[float]) -> None:
        self.clock = clock

    def read(self, size: int) -> bytes:
        self.clock[0] += 5.0  # every read lands just inside the per-read timeout
        return b"x"


def test_a_peer_that_keeps_every_read_inside_the_timeout_still_hits_the_exchange_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = [1000.0]
    monkeypatch.setattr(egress.time, "monotonic", lambda: clock[0])
    deadline = clock[0] + egress.MAX_EXCHANGE_SECONDS
    with pytest.raises(TimeoutError):
        egress._read_bounded(_Trickle(clock), 1 << 30, deadline)
    assert clock[0] - 1000.0 <= egress.MAX_EXCHANGE_SECONDS + 5.0


def test_registry_documents_above_the_ten_megabyte_library_default_are_spooled_whole(tmp_path: Path) -> None:
    exchanger = _exchanger(tmp_path)
    limit = 32 * 1024 * 1024
    body = b'{"versions":{}}' + b" " * (26 * 1024 * 1024)  # about the size of the abbreviated npm document for `next`

    class _Reader:
        def __init__(self, data: bytes) -> None:
            self.data, self.at = data, 0

        def read(self, size: int) -> bytes:
            chunk = self.data[self.at : self.at + size]
            self.at += len(chunk)
            return chunk

    read = egress._read_bounded(_Reader(body), limit, float("inf"))
    assert read == body
    outcome = exchanger._response_outcome(200, [], read, limit)
    assert (tmp_path / str(outcome["body_file"])).stat().st_size == len(body)
    assert exchanger._response_outcome(200, [], b"x" * (limit + 1), limit) == {
        "kind": "error",
        "message": "response too large",
    }


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
        _exchanger(tmp_path).fulfil(payload)


def test_non_http_scheme_is_blocked(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _unmanaged(monkeypatch)
    exchanger = _exchanger(tmp_path)
    exchanger.fulfil({"needs": [_need("file:///etc/passwd")]})
    assert exchanger.supplied[0]["outcome"] == {"kind": "blocked", "code": "egress_scheme_not_allowed"}


def _redirecting_urlopen(
    performed: list[str], routes: dict[str, str], *, final: str = "https://example.com/final"
) -> object:
    """Mimic the managed transport: validate every hop, answer 302 per route, never follow."""

    def fake_urlopen(request: object, **kwargs: object) -> object:
        url = request.full_url  # type: ignore[attr-defined]
        assert kwargs["allow_redirects"] is False
        resolved, _managed_policy = network_transport.resolved_network_policy(None)
        network_transport.validate_destination(url, resolved)
        performed.append(url)
        if url in routes:
            raise urllib.error.HTTPError(url, 302, "Found", {"Location": routes[url]}, io.BytesIO(b""))  # type: ignore[arg-type]
        assert url == final
        raise urllib.error.HTTPError(url, 200, "OK", {}, io.BytesIO(b"{}"))  # type: ignore[arg-type]

    return fake_urlopen


def test_a_redirect_to_a_disallowed_host_is_blocked_before_it_is_requested(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _managed(monkeypatch, allow_public_registries=False)
    performed: list[str] = []
    start = "https://mirror.example.com/pkg"
    routes = {start: "https://registry.npmjs.org/pkg"}
    monkeypatch.setattr(egress, "managed_urlopen", _redirecting_urlopen(performed, routes))
    exchanger = _exchanger(tmp_path)
    exchanger.fulfil({"needs": [_need(start, max_redirects=3)]})
    assert performed == [start]
    assert exchanger.supplied[0]["outcome"] == {"kind": "blocked", "code": "managed_public_registry_disabled"}


def test_redirects_are_counted_against_the_exact_limit(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _unmanaged(monkeypatch)
    performed: list[str] = []
    routes = {f"https://example.com/{i}": f"https://example.com/{i + 1}" for i in range(5)}
    monkeypatch.setattr(egress, "managed_urlopen", _redirecting_urlopen(performed, routes))
    exchanger = _exchanger(tmp_path)
    exchanger.fulfil({"needs": [_need("https://example.com/0", max_redirects=2)]})
    assert performed == ["https://example.com/0", "https://example.com/1", "https://example.com/2"]
    assert exchanger.supplied[0]["outcome"] == {"kind": "error", "message": "too many redirects"}


def test_a_redirect_within_the_limit_is_followed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _unmanaged(monkeypatch)
    performed: list[str] = []
    routes = {"https://example.com/a": "/final"}
    monkeypatch.setattr(egress, "managed_urlopen", _redirecting_urlopen(performed, routes))
    exchanger = _exchanger(tmp_path)
    exchanger.fulfil({"needs": [_need("https://example.com/a", max_redirects=1)]})
    assert performed == ["https://example.com/a", "https://example.com/final"]
    assert exchanger.supplied[0]["outcome"]["kind"] == "response"  # type: ignore[index]


@pytest.mark.parametrize("target", ["http://example.com/plain", "file:///etc/passwd", "ftp://example.com/x"])
def test_a_redirect_that_downgrades_or_leaves_http_is_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, target: str
) -> None:
    _unmanaged(monkeypatch)
    performed: list[str] = []
    monkeypatch.setattr(egress, "managed_urlopen", _redirecting_urlopen(performed, {"https://example.com/a": target}))
    exchanger = _exchanger(tmp_path)
    exchanger.fulfil({"needs": [_need("https://example.com/a", max_redirects=3)]})
    assert performed == ["https://example.com/a"]
    assert exchanger.supplied[0]["outcome"] == {"kind": "blocked", "code": "egress_redirect_not_allowed"}


def test_a_credentialed_request_never_follows_a_redirect(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _unmanaged(monkeypatch)
    performed: list[str] = []
    routes = {"https://example.com/a": "https://example.com/final"}
    monkeypatch.setattr(egress, "managed_urlopen", _redirecting_urlopen(performed, routes))
    exchanger = _exchanger(tmp_path)
    need = _need("https://example.com/a", max_redirects=3, headers={"Authorization": "Bearer t"})
    exchanger.fulfil({"needs": [need]})
    assert performed == ["https://example.com/a"]
    assert exchanger.supplied[0]["outcome"]["status"] == 302  # type: ignore[index]


def test_archive_failure_from_the_restricted_downloader_is_carried_back(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _unmanaged(monkeypatch)
    monkeypatch.setattr(
        archive_module,
        "download_restricted_archive",
        lambda *_a, **_k: RestrictedArchiveFailure(code="external_archive_http_error", message="nope"),
    )
    exchanger = _exchanger(tmp_path)
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
    assert len(requests) == transport._MAX_ROUNDS + 1
    assert len(failures) == 1


def test_a_verdict_reached_on_the_last_allowed_round_is_not_discarded(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _unmanaged(monkeypatch)
    monkeypatch.setattr(
        egress,
        "managed_urlopen",
        lambda *_a, **_k: (_ for _ in ()).throw(network_transport.ManagedNetworkError("x")),
    )
    failures: list[object] = []
    monkeypatch.setattr(transport, "_record_unbound_answer", lambda home: failures.append(home))
    needs = (egress.EGRESS_REQUIRED_CODE, {"needs": [_need("https://registry.npmjs.org/a", occurrence=1)]})
    requests = _script(monkeypatch, [needs] * transport._MAX_ROUNDS + [("ok", _ok_payload())])
    assert _payload_for(tmp_path)
    assert len(requests) == transport._MAX_ROUNDS + 1
    assert failures == []


def test_malformed_egress_answer_records_one_failure_and_blocks(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    failures: list[object] = []
    monkeypatch.setattr(transport, "_record_unbound_answer", lambda home: failures.append(home))
    _script(monkeypatch, [(egress.EGRESS_REQUIRED_CODE, {"needs": [{"class": "registry"}]})])
    with pytest.raises(transport.NativeSupplyChainEvalError):
        _payload_for(tmp_path)
    assert len(failures) == 1
