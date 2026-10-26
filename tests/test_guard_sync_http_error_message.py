import errno
import io
import json
import socket
import ssl
import threading
import time
import urllib.error
import urllib.request

import pytest

from codex_plugin_scanner.guard.runtime.runner import (
    GuardSyncNotAvailableError,
    _check_plan_restriction_403,
    _cloud_edge_block_from_http_error,
    _fetch_supply_chain_bundle_payload,
    _sync_http_error_message,
    _urlopen_json_with_timeout_retry,
    _urlopen_with_timeout_retry,
)


def _http_error(body: str, *, code: int = 500, reason: str = "Error") -> urllib.error.HTTPError:
    return urllib.error.HTTPError(
        url="https://hol.org/api/guard/insights/shares",
        code=code,
        msg=reason,
        hdrs={},
        fp=io.BytesIO(body.encode("utf-8")),
    )


def _record_sleeps(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """Record the retry waits this thread makes.

    `runner.time` is the shared `time` module, so a thread another test left
    running sleeps through the same patch. Its sleeps stay real and unrecorded.
    """
    slept: list[float] = []
    real_sleep = time.sleep
    caller = threading.get_ident()

    def sleep(seconds: float) -> None:
        if threading.get_ident() == caller:
            slept.append(seconds)
        else:
            real_sleep(seconds)

    monkeypatch.setattr("codex_plugin_scanner.guard.runtime.runner.time.sleep", sleep)
    return slept


class _JsonResponse:
    def __init__(self, payload: dict[str, object] | None = None) -> None:
        self.payload = payload or {"ok": True}

    def __enter__(self) -> "_JsonResponse":
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self) -> bytes:
        return json.dumps(self.payload).encode("utf-8")


class _EmptyResponse:
    def __enter__(self) -> "_EmptyResponse":
        return self

    def __exit__(self, *_args: object) -> None:
        return None


def test_sync_http_error_message_reads_guard_cloud_err_field() -> None:
    body = json.dumps(
        {
            "ok": False,
            "err": "Guard insights sharing is not live on Guard Cloud yet.",
        }
    )
    assert (
        _sync_http_error_message(_http_error(body, code=503, reason="Service Unavailable"))
        == "Guard insights sharing is not live on Guard Cloud yet."
    )


def test_sync_http_error_message_prefers_guard_error_msg_over_top_level_error() -> None:
    body = json.dumps(
        {
            "ok": False,
            "error": "insights_share_failed",
            "guardError": {
                "code": "guard_insights_share_unavailable",
                "msg": "Guard insights sharing is not live on Guard Cloud yet.",
            },
        }
    )
    assert _sync_http_error_message(_http_error(body)) == "Guard insights sharing is not live on Guard Cloud yet."


def test_sync_http_error_message_reads_guard_error_msg_field() -> None:
    body = json.dumps(
        {
            "ok": False,
            "guardError": {
                "code": "guard_unavailable",
                "msg": "Guard Cloud timed out. Local Guard keeps protecting this machine.",
            },
        }
    )
    assert (
        _sync_http_error_message(_http_error(body, code=524, reason="Gateway Timeout"))
        == "Guard Cloud timed out. Local Guard keeps protecting this machine."
    )


def test_sync_http_error_message_reads_legacy_error_field() -> None:
    body = json.dumps({"error": "Invalid Guard insights share payload."})
    assert _sync_http_error_message(_http_error(body, code=400)) == "Invalid Guard insights share payload."


def test_sync_http_error_message_falls_back_to_raw_body() -> None:
    body = "upstream unavailable"
    assert _sync_http_error_message(_http_error(body)) == "upstream unavailable"


def test_sync_http_error_message_falls_back_to_http_reason() -> None:
    assert _sync_http_error_message(_http_error("", code=502, reason="Bad Gateway")) == "HTTP Error 502: Bad Gateway"


def test_urlopen_json_retries_cloudflare_502_with_default_retry_after(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempts = 0
    cloudflare_body = json.dumps(
        {
            "status": 502,
            "cloudflare_error": True,
            "retryable": True,
            "retry_after": 60,
        }
    )

    def _urlopen(_request: urllib.request.Request, timeout: int, *, context=None) -> _JsonResponse:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise urllib.error.HTTPError(
                url="https://hol.org/api/guard/receipts/sync",
                code=502,
                msg="Bad Gateway",
                hdrs={},
                fp=io.BytesIO(cloudflare_body.encode("utf-8")),
            )
        return _JsonResponse({"syncedAt": "2026-06-30T21:02:46Z"})

    monkeypatch.setattr("codex_plugin_scanner.guard.runtime.runner.urllib.request.urlopen", _urlopen)
    slept = _record_sleeps(monkeypatch)

    payload = _urlopen_json_with_timeout_retry(
        request=urllib.request.Request("https://hol.org/api/guard/receipts/sync", data=b"{}"),
        timeout_seconds=20,
        retry_timeout_seconds=120,
    )

    assert payload == {"syncedAt": "2026-06-30T21:02:46Z"}
    assert attempts == 2
    assert slept == [60]


def test_urlopen_retries_cloudflare_524_with_retry_after_header(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempts = 0

    def _urlopen(_request: urllib.request.Request, timeout: int, *, context=None) -> _EmptyResponse:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise urllib.error.HTTPError(
                url="https://hol.org/api/guard/receipts/sync",
                code=524,
                msg="A Timeout Occurred",
                hdrs={"Retry-After": "5"},
                fp=io.BytesIO(b""),
            )
        return _EmptyResponse()

    monkeypatch.setattr("codex_plugin_scanner.guard.runtime.runner.urllib.request.urlopen", _urlopen)
    slept = _record_sleeps(monkeypatch)

    _urlopen_with_timeout_retry(
        request=urllib.request.Request("https://hol.org/api/guard/receipts/sync", data=b"{}"),
        timeout_seconds=20,
        retry_timeout_seconds=120,
    )

    assert attempts == 2
    assert slept == [5]


def test_fetch_supply_chain_bundle_payload_raises_retryable_unavailable_on_guard_cloud_outage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    body = json.dumps(
        {
            "ok": False,
            "error": "Guard Cloud is unavailable. Local Guard keeps protecting this machine.",
            "guardError": {
                "code": "guard_unavailable",
                "message": "Guard Cloud is unavailable. Local Guard keeps protecting this machine.",
                "retryable": True,
                "status": 503,
            },
        }
    )

    def _raise_service_unavailable(*_args: object, **_kwargs: object) -> dict[str, object]:
        raise urllib.error.HTTPError(
            url="https://hol.org/api/guard/supply-chain/bundle?workspaceId=test",
            code=503,
            msg="Service Unavailable",
            hdrs={},
            fp=io.BytesIO(body.encode("utf-8")),
        )

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.runner._urlopen_json_with_timeout_retry",
        _raise_service_unavailable,
    )
    request = urllib.request.Request("https://hol.org/api/guard/supply-chain/bundle?workspaceId=test")
    with pytest.raises(GuardSyncNotAvailableError) as exc_info:
        _fetch_supply_chain_bundle_payload(request)
    assert exc_info.value.retryable is True
    assert "Guard Cloud is unavailable" in str(exc_info.value)


@pytest.mark.parametrize(
    "reason",
    [
        ConnectionRefusedError(61, "Connection refused"),
        ConnectionResetError(54, "Connection reset by peer"),
        socket.gaierror(8, "nodename nor servname provided, or not known"),
        OSError(errno.EHOSTUNREACH, "No route to host"),
        OSError(errno.ENETUNREACH, "Network is unreachable"),
        TimeoutError("timed out"),
    ],
)
def test_fetch_supply_chain_bundle_payload_reports_unreachable_guard_cloud_as_retryable(
    monkeypatch: pytest.MonkeyPatch,
    reason: OSError,
) -> None:
    def _raise_unreachable(*_args: object, **_kwargs: object) -> dict[str, object]:
        raise urllib.error.URLError(reason)

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.runner._urlopen_json_with_timeout_retry",
        _raise_unreachable,
    )
    request = urllib.request.Request("https://hol.org/api/guard/supply-chain/bundle?workspaceId=test")
    with pytest.raises(GuardSyncNotAvailableError) as exc_info:
        _fetch_supply_chain_bundle_payload(request)
    assert exc_info.value.retryable is True
    assert str(exc_info.value) == "Guard Cloud could not be reached. Local Guard keeps protecting this machine."
    assert "Errno" not in str(exc_info.value)


def test_fetch_supply_chain_bundle_payload_keeps_tls_failures_non_retryable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _raise_tls_failure(*_args: object, **_kwargs: object) -> dict[str, object]:
        raise urllib.error.URLError(ssl.SSLCertVerificationError(1, "certificate verify failed"))

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.runner._urlopen_json_with_timeout_retry",
        _raise_tls_failure,
    )
    request = urllib.request.Request("https://hol.org/api/guard/supply-chain/bundle?workspaceId=test")
    with pytest.raises(RuntimeError) as exc_info:
        _fetch_supply_chain_bundle_payload(request)
    assert not isinstance(exc_info.value, GuardSyncNotAvailableError)
    assert "certificate verify failed" in str(exc_info.value)


def _cloudflare_error(body: str, headers: dict[str, str], *, code: int = 403) -> urllib.error.HTTPError:
    from email.message import Message

    message = Message()
    for key, value in headers.items():
        message[key] = value
    return urllib.error.HTTPError(
        url="https://hol.org/api/guard/receipts/sync",
        code=code,
        msg="Forbidden",
        hdrs=message,
        fp=io.BytesIO(body.encode("utf-8")),
    )


def test_sync_http_error_message_names_a_cloudflare_block_instead_of_dumping_its_page() -> None:
    page = (
        "<!DOCTYPE html><html><head><title>Attention Required! | Cloudflare</title></head>"
        "<body><h1>Sorry, you have been blocked</h1></body></html>"
    )
    message = _sync_http_error_message(
        _cloudflare_error(
            page,
            {"Server": "cloudflare", "CF-RAY": "a4a17d23bec08abe-SJC", "Content-Type": "text/html; charset=UTF-8"},
        )
    )
    assert message.startswith("Guard Cloud is unreachable from this network")
    assert "blocked the request (HTTP 403, Ray ID a4a17d23bec08abe)" in message
    assert "reconnecting will not help" in message
    assert "<html" not in message


def test_sync_http_error_message_names_a_cloudflare_challenge() -> None:
    message = _sync_http_error_message(
        _cloudflare_error(
            "<html><head><title>Just a moment...</title></head></html>",
            {"Server": "cloudflare", "cf-mitigated": "challenge", "Content-Type": "text/html"},
        )
    )
    assert "challenged the request (HTTP 403)" in message
    assert "Ray ID" not in message


def test_sync_http_error_message_keeps_guard_cloud_answers_behind_cloudflare() -> None:
    message = _sync_http_error_message(
        _cloudflare_error(
            json.dumps({"error": "Guard sync requires a Pro plan."}),
            {"Server": "cloudflare", "CF-RAY": "abc123-SJC", "Content-Type": "application/json"},
        )
    )
    assert message == "Guard sync requires a Pro plan."


_CLOUDFLARE_BLOCK_PAGE = (
    "<!DOCTYPE html><html><head><title>Attention Required! | Cloudflare</title></head>"
    "<body><h1>Sorry, you have been blocked</h1></body></html>"
)
_CLOUDFLARE_HEADERS = {"Server": "cloudflare", "CF-RAY": "a4a17d23bec08abe-SJC", "Content-Type": "text/html"}


def test_receipt_sync_403_reports_a_cloudflare_block_not_its_page() -> None:
    # sync_receipts routes 403s through the plan-restriction check, not _sync_http_error_message.
    is_plan, message = _check_plan_restriction_403(_cloudflare_error(_CLOUDFLARE_BLOCK_PAGE, _CLOUDFLARE_HEADERS))
    assert is_plan is False
    assert message.startswith("Guard Cloud is unreachable from this network")
    assert "Ray ID a4a17d23bec08abe" in message
    assert "<html" not in message


def test_receipt_sync_403_still_detects_a_plan_restriction_behind_cloudflare() -> None:
    body = json.dumps({"syncEnabled": False, "error": "Guard sync requires a Pro plan."})
    is_plan, message = _check_plan_restriction_403(
        _cloudflare_error(body, {"Server": "cloudflare", "CF-RAY": "abc123-SJC", "Content-Type": "application/json"})
    )
    assert (is_plan, message) == (True, "Guard sync requires a Pro plan.")


def test_receipt_sync_401_from_cloudflare_is_not_an_expired_sign_in() -> None:
    edge = _cloud_edge_block_from_http_error(_cloudflare_error(_CLOUDFLARE_BLOCK_PAGE, _CLOUDFLARE_HEADERS, code=401))
    assert edge is not None and "blocked the request (HTTP 401" in edge
    assert (
        _cloud_edge_block_from_http_error(_cloudflare_error("", {"Content-Type": "application/json"}, code=401)) is None
    )
