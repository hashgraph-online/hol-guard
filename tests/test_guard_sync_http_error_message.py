import io
import json
import urllib.error
import urllib.request

import pytest

from codex_plugin_scanner.guard.runtime.runner import (
    GuardSyncNotAvailableError,
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
    slept: list[int] = []
    cloudflare_body = json.dumps(
        {
            "status": 502,
            "cloudflare_error": True,
            "retryable": True,
            "retry_after": 60,
        }
    )

    def _urlopen(_request: urllib.request.Request, timeout: int) -> _JsonResponse:
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
    monkeypatch.setattr("codex_plugin_scanner.guard.runtime.runner.time.sleep", slept.append)

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
    slept: list[int] = []

    def _urlopen(_request: urllib.request.Request, timeout: int) -> _EmptyResponse:
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
    monkeypatch.setattr("codex_plugin_scanner.guard.runtime.runner.time.sleep", slept.append)

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
