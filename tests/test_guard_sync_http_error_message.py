import io
import json
import urllib.error
import urllib.request

import pytest

from codex_plugin_scanner.guard.runtime.runner import (
    GuardSyncNotAvailableError,
    _fetch_supply_chain_bundle_payload,
    _sync_http_error_message,
)


def _http_error(body: str, *, code: int = 500, reason: str = "Error") -> urllib.error.HTTPError:
    return urllib.error.HTTPError(
        url="https://hol.org/api/guard/insights/shares",
        code=code,
        msg=reason,
        hdrs={},
        fp=io.BytesIO(body.encode("utf-8")),
    )


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
    assert (
        _sync_http_error_message(_http_error(body))
        == "Guard insights sharing is not live on Guard Cloud yet."
    )


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
