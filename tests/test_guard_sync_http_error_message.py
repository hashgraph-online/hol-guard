import io
import json
import urllib.error

from codex_plugin_scanner.guard.runtime.runner import _sync_http_error_message


def test_sync_http_error_message_reads_guard_cloud_err_field() -> None:
    body = json.dumps(
        {
            "ok": False,
            "err": "Guard insights sharing is not live on Guard Cloud yet.",
        }
    )
    error = urllib.error.HTTPError(
        url="https://hol.org/api/guard/insights/shares",
        code=503,
        msg="Service Unavailable",
        hdrs={},
        fp=io.BytesIO(body.encode("utf-8")),
    )
    assert (
        _sync_http_error_message(error)
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
    error = urllib.error.HTTPError(
        url="https://hol.org/api/guard/insights/shares",
        code=524,
        msg="Gateway Timeout",
        hdrs={},
        fp=io.BytesIO(body.encode("utf-8")),
    )
    assert (
        _sync_http_error_message(error)
        == "Guard Cloud timed out. Local Guard keeps protecting this machine."
    )
