"""Carry the runtime session upload over urllib in unit tests.

The native ``cloud-event-sync`` command posts the runtime session itself, so a
test that fakes ``urllib`` or ``runner._urlopen_json_with_timeout_retry`` would
otherwise never see that request. Most such tests check what the runner does
with Cloud's answer (the catalog step, the summary, the queued event), not the
upload. This double sends the same request through the Python transport those
tests already fake and answers in the native command's shape.

The native upload itself (DPoP nonce retry, timeout retry, 404 and 429 skips)
is tested in ``rust/crates/guard-runtime/src/cloud_runtime_session_sync.rs``
and ``tests/test_cloud_event_sync_shim.py``; mark a test
``native_runtime_session`` to run the real command.
"""

from __future__ import annotations

import json
import urllib.error
from collections.abc import Callable, Mapping
from pathlib import Path

_SKIP_REASONS = {
    404: "runtime_session_endpoint_unavailable",
    429: "runtime_session_rate_limited",
}


def runtime_session_over_urllib(original: Callable[..., object]) -> Callable[..., object]:
    """Wrap ``cloud_event_sync`` so only ``runtime_session`` takes the Python route."""

    def cloud_event_sync(
        guard_home: Path,
        action: str,
        *,
        auth_context: Mapping[str, object] | None = None,
        session: Mapping[str, object] | None = None,
    ) -> object:
        if action != "runtime_session" or session is None or auth_context is None:
            return original(guard_home, action, auth_context=auth_context, session=session)
        return _post_runtime_session(Path(guard_home), dict(auth_context), dict(session))

    return cloud_event_sync


def _post_runtime_session(guard_home: Path, auth_context: dict[str, object], session: dict[str, object]) -> object:
    from codex_plugin_scanner.guard.runtime import runner
    from codex_plugin_scanner.guard.store import GuardStore

    url = runner._sync.normalized_runtime_sessions_sync_url(
        runner._validate_guard_sync_url(runner._auth_context_sync_url(auth_context))
    )
    request = runner._guard_sync_request(
        auth_context,
        request_url=url,
        method="POST",
        data=json.dumps({"session": session}).encode("utf-8"),
        extra_headers=None,
    )
    try:
        payload = runner._urlopen_json_with_timeout_retry(
            request=request,
            timeout_seconds=runner._RUNTIME_SYNC_TIMEOUT_SECONDS,
            retry_timeout_seconds=runner._RUNTIME_SYNC_RETRY_TIMEOUT_SECONDS,
        )
    except urllib.error.HTTPError as error:
        reason = _SKIP_REASONS.get(error.code)
        if reason is None:
            raise RuntimeError(runner._sync_http_error_message(error)) from error
        recorded_at = runner._now()
        summary: dict[str, object] = {
            "synced_at": None,
            "runtime_session_synced_at": None,
            "runtime_session_id": session.get("sessionId"),
            "runtime_sessions_visible": 0,
            "runtime_session_sync_skipped": True,
            "runtime_session_sync_reason": reason,
            "local_guard_online_at": recorded_at,
            "runtime_harness": session.get("harness"),
            "runtime_surface": session.get("surface"),
            "runtime_workspace": session.get("workspace"),
            "runtime_device_id": session.get("deviceId"),
        }
        if error.code == 429:
            summary["retry_after_seconds"] = runner._parse_retry_after_header(error)
        GuardStore(guard_home).set_sync_payload("runtime_session_summary", summary, recorded_at)
        return {"status": "skipped", "summary": summary}
    except OSError as error:
        raise RuntimeError(runner._sync_url_error_message(error)) from error
    return {"status": "synced", "response": payload}
