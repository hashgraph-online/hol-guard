"""HGP-178: exact transport never falls through to generic command authority."""

from __future__ import annotations

import io
import urllib.error
from email.message import Message
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.exact_cloud_review import EXACT_CLOUD_REVIEW_OPERATION
from codex_plugin_scanner.guard.runtime.exact_cloud_review_transport import lease_next_job


def _http_error(code: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError("https://hol.org/api/guard/review/v2/commands", code, "err", Message(), io.BytesIO())


def test_exact_failures_do_not_send_exact_jobs_on_generic_queue() -> None:
    generic_calls: list[object] = []

    def queue_request(options: object) -> dict[str, object]:
        generic_calls.append(options)
        return {"item": {"operation": "guard.packageShims.status", "id": "generic-1"}}

    with pytest.raises(urllib.error.HTTPError):
        lease_next_job(
            operations=(EXACT_CLOUD_REVIEW_OPERATION,),
            wait_ms=0,
            exact_request=lambda _options: (_ for _ in ()).throw(_http_error(404)),
            queue_request=queue_request,
        )
    assert generic_calls == []

    with pytest.raises(urllib.error.HTTPError):
        lease_next_job(
            operations=(EXACT_CLOUD_REVIEW_OPERATION,),
            wait_ms=0,
            exact_request=lambda _options: (_ for _ in ()).throw(_http_error(401)),
            queue_request=queue_request,
        )

    mixed = lease_next_job(
        operations=(EXACT_CLOUD_REVIEW_OPERATION, "guard.packageShims.status"),
        wait_ms=0,
        exact_request=lambda _options: (_ for _ in ()).throw(_http_error(404)),
        queue_request=queue_request,
    )
    assert mixed is not None
    assert mixed["operation"] != EXACT_CLOUD_REVIEW_OPERATION
    assert generic_calls and generic_calls[-1]["operations"] == ("guard.packageShims.status",)

    with pytest.raises(ValueError, match="cloud_review_protocol_upgrade_required"):
        lease_next_job(
            operations=(EXACT_CLOUD_REVIEW_OPERATION,),
            wait_ms=0,
            exact_request=lambda _options: {"protocolVersion": 1, "item": {"id": "x", "protocolVersion": 1}},
            queue_request=queue_request,
        )
