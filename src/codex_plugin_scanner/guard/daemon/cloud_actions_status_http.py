"""Dashboard route that asks Guard Cloud about the saved Cloud actions sign-ins.

The check is a POST because it calls Guard Cloud and saves the answer. It
re-validates the daemon token or dashboard session itself, so a stale route
table can never open it, and a Cloud actions sign-in sent as a bearer or as
`X-Guard-Token` is rejected like any other wrong token.
"""

from __future__ import annotations

from typing import Any

from .cloud_actions_status import (
    CloudActionsCheckBusyError,
    CloudActionsCheckedRecentlyError,
    check_cloud_actions,
)

_NO_STORE = {"Cache-Control": "no-store"}


def handle_cloud_actions_check(handler: Any, payload: dict[str, object]) -> None:
    if not handler._header_token_is_valid(payload=payload):
        handler._write_json(
            {"error": "unauthorized"},
            status=401,
            extra_headers=handler._cors_headers_for_request(),
        )
        return
    try:
        result = check_cloud_actions(handler.server.store.guard_home)
    except CloudActionsCheckedRecentlyError as error:
        handler._write_json(
            {
                "error": "checked_recently",
                "message": "Guard checked less than a minute ago. Try again shortly.",
                "retry_after_seconds": error.retry_after_seconds,
            },
            status=429,
            extra_headers={**_NO_STORE, "Retry-After": str(error.retry_after_seconds)},
        )
        return
    except CloudActionsCheckBusyError:
        handler._write_json(
            {"error": "check_running", "message": "Guard is already checking. Try again shortly."},
            status=409,
            extra_headers=_NO_STORE,
        )
        return
    except OSError:
        handler._write_json(
            {"error": "check_not_saved", "message": "Guard could not save the check on this computer."},
            status=503,
            extra_headers=_NO_STORE,
        )
        return
    handler._write_json(result, extra_headers=_NO_STORE)
