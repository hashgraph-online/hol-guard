"""Headless application result projection."""

from __future__ import annotations

from . import server as _server


def _headless_safe_failure_reasons() -> dict[str, str]:
    return {
        "offline": "Local Guard daemon is unavailable.",
        "timeout": "Local Guard daemon did not answer before the browser timeout.",
        "unauthorized": "Dashboard session is missing or stale.",
        "unsupported": "Harness is not supported by this daemon.",
        "confirmation_required": "Remove actions need the harness confirmation phrase.",
    }


def _supply_chain_package_action_error_response(
    *,
    operation: str,
    error: Exception,
) -> tuple[int, dict[str, object]]:
    if isinstance(error, _server.GuardSyncAuthorizationExpiredError):
        return (
            403,
            {
                "error": "guard_cloud_reconnect_required",
                "message": str(error).strip() or "Guard Cloud authorization expired.",
                "operation": operation,
            },
        )
    if isinstance(error, _server.GuardSyncNotConfiguredError):
        return (
            403,
            {
                "error": "guard_cloud_connect_required",
                "message": str(error).strip() or "Guard Cloud workspace is not connected.",
                "operation": operation,
            },
        )
    if isinstance(error, _server.GuardSyncNotAvailableError):
        payload: dict[str, object] = {
            "error": "supply_chain_sync_unavailable",
            "message": str(error).strip() or "Supply-chain sync is not available on this device.",
            "operation": operation,
        }
        if error.retryable:
            payload["retryable"] = True
        return (503, payload)
    message = str(error).strip() or "Guard supply-chain bundle sync failed."
    return (
        502,
        {
            "error": "supply_chain_sync_failed",
            "message": message,
            "operation": operation,
        },
    )


def _cloud_app_dashboard_session_actions(action_path: str) -> frozenset[str]:
    return _server._CLOUD_APP_DASHBOARD_SESSION_ACTIONS.get(action_path, frozenset({action_path}))


def _headless_detection_status_to_app_status(value: object) -> str:
    status_map = {
        "protected": "protected",
        "found": "observed",
        "not_found": "inactive",
    }
    return status_map.get(str(value), "unknown")


def _headless_error_payload(
    *,
    code: str,
    message: str,
    retryable: bool,
    detail: str | None = None,
) -> dict[str, object]:
    error_payload: dict[str, object] = {
        "code": code,
        "message": message,
        "retryable": retryable,
    }
    if detail:
        error_payload["detail"] = detail
    payload: dict[str, object] = {
        "status": "failed",
        "error": error_payload,
    }
    return payload


def _headless_action_error_payload(
    *,
    operation: str,
    error_code: str,
) -> tuple[int, dict[str, object]]:
    error_details = {
        "missing_harness": (
            400,
            "Choose an app before retrying.",
            False,
        ),
        "unknown_harness": (
            404,
            "This app is not supported by local Guard.",
            False,
        ),
        "confirmation_required": (
            409,
            "Disconnect needs the local confirmation phrase before Guard removes protection.",
            False,
        ),
        "unsupported_operation": (
            400,
            "This version of local Guard cannot run the requested app action.",
            False,
        ),
    }
    known_error = error_details.get(error_code)
    if known_error is not None:
        status, message, retryable = known_error
        return status, _server._headless_error_payload(
            code=error_code,
            message=message,
            retryable=retryable,
        )
    operation_code = "proof_failed" if operation == "scan" else f"{operation}_failed"
    operation_label = "connection check" if operation == "scan" else operation
    return 400, _server._headless_error_payload(
        code=operation_code,
        message=f"Guard could not finish the {operation_label}.",
        retryable=True,
    )


def _headless_app_status_from_result(*, operation: str, result: dict[str, object]) -> str:
    if operation in {"install", "repair"}:
        managed_install = result.get("managed_install")
        if isinstance(managed_install, dict) and bool(managed_install.get("active")):
            return "protected"
        return "unknown"
    if operation == "remove":
        managed_install = result.get("managed_install")
        if isinstance(managed_install, dict) and managed_install.get("active") is False:
            return "inactive"
        return "unknown"
    verification = result.get("verification")
    if isinstance(verification, dict):
        if bool(verification.get("installed")):
            return "protected"
        if bool(verification.get("command_available")) or bool(verification.get("config_paths")):
            return "observed"
        return "inactive"
    return "unknown"


def _headless_action_state_payload(
    *,
    harness: str,
    operation: str,
    result: dict[str, object],
    receipt: dict[str, object],
) -> dict[str, object]:
    app_status = _server._headless_app_status_from_result(operation=operation, result=result)
    if operation == "install":
        outcome = "app_connected"
        message = f"{harness} is connected through local Guard."
        proof_status = "pending"
    elif operation == "repair":
        outcome = "app_repaired"
        message = f"{harness} protection was refreshed."
        proof_status = "pending"
    elif operation == "remove":
        outcome = "app_disconnected"
        message = f"{harness} protection was removed."
        proof_status = "not_applicable"
    elif operation == "scan":
        proof_passed = app_status == "protected"
        # Keep protocol values stable for Cloud clients; user-facing copy below avoids jargon.
        outcome = "proof_passed" if proof_passed else "proof_failed"
        message = (
            f"{harness} connection check passed. Guard sees local protection."
            if proof_passed
            else f"{harness} connection check finished, but Guard does not see active local protection yet."
        )
        proof_status = "passed" if proof_passed else "failed"
    else:
        outcome = "status_checked"
        message = f"{harness} status checked."
        proof_status = "not_applicable"
    return {
        "app_status": app_status,
        "message": message,
        "outcome": outcome,
        "proof_status": proof_status,
        "receipt_summary": {
            "id": receipt.get("id"),
            "operation": receipt.get("operation"),
            "status": receipt.get("status"),
            "timestamp": receipt.get("timestamp"),
        },
        "retryable": operation in {"install", "repair", "scan"},
    }
