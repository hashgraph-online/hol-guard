"""Cloud workspace-audit requests for the supply-chain audit payload."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

from . import local_supply_chain as _lsc
from .mdm.network import managed_urlopen
from .native_package_audit_projection import native_batch_url

_CLOUD_AUDIT_MAX_PAGES = 100


def _should_use_cloud_workspace_audit(
    *,
    store: Any,
    posture: dict[str, object],
) -> bool:
    if store.get_cloud_sync_profile() is None or store.get_cloud_workspace_id() is None:
        return False
    bundle = posture.get("bundle")
    if not isinstance(bundle, dict):
        return False
    return str(bundle.get("tier") or "").strip().lower() == "premium"


def _run_cloud_workspace_audit(
    *,
    store: Any,
    request_payload: dict[str, object],
    auth_context: dict[str, object] | None = None,
    sync_url: str | None = None,
    token: str | None = None,
    workspace_id: str,
) -> tuple[dict[str, object] | None, dict[str, object] | None]:
    runner = _lsc._runtime_runner_module()

    resolved_auth_context = auth_context
    if resolved_auth_context is None:
        if not isinstance(sync_url, str) or not sync_url or not isinstance(token, str) or not token:
            raise TypeError("auth_context or sync_url/token is required")
        request_url = native_batch_url(store, sync_url, workspace_id)
        request_headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
    else:
        request_url = native_batch_url(store, str(resolved_auth_context["sync_url"]), workspace_id)
    aggregated_packages: list[dict[str, object]] = []
    aggregated_processed_count = 0
    aggregated_reasons: list[dict[str, object]] = []
    aggregated_total_packages = 0
    cursor: str | None = None
    last_response: dict[str, object] | None = None
    for _ in range(_CLOUD_AUDIT_MAX_PAGES):
        page_payload = dict(request_payload)
        if cursor is not None:
            page_payload["cursor"] = cursor
        request_headers = (
            {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            }
            if resolved_auth_context is None
            else runner._guard_sync_headers(resolved_auth_context, request_url=request_url, method="POST")
        )
        request = urllib.request.Request(
            request_url,
            data=json.dumps(page_payload).encode("utf-8"),
            headers=request_headers,
            method="POST",
        )
        try:
            with managed_urlopen(request, timeout=_lsc._CLOUD_AUDIT_TIMEOUT_SECONDS) as response:
                response_payload = json.load(response)
        except urllib.error.HTTPError as error:
            return (
                None,
                {
                    "code": "cloud_http_error",
                    "message": f"Guard cloud evaluation returned HTTP {error.code}, so Guard fell back locally.",
                },
            )
        except (OSError, ValueError, json.JSONDecodeError):
            return (
                None,
                {
                    "code": "cloud_timeout",
                    "message": "Guard cloud evaluation timed out, so Guard fell back locally.",
                },
            )
        if not isinstance(response_payload, dict):
            return (
                None,
                {
                    "code": "cloud_invalid_response",
                    "message": "Guard cloud evaluation returned an invalid response, so Guard fell back locally.",
                },
            )
        last_response = response_payload
        response_packages = response_payload.get("packages")
        page_processed_count = _lsc._int_value(response_payload.get("processedCount"))
        page_total_packages = _lsc._int_value(response_payload.get("totalPackages"))
        if page_total_packages is not None:
            aggregated_total_packages = max(aggregated_total_packages, page_total_packages)
        if page_processed_count is not None:
            aggregated_processed_count += page_processed_count
        elif isinstance(response_packages, list):
            aggregated_processed_count += len(response_packages)
        if isinstance(response_packages, list):
            aggregated_packages.extend(item for item in response_packages if isinstance(item, dict))
        response_reasons = response_payload.get("reasons")
        if isinstance(response_reasons, list):
            aggregated_reasons.extend(item for item in response_reasons if isinstance(item, dict))
        next_cursor = response_payload.get("nextCursor")
        if not isinstance(next_cursor, str) or not next_cursor:
            break
        cursor = next_cursor
    else:
        return (
            None,
            {
                "code": "cloud_page_limit",
                "message": "Guard cloud evaluation exceeded the maximum page count, so Guard fell back locally.",
            },
        )
    if last_response is None:
        return (None, None)
    merged_response = dict(last_response)
    merged_response["packages"] = aggregated_packages
    merged_response["processedCount"] = aggregated_processed_count
    merged_response["totalPackages"] = max(aggregated_total_packages, len(aggregated_packages))
    merged_response["reasons"] = aggregated_reasons
    return (merged_response, None)
