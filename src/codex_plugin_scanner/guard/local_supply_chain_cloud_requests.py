"""Cloud requests helpers using the original live supply-chain namespace."""

from __future__ import annotations


def _execute_cloud_workspace_audit_request(
    *,
    auth_context: dict[str, object],
    request_url: str,
    method: str,
    payload: dict[str, object] | None = None,
) -> dict[str, object]:
    runner = _api._runtime_runner_module()
    request = _api.build_cloud_workspace_audit_request(
        auth_context=auth_context,
        request_url=request_url,
        method=method,
        payload=payload,
        build_headers=runner._guard_sync_headers,
    )
    try:
        with _api.managed_urlopen(request, timeout=_api._CLOUD_AUDIT_TIMEOUT_SECONDS) as response:
            response_payload = _api.json.load(response)
    except _api.urllib.error.HTTPError as error:
        if error.code == 403:
            is_plan_restricted, message = runner._check_plan_restriction_403(error)
            if is_plan_restricted:
                raise runner.GuardSyncNotAvailableError(message) from error
            raise RuntimeError(message) from error
        message, retryable = runner._guard_cloud_http_error_details(error)
        if retryable:
            raise runner.GuardSyncNotAvailableError(message, retryable=True) from error
        raise RuntimeError(message) from error
    except OSError as error:
        raise RuntimeError(runner._sync_url_error_message(error)) from error
    except (ValueError, _api.json.JSONDecodeError) as error:
        raise RuntimeError("Guard cloud workspace audit returned an invalid response.") from error
    if not isinstance(response_payload, dict):
        raise RuntimeError("Guard cloud workspace audit returned an invalid response.")
    return response_payload


def _normalized_supply_chain_batch_job_url(
    sync_url: str,
    workspace_id: str,
    job_id: str,
    *,
    page_size: int,
) -> str:
    batch_url = _api._normalized_supply_chain_batch_url(sync_url, workspace_id)
    parsed = _api.urllib.parse.urlsplit(batch_url)
    query_pairs = _api.urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    query_pairs = [(key, value) for key, value in query_pairs if key not in {"cursor", "pageSize"}]
    query_pairs.append(("pageSize", str(max(page_size, 1))))
    return _api.urllib.parse.urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            f"{parsed.path.rstrip('/')}/{_api.urllib.parse.quote(job_id, safe='')}",
            _api.urllib.parse.urlencode(query_pairs),
            "",
        )
    )


def _enqueue_cloud_workspace_audit_job(
    *,
    auth_context: dict[str, object],
    request_payload: dict[str, object],
    workspace_id: str,
) -> dict[str, object]:
    sync_url = str(auth_context["sync_url"])
    request_url = _api._normalized_supply_chain_batch_url(sync_url, workspace_id)
    response_payload = _api._execute_cloud_workspace_audit_request(
        auth_context=auth_context,
        request_url=request_url,
        method="POST",
        payload=request_payload,
    )
    job_id = response_payload.get("jobId")
    if not isinstance(job_id, str) or not job_id.strip():
        raise RuntimeError("Guard cloud workspace audit did not return a batch job id.")
    return response_payload


def _poll_cloud_workspace_audit_job(
    *,
    auth_context: dict[str, object],
    job_id: str,
    workspace_id: str,
) -> dict[str, object]:
    sync_url = str(auth_context["sync_url"])
    request_url = _api._normalized_supply_chain_batch_job_url(
        sync_url,
        workspace_id,
        job_id,
        page_size=_api._CLOUD_AUDIT_JOB_PAGE_SIZE,
    )
    deadline = _api.time.monotonic() + _api._CLOUD_AUDIT_JOB_POLL_TIMEOUT_SECONDS
    last_response: dict[str, object] = {
        "jobId": job_id,
        "status": "queued",
        "workspaceId": workspace_id,
    }
    while _api.time.monotonic() < deadline:
        response_payload = _api._execute_cloud_workspace_audit_request(
            auth_context=auth_context,
            request_url=request_url,
            method="GET",
        )
        status = str(response_payload.get("status") or "").strip().lower()
        last_response = response_payload
        if status in {"completed", "failed"}:
            return response_payload
        _api.time.sleep(_api._CLOUD_AUDIT_JOB_POLL_INTERVAL_SECONDS)
    return last_response


def _normalized_supply_chain_batch_url(sync_url: str, workspace_id: str) -> str:
    parsed = _api.urllib.parse.urlsplit(sync_url)
    sync_path = parsed.path.rstrip("/")
    if sync_path.endswith("/receipts/sync"):
        next_path = sync_path[: -len("/receipts/sync")] + "/supply-chain/evaluate/batch"
    else:
        next_path = sync_path + "/supply-chain/evaluate/batch"
    query_pairs = [
        (key, value)
        for key, value in _api.urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        if key != "workspaceId"
    ]
    query_pairs.append(("workspaceId", workspace_id))
    return _api.urllib.parse.urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            next_path,
            _api.urllib.parse.urlencode(query_pairs),
            "",
        )
    )


# Bind after declarations so importing this owner directly preserves the facade cycle.
from . import local_supply_chain as _api  # noqa: E402
