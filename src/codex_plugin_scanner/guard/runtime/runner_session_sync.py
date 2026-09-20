"""Session sync.

Shared state and replaceable dependencies belong to the runner facade.
"""

from __future__ import annotations

from . import runner


def sync_runtime_session(
    store: runner.GuardStore,
    *,
    session: dict[str, object],
    auth_context: dict[str, object] | None = None,
) -> dict[str, object]:
    """Publish the active Guard runtime session so the dashboard can show the machine immediately."""

    resolved_auth_context = auth_context or runner._resolve_guard_sync_auth_context(store)
    sync_url = runner._normalized_runtime_sessions_sync_url(
        runner._validate_guard_sync_url(runner._auth_context_sync_url(resolved_auth_context))
    )
    session_payload = runner._cloud_runtime_session_payload(store, session)
    body = runner.json.dumps({"session": session_payload}).encode("utf-8")
    request = runner._guard_sync_request(
        resolved_auth_context,
        request_url=sync_url,
        method="POST",
        data=body,
        extra_headers=None,
    )
    try:
        payload = runner._urlopen_json_with_timeout_retry(
            request=request,
            timeout_seconds=runner._RUNTIME_SYNC_TIMEOUT_SECONDS,
            retry_timeout_seconds=runner._RUNTIME_SYNC_RETRY_TIMEOUT_SECONDS,
        )
    except runner.urllib.error.HTTPError as error:
        if error.code == 404:
            recorded_at = runner._now()
            summary = {
                "synced_at": None,
                "runtime_session_synced_at": None,
                "runtime_session_id": session_payload["sessionId"],
                "runtime_sessions_visible": 0,
                "runtime_session_sync_skipped": True,
                "runtime_session_sync_reason": "runtime_session_endpoint_unavailable",
                "local_guard_online_at": recorded_at,
                "runtime_harness": session_payload["harness"],
                "runtime_surface": session_payload["surface"],
                "runtime_workspace": session_payload["workspace"],
                "runtime_device_id": session_payload["deviceId"],
            }
            store.set_sync_payload("runtime_session_summary", summary, recorded_at)
            return summary
        if error.code == 429:
            retry_after_seconds = runner._parse_retry_after_header(error)
            recorded_at = runner._now()
            summary = {
                "synced_at": None,
                "runtime_session_synced_at": None,
                "runtime_session_id": session_payload["sessionId"],
                "runtime_sessions_visible": 0,
                "runtime_session_sync_skipped": True,
                "runtime_session_sync_reason": "runtime_session_rate_limited",
                "local_guard_online_at": recorded_at,
                "runtime_harness": session_payload["harness"],
                "runtime_surface": session_payload["surface"],
                "runtime_workspace": session_payload["workspace"],
                "runtime_device_id": session_payload["deviceId"],
                "retry_after_seconds": retry_after_seconds,
            }
            store.set_sync_payload("runtime_session_summary", summary, recorded_at)
            return summary
        raise RuntimeError(runner._sync_http_error_message(error)) from error
    except OSError as error:
        raise RuntimeError(runner._sync_url_error_message(error)) from error
    if not isinstance(payload, dict):
        raise RuntimeError("Invalid sync response")
    catalog_sync = runner._sync_extension_catalog_from_runtime_handshake(
        auth_context=resolved_auth_context,
        runtime_sync_url=sync_url,
        runtime_response=payload,
        session_payload=session_payload,
    )
    synced_at = runner._sync_timestamp(payload)
    summary = runner.runtime_session_success_summary(
        session_payload=session_payload,
        response_payload=payload,
        synced_at=synced_at,
        catalog_sync=catalog_sync,
    )
    store.set_sync_payload("runtime_session_summary", summary, synced_at)
    workspace_id = store.get_cloud_workspace_id()
    device_id = store.get_or_create_installation_id()
    if not runner._guard_events_endpoint_unavailable_recently(store):
        store.add_guard_event_v1(
            runner.build_runtime_session_event(
                session_id=str(session_payload["sessionId"]),
                occurred_at=synced_at,
                payload=session_payload,
                workspace_id=workspace_id,
                device_id=device_id,
            )
        )
    return summary


def _local_guard_runtime_session(
    *,
    device_id: str = "local-machine",
    workspace_id: str | None = None,
) -> dict[str, object]:
    session: dict[str, object] = {
        "harness": "hol-guard",
        "surface": "cli",
        "status": "active",
        "client_name": "hol-guard",
        "client_title": "HOL Guard CLI",
        "client_version": runner.__version__,
        "workspace": "local-machine",
        "capabilities": ["approval-center", "guard-cloud-sync", "local-daemon"],
        "policy_document_versions": list(runner._POLICY_DOCUMENT_VERSIONS),
        "policy_bundle_versions": list(runner._POLICY_BUNDLE_VERSIONS),
        "policy_contracts": list(runner._POLICY_CONTRACTS),
        "yaml_import": runner.os.environ.get(runner._POLICY_YAML_IMPORT_ENV) == "1",
    }
    if runner._canonical_policy_enforcement_enabled(
        device_id=device_id,
        workspace_id=workspace_id,
    ):
        session["canonical_policy_enforcement"] = True
    return session


def sync_local_guard_cloud_proof(
    store: runner.GuardStore,
    *,
    auth_context: dict[str, object] | None = None,
    now: str | None = None,
    home_dir: runner.Path | None = None,
    workspace_dir: runner.Path | None = None,
    include_aibom: bool = False,
    force_aibom: bool = False,
    managed_controls_publish: (
        runner.Callable[[runner.ExtensionControlAuthorityView, runner.Callable[[], None]], object] | None
    ) = None,
) -> dict[str, object]:
    """Publish the local Guard runtime session before syncing receipts."""
    resolved_now = now or runner._now()
    with store.hold_cloud_sync_lock():
        runner.reconcile_connect_state_with_oauth_entitlement(store, now=resolved_now)
        resolved_auth_context = (
            auth_context if auth_context is not None else runner._resolve_guard_sync_auth_context(store)
        )
        device_id = store.get_or_create_installation_id()
        workspace_id = store.get_cloud_workspace_id()
        runtime_summary = runner.sync_runtime_session(
            store,
            session=runner._local_guard_runtime_session(
                device_id=device_id,
                workspace_id=workspace_id,
            ),
            auth_context=resolved_auth_context,
        )
        receipts_summary = runner.sync_receipts(
            store,
            persist_sync_summary=False,
            persist_connect_state=False,
            auth_context=resolved_auth_context,
            home_dir=home_dir,
            workspace_dir=workspace_dir,
            include_aibom=include_aibom,
            force_aibom=force_aibom,
            managed_controls_publish=managed_controls_publish,
        )
        summary = dict(receipts_summary)
        summary.update(
            {
                "runtime_session_id": runtime_summary.get("runtime_session_id"),
                "runtime_session_synced_at": runtime_summary.get("runtime_session_synced_at"),
                "runtime_sessions_visible": runtime_summary.get("runtime_sessions_visible"),
                "local_guard_online_at": runtime_summary.get("local_guard_online_at")
                or receipts_summary.get("local_guard_online_at"),
                "runtime_harness": runtime_summary.get("runtime_harness"),
                "runtime_surface": runtime_summary.get("runtime_surface"),
                "runtime_workspace": runtime_summary.get("runtime_workspace"),
                "runtime_device_id": runtime_summary.get("runtime_device_id"),
                "runtime": runtime_summary,
                "receipts": dict(receipts_summary),
            }
        )
        recorded_at = str(summary.get("synced_at") or summary.get("runtime_session_synced_at") or runner._now())
        store.set_sync_payload("sync_summary", summary, recorded_at)
        store.record_latest_guard_connect_sync_success(sync_payload=summary, now=recorded_at)
        return summary
