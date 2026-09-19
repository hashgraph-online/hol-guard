"""Session payload.

Shared state and replaceable dependencies belong to the runner facade.
"""

from __future__ import annotations

from . import runner


def _cloud_runtime_session_payload(store: runner.GuardStore, session: dict[str, object]) -> dict[str, object]:
    device_id, device_name = runner._guard_device_metadata(store)
    workspace = runner._optional_string(session.get("workspace")) or runner.os.getcwd()
    session_id = (
        runner._optional_string(session.get("session_id") or session.get("sessionId"))
        or runner.hashlib.sha256(f"{device_id}:{workspace}".encode()).hexdigest()[:24]
    )
    created_at = runner._optional_string(session.get("created_at") or session.get("createdAt")) or runner._now()
    updated_at = runner._optional_string(session.get("updated_at") or session.get("updatedAt")) or created_at
    capabilities = list(runner._string_items(session.get("capabilities")))
    policy_document_versions = list(
        runner._string_items(session.get("policy_document_versions") or session.get("policyDocumentVersions"))
    )
    policy_bundle_versions = list(
        runner._string_items(session.get("policy_bundle_versions") or session.get("policyBundleVersions"))
    )
    policy_contracts = list(runner._string_items(session.get("policy_contracts") or session.get("policyContracts")))
    yaml_import = session.get("yaml_import") is True or session.get("yamlImport") is True
    canonical_policy_enforcement = (
        session.get("canonical_policy_enforcement") is True or session.get("canonicalPolicyEnforcement") is True
    )
    package_manager_coverage = runner._cloud_package_manager_coverage(
        store,
        workspace=workspace,
        generated_at=updated_at,
    )
    local_identity = runner._cloud_local_identity_payload(observed_at=updated_at)
    payload: dict[str, object] = {
        "sessionId": session_id,
        "harness": runner._optional_string(session.get("harness")) or "hol-guard",
        "surface": runner._optional_string(session.get("surface")) or "cli",
        "status": runner._optional_string(session.get("status")) or "active",
        "clientName": runner._optional_string(session.get("client_name") or session.get("clientName")) or "hol-guard",
        "clientTitle": runner._optional_string(session.get("client_title") or session.get("clientTitle"))
        or f"HOL Guard on {device_name}",
        "clientVersion": runner._optional_string(session.get("client_version") or session.get("clientVersion"))
        or runner.__version__,
        "deviceId": device_id,
        "deviceName": device_name,
        "localIdentity": local_identity,
        "localIdentitySource": runner._cloud_local_identity_source_payload(local_identity),
        "packageManagerCoverage": package_manager_coverage,
        "workspace": workspace,
        "capabilities": capabilities,
        "operations": [],
        "createdAt": created_at,
        "updatedAt": updated_at,
    }
    if policy_document_versions:
        payload["policyDocumentVersions"] = policy_document_versions
    if policy_bundle_versions:
        payload["policyBundleVersions"] = policy_bundle_versions
    if policy_contracts:
        payload["policyContracts"] = policy_contracts
    payload["yamlImport"] = yaml_import
    if canonical_policy_enforcement:
        payload["canonicalPolicyEnforcement"] = True
    payload.update(runner._managed_controls_runtime_sync_posture(store, generated_at=updated_at))
    return payload


def _sync_extension_catalog_from_runtime_handshake(
    *,
    auth_context: dict[str, object],
    runtime_sync_url: str,
    runtime_response: dict[str, object],
    session_payload: dict[str, object],
) -> dict[str, object]:
    """Upload the canonical catalog only after a digest-bound Cloud request."""

    summary, upload = runner.prepare_extension_catalog_handshake(
        runtime_sync_url=runtime_sync_url,
        runtime_response=runtime_response,
        session_payload=session_payload,
        catalog_factory=lambda generated_at: runner.build_builtin_extension_catalog_wire(
            guard_version=runner.__version__, generated_at=generated_at
        ),
        fallback_generated_at=runner._now(),
    )
    if upload is None:
        return summary
    request = runner._guard_sync_request(
        auth_context,
        request_url=upload.url,
        method="POST",
        data=upload.body,
        extra_headers=None,
    )
    try:
        response = runner._urlopen_json_with_timeout_retry(
            request=request,
            timeout_seconds=runner._RUNTIME_SYNC_TIMEOUT_SECONDS,
            retry_timeout_seconds=runner._RUNTIME_SYNC_RETRY_TIMEOUT_SECONDS,
        )
    except runner.urllib.error.HTTPError as error:
        raise RuntimeError(runner._sync_http_error_message(error)) from error
    except OSError as error:
        raise RuntimeError(runner._sync_url_error_message(error)) from error
    digest = session_payload.get("extensionCatalogDigest")
    if not isinstance(digest, str):
        raise RuntimeError("Invalid Extension catalog handshake response")
    runner._validate_extension_catalog_sync_response(response, expected_digest=digest)
    return summary


def _cloud_local_identity_payload(*, observed_at: str) -> dict[str, object]:
    hostname = runner._safe_hostname()
    private_ip = runner._safe_private_ip()
    if private_ip is None:
        private_ip = runner._safe_private_ipv6()
    payload: dict[str, object] = {"lastSyncedAt": observed_at}
    if hostname is not None:
        payload["hostname"] = hostname
    if private_ip is not None:
        payload["ipAddress"] = private_ip
        payload["privateIpAddress"] = private_ip
    return payload


def _cloud_local_identity_source_payload(local_identity: dict[str, object]) -> dict[str, str]:
    source: dict[str, str] = {
        "daemonId": "local-guard",
        "daemonVersion": "local-guard",
        "daemonStatus": "local-guard",
        "relayState": "local-guard",
    }
    if "hostname" in local_identity:
        source["hostname"] = "local-guard"
    if "ipAddress" in local_identity:
        source["ipAddress"] = "local-guard"
    if "privateIpAddress" in local_identity:
        source["privateIpAddress"] = "local-guard"
    if "publicIpAddress" in local_identity:
        source["publicIpAddress"] = "local-guard"
    return source


def _safe_hostname() -> str | None:
    with runner.suppress(OSError):
        hostname = runner.socket.gethostname().strip()
        if hostname:
            return hostname[:255]
    return None


def _safe_private_ip() -> str | None:
    with runner.suppress(OSError), runner.socket.socket(runner.socket.AF_INET, runner.socket.SOCK_DGRAM) as sock:
        sock.connect(("8.8.8.8", 80))  # NOSONAR(S1313) UDP route selection only; no payload is sent
        address = sock.getsockname()[0]
        if isinstance(address, str) and address and not address.startswith("127."):
            return address[:128]
    with runner.suppress(OSError):
        address = runner.socket.gethostbyname(runner.socket.gethostname())
        if address and not address.startswith("127."):
            return address[:128]
    return None


def _safe_private_ipv6() -> str | None:
    with runner.suppress(OSError):
        addresses = runner.socket.getaddrinfo(runner.socket.gethostname(), None, runner.socket.AF_INET6)
        for entry in addresses:
            candidate = entry[4][0]
            if isinstance(candidate, str) and candidate and candidate != "::1":
                return candidate[:128]
    return None


def _cloud_package_manager_coverage(
    store: runner.GuardStore,
    *,
    workspace: str,
    generated_at: str,
) -> dict[str, object]:
    coverage = runner.package_shim_cloud_coverage(
        runner.HarnessContext(
            home_dir=runner.Path.home(),
            workspace_dir=runner.Path(workspace),
            guard_home=store.guard_home,
        ),
        generated_at=generated_at,
    )
    synced_at = None
    next_refresh_at = None
    synced_timestamp = None
    for source_name, summary in (
        ("sync", store.get_sync_payload("sync_summary")),
        ("runtime", store.get_sync_payload("runtime_session_summary")),
        ("bundle", store.get_sync_payload("supply_chain_bundle_summary")),
    ):
        if not isinstance(summary, dict):
            continue
        candidate_synced_at = runner._optional_string(
            summary.get("synced_at")
            or summary.get("syncedAt")
            or summary.get("runtime_session_synced_at")
            or summary.get("runtimeSessionSyncedAt")
            or summary.get("local_guard_online_at"),
        )
        candidate_timestamp = (
            runner._parse_iso_timestamp(candidate_synced_at) if candidate_synced_at is not None else None
        )
        if candidate_timestamp is None:
            continue
        if synced_timestamp is not None and candidate_timestamp <= synced_timestamp:
            continue
        synced_at = candidate_synced_at
        synced_timestamp = candidate_timestamp
        next_refresh_at = (
            runner._optional_string(summary.get("next_refresh_at") or summary.get("nextRefreshAt"))
            if source_name == "bundle"
            else None
        )
    reference_timestamp = runner._parse_iso_timestamp(generated_at) or runner.datetime.now(runner.timezone.utc)
    stale_status = "unknown"
    if synced_at is not None:
        stale_status = "fresh"
    next_refresh_timestamp = runner._parse_iso_timestamp(next_refresh_at) if next_refresh_at is not None else None
    if next_refresh_timestamp is None and synced_at is not None:
        next_refresh_timestamp = runner._parse_iso_timestamp(synced_at)
        if next_refresh_timestamp is not None:
            next_refresh_timestamp += runner.timedelta(minutes=15)
            next_refresh_at = next_refresh_timestamp.isoformat()
    if next_refresh_timestamp is not None and next_refresh_timestamp <= reference_timestamp:
        stale_status = "stale"
    coverage["staleIntel"] = {
        "status": stale_status,
        "lastSyncedAt": synced_at,
        "nextRefreshAt": next_refresh_at,
    }
    return coverage


def _guard_device_metadata(store: runner.GuardStore) -> tuple[str, str]:
    metadata = store.get_device_metadata()
    return str(metadata["installation_id"]), str(metadata["device_label"])
