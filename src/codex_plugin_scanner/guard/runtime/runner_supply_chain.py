"""Supply chain.

Shared state and replaceable dependencies belong to the runner facade.
"""

from __future__ import annotations

from . import runner


def _guard_cloud_http_error_details(error: runner.urllib.error.HTTPError) -> tuple[str, bool]:
    try:
        raw_body = error.read().decode("utf-8", errors="replace")
    except OSError:
        raw_body = ""
    retryable = error.code in {429, 503, 524}
    payload: object = None
    if raw_body:
        try:
            payload = runner.json.loads(raw_body)
        except runner.json.JSONDecodeError:
            payload = None
    message: str | None = None
    if isinstance(payload, dict):
        message = runner._read_guard_cloud_error_message(payload)
        guard_error = payload.get("guardError")
        if isinstance(guard_error, dict):
            if guard_error.get("retryable") is True:
                retryable = True
            guard_code = guard_error.get("code")
            unavailable_codes = {"guard_unavailable", "guard_cloud_unavailable"}
            if isinstance(guard_code, str) and guard_code.strip().lower() in unavailable_codes:
                retryable = True
    if message is None:
        normalized_body = raw_body.strip()
        message = normalized_body or f"HTTP Error {error.code}: {error.reason}"
    return message, retryable


def _fetch_supply_chain_bundle_payload(request: runner.urllib.request.Request) -> dict[str, object]:
    try:
        return runner._urlopen_json_with_timeout_retry(
            request=request,
            timeout_seconds=runner._SYNC_HTTP_TIMEOUT_SECONDS,
            retry_timeout_seconds=runner._SYNC_HTTP_RETRY_TIMEOUT_SECONDS,
        )
    except runner.urllib.error.HTTPError as error:
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


def _normalized_supply_chain_bundle_index_url(bundle_url: str) -> str:
    parsed = runner.urllib.parse.urlsplit(bundle_url)
    return runner.urllib.parse.urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path.rstrip("/") + "/index",
            parsed.query,
            "",
        )
    )


def _supply_chain_partition_bundle_url(bundle_url: str, *, ecosystem: str, partition: int) -> str:
    parsed = runner.urllib.parse.urlsplit(bundle_url)
    query_pairs = [
        (key, value)
        for key, value in runner.urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        if key not in {"ecosystem", "partition"}
    ]
    query_pairs.extend((("ecosystem", ecosystem), ("partition", str(partition))))
    return runner.urllib.parse.urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            runner.urllib.parse.urlencode(query_pairs),
            "",
        )
    )


def _sync_supply_chain_bundle_incremental(
    *,
    bundle_url: str,
    cached_bundle_version: str | None,
    auth_context: dict[str, object],
    store: runner.GuardStore,
    trusted_keys: tuple[runner.SupplyChainVerificationKey, ...],
    workspace_id: str,
) -> dict[str, object] | None:
    index_request = runner._guard_sync_request(
        auth_context,
        request_url=runner._normalized_supply_chain_bundle_index_url(bundle_url),
        method="GET",
        data=None,
        extra_headers={"Accept-Encoding": "identity"},
    )
    try:
        index_payload = runner._fetch_supply_chain_bundle_payload(index_request)
    except RuntimeError:
        return None
    if not isinstance(index_payload, dict):
        return None
    raw_partitions = index_payload.get("partitions")
    if not isinstance(raw_partitions, list) or len(raw_partitions) == 0:
        return None
    cached_partition_payload = store.get_sync_payload("supply_chain_bundle_partition_cache")
    cached_partitions = {}
    if isinstance(cached_partition_payload, dict):
        raw_cached_partitions = cached_partition_payload.get("partitions")
        if isinstance(raw_cached_partitions, dict):
            cached_partitions = raw_cached_partitions
    next_partition_cache: dict[str, object] = {}
    refreshed_partitions = 0
    for descriptor in raw_partitions:
        if not isinstance(descriptor, dict):
            continue
        ecosystem = descriptor.get("ecosystem")
        partition = descriptor.get("partition")
        payload_hash = descriptor.get("payloadHash")
        if not isinstance(ecosystem, str) or not isinstance(partition, int) or not isinstance(payload_hash, str):
            continue
        cache_key = f"{ecosystem}:{partition}"
        cached_partition = cached_partitions.get(cache_key)
        response = None
        if isinstance(cached_partition, dict) and cached_partition.get("payload_hash") == payload_hash:
            raw_cached_response = cached_partition.get("response")
            if isinstance(raw_cached_response, dict):
                try:
                    response = runner.load_supply_chain_bundle_response(raw_cached_response)
                    runner.verify_supply_chain_bundle_response(
                        response,
                        trusted_keys=trusted_keys or None,
                        cached_bundle_version=cached_bundle_version,
                    )
                except runner.SupplyChainBundleError:
                    response = None
        if response is None:
            try:
                partition_request = runner._guard_sync_request(
                    auth_context,
                    request_url=runner._supply_chain_partition_bundle_url(
                        bundle_url, ecosystem=ecosystem, partition=partition
                    ),
                    method="GET",
                    data=None,
                    extra_headers={"Accept-Encoding": "identity"},
                )
                partition_payload = runner._fetch_supply_chain_bundle_payload(partition_request)
                response = runner.load_supply_chain_bundle_response(partition_payload)
                runner.verify_supply_chain_bundle_response(
                    response,
                    trusted_keys=trusted_keys or None,
                    cached_bundle_version=cached_bundle_version,
                )
            except (RuntimeError, runner.SupplyChainBundleError):
                return None
            refreshed_partitions += 1
        next_partition_cache[cache_key] = {
            "payload_hash": payload_hash,
            "response": response.to_dict(),
        }
    if not next_partition_cache:
        return None
    bundle_version = index_payload.get("bundleVersion")
    resolved_bundle_version = bundle_version if isinstance(bundle_version, str) and bundle_version else None
    if resolved_bundle_version is None:
        resolved_bundle_version = cached_bundle_version or ""
    return {
        "cache_payload": {
            "bundle_version": resolved_bundle_version,
            "partitions": next_partition_cache,
            "workspace_id": workspace_id,
        },
        "refreshed_partitions": refreshed_partitions,
        "total_partitions": len(next_partition_cache),
    }


def sync_supply_chain_bundle(
    store: runner.GuardStore,
    *,
    auth_context: dict[str, object] | None = None,
) -> dict[str, object]:
    """Fetch, verify, and persist the active supply-chain bundle for the cloud workspace."""

    resolved_auth_context = auth_context if auth_context is not None else runner._resolve_guard_sync_auth_context(store)
    workspace_id = store.get_cloud_workspace_id()
    if workspace_id is None:
        raise runner.GuardSyncNotConfiguredError("Guard Cloud workspace is not connected.")
    bundle_url = runner._normalized_supply_chain_bundle_url(str(resolved_auth_context["sync_url"]), workspace_id)
    cached_bundle = store.get_cached_supply_chain_bundle(workspace_id)
    cached_bundle_version = None
    if isinstance(cached_bundle, dict):
        cached_payload = cached_bundle.get("bundle")
        if isinstance(cached_payload, dict):
            existing_version = cached_payload.get("bundleVersion")
            if isinstance(existing_version, str) and existing_version:
                cached_bundle_version = existing_version
    trusted_keys = runner.load_supply_chain_verification_keys(store.get_sync_payload("supply_chain_bundle_keyring"))
    try:
        partition_sync: dict[str, object] | None = runner._sync_supply_chain_bundle_incremental(
            bundle_url=bundle_url,
            cached_bundle_version=cached_bundle_version,
            auth_context=resolved_auth_context,
            store=store,
            trusted_keys=trusted_keys,
            workspace_id=workspace_id,
        )
    except (RuntimeError, runner.SupplyChainBundleError):
        partition_sync = None
    if (
        partition_sync is not None
        and partition_sync.get("refreshed_partitions") == 0
        and isinstance(cached_bundle, dict)
    ):
        try:
            response = runner.load_supply_chain_bundle_response(cached_bundle)
            runner.verify_supply_chain_bundle_response(
                response,
                trusted_keys=trusted_keys or None,
                cached_bundle_version=cached_bundle_version,
            )
        except runner.SupplyChainBundleError:
            try:
                request = runner._guard_sync_request(
                    resolved_auth_context,
                    request_url=bundle_url,
                    method="GET",
                    data=None,
                    extra_headers={"Accept-Encoding": "identity"},
                )
                payload = runner._fetch_supply_chain_bundle_payload(request)
                response = runner.load_supply_chain_bundle_response(payload)
                runner.verify_supply_chain_bundle_response(
                    response,
                    trusted_keys=trusted_keys or None,
                    cached_bundle_version=cached_bundle_version,
                )
            except (RuntimeError, runner.SupplyChainBundleError) as error:
                raise RuntimeError(f"Guard supply-chain bundle sync failed: {error}") from error
    else:
        request = runner._guard_sync_request(
            resolved_auth_context,
            request_url=bundle_url,
            method="GET",
            data=None,
            extra_headers={"Accept-Encoding": "identity"},
        )
        payload = runner._fetch_supply_chain_bundle_payload(request)
        try:
            response = runner.load_supply_chain_bundle_response(payload)
            runner.verify_supply_chain_bundle_response(
                response,
                trusted_keys=trusted_keys or None,
                cached_bundle_version=cached_bundle_version,
            )
        except runner.SupplyChainBundleError as error:
            raise RuntimeError(f"Guard supply-chain bundle sync failed: {error}") from error
    synced_at = runner._now()
    store.cache_supply_chain_bundle(workspace_id, response.to_dict(), synced_at)
    store.set_sync_payload(
        "supply_chain_bundle_keyring",
        {
            "workspace_id": workspace_id,
            "keys": [item.to_dict() for item in response.verification_keys],
        },
        synced_at,
    )
    store.set_sync_payload(
        "supply_chain_bundle_entitlement",
        {
            "bundle_version": response.bundle.bundle_version,
            "key_id": response.bundle.key_id,
            "policy_hash": response.bundle.policy_hash,
            "tier": response.bundle.tier,
            "workspace_id": workspace_id,
        },
        synced_at,
    )
    if partition_sync is not None:
        cache_payload = partition_sync.get("cache_payload")
        if isinstance(cache_payload, dict):
            store.set_sync_payload(
                "supply_chain_bundle_partition_cache",
                cache_payload,
                synced_at,
            )
    summary: dict[str, object] = {
        "advisory_count": len(response.bundle.advisories),
        "bundle_version": response.bundle.bundle_version,
        "ecosystem_support": list(runner.ecosystem_support_matrix()),
        "feed_snapshot_hash": response.bundle.feed_snapshot_hash,
        "package_count": len(response.bundle.packages),
        "policy_hash": response.bundle.policy_hash,
        "status": "synced",
        "synced_at": synced_at,
        "tier": response.bundle.tier,
        "workspace_id": workspace_id,
    }
    if partition_sync is not None:
        summary["partition_sync"] = {
            "enabled": True,
            "refreshed": runner._int_value(partition_sync.get("refreshed_partitions")) or 0,
            "total": runner._int_value(partition_sync.get("total_partitions")) or 0,
        }
    store.set_sync_payload("supply_chain_bundle_summary", summary, synced_at)
    return summary
