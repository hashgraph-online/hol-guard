"""Cloud audit helpers using the original live supply-chain namespace."""

from __future__ import annotations


def _should_use_cloud_workspace_audit(
    *,
    store: _api.Any,
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
    request_payload: dict[str, object],
    auth_context: dict[str, object] | None = None,
    sync_url: str | None = None,
    token: str | None = None,
    workspace_id: str,
) -> tuple[dict[str, object] | None, dict[str, object] | None]:
    runner = _api._runtime_runner_module()

    resolved_auth_context = auth_context
    if resolved_auth_context is None:
        if not isinstance(sync_url, str) or not sync_url or not isinstance(token, str) or not token:
            raise TypeError("auth_context or sync_url/token is required")
        request_url = _api._normalized_supply_chain_batch_url(sync_url, workspace_id)
        request_headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
    else:
        request_url = _api._normalized_supply_chain_batch_url(str(resolved_auth_context["sync_url"]), workspace_id)
    aggregated_packages: list[dict[str, object]] = []
    aggregated_processed_count = 0
    aggregated_reasons: list[dict[str, object]] = []
    aggregated_total_packages = 0
    cursor: str | None = None
    last_response: dict[str, object] | None = None
    for _ in range(_api._CLOUD_AUDIT_MAX_PAGES):
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
        request = _api.urllib.request.Request(
            request_url,
            data=_api.json.dumps(page_payload).encode("utf-8"),
            headers=request_headers,
            method="POST",
        )
        try:
            with _api.managed_urlopen(request, timeout=_api._CLOUD_AUDIT_TIMEOUT_SECONDS) as response:
                response_payload = _api.json.load(response)
        except _api.urllib.error.HTTPError as error:
            return (
                None,
                {
                    "code": "cloud_http_error",
                    "message": f"Guard cloud evaluation returned HTTP {error.code}, so Guard fell back locally.",
                },
            )
        except (OSError, ValueError, _api.json.JSONDecodeError):
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
        page_processed_count = _api._int_value(response_payload.get("processedCount"))
        page_total_packages = _api._int_value(response_payload.get("totalPackages"))
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


def _codebase_label_from_remote(remote: str) -> str | None:
    normalized_remote = remote.strip().rstrip("/")
    if not normalized_remote:
        return None
    if "://" in normalized_remote:
        parsed = _api.urllib.parse.urlparse(normalized_remote)
        path = parsed.path.lstrip("/")
    elif ":" in normalized_remote:
        path = normalized_remote.split(":", 1)[1]
    else:
        path = normalized_remote
    label = path.strip("/")
    if not label:
        return None
    return label[:-4] if label.endswith(".git") else label


def _read_git_origin_codebase(workspace_dir: _api.Path) -> str | None:
    config_path = workspace_dir / ".git" / "config"
    try:
        config_text = config_path.read_text(encoding="utf-8")
    except OSError:
        return None
    in_origin = False
    for raw_line in config_text.splitlines():
        line = raw_line.strip()
        if line.startswith("[") and line.endswith("]"):
            in_origin = line == '[remote "origin"]'
            continue
        if not in_origin or not line.startswith("url") or "=" not in line:
            continue
        _key, _sep, value = line.partition("=")
        return _api._codebase_label_from_remote(value)
    return None


def _safe_machine_name() -> str | None:
    try:
        machine = _api.socket.gethostname().strip()
    except OSError:
        return None
    return machine or None


def _redacted_workspace_folder_path(workspace_dir: _api.Path) -> str:
    raw_path = str(workspace_dir)
    redacted = _api.redact_local_path(raw_path)
    if redacted != raw_path or not workspace_dir.is_absolute():
        return redacted
    parts = [part for part in workspace_dir.parts if part not in {"", "/"}]
    if len(parts) >= 2:
        return f"…/{parts[-2]}/{parts[-1]}"
    return f"…/{workspace_dir.name}"


def _build_workspace_context_payload(
    workspace_dir: _api.Path,
    manifest_paths: tuple[str, ...],
    lockfile_paths: tuple[str, ...],
) -> dict[str, object]:
    codebase = _api._read_git_origin_codebase(workspace_dir) or workspace_dir.name
    return {
        "agent": _api._LOCAL_SUPPLY_CHAIN_HARNESS,
        "codebase": codebase,
        "folderPath": _api._redacted_workspace_folder_path(workspace_dir),
        "lockfilePaths": list(lockfile_paths),
        "machine": _api._safe_machine_name(),
        "manifestPaths": list(manifest_paths),
        "packageManager": _api._package_manager_for_scan(manifest_paths),
        "workspaceName": workspace_dir.name,
    }


def _build_cloud_audit_payload(
    *,
    workspace_dir: _api.Path,
    workspace_id: str,
    store: _api.Any,
    manifest_paths: tuple[str, ...],
    lockfile_paths: tuple[str, ...],
    inventory: tuple[dict[str, object], ...],
    mode: str = "paged",
    page_size: int | None = None,
) -> dict[str, object]:
    summary = store.get_sync_payload("supply_chain_bundle_summary")
    policy_version = "local:none"
    if isinstance(summary, dict):
        policy_hash = summary.get("policy_hash")
        if isinstance(policy_hash, str) and policy_hash:
            policy_version = policy_hash
    workspace_fingerprint = _api._workspace_audit_fingerprint(
        workspace_id=workspace_id,
        workspace_dir=workspace_dir,
        manifest_paths=manifest_paths,
        lockfile_paths=lockfile_paths,
        policy_version=policy_version,
    )
    payload: dict[str, object] = {
        "commandShape": {
            "argCount": 3,
            "flags": [],
            "packageManager": _api._package_manager_for_scan(manifest_paths),
            "redacted": True,
            "verb": "audit",
        },
        "harness": _api._LOCAL_SUPPLY_CHAIN_HARNESS,
        "lockfileContext": _api._workspace_audit_lockfile_context(
            workspace_dir, manifest_paths, lockfile_paths, inventory
        ),
        "mode": mode,
        "pageSize": min(_api._CLOUD_AUDIT_PAGE_SIZE, max(page_size or len(inventory), 1)),
        "packages": [
            {
                "direct": bool(item.get("direct")),
                "ecosystem": str(item["ecosystem"]),
                "name": str(item["name"]),
                "namespace": item.get("namespace"),
                **({"version": str(item["version"])} if isinstance(item.get("version"), str) else {}),
                **({"range": str(item["range"])} if isinstance(item.get("range"), str) else {}),
            }
            for item in inventory
        ],
        "policyVersion": policy_version,
        "workspaceContext": _api._build_workspace_context_payload(
            workspace_dir,
            manifest_paths,
            lockfile_paths,
        ),
        "workspaceFingerprint": workspace_fingerprint,
    }
    if payload["lockfileContext"] is None:
        payload.pop("lockfileContext")
    return payload


# Bind after declarations so importing this owner directly preserves the facade cycle.
from . import local_supply_chain as _api  # noqa: E402
