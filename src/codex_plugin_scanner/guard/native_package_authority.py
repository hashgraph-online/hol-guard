"""Resident bridge for the ``package_authority`` ops (RTM-029).

Mirrors ``native_approval_gate.approval_gate_native``: each caller invokes
:func:`package_authority_native` first; when the resident answers it returns
the decoded payload, and when the resident is unavailable/mismatched it returns
``None`` so the caller falls back to the in-process Python body.

The bridge returns ``None`` only for transport failures (resident missing,
timeout, malformed envelope, capability absent). A well-formed ``error``
envelope is treated like the local path raising — the caller sees the
``status``/``code`` in the envelope and falls back only when the payload is
missing entirely, matching the approval-gate bridge contract.
"""

from __future__ import annotations

import json
import os
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .native_resident_client import native_resident_client_request
from .native_runtime import _isolated_environment, native_runtime_status
from .native_runtime_resilience import (
    native_record_resident_failure,
    native_record_resident_success,
)

_MAX_REQUEST_BYTES = 256 * 1024
_RESIDENT_PROTOCOL_FEATURE = "resident-protocol-v2"
_PACKAGE_AUTHORITY_FEATURE = "package-authority-v1"
_REQUEST_SCHEMA = "guard-package-authority-request.v1"
_RESULT_SCHEMA = "guard-package-authority-result.v1"
_request_counter = 0


def _request_id() -> str:
    global _request_counter
    _request_counter += 1
    return f"package-authority-{_request_counter}-{time.monotonic_ns()}"


def _resident_request(
    *,
    operation: str,
    request: dict[str, object],
    guard_home: Path,
    timeout_seconds: float,
) -> dict[str, object] | None:
    """Envelope + transport shared by the three package-authority ops."""
    status = native_runtime_status()
    if not status.available or not status.compatible or status.identity is None or status.capabilities is None:
        return None
    features = set(status.capabilities.features)
    if _RESIDENT_PROTOCOL_FEATURE not in features or _PACKAGE_AUTHORITY_FEATURE not in features:
        return None

    envelope = {"operation": operation, "request": request}
    try:
        payload = json.dumps(envelope).encode("utf-8")
    except (TypeError, ValueError):
        return None
    if len(payload) > _MAX_REQUEST_BYTES:
        return None
    environment = _isolated_environment()
    response = native_resident_client_request(
        executable=status.identity.path,
        guard_home=guard_home,
        environment=environment,
        payload=payload,
        timeout_seconds=timeout_seconds,
    )
    if response is None:
        native_record_resident_failure(status.identity.sha256, guard_home, reason=f"native_{operation}_transport")
        return None
    try:
        decoded = json.loads(response.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        native_record_resident_failure(status.identity.sha256, guard_home, reason=f"native_{operation}_malformed")
        return None
    if not isinstance(decoded, dict):
        return None
    if decoded.get("schema") != _RESULT_SCHEMA:
        native_record_resident_failure(status.identity.sha256, guard_home, reason=f"native_{operation}_schema")
        return None
    if decoded.get("status") != "ok":
        # Business-rule rejection or deterministic eval failure — surface the
        # code so callers can distinguish, but still fall back to Python so the
        # legacy path produces the authoritative decision.
        return None
    native_record_resident_success(status.identity.sha256, guard_home)
    return decoded if isinstance(decoded, dict) else None


def package_intent_parse_native(
    command_text: str,
    *,
    workspace: Path | None = None,
    home_dir: Path | None = None,
    canonical_command: Mapping[str, object] | None = None,
    environment: Mapping[str, str] | None = None,
    guard_home: Path,
    timeout_seconds: float = 5.0,
) -> dict[str, object] | None:
    """``package_intent_parse`` op — returns the decoded payload dict."""
    request: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": _request_id(),
        "command_text": command_text,
        "workspace": str(workspace) if workspace is not None else None,
        "home_dir": str(home_dir) if home_dir is not None else None,
        "canonical_command": dict(canonical_command) if canonical_command else None,
        "environment": dict(environment) if environment else None,
    }
    response = _resident_request(
        operation="package_intent_parse",
        request=request,
        guard_home=guard_home,
        timeout_seconds=timeout_seconds,
    )
    if response is None:
        return None
    payload = response.get("payload")
    return payload if isinstance(payload, dict) else None


def supply_chain_cloud_transport_available() -> bool:
    """Whether native evaluation can own authenticated Cloud service calls."""
    status = native_runtime_status()
    return bool(
        status.available
        and status.compatible
        and status.capabilities is not None
        and "supply-chain-cloud-transport-v1" in status.capabilities.features
    )


def supply_chain_eval_native(
    artifact: Mapping[str, object],
    *,
    store_path: Path,
    guard_home: Path,
    workspace_dir: Path | None = None,
    now: str | None = None,
    external_archive_network_authorized: bool = False,
    retain_external_archive_blob: bool = False,
    runtime_private_metadata: Mapping[str, object] | None = None,
    timeout_seconds: float = 10.0,
) -> dict[str, object] | None:
    """``supply_chain_eval`` op — returns the evaluation payload dict."""
    request: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": _request_id(),
        "store_path": str(store_path),
        "guard_home": str(guard_home),
        "artifact": dict(artifact),
        "workspace_dir": str(workspace_dir) if workspace_dir is not None else None,
        "now": now,
        "external_archive_network_authorized": bool(external_archive_network_authorized),
        "retain_external_archive_blob": bool(retain_external_archive_blob),
    }
    if runtime_private_metadata:
        request["runtime_private_metadata"] = dict(runtime_private_metadata)
    # Test-only seam: when running under pytest and the env exports a Guard
    # Cloud auth-context override, forward it to the resident so coverage tests
    # exercise the native auth-expired / cloud-transport branches hermetically
    # (the resident subprocess does not run Python monkeypatches). Mirrors the
    # in-process `runner._test_sync_auth_context_from_env` seam.
    if os.environ.get("PYTEST_CURRENT_TEST"):
        raw_override = os.environ.get("HOL_GUARD_TEST_SYNC_AUTH_CONTEXT_JSON")
        if raw_override:
            try:
                parsed = json.loads(raw_override)
            except (TypeError, ValueError):
                parsed = None
            if isinstance(parsed, dict):
                request["sync_auth_context_override"] = parsed
        # Companion test-only seam: forward a Guard Cloud package entitlement
        # override so the resident's unpaid-entitlement fallback
        # (`paid_guard_cloud_required`) runs without monkeypatching the
        # store-reading resolver the resident performs natively.
        raw_entitlement = os.environ.get("HOL_GUARD_TEST_PACKAGE_ENTITLEMENT_JSON")
        if raw_entitlement:
            try:
                parsed_entitlement = json.loads(raw_entitlement)
            except (TypeError, ValueError):
                parsed_entitlement = None
            if isinstance(parsed_entitlement, dict):
                request["package_entitlement_override"] = parsed_entitlement
    response = _resident_request(
        operation="supply_chain_eval",
        request=request,
        guard_home=guard_home,
        timeout_seconds=timeout_seconds,
    )
    if response is None:
        return None
    payload = response.get("payload")
    return payload if isinstance(payload, dict) else None


def package_authority_decide_native(
    command_text: str,
    *,
    store_path: Path,
    guard_home: Path,
    workspace_dir: Path | None = None,
    artifact_kind: str = "package_request",
    artifact_type: str = "package_request",
    now: str | None = None,
    external_archive_network_authorized: bool = False,
    retain_external_archive_blob: bool = False,
    timeout_seconds: float = 10.0,
) -> dict[str, object] | None:
    """``package_authority_decide`` op — parse + artifact + eval in one call."""
    request: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": _request_id(),
        "store_path": str(store_path),
        "guard_home": str(guard_home),
        "command_text": command_text,
        "workspace_dir": str(workspace_dir) if workspace_dir is not None else None,
        "artifact_kind": artifact_kind,
        "artifact_type": artifact_type,
        "now": now,
        "external_archive_network_authorized": bool(external_archive_network_authorized),
        "retain_external_archive_blob": bool(retain_external_archive_blob),
    }
    response = _resident_request(
        operation="package_authority_decide",
        request=request,
        guard_home=guard_home,
        timeout_seconds=timeout_seconds,
    )
    if response is None:
        return None
    payload = response.get("payload")
    return payload if isinstance(payload, dict) else None


def evaluation_from_native_payload(payload: Mapping[str, object]) -> Any:
    """Reconstruct ``PackageRequestEvaluation`` from the resident's dict.

    Local import keeps the module importable without the eval dep.
    """
    from .runtime.supply_chain_package_eval import PackageRequestEvaluation

    data = dict(payload)
    bundle_version = data.get("bundle_version")
    raw_workspace_fingerprint = data.get("workspace_fingerprint")
    workspace_fingerprint: str | None = (
        raw_workspace_fingerprint if isinstance(raw_workspace_fingerprint, str) else None
    )
    return PackageRequestEvaluation.from_cache_dict(
        data,
        package_intent_hash=str(data.get("package_intent_hash") or ""),
        policy_version=str(data.get("policy_version") or ""),
        bundle_version=bundle_version if isinstance(bundle_version, str) else None,
        workspace_fingerprint=workspace_fingerprint,
    )
