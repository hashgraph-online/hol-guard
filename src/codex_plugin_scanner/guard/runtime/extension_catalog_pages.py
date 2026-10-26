"""Bounded native Cloud producer bridge; no Python catalog construction."""

from __future__ import annotations

import base64
import hashlib
import json
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# Advertised protocol name only. The native runtime defines and enforces the
# v2 wire contract; nothing here restates its limits or its upload policy.
CAPABILITY = "extension-catalog.v2"


def encoded(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def native_call(home: Path, **request: object) -> dict[str, Any]:
    from ..native_execution import _resident_request
    from .extension_catalog_sync import ExtensionCatalogLimitError, ExtensionCatalogUnavailableError

    reply = _resident_request(
        operation="cloud_catalog",
        request={"guard_home": str(home.absolute()), **request},
        guard_home=home,
        timeout_seconds=120.0,
        required_feature="cloud-catalog-producer-v2",
        response_schema="guard-cloud-catalog-result.v2",
        max_request_bytes=4 * 1024 * 1024,
    )
    if not isinstance(reply, dict):
        raise ExtensionCatalogUnavailableError("Native complete catalog producer unavailable")
    if reply.get("error") == "catalog_limit":
        raise ExtensionCatalogLimitError("Complete catalog exceeds native wire limits")
    payload = reply.get("payload")
    if not isinstance(payload, dict) or "error" in reply:
        raise ValueError("Native complete catalog producer rejected metadata")
    if "policy_error" in payload:
        from ..managed_controls_policy_fields import ManagedControlsPolicyError

        raise ManagedControlsPolicyError(payload["policy_error"], payload["message"])
    return payload


@dataclass(frozen=True)
class PreparedCatalogView:
    guard_home: Path
    token: str
    _manifest: bytes
    discovery_root: str
    discovery_authority: str

    @classmethod
    def from_native(cls, home: Path, payload: dict[str, Any]) -> PreparedCatalogView:
        return cls(
            home,
            payload["token"],
            encoded(payload["manifest"]),
            payload["discovery_root"],
            payload["discovery_authority"],
        )

    @property
    def manifest(self) -> dict[str, Any]:
        return json.loads(self._manifest)

    def request_bytes(self, operation: str, ordinal: int | None = None) -> bytes:
        body = bytearray()
        while True:
            result = native_call(
                self.guard_home,
                action="request",
                token=self.token,
                operation=operation,
                ordinal=ordinal,
                offset=len(body),
            )
            chunk = base64.b64decode(result["body_chunk"], validate=True)
            if not chunk:
                raise ValueError("Native catalog request chunk is empty")
            body.extend(chunk)
            # The native runtime bounds the body; reassembly only has to end
            # and to reproduce exactly the body the runtime digested.
            if len(body) >= result["total_bytes"]:
                break
        if len(body) != result["total_bytes"] or hashlib.sha256(body).hexdigest() != result["body_sha256"]:
            raise ValueError("Native catalog request reassembled out of sequence")
        return bytes(body)

    def pages(self):
        for ordinal in range(self.manifest["pageCount"]):
            yield json.loads(self.request_bytes("page", ordinal))["page"]

    def legacy(self):
        # The native read holds the cache lock itself, so no transfer lease is taken.
        return native_call(self.guard_home, action="legacy", token=self.token)["catalog"]

    @contextmanager
    def pinned(self):
        lease = native_call(self.guard_home, action="acquire", token=self.token)["lease"]
        try:
            yield
        finally:
            native_call(self.guard_home, action="release", lease=lease)


def _raw_extension(item):
    """Marshal local objects without computing a Cloud projection in Python."""
    return {
        "extension_id": item.extension_id,
        "version": item.version,
        "name": item.name,
        "source": item.source,
        "executables": item.executables,
        "ecosystem_ids": item.ecosystem_ids,
        "risk_classes": item.risk_classes,
        "delegated_protection": item.delegated_protection,
        "permissions": [
            {
                "extension_id": item.extension_id,
                "permission_id": p.permission_id,
                "label": p.label,
                "configurable": p.configurable,
                "risk_tier": p.risk_tier,
                "typed_capabilities": p.typed_capabilities,
            }
            for p in item.permissions
        ],
    }


def prepare_installed_catalog_view(
    guard_home: Path, *, registry, guard_version: str, generated_at: str
) -> PreparedCatalogView:
    from ..catalog_delivery import discovery

    handle = discovery.require_handle(discovery.installed_discovery(guard_home), guard_home)
    # A root is metadata integrity only. Factory authentication remains required.
    observation = {
        "guard_home": str(guard_home.absolute()),
        "discovery_root": handle.root,
        "discovery_authority": handle.authority,
        "enforcement_catalog_digest": registry.catalog_digest,
        "guard_version": guard_version,
        "generated_at": generated_at,
    }
    # The native cache answers with a view this observation already produced, so
    # an unchanged catalog is not marshalled again one extension at a time.
    reused = native_call(guard_home, action="reuse", observation=observation)
    if reused:
        discovery.require_handle(handle, guard_home)
        return PreparedCatalogView.from_native(guard_home, reused)
    draft = native_call(guard_home, action="begin", observation=observation)["draft"]
    try:
        for item in registry.extensions:
            native_call(guard_home, action="append", draft=draft, entry=_raw_extension(item))
        discovery.require_handle(handle, guard_home)
        result = native_call(guard_home, action="finish", draft=draft)
        discovery.require_handle(handle, guard_home)
        return PreparedCatalogView.from_native(guard_home, result)
    except BaseException:
        with suppress(ValueError, RuntimeError, OSError):
            native_call(guard_home, action="abort", draft=draft)
        raise


def observed_view(session: dict[str, object], guard_home: Path | None = None) -> PreparedCatalogView:
    if guard_home is None:
        raise ValueError("Explicit Guard home required for native catalog observation")
    result = native_call(
        guard_home,
        action="observe",
        view_digest=session.get("extensionCatalogViewDigest"),
        enforcement_digest=session.get("extensionCatalogEnforcementDigest"),
        generated_at=session.get("extensionCatalogGeneratedAt"),
    )
    return PreparedCatalogView.from_native(guard_home, result)
