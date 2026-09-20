"""Signed managed controls for probes using the verified loopback TLS fixture.

Enrollment and trust remain synthetic inputs inherited from SignedPolicyFixture.
No policy authority, runtime capability, acknowledgement or receipt is seeded.
These payloads are fixture-authored, not evidence of a production builder flow.
"""

from __future__ import annotations

import copy
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path
from uuid import NAMESPACE_OID, uuid5

from ci.native_runtime.installed_scoped_policy_fixture import SignedPolicyFixture
from codex_plugin_scanner.guard.managed_controls_policy_bundle import (
    parsed_managed_controls_from_validated_policy_bundle,
    signed_cloud_extension_projection_digest,
)
from codex_plugin_scanner.guard.managed_controls_policy_fields import (
    EXTENSION_CONTROL_LAYER_CAPABILITY,
    HOL_EXTENSION_CONTROLS_FIELD,
    HOL_EXTENSION_CONTROLS_SCHEMA_VERSION,
    MANAGED_CONTROLS_ATOMIC_APPLY_CAPABILITY,
    POLICY_EXTENSION_TARGETS_CAPABILITY,
    ManagedControlsPolicyError,
    is_mapping,
)
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_catalog_sync import validate_extension_catalog_wire


class ManagedPolicyFixture(SignedPolicyFixture):
    """Deliver controls and defaults through the existing signed TLS transport."""

    def __init__(self, root: Path) -> None:
        self.negotiated_capabilities: tuple[str, ...] = ()
        self.runtime_session: dict[str, object] | None = None
        self.catalog_digest: str | None = None
        self.catalog_uploads = 0
        super().__init__(root)

    def response_for_request(self, path: str, request: dict[str, object]) -> dict[str, object]:
        if path == "/api/guard/runtime/sessions/sync":
            session = request.get("session")
            advertised = session.get("managedControlsCapabilities") if isinstance(session, dict) else None
            supported = (
                EXTENSION_CONTROL_LAYER_CAPABILITY,
                POLICY_EXTENSION_TARGETS_CAPABILITY,
                MANAGED_CONTROLS_ATOMIC_APPLY_CAPABILITY,
            )
            self.negotiated_capabilities = tuple(
                item for item in supported if isinstance(advertised, list) and item in advertised
            )
            self.runtime_session = copy.deepcopy(session) if isinstance(session, dict) else None
            digest = session.get("extensionCatalogDigest") if isinstance(session, dict) else None
            if not isinstance(digest, str) or not is_mapping(session):
                return {"syncedAt": datetime.now(timezone.utc).isoformat(), "items": []}
            known = self.catalog_digest == digest
            return {
                "syncedAt": datetime.now(timezone.utc).isoformat(),
                "items": [{"sessionId": session.get("sessionId"), "deviceId": session.get("deviceId")}],
                "extensionCatalogSync": {
                    "catalogDigest": digest,
                    "catalogKnown": known,
                    "uploadRequired": not known,
                    "uploadPath": "/api/guard/runtime/extension-catalog/sync",
                },
            }
        if path == "/api/guard/runtime/extension-catalog/sync":
            try:
                catalog = validate_extension_catalog_wire(request.get("catalog"))
            except (TypeError, ValueError):
                return {"accepted": False}
            digest = catalog["catalogDigest"]
            if (
                self.runtime_session is None
                or digest != self.runtime_session.get("extensionCatalogDigest")
                or request.get("idempotencyKey") != f"catalog:{digest}"
            ):
                return {"accepted": False}
            known = self.catalog_digest == digest
            self.catalog_digest = digest
            self.catalog_uploads += 1
            now = datetime.now(timezone.utc).isoformat()
            return {
                "schemaVersion": "guard.extension-catalog-sync.v1",
                "accepted": True,
                "catalogDigest": digest,
                "alreadyKnown": known,
                "deviceCount": 1,
                "firstSeenAt": now,
                "lastSeenAt": now,
            }
        response = super().response_for_request(path, request)
        if path == "/api/guard/receipts/sync":
            response["managedControlsCapabilities"] = list(self.negotiated_capabilities)
            delivery = self._managed_delivery()
            if delivery is not None:
                response["policyBundleDelivery"] = delivery
        return response

    def _managed_delivery(self) -> dict[str, object] | None:
        """Correlate delivery with the runtime request actually received over TLS.

        No receiver Store state is read or written here. Deliberately invalid
        controls remain deliverable, so the real parser supplies their refusal.
        """
        bundle, session = self.bundle, self.runtime_session
        if bundle is None or session is None or self.catalog_digest != session.get("extensionCatalogDigest"):
            return None
        try:
            parsed = parsed_managed_controls_from_validated_policy_bundle(
                bundle,
                registry=BUILT_IN_COMMAND_EXTENSION_REGISTRY,
                negotiated_capabilities=frozenset(self.negotiated_capabilities),
            )
        except ManagedControlsPolicyError:
            return None
        payload = bundle["payload"]
        assert is_mapping(payload)
        metadata = payload["metadata"]
        assert is_mapping(metadata)
        rollback = bundle.get("rollback")
        identity = (
            f"{bundle['bundleHash']}:{session.get('sessionId')}:"
            f"{session.get('extensionAuthorityRevision')}:{session.get('effectiveProjectionDigest')}"
        )
        assert isinstance(self.catalog_digest, str)
        return {
            "bundleId": metadata["id"],
            "bundleHash": bundle["bundleHash"],
            "bundleVersion": bundle["bundleVersion"],
            "workspaceId": bundle["workspaceId"],
            "deviceId": session.get("deviceId"),
            "runtimeSessionId": session.get("sessionId"),
            "deliveryId": str(uuid5(NAMESPACE_OID, identity)),
            "policyRevision": metadata["revision"],
            "extensionAuthorityRevision": session.get("extensionAuthorityRevision"),
            "catalogDigest": self.catalog_digest,
            "effectiveProjectionDigest": session.get("effectiveProjectionDigest"),
            "payloadHash": bundle["payloadHash"],
            "extensionProjectionDigest": signed_cloud_extension_projection_digest(
                parsed, catalog_digest=self.catalog_digest
            ),
            "lastKnownGoodBundleHash": rollback.get("lastGoodBundleHash") if is_mapping(rollback) else None,
        }

    def signed_managed_bundle(
        self,
        version: int,
        *,
        controls: Sequence[Mapping[str, str]] = (),
        lockdown: bool = False,
        defaults: Mapping[str, str] | None = None,
        authority_mode: str = "managed-restrictive",
    ) -> dict[str, object]:
        """Sign a rule-free payload, including deliberate parser refusal cases.

        Enabled controls are not normalized or silently removed: callers can
        deliver them to prove that actual validation refuses weaker authority.
        """
        bundle = self.signed_bundle(version)
        payload = bundle["payload"]
        assert is_mapping(payload)
        spec = payload["spec"]
        assert is_mapping(spec)
        spec["rules"] = []
        if defaults is not None:
            spec["defaults"] = dict(defaults)
        payload[HOL_EXTENSION_CONTROLS_FIELD] = {
            "schemaVersion": HOL_EXTENSION_CONTROLS_SCHEMA_VERSION,
            "authorityMode": authority_mode,
            "controls": [dict(control) for control in controls],
            **({"globalLockdown": True} if lockdown else {}),
        }
        return self.sign(bundle)
