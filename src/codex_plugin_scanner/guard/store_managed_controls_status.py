"""Public, redacted projection of authenticated managed-control state."""

from __future__ import annotations

import json
import sqlite3
from typing import TYPE_CHECKING

from .managed_controls_policy_bundle import (
    MANAGED_CONTROLS_ACTIVE_STATE_KEY,
    managed_controls_layers_from_activation_state,
)
from .runtime.extension_control_authority import ExtensionControlAuthorityError


class ManagedControlsStatusUnavailableError(RuntimeError):
    """Managed status could not be projected without weakening the base API."""


def _bounded_string(state: dict[str, object], field: str, limit: int = 160) -> str | None:
    value = state.get(field)
    return value[:limit] if isinstance(value, str) and value else None


class StoreManagedControlsStatusMixin:
    if TYPE_CHECKING:

        def get_sync_payload(self, state_key: str) -> dict[str, object] | list[object] | None: ...

        def _authority_key(self, *, required: bool) -> bytes | None: ...

    def managed_controls_public_status(self, *, catalog_digest: str) -> dict[str, object] | None:
        """Return a bounded projection; redact persistence and credential failures."""

        try:
            state = self.get_sync_payload(MANAGED_CONTROLS_ACTIVE_STATE_KEY)
            if not isinstance(state, dict):
                return None
            key = self._authority_key(required=False)
            if key is None:
                return None
            _layers, managed_revision = managed_controls_layers_from_activation_state(
                state,
                catalog_digest=catalog_digest,
                authority_key=key,
            )
        except (json.JSONDecodeError, sqlite3.Error, ExtensionControlAuthorityError) as exc:
            raise ManagedControlsStatusUnavailableError("managed controls status unavailable") from exc

        acknowledgement = state.get("acknowledgement")
        if not isinstance(acknowledgement, dict):
            return None
        status = acknowledgement.get("status")
        acknowledgement_payload: dict[str, object] = {
            "extension_authority_revision": managed_revision,
            "status": status if isinstance(status, str) else "unknown",
        }
        policy_revision = acknowledgement.get("policyRevision")
        if isinstance(policy_revision, (str, int)) and not isinstance(policy_revision, bool):
            acknowledgement_payload["policy_revision"] = policy_revision
        projection_digest = acknowledgement.get("effectiveProjectionDigest")
        if isinstance(projection_digest, str) and len(projection_digest) == 64:
            acknowledgement_payload["effective_projection_digest"] = projection_digest

        result: dict[str, object] = {
            "bundle_version": state.get("bundleVersion"),
            "workspace_id": _bounded_string(state, "workspaceId"),
            "catalog_digest": catalog_digest,
            "acknowledgement": acknowledgement_payload,
        }
        authority_mode = _bounded_string(state, "authorityMode", 40)
        if authority_mode is not None:
            result["authority_mode"] = authority_mode
        for source, target in (
            ("controlSetId", "control_set_id"),
            ("controlSetName", "control_set_name"),
            ("issuedAt", "issued_at"),
            ("expiresAt", "expires_at"),
        ):
            value = _bounded_string(state, source)
            if value is not None:
                result[target] = value
        return result
