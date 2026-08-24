"""Canonical OAuth target binding for Guard Review surfaces."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


class GuardReviewContractError(ValueError):
    """Raised when a Guard Review backend contract is malformed or unsafe."""


@dataclass(frozen=True, slots=True)
class GuardReviewOAuthMetadata:
    device_id: str
    grant_id: str | None
    installation_id: str
    machine_id: str
    runtime_id: str | None
    workspace_id: str


class _OAuthBindingStore(Protocol):
    def get_oauth_local_credentials(self, *, allow_primary: bool = False) -> dict[str, object] | None: ...
    def get_or_create_installation_id(self) -> str: ...


def guard_review_oauth_metadata(
    store: _OAuthBindingStore,
    *,
    require_device_dpop_binding: bool = False,
) -> GuardReviewOAuthMetadata:
    credentials = store.get_oauth_local_credentials(allow_primary=False)
    if not isinstance(credentials, dict):
        raise GuardReviewContractError("missing_oauth_credentials")
    installation_id = _text(store.get_or_create_installation_id())
    machine_id = _text(credentials.get("machine_id"))
    explicit_device_id = _text(credentials.get("device_id"))
    device_id = explicit_device_id if require_device_dpop_binding else explicit_device_id or machine_id
    dpop_thumbprint = _text(credentials.get("dpop_public_jwk_thumbprint"))
    workspace_id = _text(credentials.get("workspace_id"))
    if installation_id is None or machine_id is None or device_id is None or workspace_id is None:
        raise GuardReviewContractError("missing_oauth_binding")
    if require_device_dpop_binding and (dpop_thumbprint is None or device_id != dpop_thumbprint):
        raise GuardReviewContractError("oauth_device_binding_mismatch")
    return GuardReviewOAuthMetadata(
        device_id=device_id,
        grant_id=_text(credentials.get("grant_id")),
        installation_id=installation_id,
        machine_id=machine_id,
        runtime_id=_text(credentials.get("runtime_id")),
        workspace_id=workspace_id,
    )


def _text(value: object) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


__all__ = ["GuardReviewContractError", "GuardReviewOAuthMetadata", "guard_review_oauth_metadata"]
