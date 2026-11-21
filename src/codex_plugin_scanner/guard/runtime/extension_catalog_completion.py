"""Authenticated HTTP/session marshaling; completion authority stays native."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path

from ..oauth_token_claims import decode_oauth_access_token_claims, oauth_claim_string
from .extension_catalog_pages import encoded, native_call, observed_view

_UNBOUND = object()


def credential_identity(auth_context):
    token = auth_context.get("access_token")
    if not isinstance(token, str) or not auth_context.get("dpop_key_material"):
        raise RuntimeError("Catalog completion requires OAuth/DPoP authentication")
    claims = decode_oauth_access_token_claims(token)
    identity = {
        "ownerUserId": oauth_claim_string(claims, "sub"),
        "workspaceId": oauth_claim_string(claims, "workspace", "workspaceId"),
        "deviceId": oauth_claim_string(claims, "machine", "deviceId")
        or oauth_claim_string(claims, "machine", "machineId"),
        "runtimeId": oauth_claim_string(claims, "runtime", "runtimeId"),
    }
    if not all(identity.values()):
        raise RuntimeError("Catalog OAuth credential lacks enrolled identity")
    # Claims are not independently trusted: native requires their exact match
    # to a receipt bound by the server to this actually authenticated token.
    return identity, hashlib.sha256(token.encode()).hexdigest()


def current_catalog_registry(store):
    from ..catalog_delivery.projection import capture
    from ..managed_controls_policy_fields import ManagedControlsPolicyError
    from ..native_command_control_projection import read_control_projection

    try:
        metadata, registry, record_digest = capture(store)
        binding, _ = read_control_projection(store, metadata, None, registry=registry, record_digest=record_digest)
    except (OSError, RuntimeError, TypeError, ValueError) as error:
        raise ManagedControlsPolicyError(
            "policy_local_view_invalid", "Authenticated active catalog is unavailable."
        ) from error
    if binding.get("health") != "protected" or binding.get("catalog_digest") != registry.catalog_digest:
        raise ManagedControlsPolicyError(
            "policy_local_view_invalid", "Current native enforcement catalog is unavailable."
        )
    return registry


def local_observation(view, registry):
    from ..catalog_delivery import discovery

    handle = discovery.require_handle(discovery.installed_discovery(view.guard_home), view.guard_home)
    if (handle.root, handle.authority) != (view.discovery_root, view.discovery_authority):
        raise RuntimeError("Catalog discovery changed in flight")
    return {
        "guard_home": str(view.guard_home.absolute()),
        "discovery_root": handle.root,
        "discovery_authority": handle.authority,
        "enforcement_catalog_digest": registry.catalog_digest,
        "guard_version": view.manifest["guardVersion"],
        "generated_at": view.manifest["generatedAt"],
    }


def complete_authenticated_view(*, store, view, auth_context, url, send):
    from urllib.parse import urlsplit

    from ..cli.oauth_client import validate_guard_sync_endpoint
    from ..native_command_control_authority_io import hold_command_control_authority_lock

    identity, binding = credential_identity(auth_context)
    claims = decode_oauth_access_token_claims(auth_context["access_token"])
    issuer = oauth_claim_string(claims, "iss")
    if issuer is None or urlsplit(url).scheme != "https":
        raise RuntimeError("Catalog completion requires the fixed OAuth HTTPS origin")
    validate_guard_sync_endpoint(url, issuer=issuer)
    observation = local_observation(view, current_catalog_registry(store))
    request = dict(token=view.token, observation=observation, origin=url, credential_binding=binding, identity=identity)
    body = native_call(view.guard_home, action="completion_begin", **request)
    response = send(url, encoded(body))
    # Re-capture authenticated activation/custom authority after HTTP, then
    # exclude activation mutations through native stamp publication.
    registry = current_catalog_registry(store)
    with hold_command_control_authority_lock(store.guard_home, shared=True):
        current = local_observation(view, current_catalog_registry(store))
        if registry.catalog_digest != current["enforcement_catalog_digest"] or current != observation:
            raise RuntimeError("Catalog enforcement changed in flight")
        receipt = native_call(view.guard_home, action="completion_accept", response=response, **request)
    return {
        "policyMetadataIdentity": receipt["identity"],
        "policyMetadataObservedAt": receipt["observedAt"],
        "runtime_credential_id": identity["runtimeId"],
    }


def local_policy_view(
    *, guard_home: Path, runtime_summary: dict[str, object], registry, policy_workspace_id: object = _UNBOUND
) -> dict[str, object]:
    """Marshal a previously authenticated session and current local discovery.

    No metadata, enforcement digest or filesystem location from a policy
    response is accepted here; missing authenticated observation identity fails
    closed. A caller binding this view to a signed policy envelope passes that
    envelope's workspace; the native runtime, not this module, decides whether
    it matches.
    """
    from ..catalog_delivery import discovery
    from .extension_catalog_pages import native_call

    view = observed_view(runtime_summary, guard_home)
    handle = discovery.require_handle(discovery.installed_discovery(guard_home), guard_home)
    bound = {} if policy_workspace_id is _UNBOUND else {"policy_workspace_id": policy_workspace_id}
    return native_call(
        guard_home,
        action="policy_view",
        **bound,
        runtime_summary={
            "policyMetadataIdentity": runtime_summary.get("policyMetadataIdentity"),
            "policyMetadataObservedAt": runtime_summary.get("policyMetadataObservedAt"),
            "runtime_credential_id": runtime_summary.get("runtime_credential_id"),
            "runtime_device_id": runtime_summary.get("runtime_device_id"),
        },
        view={
            "token": view.token,
            "manifest": view.manifest,
            "discovery_root": view.discovery_root,
            "discovery_authority": view.discovery_authority,
        },
        discovery={"root": handle.root, "authority": handle.authority},
        enforcement_catalog_digest=registry.catalog_digest,
        now=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    )


def policy_view_ready(*, store, registry) -> bool:
    """A native policy view is itself the readiness proof for the session.

    The runtime validates the authenticated completed observation before
    returning one, and an older resident cannot answer the request at all.
    """
    summary = getattr(store, "get_sync_payload", lambda _key: None)("runtime_session_summary")
    if not isinstance(summary, dict):
        return False
    try:
        local_policy_view(guard_home=store.guard_home, runtime_summary=summary, registry=registry)
    except (ImportError, OSError, RuntimeError, TypeError, ValueError):
        return False
    return True
