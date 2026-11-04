"""Cloud actions access for one AI tool, taken from the ``hol-guard connect`` pairing.

There is no separate Cloud actions sign-in. When an AI tool needs Cloud
actions, Guard exchanges this computer's pairing for short-lived access that
names that one AI tool (RFC 8693 token exchange at the pairing's own Guard
Cloud). The exchange is signed with the pairing's key, so only this computer
can ask for it, and Guard Cloud grants it only while the pairing is active and
still has Cloud actions turned on.

The access reaches the Cloud actions server only, and the pairing never
leaves Guard: it is presented to Guard Cloud's token endpoint and nowhere else.
Ending one AI tool's access, or all of them, goes through the same pairing.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from ..oauth_token_claims import decode_oauth_access_token_claims
from ..store import GuardStore
from .connect_cloud_actions import CLOUD_ACTIONS_RECONNECT_COMMAND, read_cloud_actions_connect_report
from .oauth_client import GuardDpopKeyMaterial, guard_api_base_path, resolve_guard_oauth_client_config

CLOUD_ACTIONS_RESOURCE_PATH = "/api/guard/gateway/mcp"
CLOUD_ACTIONS_REVOKE_PATH = "/api/guard/oauth/cloud-actions/revoke"
TOKEN_EXCHANGE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange"
ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"
_HTTP_TIMEOUT_SECONDS = 30
_MAX_RESPONSE_BYTES = 256 * 1024
_MAX_NONCE_RETRIES = 3


class CloudActionsAccessError(RuntimeError):
    """Cloud actions access could not be obtained or ended; ``reason`` is stable for scripts."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason


@dataclass(frozen=True, slots=True)
class CloudActionsPairing:
    """The parts of this computer's pairing that Cloud actions use."""

    origin: str
    workspace_id: str | None

    @property
    def gateway_resource(self) -> str:
        """The resource Guard Cloud names in the access; no path prefix."""

        return f"{self.origin}{CLOUD_ACTIONS_RESOURCE_PATH}"

    @property
    def gateway_url(self) -> str:
        """Where the Cloud actions server answers on this Guard Cloud."""

        return f"{self.origin}{guard_api_base_path(self.origin)}{CLOUD_ACTIONS_RESOURCE_PATH}"

    @property
    def revoke_url(self) -> str:
        return f"{self.origin}{guard_api_base_path(self.origin)}{CLOUD_ACTIONS_REVOKE_PATH}"


@dataclass(frozen=True, slots=True)
class CloudActionsAccess:
    access_token: str
    expires_at: float
    workspace_id: str
    scopes: tuple[str, ...]

    def expires_within(self, seconds: float, *, now: float | None = None) -> bool:
        return self.expires_at - (time.time() if now is None else now) <= seconds


_NOT_PAIRED_MESSAGE = f"This computer is not paired with Guard Cloud. Run {CLOUD_ACTIONS_RECONNECT_COMMAND} first."
_NATIVE_UNAVAILABLE_MESSAGE = (
    "Guard's native runtime is not available, so Cloud actions access was not used. "
    "Run hol-guard doctor, then try again."
)
_TURNED_OFF_MESSAGE = (
    f"Cloud actions are off for this computer. Run {CLOUD_ACTIONS_RECONNECT_COMMAND} again and choose "
    '"Let AI tools on this computer use Cloud actions".'
)


def open_paired_store(guard_home: Path) -> GuardStore:
    """The Guard store holding this computer's pairing; never creates a Guard home."""

    if not (guard_home / "guard.db").is_file():
        raise CloudActionsAccessError("not_paired", _NOT_PAIRED_MESSAGE)
    return GuardStore(guard_home)


def read_cloud_actions_pairing(store: GuardStore) -> CloudActionsPairing:
    """This computer's pairing, read locally; raises when there is none."""

    health = store.get_oauth_local_credential_health()
    issuer = health.get("issuer")
    if health.get("state") != "healthy" or not isinstance(issuer, str) or not issuer:
        raise CloudActionsAccessError("not_paired", _NOT_PAIRED_MESSAGE)
    try:
        origin = resolve_guard_oauth_client_config(issuer).issuer
    except ValueError:
        raise CloudActionsAccessError("not_paired", _NOT_PAIRED_MESSAGE) from None
    workspace_id = health.get("workspace_id")
    return CloudActionsPairing(
        origin=origin,
        workspace_id=workspace_id.lower() if isinstance(workspace_id, str) and workspace_id else None,
    )


def _check_not_turned_off(store: GuardStore) -> None:
    """Refuse early when the last connect said Cloud actions are off.

    Only a hint: Guard Cloud decides on every exchange, so an unknown answer
    still tries.
    """

    health = store.get_oauth_local_credential_health()
    grant_id = health.get("grant_id")
    report = read_cloud_actions_connect_report(store, grant_id=grant_id if isinstance(grant_id, str) else None)
    if report is not None and report["status"] == "off":
        raise CloudActionsAccessError("cloud_actions_off", _TURNED_OFF_MESSAGE)


def _pairing_auth_context(store: GuardStore) -> dict[str, object]:
    """The pairing's current access, refreshed when needed, with failures as access errors."""

    from ..runtime import runner

    try:
        return runner._resolve_guard_sync_auth_context(store)  # pyright: ignore[reportPrivateUsage]
    except (runner.GuardSyncAuthorizationExpiredError, runner.GuardSyncEndpointUntrustedError) as error:
        raise CloudActionsAccessError("pairing_expired", str(error)) from error
    except runner.GuardSyncNotAvailableError as error:
        raise CloudActionsAccessError("cloud_unreachable", str(error)) from error
    except runner._GuardOAuthRefreshRateLimitedError as error:  # pyright: ignore[reportPrivateUsage]
        raise CloudActionsAccessError(
            "rate_limited",
            f"Guard Cloud asked this computer to wait {error.retry_after_seconds} seconds. Try again after that.",
        ) from error


def exchange_cloud_actions_access(store: GuardStore, *, ai_tool: str) -> CloudActionsAccess:
    """Exchange the pairing for one AI tool's Cloud actions access."""

    from ..runtime import runner

    pairing = read_cloud_actions_pairing(store)
    _check_not_turned_off(store)
    credentials = store.get_oauth_local_credentials(allow_primary=True)
    client_id = credentials.get("client_id") if isinstance(credentials, dict) else None
    if not isinstance(client_id, str) or not client_id:
        raise CloudActionsAccessError("not_paired", _NOT_PAIRED_MESSAGE)
    auth_context = _pairing_auth_context(store)
    dpop_key_material = auth_context.get("dpop_key_material")
    if not isinstance(dpop_key_material, GuardDpopKeyMaterial):
        raise CloudActionsAccessError("pairing_expired", _NOT_PAIRED_MESSAGE)
    token_endpoint = resolve_guard_oauth_client_config(pairing.origin).token_endpoint
    body = urllib.parse.urlencode(
        {
            "grant_type": TOKEN_EXCHANGE_GRANT_TYPE,
            "client_id": client_id,
            "subject_token": str(auth_context["access_token"]),
            "subject_token_type": ACCESS_TOKEN_TYPE,
            "resource": pairing.gateway_resource,
            "requested_application_id": ai_tool,
        }
    ).encode("utf-8")
    nonce: str | None = None
    for _ in range(_MAX_NONCE_RETRIES + 1):
        proof = runner._sign_guard_dpop_proof(  # pyright: ignore[reportPrivateUsage]
            request_url=token_endpoint,
            method="POST",
            dpop_key_material=dpop_key_material,
            nonce=nonce,
        )
        request = urllib.request.Request(
            token_endpoint,
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
                "User-Agent": runner._GUARD_SYNC_USER_AGENT,  # pyright: ignore[reportPrivateUsage]
                "DPoP": proof,
            },
        )
        try:
            payload = _send_json(request)
        except urllib.error.HTTPError as error:
            answer = runner._http_error_payload(error)  # pyright: ignore[reportPrivateUsage]
            challenge = runner._dpop_nonce_from_http_error(error, answer)  # pyright: ignore[reportPrivateUsage]
            if challenge is not None and challenge != nonce:
                nonce = challenge
                continue
            raise _exchange_refused(error, answer) from error
        return read_cloud_actions_access(payload, pairing=pairing)
    raise CloudActionsAccessError("exchange_refused", "Guard Cloud kept asking for a new proof. Try again shortly.")


def _exchange_refused(error: urllib.error.HTTPError, answer: object) -> CloudActionsAccessError:
    code = answer.get("error") if isinstance(answer, Mapping) else None
    verdict = _native({"op": "refused", "status": error.code, "error": code if isinstance(code, str) else None})
    reason, message = verdict.get("reason"), verdict.get("message")
    if not isinstance(reason, str) or not isinstance(message, str):
        return _native_unavailable()
    return CloudActionsAccessError(reason, message)


def read_cloud_actions_access(
    payload: Mapping[str, object],
    *,
    pairing: CloudActionsPairing,
    now: float | None = None,
) -> CloudActionsAccess:
    """Accept the answer only when it is Cloud actions access for this pairing's workspace.

    The native runtime checks the answer and the token's claims; the token stays here.
    """

    token = payload.get("access_token")
    claims = decode_oauth_access_token_claims(token) if isinstance(token, str) else {}
    verdict = _native(
        {
            "op": "access",
            "token": isinstance(token, str) and bool(token),
            "token_type": payload.get("token_type"),
            "expires_in": payload.get("expires_in"),
            "scope": payload.get("scope"),
            "audience": claims.get("aud"),
            "workspace": claims.get("workspace"),
            "resource": pairing.gateway_resource,
            "workspace_id": pairing.workspace_id,
        }
    )
    if isinstance(refused := verdict.get("refused"), str):
        raise CloudActionsAccessError("access_invalid", refused)
    accepted = verdict.get("accepted")
    if not isinstance(token, str) or not isinstance(accepted, Mapping):
        raise _native_unavailable()
    workspace_id, scopes, expires_in = (accepted.get(key) for key in ("workspace_id", "scopes", "expires_in"))
    if not isinstance(workspace_id, str) or not isinstance(scopes, list) or not isinstance(expires_in, int):
        raise _native_unavailable()
    issued = time.time() if now is None else now
    return CloudActionsAccess(
        access_token=token,
        expires_at=issued + expires_in,
        workspace_id=workspace_id,
        scopes=tuple(str(scope) for scope in cast("list[object]", scopes)),
    )


def _native(request: dict[str, object]) -> Mapping[str, object]:
    """Ask the native ``cloud_actions_access`` kind; a request it cannot answer accepts no access."""

    from ..native_runner_authority import native_runner_authority

    try:
        return native_runner_authority("cloud_actions_access", request)
    except (ValueError, TypeError) as error:  # NativeRunnerAuthorityError is a ValueError
        raise _native_unavailable() from error


def _native_unavailable() -> CloudActionsAccessError:
    return CloudActionsAccessError("native_unavailable", _NATIVE_UNAVAILABLE_MESSAGE)


def revoke_cloud_actions_access(store: GuardStore, *, ai_tool: str | None) -> list[str]:
    """End Cloud actions access for one AI tool, or all of them; returns what Guard Cloud confirmed."""

    from ..runtime import runner

    pairing = read_cloud_actions_pairing(store)
    auth_context = _pairing_auth_context(store)
    request = runner._guard_sync_request(  # pyright: ignore[reportPrivateUsage]
        auth_context,
        request_url=pairing.revoke_url,
        method="POST",
        data=json.dumps({} if ai_tool is None else {"ai_tool": ai_tool}).encode("utf-8"),
    )
    try:
        payload = runner._urlopen_json_with_timeout_retry(  # pyright: ignore[reportPrivateUsage]
            request=request, timeout_seconds=_HTTP_TIMEOUT_SECONDS, retry_timeout_seconds=_HTTP_TIMEOUT_SECONDS
        )
    except urllib.error.HTTPError as error:
        raise CloudActionsAccessError(
            "revoke_refused", f"Guard Cloud did not end Cloud actions access (HTTP {error.code})."
        ) from error
    except (OSError, RuntimeError) as error:
        raise CloudActionsAccessError("cloud_unreachable", "Guard Cloud could not be reached.") from error
    revoked = payload.get("revoked_ai_tools")
    if not isinstance(revoked, list):
        raise CloudActionsAccessError("revoke_refused", "Guard Cloud's answer did not say what it ended.")
    return [item for item in revoked if isinstance(item, str)]


def _send_json(request: urllib.request.Request) -> Mapping[str, object]:
    from ..mdm.network import managed_urlopen

    try:
        with managed_urlopen(request, timeout=_HTTP_TIMEOUT_SECONDS) as response:
            raw = response.read(_MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError:
        raise
    except OSError as error:
        raise CloudActionsAccessError("cloud_unreachable", "Guard Cloud could not be reached.") from error
    if len(raw) > _MAX_RESPONSE_BYTES:
        raise CloudActionsAccessError("access_invalid", "Guard Cloud's answer was too large.")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise CloudActionsAccessError("access_invalid", "Guard Cloud's answer could not be read.") from None
    if not isinstance(payload, dict):
        raise CloudActionsAccessError("access_invalid", "Guard Cloud's answer could not be read.")
    return payload  # pyright: ignore[reportUnknownVariableType]


__all__ = [
    "CLOUD_ACTIONS_RESOURCE_PATH",
    "CloudActionsAccess",
    "CloudActionsAccessError",
    "CloudActionsPairing",
    "exchange_cloud_actions_access",
    "open_paired_store",
    "read_cloud_actions_access",
    "read_cloud_actions_pairing",
    "revoke_cloud_actions_access",
]
