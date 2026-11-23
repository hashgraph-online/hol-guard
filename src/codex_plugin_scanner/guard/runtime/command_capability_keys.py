"""How the command-capability bridge hands the policy-integrity key to the resident.

The HMAC, the canonical bytes it covers and every comparison against them
live in the resident, which reads the key from its own vault when the store
is the plain encrypted-file vault. This module reads the key out of the
secret store only for callers whose key the resident cannot read itself, and
decides when one has to be minted, which is provisioning, not a verdict.
"""

from __future__ import annotations

import base64
from pathlib import Path

from ..native_command_capability import (
    COMMAND_CAPABILITY_RESIDENT_KEY_FEATURE,
    CommandCapabilityUnavailableError,
)
from ..native_command_envelope import (
    COMMAND_ENVELOPE_RESIDENT_KEY_FEATURE,
    CommandEnvelopeUnavailableError,
    native_command_envelope,
)
from ..native_runtime import native_runtime_status
from ..store import GuardStore
from ..store_base import EncryptedFileSecretStore


class CommandCapabilityError(ValueError):
    """Fail-closed command capability or lease validation error."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _envelope(
    store: GuardStore,
    action: str,
    payload: object,
    *,
    create_key: bool = False,
) -> object:
    """One signed-envelope answer from the runtime, or its refusal raised.

    The HMAC, the canonical bytes it covers and every comparison against them
    live in the resident. A store kept in the plain vault lets the resident
    read the key itself; any other store reads the key out here and sends it.
    This side also decides when a key has to be minted, which is provisioning,
    not a verdict.
    """

    home = _resident_home(store)
    resident_key = action != "digest" and _resident_reads_key(store, COMMAND_ENVELOPE_RESIDENT_KEY_FEATURE)
    if action == "digest" or resident_key:
        # The runtime digests the payload alone and never reads the key for
        # this action, so reading the policy integrity secret out of the store
        # and putting it on the socket for every replay row and approval match
        # would spend the secret for nothing. A store kept in the plain vault
        # is one the resident reads itself, so its key stays off the socket
        # too; this side only mints it when the caller issues a capability.
        key_b64, key_id = None, None
        if resident_key and create_key:
            store._policy_integrity_secret_material(create=True)
    else:
        key_b64, key_id = _signing_material_for_resident(store, create=create_key)
    try:
        answer = native_command_envelope(
            action=action,
            payload=payload,
            integrity_key_b64=key_b64,
            integrity_key_id=key_id,
            guard_home=home,
            resident_key=resident_key,
        )
    except CommandEnvelopeUnavailableError as error:
        # Every caller of this module already reads a `CommandCapabilityError`
        # as a fail-closed refusal: the queue poll records it on the job result
        # and the CLI prints it as `{"status": "error"}` with exit code 2. A
        # resident that gives no answer is the same refusal, so it reaches them
        # as one and keeps its own code.
        raise CommandCapabilityError(CommandEnvelopeUnavailableError.reason) from error
    if not answer.get("accepted"):
        raise CommandCapabilityError(str(answer.get("reason") or "signed_payload_missing"))
    return answer.get("result")


def _resident_home(store: GuardStore) -> Path:
    """The Guard home the resident answers for, or no answer at all."""

    guard_home = getattr(store, "guard_home", None)
    if not isinstance(guard_home, Path):
        raise CommandCapabilityUnavailableError
    return guard_home


def _verify_key(store: GuardStore) -> tuple[bool, str | None, str | None]:
    """How the capability verdict hands the resident its key.

    ``(True, None, None)`` when the resident reads the key from its own vault,
    so the key stays off the socket; otherwise ``(False, key, key_id)`` with
    the caller's copy, or a missing pair the resident refuses itself.
    """

    if _resident_reads_key(store, COMMAND_CAPABILITY_RESIDENT_KEY_FEATURE):
        return True, None, None
    key_b64, key_id = _signing_material_for_resident(store)
    return False, key_b64, key_id


def _resident_reads_key(store: GuardStore, feature: str) -> bool:
    """Whether the resident can read the policy-integrity key for this store.

    Only the plain encrypted-file vault qualifies. A system keyring, or a
    store that mirrors one, may hold a key the resident cannot read, so those
    callers keep sending their own copy. A resident that does not advertise
    ``feature`` predates reading the key itself, so the caller sends its copy
    to that resident too rather than asking for a request it cannot answer.
    """

    if type(getattr(store, "_policy_integrity_secret_store", None)) is not EncryptedFileSecretStore:
        return False
    return _resident_has(feature)


def _resident_has(feature: str) -> bool:
    """Whether the running resident advertises ``feature``.

    A status that cannot be read answers no, so the caller sends its own key;
    the request itself then fails closed if the resident is really down.
    """

    try:
        status = native_runtime_status()
    except Exception:
        return False
    capabilities = status.capabilities
    if not status.available or not status.compatible or capabilities is None:
        return False
    return feature in capabilities.features


def _signing_material_for_resident(store: GuardStore, *, create: bool = False) -> tuple[str | None, str | None]:
    """The local signing secret as the resident takes it, or a missing pair.

    A store with no key is not an error here: the resident answers
    ``local_signing_key_unavailable`` itself, in the same place it would have
    refused a key that does not match the envelope. ``create`` mints the key
    for the one caller that issues a capability; whether the envelope it goes
    on is genuine is still the runtime's answer.
    """

    key, key_id = store._policy_integrity_secret_material(create=create)
    if not isinstance(key, bytes) or not isinstance(key_id, str):
        return None, None
    return base64.urlsafe_b64encode(key).rstrip(b"=").decode("ascii"), key_id
