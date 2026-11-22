"""Native digest and shape of the stored Guard Cloud sign-in record."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol

_STAMP = re.compile(r"[0-9a-f]{64}")


class _NativeStore(Protocol):
    _oauth_local_credentials_state_key: str

    def _native_store_call(
        self, method: str, args: Mapping[str, object], *, busy_timeout_seconds: float | None = None
    ) -> Any: ...


def oauth_sign_in_stamp_from_native(answer: object) -> str | None:
    """Check the native answer: a SHA-256 hex digest, or ``None`` for no readable record."""

    if not isinstance(answer, dict) or set(answer) != {"stamp"}:
        raise RuntimeError("native oauth_sign_in_stamp returned no answer")
    stamp = answer["stamp"]
    if stamp is None:
        return None
    if not isinstance(stamp, str) or _STAMP.fullmatch(stamp) is None:
        raise RuntimeError("native oauth_sign_in_stamp returned no answer")
    return stamp


@dataclass(frozen=True)
class OAuthSignInPresence:
    """Whether a sign-in record is stored, and whether it names a device."""

    present: bool
    device_bound: bool

    @classmethod
    def from_native(cls, answer: object) -> OAuthSignInPresence:
        if not isinstance(answer, dict) or set(answer) != {"present", "device_bound"}:
            raise RuntimeError("native oauth_sign_in_presence returned no answer")
        present, device_bound = answer["present"], answer["device_bound"]
        if not isinstance(present, bool) or not isinstance(device_bound, bool) or (device_bound and not present):
            raise RuntimeError("native oauth_sign_in_presence returned no answer")
        return cls(present=present, device_bound=device_bound)


class StoreOAuthSignInStampMixin:
    """A digest of the stored sign-in record; the record itself stays in the store."""

    def oauth_sign_in_stamp(self: _NativeStore) -> str | None:
        """The digest of this source's stored sign-in record, or ``None`` when there is none."""

        answer = self._native_store_call("oauth_sign_in_stamp", {"state_key": self._oauth_local_credentials_state_key})
        return oauth_sign_in_stamp_from_native(answer)

    def oauth_sign_in_presence(self: _NativeStore, state_key: str) -> OAuthSignInPresence:
        """Whether the sign-in record under ``state_key`` is stored and names a device."""

        answer = self._native_store_call("oauth_sign_in_presence", {"state_key": state_key})
        return OAuthSignInPresence.from_native(answer)


__all__ = ["OAuthSignInPresence", "StoreOAuthSignInStampMixin", "oauth_sign_in_stamp_from_native"]
