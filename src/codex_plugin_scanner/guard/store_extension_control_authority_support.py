"""Shared validation, credential, and row helpers for extension-control authority."""

# pyright: reportAttributeAccessIssue=false, reportPrivateUsage=false, reportUnknownMemberType=false, reportUninitializedInstanceVariable=false

from __future__ import annotations

import base64
import hashlib
import hmac
import sqlite3
import sys
from collections.abc import Generator
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import cast

from .runtime.extension_control_authority import (
    AuthorityAnchor,
    AuthorityHealth,
    ExtensionControlAuthorityError,
    ExtensionControlAuthorityView,
    anchor_from_json,
    anchor_to_json,
)
from .runtime.extension_control_contract import ControlLayerKind, ExtensionControlLayer
from .runtime.extension_control_resolver import compose_control_layers
from .store_base import EncryptedFileSecretStore, SecretStore, SystemKeyringSecretStore

_KEY_REF_SUFFIX = ":authentication-key"
_ANCHOR_REF_SUFFIX = ":anchor"
_MAX_TRANSITION_ID_LENGTH = 256
_MAX_CONTROLS_PER_LAYER = 512
_MAX_SERIALIZED_LAYERS_BYTES = 256 * 1024


class _ExtensionControlAuthoritySupportMixin:
    def _authority_key(self, *, required: bool) -> bytes | None:
        try:
            value = self._secret_store().get_secret(self._key_ref())
        except Exception as exc:
            if required:
                raise ExtensionControlAuthorityError("extension control credential store unavailable") from exc
            raise
        if value is None:
            if required:
                raise ExtensionControlAuthorityError("extension control authentication key missing")
            return None
        try:
            key = base64.urlsafe_b64decode(value.encode("ascii"))
        except (ValueError, UnicodeEncodeError) as exc:
            raise ExtensionControlAuthorityError("invalid extension control authentication key") from exc
        if len(key) != 32:
            raise ExtensionControlAuthorityError("invalid extension control authentication key")
        return key

    def _read_anchor(self, *, key: bytes) -> AuthorityAnchor | None:
        value = self._secret_store().get_secret(self._anchor_ref())
        return None if value is None else anchor_from_json(value, key=key)

    def _write_and_verify_anchor(self, anchor: AuthorityAnchor, *, key: bytes) -> None:
        encoded = anchor_to_json(anchor, key=key)
        self._secret_store().set_secret(self._anchor_ref(), encoded)
        observed = self._secret_store().get_secret(self._anchor_ref())
        if observed != encoded:
            raise ExtensionControlAuthorityError("extension control anchor read-back mismatch")

    def _secret_store(self) -> SecretStore:
        current = self._extension_control_authority_secret_store
        if current is None:
            if sys.platform == "darwin":
                current = EncryptedFileSecretStore(cast(Path, self.guard_home))
            else:
                current = SystemKeyringSecretStore(service_name="hol-guard.extension-control-authority")
            self._extension_control_authority_secret_store = current
        if isinstance(current, SystemKeyringSecretStore) and not current._is_available():
            raise RuntimeError("extension control credential store unavailable")
        return current

    def _authority_ref_prefix(self) -> str:
        home = str(cast(Path, self.guard_home).resolve())
        return "extension-control:" + hashlib.sha256(home.encode("utf-8")).hexdigest()[:20]

    def _key_ref(self) -> str:
        return self._authority_ref_prefix() + _KEY_REF_SUFFIX

    def _anchor_ref(self) -> str:
        return self._authority_ref_prefix() + _ANCHOR_REF_SUFFIX

    @contextmanager
    def _extension_control_authority_lock(self) -> Generator[None, None, None]:
        with self._hold_advisory_file_lock(
            path=cast(Path, self.guard_home) / "extension-control-authority.lock",
            timeout_seconds=30.0,
            poll_seconds=0.05,
            timeout_message="Timed out waiting for the extension control authority lock.",
        ):
            yield

    @staticmethod
    def _validate_layers(layers: tuple[ExtensionControlLayer, ...], catalog_digest: str) -> None:
        if len(layers) > len(ControlLayerKind):
            raise ExtensionControlAuthorityError("too many extension control layers")
        if any(len(layer.controls) > _MAX_CONTROLS_PER_LAYER for layer in layers):
            raise ExtensionControlAuthorityError("too many extension controls in layer")
        if any(layer.catalog_digest != catalog_digest for layer in layers):
            raise ExtensionControlAuthorityError("extension control catalog digest mismatch")
        composed = compose_control_layers(layers)
        if composed.failures:
            raise ExtensionControlAuthorityError("invalid extension control layers")
        if len({layer.kind for layer in layers}) != len(layers):
            raise ExtensionControlAuthorityError("duplicate extension control layer")
        if any(layer.kind not in {ControlLayerKind.LOCAL_ADMIN, ControlLayerKind.SIGNED_CLOUD} for layer in layers):
            raise ExtensionControlAuthorityError("invalid extension control layer kind")

    @classmethod
    def _validate_commit_input(
        cls,
        layers: tuple[ExtensionControlLayer, ...],
        *,
        catalog_digest: str,
        actor_id: str,
        expected_revision: int,
        idempotency_key: str,
        nonce: str,
    ) -> None:
        cls._validate_layers(layers, catalog_digest)
        if type(expected_revision) is not int or expected_revision < 0:
            raise ExtensionControlAuthorityError("invalid expected authority revision")
        identities = (actor_id, idempotency_key, nonce)
        if any(not value.strip() or len(value) > _MAX_TRANSITION_ID_LENGTH for value in identities):
            raise ExtensionControlAuthorityError("invalid extension control transition identity")

    @staticmethod
    def _validate_serialized_layers(layers_json: str) -> None:
        if len(layers_json.encode("utf-8")) > _MAX_SERIALIZED_LAYERS_BYTES:
            raise ExtensionControlAuthorityError("extension control layers exceed storage limit")

    def _degraded_view(self, catalog_digest: str) -> ExtensionControlAuthorityView:
        health = (
            AuthorityHealth.DEGRADED_ACKNOWLEDGED
            if self._extension_control_degraded_acknowledged
            else AuthorityHealth.DEGRADED_UNACKNOWLEDGED
        )
        return ExtensionControlAuthorityView(health, 0, catalog_digest, ())

    @staticmethod
    def _tampered_view(catalog_digest: str) -> ExtensionControlAuthorityView:
        return ExtensionControlAuthorityView(AuthorityHealth.TAMPERED, 0, catalog_digest, ())


def _row_str(row: sqlite3.Row, name: str) -> str:
    value = cast(object, row[name])
    if not isinstance(value, str):
        raise ExtensionControlAuthorityError("invalid extension control authority row")
    return value


def _row_optional_str(row: sqlite3.Row, name: str) -> str | None:
    value = cast(object, row[name])
    if value is not None and not isinstance(value, str):
        raise ExtensionControlAuthorityError("invalid extension control authority row")
    return value


def _row_int(row: sqlite3.Row, name: str) -> int:
    value = cast(object, row[name])
    if type(value) is not int:
        raise ExtensionControlAuthorityError("invalid extension control authority row")
    return value


def _private_hash(value: str, *, key: bytes, purpose: str) -> str:
    framed = b"hol-guard.extension-control.private-ref.v1\x00" + purpose.encode("ascii")
    return hmac.new(key, framed + b"\x00" + value.encode("utf-8"), hashlib.sha256).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
