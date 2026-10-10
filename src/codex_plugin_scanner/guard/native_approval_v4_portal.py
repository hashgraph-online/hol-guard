"""Bounded browser proof-envelope validators for native approval V4.

This module mirrors the Portal transport shape only. Rust remains authoritative
for WebAuthn semantics, cryptography, policy, replay, and approval decisions.
"""

from __future__ import annotations

from . import native_approval_protocol as _base

_NATIVE_APPROVAL_MAX_STRING_BYTES = _base._NATIVE_APPROVAL_MAX_STRING_BYTES
_MAX_APPROVAL_TTL_MS = _base._MAX_APPROVAL_TTL_MS
_lower_hex = _base._lower_hex

_CHALLENGE_V4_KEYS = _base._CHALLENGE_KEYS | {"webauthn"}
