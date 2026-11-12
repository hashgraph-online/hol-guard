"""Forge extension-control authority records the way the runtime seals them.

The runtime owns sealing and verification. Tests use this to plant records
directly in a store, including legacy and malformed ones the runtime refuses
to write.
"""

from __future__ import annotations

import hashlib
import hmac
import json

from codex_plugin_scanner.guard.runtime.extension_control_authority import AuthorityAnchor

SNAPSHOT_PURPOSE = "extension-control.snapshot"
TRANSITION_PURPOSE = "extension-control.transition"
ANCHOR_PURPOSE = "extension-control.anchor"
_AUTH_DOMAIN = b"hol-guard.extension-control-authority.v1\0"


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def authenticated_record(payload: dict[str, object], *, key: bytes, purpose: str) -> tuple[str, str, str]:
    encoded = _canonical_json({"authority_schema_version": 1, "purpose": purpose, **payload})
    purpose_key = hmac.new(key, _AUTH_DOMAIN + purpose.encode("utf-8"), hashlib.sha256).digest()
    digest = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
    mac = hmac.new(purpose_key, encoded.encode("utf-8"), hashlib.sha256).hexdigest()
    return encoded, digest, mac


def anchor_to_json(anchor: AuthorityAnchor, *, key: bytes) -> str:
    encoded, digest, mac = authenticated_record(
        {"revision": anchor.revision, "snapshot_digest": anchor.snapshot_digest, "phase": anchor.phase.value},
        key=key,
        purpose=ANCHOR_PURPOSE,
    )
    return _canonical_json({"record": encoded, "digest": digest, "mac": mac})
