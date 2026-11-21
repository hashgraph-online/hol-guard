#!/usr/bin/env python3
"""Record policy-integrity row vectors from the ORIGINAL Python signer.

The Python implementation has since been removed; the resident op is the
only signer. Re-recording needs a checkout from before that removal (the
commit that added this file), never Rust output:

    PYTHONPATH=$PWD/src python3 <this-file> <output vectors.json>

Each case is a full ``policy_integrity_rows`` request, the request digest the
Python transport binds replies to (every field except ``integrity_key_b64``,
so the digest never covers key bytes), and the payload the Python functions
produce for it: ``verify_local_policy_row`` per verify item and
``sign_local_policy_row`` per sign item. Rows signed by an earlier case are
reused so a signature is verified by the code that would later read it.

The key is synthetic and exists only in this file's output.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import json
import sys
from pathlib import Path

from codex_plugin_scanner.guard.native_context import _canonical_request_sha256
from codex_plugin_scanner.guard.policy_integrity import (
    _LEGACY_POLICY_INTEGRITY_VERSION as LEGACY_POLICY_INTEGRITY_VERSION,
)
from codex_plugin_scanner.guard.policy_integrity import (
    canonical_policy_payload,
    sign_local_policy_row,
    verify_local_policy_row,
)

REQUEST_SCHEMA = "guard-policy-integrity-rows-request.v1"
KEY = bytes(range(32))
KEY_REF = "guard-policy-integrity-key:00000000deadbeef"
KEY_ID = f"{KEY_REF}:{hashlib.sha256(KEY).hexdigest()[:16]}"
OTHER_KEY_ID = f"{KEY_REF}:0123456789abcdef"
SIGNED_AT = "2026-10-13T12:00:00Z"


def _encode_key(key: bytes) -> str:
    return base64.urlsafe_b64encode(key).rstrip(b"=").decode("ascii")


def _base_row(**overrides: object) -> dict[str, object]:
    row: dict[str, object] = {
        "decision_id": 7,
        "harness": "claude-code",
        "scope": "artifact",
        "artifact_id": "claude-code:project:/workspace/demo:Bash:npm test",
        "artifact_hash": "sha256:" + "ab" * 32,
        "workspace": "/workspace/demo",
        "publisher": None,
        "action": "allow",
        "reason": "approved from the review queue",
        "owner": "local",
        "source": "local",
        "expires_at": None,
        "created_at": "2026-10-13T11:59:00Z",
        "updated_at": "2026-10-13T11:59:30Z",
    }
    row.update(overrides)
    return row


SIGN_ROWS: dict[str, tuple[dict[str, object], int]] = {
    "plain": (_base_row(), 1),
    "unicode": (
        _base_row(
            reason="Freigabe für étape — 日本語 \U0001f600",
            publisher="éditeur",
            workspace="/workspace/démo",
        ),
        3,
    ),
    "empty_strings": (
        _base_row(reason="", owner="", publisher="", workspace="", expires_at=""),
        2,
    ),
    "nulls": (
        _base_row(
            decision_id=None,
            artifact_hash=None,
            workspace=None,
            reason=None,
            owner=None,
            updated_at=None,
        ),
        1,
    ),
    "bool_decision_id": (_base_row(decision_id=True), 4),
    "digit_string_decision_id": (_base_row(decision_id=" 42 "), 5),
    "non_digit_decision_id": (_base_row(decision_id="4x2"), 5),
    "non_string_fields": (_base_row(reason=17, owner=False, action=["allow"]), 6),
    "escapes": (
        _base_row(artifact_id='Bash:printf "a\\tb\\n" </dev/null', reason="line\nbreak\ttab\u0001ctl"),
        2,
    ),
    "expiring": (_base_row(expires_at="2026-10-14T00:00:00Z", scope="workspace", artifact_id=None), 9),
    "generation_zero": (_base_row(), 0),
    "generation_large": (_base_row(), 2**53 + 1),
}


def _signed(name: str) -> dict[str, object]:
    row, generation = SIGN_ROWS[name]
    signed = dict(row)
    signed.update(sign_local_policy_row(row, key=KEY, key_id=KEY_ID, signed_at=SIGNED_AT, generation=generation))
    return signed


def _legacy_signed(row: dict[str, object]) -> dict[str, object]:
    payload = canonical_policy_payload(row, integrity_version=LEGACY_POLICY_INTEGRITY_VERSION)
    signed = dict(row)
    signed.update(
        {
            "integrity_version": LEGACY_POLICY_INTEGRITY_VERSION,
            "integrity_generation": None,
            "payload_hash": hashlib.sha256(payload).hexdigest(),
            "payload_mac": hmac.new(KEY, payload, hashlib.sha256).hexdigest(),
            "integrity_key_id": KEY_ID,
            "signed_at": SIGNED_AT,
        }
    )
    return signed


def _verify_items() -> list[tuple[str, dict[str, object], bool, int | None]]:
    items: list[tuple[str, dict[str, object], bool, int | None]] = []
    for name, (_row, generation) in SIGN_ROWS.items():
        items.append((f"{name}_valid", _signed(name), False, generation))
        items.append((f"{name}_untrusted_generation", _signed(name), False, None))
    plain = _signed("plain")
    items.append(("rollback", plain, False, 2))
    items.append(("degraded", plain, True, 1))
    items.append(("degraded_unsigned", _base_row(), True, None))
    items.append(("missing_all", _base_row(), False, 1))
    for column in ("integrity_version", "integrity_key_id", "payload_hash", "payload_mac", "signed_at"):
        items.append((f"missing_{column}", {**plain, column: None}, False, 1))
        items.append((f"empty_{column}", {**plain, column: ""}, False, 1))
    items.append(("version_three", {**plain, "integrity_version": 3}, False, 1))
    items.append(("version_zero", {**plain, "integrity_version": 0}, False, 1))
    items.append(("version_string", {**plain, "integrity_version": "2"}, False, 1))
    items.append(("version_padded_string", {**plain, "integrity_version": " 2 "}, False, 1))
    items.append(("version_bool_true", {**plain, "integrity_version": True}, False, 1))
    items.append(("wrong_key_id", {**plain, "integrity_key_id": OTHER_KEY_ID}, False, 1))
    items.append(("action_tampered", {**plain, "action": "block"}, False, 1))
    items.append(("reason_tampered", {**plain, "reason": "approved"}, False, 1))
    items.append(("generation_tampered", {**plain, "integrity_generation": 2}, False, 2))
    items.append(("extra_column_ignored", {**plain, "created_at": "2020-01-01T00:00:00Z"}, False, 1))
    items.append(("hash_uppercase", {**plain, "payload_hash": str(plain["payload_hash"]).upper()}, False, 1))
    mac = str(plain["payload_mac"])
    items.append(("mac_tampered", {**plain, "payload_mac": ("0" if mac[0] != "0" else "1") + mac[1:]}, False, 1))
    items.append(("mac_truncated", {**plain, "payload_mac": mac[:-2]}, False, 1))
    legacy = _legacy_signed(_base_row())
    items.append(("legacy_valid", legacy, False, None))
    items.append(("legacy_ignores_trusted_generation", legacy, False, 5))
    items.append(("legacy_reason_unsigned", {**legacy, "reason": "changed"}, False, None))
    items.append(("legacy_action_tampered", {**legacy, "action": "block"}, False, None))
    items.append(("legacy_as_v2", {**legacy, "integrity_version": 2}, False, None))
    return items


def _verify_payload(row: dict[str, object], degraded: bool, trusted: int | None, *, keyed: bool) -> dict[str, object]:
    result = verify_local_policy_row(
        row,
        key=KEY if keyed else None,
        key_id=KEY_ID if keyed else None,
        degraded_mode=degraded,
        trusted_generation=trusted,
    )
    return {
        "status": result.status,
        "payload_hash": result.payload_hash,
        "key_id": result.key_id,
        "message": result.message,
    }


def _verify_request_item(row: dict[str, object], degraded: bool, trusted: int | None) -> dict[str, object]:
    item: dict[str, object] = {"row": row, "degraded_mode": degraded}
    if trusted is not None:
        item["trusted_generation"] = trusted
    return item


def _case(name: str, request: dict[str, object], payload: dict[str, object]) -> dict[str, object]:
    return {
        "name": name,
        "request": request,
        "request_sha256": "sha256:"
        + _canonical_request_sha256({key: value for key, value in request.items() if key != "integrity_key_b64"}),
        "payload": payload,
    }


def _cases() -> list[dict[str, object]]:
    keyed = {
        "schema": REQUEST_SCHEMA,
        "request_id": "",
        "integrity_key_b64": _encode_key(KEY),
        "integrity_key_id": KEY_ID,
    }
    cases: list[dict[str, object]] = []

    sign_names = list(SIGN_ROWS)
    sign_request = {
        **keyed,
        "request_id": "sign-batch",
        "verify": [],
        "sign": [
            {"row": SIGN_ROWS[name][0], "generation": SIGN_ROWS[name][1], "signed_at": SIGNED_AT} for name in sign_names
        ],
    }
    sign_payload = [
        sign_local_policy_row(
            SIGN_ROWS[name][0], key=KEY, key_id=KEY_ID, signed_at=SIGNED_AT, generation=SIGN_ROWS[name][1]
        )
        for name in sign_names
    ]
    cases.append(_case("sign_batch", sign_request, {"verify": [], "sign": sign_payload}))

    resign_source = _signed("plain")
    resign_request = {
        **keyed,
        "request_id": "advance-generation",
        "verify": [_verify_request_item(resign_source, False, 1)],
        "sign": [{"row": resign_source, "generation": 2, "signed_at": "2026-10-13T12:05:00Z"}],
    }
    cases.append(
        _case(
            "advance_generation",
            resign_request,
            {
                "verify": [_verify_payload(resign_source, False, 1, keyed=True)],
                "sign": [
                    sign_local_policy_row(
                        resign_source, key=KEY, key_id=KEY_ID, signed_at="2026-10-13T12:05:00Z", generation=2
                    )
                ],
            },
        )
    )

    for name, row, degraded, trusted in _verify_items():
        cases.append(
            _case(
                f"verify_{name}",
                {**keyed, "request_id": name, "verify": [_verify_request_item(row, degraded, trusted)], "sign": []},
                {"verify": [_verify_payload(row, degraded, trusted, keyed=True)], "sign": []},
            )
        )

    unkeyed_rows = [_signed("plain"), _base_row(), _legacy_signed(_base_row())]
    cases.append(
        _case(
            "verify_without_key",
            {
                "schema": REQUEST_SCHEMA,
                "request_id": "unkeyed",
                "verify": [_verify_request_item(row, False, 1) for row in unkeyed_rows],
                "sign": [],
            },
            {"verify": [_verify_payload(row, False, 1, keyed=False) for row in unkeyed_rows], "sign": []},
        )
    )
    cases.append(
        _case(
            "verify_degraded_without_key",
            {
                "schema": REQUEST_SCHEMA,
                "request_id": "unkeyed-degraded",
                "verify": [_verify_request_item(_signed("plain"), True, None)],
                "sign": [],
            },
            {"verify": [_verify_payload(_signed("plain"), True, None, keyed=False)], "sign": []},
        )
    )
    cases.append(
        _case("empty_batch", {**keyed, "request_id": "empty", "verify": [], "sign": []}, {"verify": [], "sign": []})
    )
    return cases


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: record_vectors.py <output vectors.json>", file=sys.stderr)
        return 2
    vectors = {
        "schema": "guard-policy-integrity-rows-vectors.v1",
        "key_b64": _encode_key(KEY),
        "key_id": KEY_ID,
        "cases": copy.deepcopy(_cases()),
    }
    Path(argv[1]).write_text(json.dumps(vectors, indent=1, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
