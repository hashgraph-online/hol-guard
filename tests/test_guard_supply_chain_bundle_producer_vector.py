"""Verify a supply-chain bundle that an independent producer signed.

The other bundle tests sign with ``canonical_supply_chain_bundle_payload``
itself, so they cannot notice when the verifier's canonical bytes drift from the
producer's. This vector was signed by a separate implementation that writes
non-ASCII text as UTF-8 and sorts keys by code point.
"""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.supply_chain_bundle import (
    SupplyChainBundleKeyringError,
    SupplyChainBundlePayloadHashError,
    SupplyChainBundleSignatureError,
    canonical_supply_chain_bundle_payload,
    load_supply_chain_bundle_response,
    payload_hash_for_supply_chain_bundle,
    verify_supply_chain_bundle_response,
)

_VECTOR = json.loads(
    (Path(__file__).parent / "fixtures" / "supply-chain-bundle-producer-vector.v1.json").read_text(encoding="utf-8")
)
_NOW = float(_VECTOR["verify_at_epoch_seconds"])


def _response() -> dict[str, object]:
    return copy.deepcopy(_VECTOR["response"])


def test_canonical_payload_keeps_non_ascii_text_as_utf8() -> None:
    bundle = _VECTOR["response"]["bundle"]

    canonical = canonical_supply_chain_bundle_payload(bundle)

    assert canonical == _VECTOR["canonical_payload_utf8"].encode("utf-8")
    assert "\\u" not in canonical.decode("utf-8")


@pytest.mark.parametrize("case", _VECTOR["string_vectors"], ids=lambda case: ascii(case["text"])[:24])
def test_string_escaping_matches_the_producer(case: dict[str, str]) -> None:
    canonical = canonical_supply_chain_bundle_payload({"text": case["text"]})

    assert canonical == case["canonical"].encode("utf-8")


def test_payload_hash_matches_the_producer_digest() -> None:
    bundle = _VECTOR["response"]["bundle"]

    assert payload_hash_for_supply_chain_bundle(bundle) == _VECTOR["response"]["payloadHash"]


def test_verifier_accepts_a_producer_signed_bundle_with_non_ascii_advisories() -> None:
    response = load_supply_chain_bundle_response(_response())

    verify_supply_chain_bundle_response(response, trusted_keys=response.verification_keys, now=_NOW)


def test_verifier_still_rejects_changed_text_under_the_producer_hash() -> None:
    raw = _response()
    raw["bundle"]["advisories"][0]["title"] = "Creation de chemin non securisee"
    response = load_supply_chain_bundle_response(raw)

    with pytest.raises(SupplyChainBundlePayloadHashError):
        verify_supply_chain_bundle_response(response, trusted_keys=response.verification_keys, now=_NOW)


def test_verifier_still_rejects_a_forged_hash_over_changed_text() -> None:
    raw = _response()
    raw["bundle"]["advisories"][0]["title"] = "Creation de chemin non securisee"
    raw["payloadHash"] = hashlib.sha256(canonical_supply_chain_bundle_payload(raw["bundle"])).hexdigest()
    response = load_supply_chain_bundle_response(raw)

    with pytest.raises(SupplyChainBundleSignatureError):
        verify_supply_chain_bundle_response(response, trusted_keys=response.verification_keys, now=_NOW)


def test_verifier_still_rejects_an_unanchored_signing_key() -> None:
    response = load_supply_chain_bundle_response(_response())
    other = copy.deepcopy(response.verification_keys[0])
    object.__setattr__(other, "fingerprint_sha256", "0" * 64)

    with pytest.raises(SupplyChainBundleKeyringError):
        verify_supply_chain_bundle_response(response, trusted_keys=(other,), now=_NOW)


def test_lone_surrogate_text_escapes_like_a_well_formed_producer_and_fails_closed() -> None:
    raw = _response()
    raw["bundle"]["advisories"][0]["summary"] = "broken \ud800 text"

    canonical = canonical_supply_chain_bundle_payload(raw["bundle"]).decode("utf-8")

    assert '"summary":"broken \\ud800 text"' in canonical
    response = load_supply_chain_bundle_response(raw)
    with pytest.raises(SupplyChainBundlePayloadHashError):
        verify_supply_chain_bundle_response(response, trusted_keys=response.verification_keys, now=_NOW)
