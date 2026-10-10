"""Review reuse must preserve real native receipt integrity and the policy domain."""

from __future__ import annotations

import hashlib
import json
from typing import Any

import pytest

from codex_plugin_scanner.guard.daemon.hook_native_review_binding import (
    native_review_policy_binding,
)
from codex_plugin_scanner.guard.native_decision_receipt import validate_native_decision_receipt
from tests.test_native_command_observations import _edge, _observations, _receipt, _rehash


def _fixture() -> tuple[dict[str, Any], dict[str, Any]]:
    observations = _observations()
    return _edge(observations)["result"], _receipt(observations)


def _binding(result: dict[str, Any], receipt: dict[str, Any]) -> dict[str, Any]:
    bound = native_review_policy_binding(harness="claude-code", native_result=result, verified_receipt=receipt)
    assert bound is not None
    return bound


def _resign_identity(receipt: dict[str, Any]) -> None:
    identity = {
        **{key: value for key, value in receipt.items() if key not in {"authority", "decision_id"}},
        "schema": "guard-native-hook-decision-identity.v1",
    }
    receipt["decision_id"] = hashlib.sha256(
        json.dumps(identity, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
    ).hexdigest()
    assert validate_native_decision_receipt(receipt) == receipt


def test_review_binding_captures_verified_domain_without_aliasing_receipt() -> None:
    result, receipt = _fixture()
    binding = _binding(result, receipt)
    assert binding == {
        "schema": "guard.native-review-policy-binding.v1",
        **{key: receipt[key] for key in ("policy_digest", "rule_digest", "runtime_identity", "command_extensions")},
    }
    receipt["command_extensions"]["control_revision"] += 1
    assert binding["command_extensions"]["control_revision"] == 3


@pytest.mark.parametrize("missing", ["receipt", "result", "receipt-domain", "result-domain"])
def test_partial_extension_domain_cannot_become_legacy_review(missing: str) -> None:
    result, receipt = _fixture()
    if missing == "receipt":
        receipt = {}
    elif missing == "result":
        result = {}
    elif missing == "receipt-domain":
        receipt = _receipt(None)
    else:
        result.pop("command_extensions")
    with pytest.raises(ValueError, match="native_review_policy_binding_invalid"):
        native_review_policy_binding(harness="claude-code", native_result=result, verified_receipt=receipt)


@pytest.mark.parametrize("field", ["policy_digest", "rule_digest", "runtime_identity", "decision", "reason_code"])
def test_tampered_receipt_cannot_authorize_review_reuse(field: str) -> None:
    result, receipt = _fixture()
    receipt[field] = "tampered"
    with pytest.raises(ValueError, match="native_review_policy_binding_invalid"):
        native_review_policy_binding(harness="claude-code", native_result=result, verified_receipt=receipt)


def test_valid_but_uncertain_native_domain_cannot_authorize_reuse() -> None:
    observations = _observations()
    observations["observations"][0]["uncertainty_reasons"] = ["matcher-failure"]
    observations["binding"]["uncertainty_count"] = 1
    _rehash(observations)
    result, receipt = _edge(observations)["result"], _receipt(observations)
    assert validate_native_decision_receipt(receipt) == receipt
    with pytest.raises(ValueError, match="native_review_policy_binding_invalid"):
        native_review_policy_binding(harness="claude-code", native_result=result, verified_receipt=receipt)
