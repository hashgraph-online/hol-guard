"""Review reuse must preserve real native receipt integrity and the policy domain."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard.hook_review.hook_native_review_binding import (
    native_review_policy_binding,
)
from codex_plugin_scanner.guard.native_decision_receipt import validate_native_decision_receipt
from tests.test_native_command_observations import _edge, _observations, _receipt, _rehash


def _fixture() -> tuple[dict[str, Any], dict[str, Any]]:
    observations = _observations()
    return _edge(observations)["result"], _receipt(observations)


def _binding(result: dict[str, Any], receipt: dict[str, Any], guard_home: Path) -> dict[str, Any]:
    bound = native_review_policy_binding(
        harness="claude-code", native_result=result, verified_receipt=receipt, guard_home=guard_home
    )
    assert bound is not None
    return bound


def test_production_binding_delegates_to_the_resident(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard.hook_review import hook_native_review_binding as binding_module

    result, receipt = _fixture()
    expected = {
        "schema": "guard.native-review-policy-binding.v2",
        "rule_digest": receipt["rule_digest"],
        "runtime_identity": receipt["runtime_identity"],
        "command_extensions": receipt["command_extensions"],
    }
    calls: list[dict[str, object]] = []

    def resident(**kwargs: object) -> dict[str, object]:
        calls.append(kwargs)
        return expected

    monkeypatch.setattr(binding_module, "native_hook_review_policy_binding", resident)
    assert (
        binding_module.native_review_policy_binding(
            harness="claude-code",
            native_result=result,
            verified_receipt=receipt,
            guard_home=tmp_path,
        )
        == expected
    )
    assert calls[0]["guard_home"] == tmp_path


def _resign_identity(receipt: dict[str, Any]) -> None:
    identity = {
        **{
            key: value
            for key, value in receipt.items()
            if key not in {"authority", "decision_id", "review_anchor_digest"}
        },
        "schema": "guard-native-hook-decision-identity.v1",
    }
    receipt["decision_id"] = hashlib.sha256(
        json.dumps(identity, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
    ).hexdigest()
    assert validate_native_decision_receipt(receipt) == receipt


def test_review_binding_captures_verified_domain_without_aliasing_receipt(native_approval_reuse_runtime: Path) -> None:
    result, receipt = _fixture()
    binding = _binding(result, receipt, native_approval_reuse_runtime)
    assert binding == {
        "schema": "guard.native-review-policy-binding.v2",
        **{key: receipt[key] for key in ("rule_digest", "runtime_identity", "command_extensions")},
    }
    receipt["command_extensions"]["control_revision"] += 1
    assert binding["command_extensions"]["control_revision"] == 3


def test_review_binding_omits_the_republishing_snapshot_digest(native_approval_reuse_runtime: Path) -> None:
    """``policy_digest`` is ``H(config_digest, rule_digest)`` over the whole
    compiled snapshot, so it moves on a republish that recorded observed state
    and nothing else. Binding a retry to it strands the approval that retry
    needs. The receipt must still carry a well-formed one."""

    result, receipt = _fixture()
    assert "policy_digest" not in _binding(result, receipt, native_approval_reuse_runtime)
    republished = dict(receipt)
    republished["policy_digest"] = "9" * 64
    _resign_identity(republished)
    assert _binding(result, republished, native_approval_reuse_runtime) == _binding(
        result, receipt, native_approval_reuse_runtime
    )
    del republished["policy_digest"]
    with pytest.raises(ValueError, match="native_review_policy_binding_invalid"):
        native_review_policy_binding(
            harness="claude-code",
            native_result=result,
            verified_receipt=republished,
            guard_home=native_approval_reuse_runtime,
        )


@pytest.mark.parametrize("missing", ["receipt", "result", "receipt-domain", "result-domain"])
def test_partial_extension_domain_cannot_become_legacy_review(
    missing: str, native_approval_reuse_runtime: Path
) -> None:
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
        native_review_policy_binding(
            harness="claude-code",
            native_result=result,
            verified_receipt=receipt,
            guard_home=native_approval_reuse_runtime,
        )


@pytest.mark.parametrize("field", ["policy_digest", "rule_digest", "runtime_identity", "decision", "reason_code"])
def test_tampered_receipt_cannot_authorize_review_reuse(field: str, native_approval_reuse_runtime: Path) -> None:
    result, receipt = _fixture()
    receipt[field] = "tampered"
    with pytest.raises(ValueError, match="native_review_policy_binding_invalid"):
        native_review_policy_binding(
            harness="claude-code",
            native_result=result,
            verified_receipt=receipt,
            guard_home=native_approval_reuse_runtime,
        )


def test_valid_but_uncertain_native_domain_cannot_authorize_reuse(native_approval_reuse_runtime: Path) -> None:
    observations = _observations()
    observations["observations"][0]["uncertainty_reasons"] = ["matcher-failure"]
    observations["binding"]["uncertainty_count"] = 1
    _rehash(observations)
    result, receipt = _edge(observations)["result"], _receipt(observations)
    assert validate_native_decision_receipt(receipt) == receipt
    with pytest.raises(ValueError, match="native_review_policy_binding_invalid"):
        native_review_policy_binding(
            harness="claude-code",
            native_result=result,
            verified_receipt=receipt,
            guard_home=native_approval_reuse_runtime,
        )
