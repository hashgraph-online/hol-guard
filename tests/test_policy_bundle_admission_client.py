"""Malformed native answers to the policy-bundle admission client fail closed."""

from __future__ import annotations

import json
from typing import cast

import pytest

from codex_plugin_scanner.guard import policy_bundle_parser as parser
from codex_plugin_scanner.guard.native_policy_bundle import (
    PolicyBundleNativeError,
    PolicyBundleNativeUnavailableError,
)


@pytest.mark.parametrize("answer", [{}, {"rejection": 7}, {"rejection": ""}, {"error": 7, "rejection": None}])
def test_candidate_admission_never_reads_a_malformed_answer_as_a_pass(
    monkeypatch: pytest.MonkeyPatch, answer: dict[str, object]
) -> None:
    monkeypatch.setattr(parser, "native_policy_bundle", lambda *_args, **_kwargs: answer)
    with pytest.raises(PolicyBundleNativeUnavailableError):
        parser.policy_bundle_admission_rejection({"bundleVersion": 3}, None)


def test_candidate_admission_error_is_a_typed_rejection(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(parser, "native_policy_bundle", lambda *_args, **_kwargs: {"error": "limit_bytes"})
    with pytest.raises(PolicyBundleNativeError) as raised:
        parser.policy_bundle_admission_rejection({"bundleVersion": 3}, None)
    assert raised.value.code == "limit_bytes"


@pytest.mark.parametrize("answer", [{}, {"value": None}, {"value": "yes"}])
def test_downgrade_verdict_never_reads_a_malformed_answer_as_no_downgrade(
    monkeypatch: pytest.MonkeyPatch, answer: dict[str, object]
) -> None:
    monkeypatch.setattr(parser, "native_policy_bundle", lambda *_args, **_kwargs: answer)
    with pytest.raises(PolicyBundleNativeUnavailableError):
        parser.policy_bundle_downgrade_verdict({"bundleVersion": 2}, {"bundleVersion": 3})


def test_reference_exception_set_crosses_the_transport_as_its_hash(monkeypatch: pytest.MonkeyPatch) -> None:
    requests: list[tuple[str, dict[str, object]]] = []

    def fake(kind: str, request: dict[str, object], **_kwargs: object) -> dict[str, object]:
        requests.append((kind, request))
        return {"value": "sha256:set"} if kind == "v2_cloud_exceptions_hash" else {"value": False}

    monkeypatch.setattr(parser, "native_policy_bundle", fake)
    candidate: dict[str, object] = {"contractVersion": "guard-policy-bundle.v2", "bundleVersion": 3}
    reference: dict[str, object] = {"bundleVersion": 2, "cloudExceptions": [{"id": "x" * 64}]}
    assert parser.policy_bundle_downgrade_verdict(reference, candidate) is False
    kind, request = requests[-1]
    assert kind == "downgrade_verdict"
    sent = json.loads("".join(cast(list[str], request["reference_chunks"])))
    assert sent == {"bundleVersion": 2, "cloudExceptionsHash": "sha256:set"}
