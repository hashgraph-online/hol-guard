"""Approval presentation copies must not alias the resident challenge."""

from __future__ import annotations

from typing import cast

import pytest

from codex_plugin_scanner.guard.native_approval_models import _new_session
from codex_plugin_scanner.guard.native_approval_v4_protocol import decode_native_approval_v4_challenge
from tests.test_native_approval_v4_transport import _challenge


@pytest.mark.parametrize("mutation_target", ["decoded_input", "returned_copy"])
def test_nested_webauthn_fields_are_detached(mutation_target: str) -> None:
    decoded = decode_native_approval_v4_challenge(_challenge())
    assert decoded is not None
    session = _new_session(decoded, b"{}")
    expected = _challenge()
    target = decoded if mutation_target == "decoded_input" else session.challenge
    webauthn = cast(dict[str, object], target["webauthn"])
    webauthn["origin"] = "https://changed.example.invalid"
    webauthn["challenge"] = "B" * 43
    assert session.challenge == expected
    assert session.challenge["webauthn"] is not session.challenge["webauthn"]
