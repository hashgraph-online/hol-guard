"""The command tokens Guard persists must be redacted the same way both sides.

``redacted_command_tokens`` is what turns a package manager invocation into the
command text Guard stores on a receipt and prints in a review. Each token goes
through ``redact_package_request_token`` first, then a key-fragment check that
masks ``API_KEY=...`` and ``api-key: ...`` shaped tokens, then ``redact_text``
for whatever is left. ``guard_command::redacted_command_tokens`` is the
resident's copy of that same chain, and each side redacts on the route it owns,
so a fragment dropped or an order swapped in one copy would persist a secret the
other copy masks without either side failing.

Both sides read ``tests/fixtures/redacted-command-tokens.v1.json``. The two
sub-routines are already pinned on their own; these vectors cover the chain: the
five key fragments, the ``=``-before-``:`` order, and the tokens where package
redaction runs first and the text rules then act on what it left. Each case
assembles its tokens from fragments so no complete secret-shaped literal sits in
the tree, the same discipline the Rust oracle vectors follow.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.local_supply_chain import redacted_command_tokens

_VECTORS = json.loads(
    (Path(__file__).parent / "fixtures" / "redacted-command-tokens.v1.json").read_text(encoding="utf-8")
)
_KEY_FRAGMENTS = ("token", "secret", "api_key", "api-key", "password")


def _command(case: dict[str, object]) -> list[str]:
    return ["".join(parts) for parts in case["command"]]


def test_the_fixture_is_the_shape_both_sides_read() -> None:
    assert _VECTORS["schema"] == "redacted-command-tokens-parity.v1"
    assert len(_VECTORS["cases"]) >= 19


def test_every_key_fragment_has_a_recorded_case() -> None:
    masked_keys = {
        redacted.split("=")[0].split(":")[0].lower()
        for case in _VECTORS["cases"]
        for redacted in case["redacted"]
        if redacted.endswith("*****")
    }
    for fragment in _KEY_FRAGMENTS:
        assert any(fragment in key for key in masked_keys), fragment


@pytest.mark.parametrize("case", _VECTORS["cases"], ids=lambda case: case["name"])
def test_a_recorded_command_redacts_to_its_recorded_tokens(case: dict[str, object]) -> None:
    assert list(redacted_command_tokens(_command(case))) == case["redacted"]


def test_no_redacted_token_keeps_the_fragment_it_masked() -> None:
    for case in _VECTORS["cases"]:
        for parts, redacted in zip(case["command"], case["redacted"], strict=True):
            if "".join(parts) == redacted:
                continue
            for fragment in parts:
                if len(fragment) >= 8 and fragment.isalnum():
                    assert fragment not in redacted, case["name"]
