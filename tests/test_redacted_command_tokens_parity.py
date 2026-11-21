"""The vectors that pin how Guard redacts a package command it stores.

Guard stores the command text of a package manager invocation on a receipt and
prints it in a review. The resident redacts each token: package-source
credentials first, then a key-fragment check that masks ``API_KEY=...`` and
``api-key: ...`` shaped tokens, then the text rules for whatever is left.
``guard_command::redacted_command_tokens`` and the runtime's
``package_command_redaction`` kind both replay
``tests/fixtures/redacted-command-tokens.v1.json``.

These checks keep the fixture itself honest: its shape, a recorded case for
every key fragment, and no redacted token that still carries a fragment it was
meant to mask. Each case assembles its tokens from fragments so no complete
secret-shaped literal sits in the tree.
"""

from __future__ import annotations

import json
from pathlib import Path

_VECTORS = json.loads(
    (Path(__file__).parent / "fixtures" / "redacted-command-tokens.v1.json").read_text(encoding="utf-8")
)
_KEY_FRAGMENTS = ("token", "secret", "api_key", "api-key", "password")


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


def test_no_redacted_token_keeps_the_fragment_it_masked() -> None:
    for case in _VECTORS["cases"]:
        for parts, redacted in zip(case["command"], case["redacted"], strict=True):
            if "".join(parts) == redacted:
                continue
            for fragment in parts:
                if len(fragment) >= 8 and fragment.isalnum():
                    assert fragment not in redacted, case["name"]
