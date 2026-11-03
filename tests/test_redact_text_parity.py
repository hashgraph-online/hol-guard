"""The secret redaction Python applies must match the native one.

``redact_text`` masks bearer tokens, provider keys, private keys, secret
environment assignments and connection strings before Guard prints or syncs
text. The resident keeps its own copy of the same twelve rules in
``guard_command::redacted_command_tokens::redact_text``, and each side redacts
on the route it owns, so a pattern edited in one copy would print or persist a
secret the other copy masks without either side failing.

Both sides read the vectors in ``tests/fixtures/redact-text-parity.v1.json``.
Each case assembles its input from fragments so no complete secret-shaped
literal sits in the tree, the same discipline the Rust oracle vectors follow.
A rule that stops matching its recorded output, classifiers or count fails
here, and the companion Rust case fails for the same file.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.redaction import redact_text

_VECTORS = json.loads((Path(__file__).parent / "fixtures" / "redact-text-parity.v1.json").read_text(encoding="utf-8"))
_CLASSIFIERS = {
    "bearer-token",
    "openai-token",
    "github-token",
    "aws-access-key",
    "aws-secret-access-key",
    "npm-token",
    "python-index-token",
    "private-key",
    "secret-env",
    "connection-env",
    "connection-string",
    "remote-pairing-code",
}


def test_the_fixture_is_the_shape_both_sides_read() -> None:
    assert _VECTORS["schema"] == "redact-text-parity.v1"
    assert len(_VECTORS["cases"]) >= 32


def test_every_rule_has_a_recorded_case() -> None:
    fired = {classifier for case in _VECTORS["cases"] for classifier in case["classifiers"]}
    assert fired == _CLASSIFIERS


# The operator boundary is only visible in these cases: each one records a value
# ending at a different shell operator, so a count alone would let any of them be
# dropped and replaced by a duplicate of an existing `secret-env` case.
_BOUNDED_VALUE_CASES = (
    "a quoted value keeps an operator inside it",
    "a single-quoted value keeps an operator inside it",
    "an assignment ends at a pipe",
    "an assignment ends at a background operator",
    "an escaped operator inside a value still ends it",
)


def test_every_operator_boundary_keeps_its_own_case() -> None:
    names = [case["name"] for case in _VECTORS["cases"]]
    for required in _BOUNDED_VALUE_CASES:
        assert names.count(required) == 1, required


def test_a_quoted_value_keeps_the_operators_inside_it() -> None:
    """The quoted alternative is why a value may hold `&&` and still be masked whole."""
    quoted = [case for case in _VECTORS["cases"] if "quoted value keeps an operator" in case["name"]]
    assert len(quoted) == 2, [case["name"] for case in _VECTORS["cases"]]
    for case in quoted:
        assert case["text"].count("*****") == 1, case["name"]
        assert case["text"].endswith("run"), case["name"]


@pytest.mark.parametrize("case", _VECTORS["cases"], ids=lambda case: case["name"])
def test_a_recorded_input_redacts_to_its_recorded_result(case: dict[str, object]) -> None:
    result = redact_text("".join(case["input"]))

    assert result.text == case["text"]
    assert result.count == case["count"]
    assert list(result.classifiers) == case["classifiers"]
    assert result.original_sha256 == ""


def test_no_recorded_secret_survives_its_redaction() -> None:
    for case in _VECTORS["cases"]:
        if not case["classifiers"]:
            continue
        for fragment in case["input"]:
            if len(fragment) >= 8 and fragment.isalnum():
                assert fragment not in case["text"], case["name"]
