"""The package argv redaction Python keeps must match the native one.

``redact_package_request_token`` strips credentials out of a package argv token
before Guard persists the command it reviewed. The resident keeps its own copy
of that routine in ``guard_command::package_intent_common::sanitize_url``, and
each side redacts the command on the route it owns, so a rule edited in one
copy would persist a different command text for the same install without
either side failing.

Both sides read the vectors in ``tests/fixtures/package-request-redaction.v1.json``.
A branch that stops matching the recorded output fails here, and the companion
Rust case fails for the same file.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.package_intent_common import redact_package_request_token

_VECTORS = json.loads(
    (Path(__file__).parent / "fixtures" / "package-request-redaction.v1.json").read_text(encoding="utf-8")
)


def test_the_fixture_is_the_shape_both_sides_read() -> None:
    assert _VECTORS["schema"] == "package-request-redaction-parity.v1"
    assert len(_VECTORS["cases"]) >= 14


@pytest.mark.parametrize("case", _VECTORS["cases"], ids=lambda case: case["name"])
def test_a_recorded_token_redacts_to_its_recorded_text(case: dict[str, str]) -> None:
    assert redact_package_request_token(case["token"]) == case["redacted"]


def test_credentials_never_survive_the_recorded_cases() -> None:
    for case in _VECTORS["cases"]:
        if "@" in case["token"].split("://", 1)[-1].split("/", 1)[0]:
            assert "@" not in case["redacted"], case["name"]
