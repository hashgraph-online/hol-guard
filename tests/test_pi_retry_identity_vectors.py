"""Keep mocked receipts aligned with the same vectors checked by Rust authority."""

import json
from pathlib import Path

import pytest

from tests.test_native_review_fixtures import request_digest_for_fixture

_VECTORS = json.loads((Path(__file__).parent / "fixtures/pi-retry-identity-vectors.json").read_text())


@pytest.mark.parametrize("vector", _VECTORS, ids=lambda vector: vector["name"])
def test_mocked_receipt_matches_native_identity_vector(vector: dict[str, object]) -> None:
    before = request_digest_for_fixture(vector["harness"], vector["before"], None)
    after = request_digest_for_fixture(vector["harness"], vector["after"], None)
    assert (before == after) is vector["same_identity"]
