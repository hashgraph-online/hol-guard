"""Applying an exact Cloud Review decision builds each signed-claim check once."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard import review_contracts, review_exact_capability_advertisement
from codex_plugin_scanner.guard.runtime.exact_cloud_review import (
    apply_exact_cloud_review,
    enable_exact_cloud_review,
)
from tests.guard_exact_cloud_review_support import (
    add_review_request,
    connected_exact_review_store,
    remote_approval,
    review_request,
)


def test_exact_cloud_review_builds_each_claim_once_without_reading_the_capability_advertisement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = connected_exact_review_store(tmp_path)
    target = review_request("exact-claim-count")
    add_review_request(store, target)
    enable_exact_cloud_review(store)
    signed = remote_approval(store, target.request_id, receipt_id="exact-claim-count-receipt")
    built: list[bool] = []
    advertised: list[str] = []
    build_claim = review_contracts.build_local_review_request_claim
    advertise = review_exact_capability_advertisement.exact_review_capability_advertisement

    def counting_build(**kwargs: Any) -> dict[str, object]:
        built.append(bool(kwargs.get("advertise_capability", True)))
        return build_claim(**kwargs)

    def counting_advertise(**kwargs: Any) -> dict[str, object] | None:
        advertised.append("advertisement")
        return advertise(**kwargs)

    monkeypatch.setattr(review_contracts, "build_local_review_request_claim", counting_build)
    monkeypatch.setattr(
        review_exact_capability_advertisement, "exact_review_capability_advertisement", counting_advertise
    )

    resolution = apply_exact_cloud_review(store, remote_approval=signed, expected_harness="codex")

    assert resolution.request_id == target.request_id
    # One claim for the matching outbox snapshot and one for the live row; binding reuses the snapshot's.
    assert built == [False, False]
    assert advertised == []
