from __future__ import annotations

import time
from collections.abc import Mapping

from ci.native_runtime.probe_native_default_auto import (
    _receipt_corpus_is_complete,
    _wait_for_receipt_corpus,
)


def test_receipt_corpus_complete_requires_processed_count() -> None:
    stats: Mapping[str, object] = {
        "receipt_accepted": 21,
        "receipt_processed": 20,
        "receipt_dropped": 0,
        "receipt_failures": 1,
        "receipt_durable_pending": 1,
    }
    assert not _receipt_corpus_is_complete(stats, expected=21)
    assert _receipt_corpus_is_complete(
        {
            "receipt_accepted": 21,
            "receipt_processed": 21,
            "receipt_dropped": 0,
            "receipt_failures": 0,
            "receipt_durable_pending": 0,
        },
        expected=21,
    )


def test_wait_for_receipt_corpus_polls_until_processed() -> None:
    snapshots = iter(
        (
            {
                "receipt_accepted": 21,
                "receipt_processed": 20,
                "receipt_dropped": 0,
                "receipt_failures": 1,
                "receipt_durable_pending": 1,
            },
            {
                "receipt_accepted": 21,
                "receipt_processed": 21,
                "receipt_dropped": 0,
                "receipt_failures": 0,
                "receipt_durable_pending": 0,
            },
        )
    )

    class FakeWriter:
        def stats(self) -> Mapping[str, object]:
            return next(snapshots)

    started = time.monotonic()
    complete = _wait_for_receipt_corpus(FakeWriter(), expected=21, timeout_seconds=1.0)
    assert complete["receipt_processed"] == 21
    assert time.monotonic() - started < 1.0
