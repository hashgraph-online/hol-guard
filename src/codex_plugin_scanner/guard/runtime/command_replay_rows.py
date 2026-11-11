"""Narrow the stored replay rows to the ones a job question could match."""

from __future__ import annotations

from collections.abc import Mapping


def replay_rows_naming(items: list[dict[str, object]], subject: object) -> list[dict[str, object]]:
    """The replay rows the runtime could match against ``subject``.

    The runtime matches a row by identity digest, job id or idempotency key.
    Every row records the id and key of the identity its digest covers, so a
    row naming neither of the subject's values cannot match by any of the
    three. Rows missing either field are kept for the runtime to judge, and
    a subject that is not a mapping keeps them all so the runtime refuses it
    as it always has.
    """

    if not isinstance(subject, Mapping):
        return items
    names: set[str] = set()
    for field in ("id", "idempotencyKey"):
        value = subject.get(field)
        if isinstance(value, str):
            names.update((value, value.strip()))
    return [
        item
        for item in items
        if not isinstance(item.get("jobId"), str)
        or not isinstance(item.get("idempotencyKey"), str)
        or item["jobId"] in names
        or item["idempotencyKey"] in names
    ]
