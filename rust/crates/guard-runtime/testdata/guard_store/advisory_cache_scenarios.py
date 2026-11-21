"""Scenarios for the advisory cache parity vectors.

Run by the recorder through the ORIGINAL Python store. Steps are either
`{"sql": [(statement, params), ...]}` or `{"method", "kwargs"}`.
"""

from __future__ import annotations

T1, T2, T3, T4 = (
    "2026-10-01T00:00:00+00:00",
    "2026-10-02T00:00:00+00:00",
    "2026-10-03T00:00:00+00:00",
    "2026-10-04T00:00:00+00:00",
)


def cache(label: str, advisories: list[object], now: str) -> dict[str, object]:
    return {"method": "cache_advisories", "label": label, "kwargs": {"advisories": advisories, "now": now}}


def listed(label: str, **kwargs: object) -> dict[str, object]:
    return {"method": "list_cached_advisories", "label": label, "kwargs": kwargs}


def row(key: str, payload: str, updated_at: str) -> tuple[str, list[object]]:
    return (
        "insert into publisher_cache (publisher_key, payload_json, updated_at) values (?, ?, ?)",
        [key, payload, updated_at],
    )


SCENARIOS: list[dict[str, object]] = [
    {
        "name": "cache_keys",
        "steps": [
            cache("nothing to cache", [], T1),
            cache(
                "ids, stripped ids and anonymous digests",
                [
                    {"id": "ADV-1", "severity": "high", "publisher": "acme"},
                    {"id": "  ADV-2 \x1f\u2003", "severity": "low"},
                    {"id": "   ", "title": "blank id"},
                    {"id": 7, "title": "numeric id"},
                    {"id": None, "title": "null id"},
                    {"title": "no id", "z": {"b": [1, 2.5, 1e-7, 10**30], "a": True}, "é": "café \U0001f600"},
                    {"b": 1.0, "a": -0.0, "c": 123456789012345678901234567890.5},
                    {"title": 'quote " and \\ and \n'},
                ],
                T1,
            ),
            cache(
                "upsert replaces payload and time",
                [{"id": "ADV-1", "severity": "critical"}, {"id": "ADV-1", "severity": "medium"}],
                T2,
            ),
            cache(
                "same anonymous body maps to the same key",
                [{"b": 1.0, "a": -0.0, "c": 123456789012345678901234567890.5}],
                T3,
            ),
            listed("default limit"),
        ],
    },
    {
        "name": "list_rows",
        "steps": [
            {
                "sql": [
                    row("a", '{"id": "a", "n": 1}', T1),
                    row("b", "[1, 2]", T2),
                    row("c", '"text"', T3),
                    row("d", '{"cache_key": "inner", "updated_at": "inner", "x": null}', T4),
                    row("e", '{"z": 1, "a": {"y": 2, "b": 3}}', "2026-09-30T00:00:00+00:00"),
                ]
            },
            listed("default limit"),
            listed("no limit", limit=None),
            listed("limit three", limit=3),
            listed("limit one", limit=1),
            listed("limit zero", limit=0),
            listed("negative limit is unbounded", limit=-1),
        ],
    },
]
