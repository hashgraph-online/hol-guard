#!/usr/bin/env python3
"""Record `codex_host_inventory` replay vectors from the ORIGINAL Python reader.

Run against a checkout whose `codex_host_inventory` still validates the
`app/installed` and `app/read` replies in Python (`_installed_apps` and
`_merge_metadata`, the base of the commit that introduced the native
`codex_host_inventory` kind), never from Rust output:

    cd <base-worktree>
    PYTHONPATH=$PWD/src python3 <this-file> <output codex_host_inventory_vectors.json>

Each case records the request the native kind takes and what Python made of
it: the app rows (and, for a metadata page, whether it was complete), or the
`codex_host_*` code it raised.
"""

from __future__ import annotations

import copy
import json
import sys

from codex_plugin_scanner.guard.runtime import codex_host_inventory as inventory

SCHEMA = "guard-codex-host-inventory-vectors.v1"

TEXTS: list[object] = [
    None,
    "",
    "   ",
    "\u3000",
    "\x1c\x1d\x1e\x1f",
    "a\tb\n c",
    "a\x1cb",
    "a\x85b",
    "a\xa0b",
    "a\u200bb",
    "a\u180eb",
    "a\u2028b\u2029c",
    "x" * 256,
    "x" * 257,
    "\xe9" * 256,
    "\xe9" * 257,
    "  padded  ",
    "\x00",
    "a\x00b",
    5,
    True,
    ["x"],
    {"x": 1},
]

IDENTIFIERS: list[object] = [
    " example",
    "example\n",
    "example tool",
    "\x00example",
    "",
    "x" * 256,
    "x" * 257,
    "\xe9" * 256,
    "\xe9" * 257,
    "a\x07",
    "a\x7f",
    "a\u3000",
    "a\x1f",
    "a\x85",
    "a\u200b",
    "caf\xe9",
    7,
    None,
]

SUMMARIES: list[object] = [
    *TEXTS,
    "t" * 700,
    "d" * 9030,
    "\xe9" * 600,
    " " * 600 + "x",
    "x" * 511 + " y",
    "x" * 510 + "\u3000\u3000y",
    "x" * 600 + "\x00",
]


def app(app_id: object, **fields: object) -> dict[str, object]:
    return {"id": app_id, "enabled": True, "callable": False, **fields}


def installed_cases() -> list[tuple[str, object]]:
    cases: list[tuple[str, object]] = [
        ("two-apps", {"apps": [app("one", runtimeName="One"), app("two", enabled=False, callable=True)]}),
        ("empty-list", {"apps": []}),
        ("apps-missing", {}),
        ("apps-null", {"apps": None}),
        ("apps-object", {"apps": {"one": app("one")}}),
        ("apps-text", {"apps": "one"}),
        ("row-text", {"apps": ["one"]}),
        ("row-null", {"apps": [None]}),
        ("duplicate-id", {"apps": [app("one"), app("one")]}),
        ("extra-fields-ignored", {"apps": [app("one", isAccessible=True, tools=[{"name": "x"}])]}),
    ]
    for index, value in enumerate(IDENTIFIERS):
        cases.append((f"id-{index}", {"apps": [app(value)]}))
    cases.append(("id-missing", {"apps": [{"enabled": True, "callable": True}]}))
    for flag in ("enabled", "callable"):
        for index, value in enumerate([1, 0, "true", None, [True]]):
            cases.append((f"{flag}-{index}", {"apps": [app("one", **{flag: value})]}))
        row = app("one")
        row.pop(flag)
        cases.append((f"{flag}-missing", {"apps": [row]}))
    for index, value in enumerate(TEXTS):
        cases.append((f"runtime-name-{index}", {"apps": [app("one", runtimeName=value)]}))
    cases.append(("bad-row-after-good", {"apps": [app("one"), app("two", runtimeName=5)]}))
    cases.append(("bad-id-after-bad-name", {"apps": [app("one", runtimeName=5), app(" two")]}))
    return cases


def tool(name: object, **fields: object) -> dict[str, object]:
    return {"name": name, **fields}


def metadata(app_id: object, **fields: object) -> dict[str, object]:
    return {"id": app_id, "name": "Example", "tools": [], **fields}


def read_cases() -> list[tuple[str, list[str], object]]:
    one = ["example"]
    two = ["example", "other"]
    cases: list[tuple[str, list[str], object]] = [
        (
            "tools",
            one,
            {
                "apps": [
                    metadata(
                        "example",
                        name="  Example  connector ",
                        tools=[
                            tool("send_message", title="Send a message", description="Change external content"),
                            tool("delete", description="", isReadOnly=True, isEnabled=True, inputSchema={}),
                        ],
                    )
                ],
                "missingAppIds": [],
            },
        ),
        (
            "summaries-win",
            one,
            {"apps": [metadata("example", toolSummaries=[tool("a")], tools=[tool("b")])], "missingAppIds": []},
        ),
        (
            "summaries-null",
            one,
            {"apps": [metadata("example", toolSummaries=None, tools=[tool("b")])], "missingAppIds": []},
        ),
        ("tools-missing", one, {"apps": [{"id": "example", "name": "Example"}], "missingAppIds": []}),
        ("tools-null", one, {"apps": [metadata("example", tools=None)], "missingAppIds": []}),
        ("tools-text", one, {"apps": [metadata("example", tools="a")], "missingAppIds": []}),
        ("tools-object", one, {"apps": [metadata("example", tools={"a": tool("a")})], "missingAppIds": []}),
        ("tool-text", one, {"apps": [metadata("example", tools=["a"])], "missingAppIds": []}),
        ("tool-duplicate", one, {"apps": [metadata("example", tools=[tool("a"), tool("a")])], "missingAppIds": []}),
        ("missing-other", two, {"apps": [metadata("example")], "missingAppIds": ["other"]}),
        ("both-missing", two, {"apps": [], "missingAppIds": ["other", "example"]}),
        ("not-covered", two, {"apps": [metadata("example")], "missingAppIds": []}),
        ("missing-key", one, {"apps": [metadata("example")]}),
        ("missing-null", one, {"apps": [metadata("example")], "missingAppIds": None}),
        ("missing-text", one, {"apps": [metadata("example")], "missingAppIds": "other"}),
        ("missing-unknown", one, {"apps": [metadata("example")], "missingAppIds": ["third"]}),
        ("missing-covered", one, {"apps": [metadata("example")], "missingAppIds": ["example"]}),
        ("missing-repeated", two, {"apps": [metadata("example")], "missingAppIds": ["other", "other"]}),
        ("missing-bad-id", two, {"apps": [metadata("example")], "missingAppIds": [" other"]}),
        ("app-unknown", one, {"apps": [metadata("third")], "missingAppIds": []}),
        ("app-repeated", one, {"apps": [metadata("example"), metadata("example")], "missingAppIds": []}),
        ("app-text", one, {"apps": ["example"], "missingAppIds": []}),
        ("apps-missing", one, {"missingAppIds": ["example"]}),
        ("apps-too-many", one, {"apps": [metadata(f"a{index}") for index in range(101)], "missingAppIds": []}),
        ("missing-too-many", one, {"apps": [], "missingAppIds": [f"a{index}" for index in range(101)]}),
        ("bad-tool-before-missing-limit", one, {"apps": [metadata("example", tools=[tool(" a")])]}),
        ("limit-before-later-invalid", one, {"apps": [metadata("example", tools="a"), "x"], "missingAppIds": []}),
    ]
    for index, value in enumerate(TEXTS):
        if value is None:
            cases.append(("name-missing", one, {"apps": [{"id": "example", "tools": []}], "missingAppIds": []}))
        cases.append((f"name-{index}", one, {"apps": [metadata("example", name=value)], "missingAppIds": []}))
    for index, value in enumerate(IDENTIFIERS):
        cases.append(
            (f"tool-name-{index}", one, {"apps": [metadata("example", tools=[tool(value)])], "missingAppIds": []})
        )
    for index, value in enumerate(SUMMARIES):
        tools = [tool("a", title=value, description=value)]
        cases.append(
            (f"summary-{index}", one, {"apps": [metadata("example", toolSummaries=tools)], "missingAppIds": []})
        )
    return cases


def outcome(run) -> dict[str, object]:
    try:
        return run()
    except ValueError as error:
        code = str(error)
        if not code.startswith("codex_host_"):
            raise
        return {"error": code}


def main(output: str) -> None:
    records: list[dict[str, object]] = []
    for name, result in installed_cases():
        request = {"installed": copy.deepcopy(result)}
        expect = outcome(lambda result=result: {"apps": inventory._installed_apps(copy.deepcopy(result))})
        records.append({"name": f"installed-{name}", "request": request, "expect": expect})
    for name, ids, result in read_cases():
        page = inventory._installed_apps({"apps": [app(app_id) for app_id in ids]})
        request = {"page": copy.deepcopy(page), "read": copy.deepcopy(result)}

        def merge(page=page, result=result) -> dict[str, object]:
            complete = inventory._merge_metadata(page, copy.deepcopy(result))
            return {"apps": page, "complete": complete}

        records.append({"name": f"read-{name}", "request": request, "expect": outcome(merge)})
    names = [record["name"] for record in records]
    assert len(names) == len(set(names)), "case names repeat"
    with open(output, "w", encoding="utf-8") as stream:
        json.dump({"schema": SCHEMA, "cases": records}, stream, ensure_ascii=False, indent=1, sort_keys=True)
        stream.write("\n")


if __name__ == "__main__":
    main(sys.argv[1])
