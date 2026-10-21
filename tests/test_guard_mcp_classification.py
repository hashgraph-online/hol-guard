"""The MCP classification bridge carries declarations; it never describes them.

Describing a tool is the native runtime's job, and the semantics of that
description are covered by its own tests. What matters here is that Python
hands the declaration over unchanged, keeps the answers in request order and
produces nothing at all when the resident cannot answer.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_mcp_classification, store_mcp_provider_catalog
from codex_plugin_scanner.guard.native_mcp_classification import (
    _MAX_ITEMS,
    _MAX_JSON_COLLECTION_ITEMS,
    _MAX_JSON_STRING_BYTES,
    _MAX_REQUEST_BYTES,
    McpClassificationUnavailableError,
)
from codex_plugin_scanner.guard.runtime.mcp_classification import (
    classify_mcp_action,
    classify_mcp_actions,
)
from codex_plugin_scanner.guard.store_mcp_provider_catalog import describe_provider_actions


def _install_transport(
    monkeypatch: pytest.MonkeyPatch,
    *,
    available: bool = True,
) -> list[list[dict[str, object]]]:
    """Record the batches that reach the resident and answer each by name."""

    sent: list[list[dict[str, object]]] = []

    def resident_request(**kwargs: object) -> dict[str, object]:
        request = kwargs["request"]
        assert isinstance(request, dict)
        items = request["items"]
        assert isinstance(items, list)
        sent.append([dict(item) for item in items if isinstance(item, dict)])
        return {"status": "ok"}

    def payload(
        response: dict[str, object] | None,
        request: dict[str, object],
        guard_home: Path,
    ) -> dict[str, object]:
        del response, guard_home
        items = request["items"]
        assert isinstance(items, list)
        return {"classifications": [{"described": item["name"]} for item in items]}

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.native_mcp_classification.ensure_resident_prerequisite",
        lambda guard_home: available,
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.native_mcp_classification._resident_request",
        resident_request,
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.native_mcp_classification._payload",
        payload,
    )
    return sent


def test_a_declaration_travels_to_the_resident_exactly_as_declared(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    sent = _install_transport(monkeypatch)
    schema = {"properties": {"query": {"type": "string", "default": "SECRET"}}}
    described = classify_mcp_action(
        "SLACK_SEARCH_MESSAGES",
        schema,
        guard_home=tmp_path,
        provider="composio",
        annotations={"readOnlyHint": True},
        full_schema=False,
    )

    assert described == {"described": "SLACK_SEARCH_MESSAGES"}
    assert sent == [
        [
            {
                "name": "SLACK_SEARCH_MESSAGES",
                "schema": schema,
                "provider": "composio",
                "annotations": {"readOnlyHint": True},
                "full_schema": False,
            }
        ]
    ]


def test_a_batch_comes_back_in_the_order_it_was_asked(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _install_transport(monkeypatch)
    names = [f"tool_{index}" for index in range(12)]
    described = classify_mcp_actions(
        [{"name": name, "schema": {"type": "object"}} for name in names],
        guard_home=tmp_path,
    )

    assert [entry["described"] for entry in described] == names


def test_nothing_is_asked_for_an_empty_batch(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    sent = _install_transport(monkeypatch, available=False)

    assert classify_mcp_actions([], guard_home=tmp_path) == []
    assert sent == []


def test_a_batch_is_split_under_the_count_cap_and_stays_in_order(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    sent = _install_transport(monkeypatch)
    names = [f"tool_{index}" for index in range(_MAX_ITEMS + 5)]
    described = classify_mcp_actions([{"name": name, "schema": None} for name in names], guard_home=tmp_path)

    assert len(sent) == 2
    assert [len(batch) for batch in sent] == [_MAX_ITEMS, 5]
    assert [entry["described"] for entry in described] == names


def test_a_batch_is_split_under_the_byte_cap(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    sent = _install_transport(monkeypatch)
    # Three strings just under the parser's own string cap, so each schema is
    # large enough to force a split without being refused as untransportable.
    filler = "f" * (_MAX_JSON_STRING_BYTES - 1)
    definitions = [
        {"name": f"tool_{index}", "schema": {"properties": {f"{letter}{filler}": {} for letter in "abc"}}}
        for index in range(6)
    ]
    described = classify_mcp_actions(definitions, guard_home=tmp_path)

    assert len(sent) > 1
    assert all(len(batch) >= 1 for batch in sent)
    assert [entry["described"] for entry in described] == [str(item["name"]) for item in definitions]


def test_a_declaration_too_large_to_send_is_left_undescribed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    sent = _install_transport(monkeypatch)
    oversized = {"name": "huge", "schema": {"properties": {"f" * (_MAX_REQUEST_BYTES + 1): {}}}}

    assert classify_mcp_actions([oversized], guard_home=tmp_path) == [None]
    assert sent == []


@pytest.mark.parametrize(
    "schema",
    [
        pytest.param({"description": "d" * (_MAX_JSON_STRING_BYTES + 1)}, id="description-past-the-string-cap"),
        pytest.param({"default": 2**64}, id="integer-past-the-json-range"),
        pytest.param({"default": -(2**63) - 1}, id="integer-below-the-json-range"),
        pytest.param({"default": float("inf")}, id="non-finite-number"),
        pytest.param({"default": float("nan")}, id="not-a-number"),
        pytest.param({"enum": [0] * (_MAX_JSON_COLLECTION_ITEMS + 1)}, id="array-past-the-collection-cap"),
        pytest.param({"description": "\ud800"}, id="lone-surrogate-in-a-value"),
        pytest.param({"\ud800": {"type": "string"}}, id="lone-surrogate-in-a-field-name"),
    ],
)
def test_a_declaration_the_resident_parser_refuses_costs_only_itself(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, schema: dict[str, object]
) -> None:
    """One provider-controlled schema must not sink the rest of the page.

    The resident refuses the whole frame over any of these, so a declaration
    carrying one travels nowhere and comes back undescribed. Its neighbours
    are still described.
    """

    sent = _install_transport(monkeypatch)
    described = classify_mcp_actions(
        [
            {"name": "before", "schema": {"type": "object"}},
            {"name": "refused", "schema": schema},
            {"name": "after", "schema": {"type": "object"}},
        ],
        guard_home=tmp_path,
    )

    assert described == [{"described": "before"}, None, {"described": "after"}]
    assert [item["name"] for batch in sent for item in batch] == ["before", "after"]


def test_a_declaration_nested_past_the_parser_depth_is_left_undescribed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    sent = _install_transport(monkeypatch)
    deep: dict[str, object] = {}
    node = deep
    for _ in range(64):
        child: dict[str, object] = {}
        node["properties"] = child
        node = child

    assert classify_mcp_actions([{"name": "deep", "schema": deep}], guard_home=tmp_path) == [None]
    assert sent == []


def test_an_unavailable_resident_yields_no_classification(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    sent = _install_transport(monkeypatch, available=False)

    with pytest.raises(McpClassificationUnavailableError):
        classify_mcp_action("anything", {"type": "object"}, guard_home=tmp_path)
    assert sent == []


def test_a_reply_that_does_not_answer_every_item_is_refused(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _install_transport(monkeypatch)
    monkeypatch.setattr(
        native_mcp_classification,
        "_payload",
        lambda response, request, guard_home: {"classifications": [{"described": "only-one"}]},
    )

    with pytest.raises(McpClassificationUnavailableError):
        classify_mcp_actions(
            [{"name": "a", "schema": None}, {"name": "b", "schema": None}],
            guard_home=tmp_path,
        )


def test_a_transport_failure_never_becomes_a_local_description(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _install_transport(monkeypatch)

    def failing_request(**kwargs: object) -> dict[str, object]:
        raise OSError("resident gone")

    monkeypatch.setattr(native_mcp_classification, "_resident_request", failing_request)

    with pytest.raises(McpClassificationUnavailableError):
        classify_mcp_action("anything", {"type": "object"}, guard_home=tmp_path)


def test_a_page_the_resident_cannot_describe_still_names_every_action(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """An absent description costs the page its hints, not its contents.

    The classification is advisory: the action, its permission state and its
    revision are what the page is for, and they come from the store.
    """

    monkeypatch.setattr(
        store_mcp_provider_catalog,
        "classify_mcp_actions",
        lambda declarations, *, guard_home: [{"described": "first"}, None],
    )
    page = describe_provider_actions(
        {"actions": [{"tool_slug": "first"}, {"tool_slug": "second"}]},
        [{"name": "first"}, {"name": "second"}],
        guard_home=tmp_path,
    )

    assert page["actions"] == [
        {"tool_slug": "first", "classification": {"described": "first"}},
        {"tool_slug": "second"},
    ]


def test_a_page_asked_for_without_a_resident_is_still_a_page(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def unavailable(declarations: object, *, guard_home: Path) -> list[dict[str, object] | None]:
        del declarations, guard_home
        raise McpClassificationUnavailableError

    monkeypatch.setattr(store_mcp_provider_catalog, "classify_mcp_actions", unavailable)
    page = describe_provider_actions(
        {"actions": [{"tool_slug": "first"}]},
        [{"name": "first"}],
        guard_home=tmp_path,
    )

    assert page["actions"] == [{"tool_slug": "first"}]
