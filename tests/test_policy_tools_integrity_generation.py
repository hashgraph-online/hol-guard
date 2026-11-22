"""The MCP policy tools read the integrity generation through the native store."""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.mcp.policy_tools import _read_policy_integrity_generation


class _Store:
    def __init__(self, answer: object = None, error: Exception | None = None) -> None:
        self.answer = answer
        self.error = error
        self.calls: list[tuple[str, dict[str, object]]] = []

    def _native_store_call(self, method: str, args: dict[str, object]) -> object:
        self.calls.append((method, args))
        if self.error is not None:
            raise self.error
        return self.answer

    def _connect(self) -> object:
        raise AssertionError("the generation read must not open a Python connection")


def test_the_generation_is_read_from_the_native_sync_payload() -> None:
    store = _Store({"generation": 7, "digest": "d"})
    assert _read_policy_integrity_generation(store) == 7  # pyright: ignore[reportArgumentType]
    assert store.calls == [("get_sync_payload", {"state_key": "policy_integrity"})]


@pytest.mark.parametrize(
    ("answer", "expected"),
    [
        (None, None),
        ([], None),
        ({}, None),
        ({"generation": None}, None),
        ({"generation": 3.0}, 3),
        ({"generation": "12"}, 12),
        ({"generation": " "}, None),
        ({"generation": "x"}, None),
        ({"generation": [1]}, None),
    ],
)
def test_the_stored_generation_is_decoded_as_before(answer: object, expected: int | None) -> None:
    assert _read_policy_integrity_generation(_Store(answer)) == expected  # pyright: ignore[reportArgumentType]


def test_a_failed_native_read_has_no_generation() -> None:
    assert _read_policy_integrity_generation(_Store(error=RuntimeError("down"))) is None  # pyright: ignore[reportArgumentType]
