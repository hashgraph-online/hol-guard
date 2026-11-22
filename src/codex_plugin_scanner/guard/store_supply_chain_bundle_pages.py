"""Read the cached supply-chain bundle response in pages under the native reply cap."""

from __future__ import annotations

from collections.abc import Callable, Mapping

_BUNDLE_READ_ATTEMPTS = 3


def _bundle_page(answer: object) -> tuple[str, int, str] | None:
    if answer is None:
        return None
    if not isinstance(answer, dict) or set(answer) != {"page", "length", "cached_at"}:
        raise RuntimeError("native get_cached_supply_chain_bundle returned no answer")
    page = answer["page"]
    length = answer["length"]
    cached_at = answer["cached_at"]
    if (
        not isinstance(page, str)
        or isinstance(length, bool)
        or not isinstance(length, int)
        or length < 0
        or not isinstance(cached_at, str)
    ):
        raise RuntimeError("native get_cached_supply_chain_bundle returned no answer")
    return page, length, cached_at


def read_cached_bundle_text(
    call: Callable[[str, Mapping[str, object]], object], workspace_id: str
) -> tuple[str, str] | None:
    """Join the stored response text from native pages, each under the reply cap.

    A cloud sync between two pages changes ``cached_at`` or the length; the
    read then starts over so it never joins two different responses.
    """

    for _ in range(_BUNDLE_READ_ATTEMPTS):
        first = _bundle_page(call("get_cached_supply_chain_bundle", {"workspace_id": workspace_id, "offset": 0}))
        if first is None:
            return None
        text, length, cached_at = first
        pages = [text]
        read = len(text)
        changed = False
        while read < length:
            page = _bundle_page(call("get_cached_supply_chain_bundle", {"workspace_id": workspace_id, "offset": read}))
            if page is None or page[1] != length or page[2] != cached_at or not page[0]:
                changed = True
                break
            pages.append(page[0])
            read += len(page[0])
        if not changed and read == length:
            return "".join(pages), cached_at
    raise RuntimeError("native get_cached_supply_chain_bundle kept changing while it was read")
