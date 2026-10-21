"""Scenarios for the Composio discovery catalog parity vectors.

Run by the recorder through the ORIGINAL Python store. A step is
`{"method": "record_composio_discovery", "kwargs": {...}}`, whose `actions`
and `proposals` are the dataclass fields as dicts.
"""

from __future__ import annotations

#: The wall clock the vectors assume wherever Python fell back to now.
NOW = "2026-10-10T12:00:00+00:00"
FIRST = "2026-09-27T12:00:00Z"
SECOND = "2026-09-27T12:01:00Z"
THIRD = "2026-09-27T12:02:00Z"

TOOL = "mcp__codex_apps__composio__composio_search_tools"
OTHER_TOOL = "mcp__composio__composio_search_tools"


def action(
    slug: str = "SLACK_SEARCH_MESSAGES",
    *,
    toolkit: str = "slack",
    description: str = "Synthetic metadata",
    input_schema: dict | None = None,
    full_schema: bool = True,
) -> dict[str, object]:
    return {
        "toolkit": toolkit,
        "tool_slug": slug,
        "description": description,
        "input_schema": {"type": "object"} if input_schema is None else input_schema,
        "full_schema": full_schema,
    }


def proposal(primary: tuple[str, ...], supporting: tuple[str, ...] = (), *, guidance: bool = True) -> dict[str, object]:
    return {"primary": list(primary), "supporting": list(supporting), "guidance_present": guidance}


def record(label: str, actions: list[dict], *, seen_at: str = FIRST, proposals: list[dict] | None = None, tool: str = TOOL) -> dict[str, object]:
    kwargs: dict[str, object] = {"tool": tool, "actions": actions, "seen_at": seen_at}
    if proposals is not None:
        kwargs["proposals"] = proposals
    return {"method": "record_composio_discovery", "label": label, "kwargs": kwargs}


SCENARIOS: list[dict[str, object]] = [
    {
        "name": "first_discovery",
        "steps": [
            record("one action, no proposals", [action()]),
            record("the same action again changes nothing", [action()], seen_at=SECOND),
        ],
    },
    {
        "name": "revision_moves_only_with_authority",
        "steps": [
            record("initial", [action()]),
            record("new description keeps the revision", [action(description="New display text")], seen_at=SECOND),
            record(
                "a widened schema moves it",
                [action(input_schema={"type": "object", "required": ["query"]})],
                seen_at=SECOND,
            ),
            record("a renamed toolkit moves it", [action(toolkit="other", input_schema={"type": "object", "required": ["query"]})], seen_at=SECOND),
            record(
                "dropping the full schema moves it",
                [action(toolkit="other", input_schema={"type": "object", "required": ["query"]}, full_schema=False)],
                seen_at=THIRD,
            ),
        ],
    },
    {
        "name": "subsets_merge",
        "steps": [
            record("first slug", [action()]),
            record("second slug, the first stays", [action("SLACK_SEND_MESSAGE")], seen_at=SECOND),
            record(
                "both slugs in one batch",
                [action(), action("SLACK_SEND_MESSAGE", toolkit="other")],
                seen_at=THIRD,
            ),
        ],
    },
    {
        "name": "repeated_slug_in_one_batch",
        "steps": [
            record(
                "the last copy of a repeated slug wins",
                [action(), action(description="second copy"), action(toolkit="other")],
            ),
        ],
    },
    {
        "name": "workflow_proposals",
        "steps": [
            record(
                "a proposal arrives with the catalog",
                [action()],
                proposals=[proposal(("SLACK_SEARCH_MESSAGES",), ("SLACK_SEND_MESSAGE",))],
            ),
            record(
                "the same proposal refreshes rather than duplicating",
                [action()],
                seen_at=SECOND,
                proposals=[proposal(("SLACK_SEARCH_MESSAGES",), ("SLACK_SEND_MESSAGE",))],
            ),
            record(
                "a different proposal is a second row",
                [action()],
                seen_at=SECOND,
                proposals=[proposal(("SLACK_SEARCH_MESSAGES",), guidance=False)],
            ),
            record("no proposals leaves the stored ones alone", [action()], seen_at=THIRD, proposals=[]),
        ],
    },
    {
        "name": "proposal_capacity",
        "steps": [
            record(
                "fifty-one proposals are refused",
                [action()],
                proposals=[proposal((f"SLACK_ACTION_{index}",)) for index in range(51)],
            ),
        ],
    },
    {
        "name": "separate_connections",
        "steps": [
            record("the codex_apps connection", [action()]),
            record("a different server is a different catalog", [action()], seen_at=SECOND, tool=OTHER_TOOL),
        ],
    },
]
