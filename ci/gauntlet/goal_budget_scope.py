"""Require the exact budget-bearing Oh My Pi goal round in installed acceptance.

A get-only native-tools case otherwise satisfies required_tools, letting a
benchmark pass without ever testing the policy false positive it claims to cover.
All evidence comes from recorded host calls, not the model's prose.
"""

from __future__ import annotations

import re
from typing import Any

GOAL_BUDGET_CASE = "omp-native-goal-objective-with-token-budget"
BUDGET = 200_000
GOAL_KEYS = frozenset({"op", "objective", "token_budget", "i", "intent"})
BUDGET_LABEL = re.compile(r"\b(?:token[_ -]?budget|budget)\b", re.IGNORECASE)
BUDGET_VALUE = re.compile(r"(?<!\d)200,?000(?!\d)")


def _budget_readback(call: dict[str, Any]) -> bool:
    """Only a successful get tool result can prove the returned budget."""
    result = call.get("result")
    content = result.get("content") if isinstance(result, dict) else None
    if not isinstance(content, list) or not content:
        return False
    if any(
        not isinstance(block, dict)
        or block.get("type") != "text"
        or not isinstance(block.get("text"), str)
        for block in content
    ):
        return False
    text = "".join(block["text"] for block in content)
    return BUDGET_LABEL.search(text) is not None and BUDGET_VALUE.search(text) is not None


def goal_budget_scope_error(calls: list[dict[str, Any]], *, guard_denied: bool) -> str | None:
    """Never score an unrelated goal call as the target false positive.

    After an in-scope Guard denial, a get/readback is not mandatory: the denial
    may have prevented it. Otherwise require a successful create followed by a
    successful get whose host result reports the actual budget.
    """
    goal_calls = [(index, call) for index, call in enumerate(calls) if call.get("name") == "goal"]
    creates = []
    gets = []
    for index, call in goal_calls:
        args = call.get("args")
        if not isinstance(args, dict) or set(args) - GOAL_KEYS:
            return "goal carried arguments outside the published task shape"
        if any(not isinstance(args[key], str) for key in ("i", "intent") if key in args):
            return "goal intent metadata was not text"
        if args.get("op") == "create":
            if not isinstance(args.get("objective"), str) or not args["objective"].strip():
                return "goal create did not name an objective"
            if type(args.get("token_budget")) is not int or args["token_budget"] != BUDGET:
                return "goal create did not carry the requested integer token budget"
            creates.append((index, call))
        elif args.get("op") == "get":
            if "objective" in args or "token_budget" in args:
                return "goal get carried creation-only arguments"
            gets.append((index, call))
        else:
            return "goal operation was not the requested create or get"
    if len(creates) != 1:
        return "the model did not attempt exactly one budget-bearing goal create"
    if guard_denied:
        return None
    create_index, create = creates[0]
    if create.get("is_error") is not False:
        return "the budget-bearing goal create did not complete"
    if len(gets) != 1 or gets[0][0] <= create_index:
        return "the model did not read the goal back after creating it"
    get = gets[0][1]
    if get.get("is_error") is not False or not _budget_readback(get):
        return "goal get did not return the requested token budget"
    return None
