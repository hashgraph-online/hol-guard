"""Canonical product wording for each enforcement action."""

from __future__ import annotations

from typing import Literal

from ..models import GuardAction

GuardDecisionAction = Literal["allow", "warn", "ask", "block"]


_ACTION_MESSAGES: dict[GuardAction, tuple[GuardDecisionAction, str, str, str]] = {
    "allow": (
        "allow",
        "Allowed by policy",
        "Policy allows this action.",
        "HOL Guard allowed this action because policy already trusts it.",
    ),
    "warn": (
        "warn",
        "Risk signals found",
        "HOL Guard noticed risk signals, but policy allows the harness to continue.",
        "Review the warning if this action was unexpected.",
    ),
    "review": (
        "ask",
        "Approval required",
        "HOL Guard needs your approval before this action can run.",
        "Choose an approval scope, then retry in the harness.",
    ),
    "sandbox-required": (
        "ask",
        "Sandbox review required",
        "HOL Guard wants this action reviewed and run in a sandboxed path.",
        "Run this action in an approved sandbox, then retry.",
    ),
    "require-reapproval": (
        "ask",
        "Fresh approval required",
        "HOL Guard needs a fresh approval because this action changed.",
        "Choose the smallest approval scope that matches your intent, then retry.",
    ),
    "block": (
        "block",
        "Blocked by policy",
        "HOL Guard blocked this action.",
        "Review the details before changing policy or retrying.",
    ),
}
