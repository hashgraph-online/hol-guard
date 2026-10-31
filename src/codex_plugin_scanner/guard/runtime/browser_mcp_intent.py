"""Browser MCP operation classification, answered by the native runtime.

Browser classification is owned by the bundled Rust runtime; native failure
never means a safe/non-browser match.
"""

from __future__ import annotations

from typing import Literal

from ..native_context import context_browser_mcp

BrowserIntent = Literal[
    "browser.navigation",
    "browser.inspect",
    "browser.interact",
    "browser.transfer",
    "browser.privileged",
]


def classify_browser_operation(operation: str, server_name: str = "") -> BrowserIntent | None:
    return context_browser_mcp(
        {
            "operation": "classify",
            "tool_operation": operation,
            "server_name": server_name,
        }
    )["intent"]


__all__ = [
    "BrowserIntent",
    "classify_browser_operation",
]
