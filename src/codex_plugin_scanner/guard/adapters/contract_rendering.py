"""Display labels and Markdown rendering for harness contracts."""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .contracts import HarnessProtectionContract

DISPLAY_NAMES = {
    "codex": "Codex",
    "claude-code": "Claude Code",
    "opencode": "OpenCode",
    "copilot": "Copilot",
    "cursor": "Cursor",
    "cline": "Cline",
    "gemini": "Gemini",
    "hermes": "Hermes",
    "openclaw": "OpenClaw",
    "antigravity": "Antigravity",
    "kimi": "Kimi",
    "grok": "Grok",
    "pi": "Pi",
    "omp": "Oh My Pi",
    "zcode": "ZCode",
    "paseo": "Paseo",
}


def render_harness_contracts(contracts: Sequence[HarnessProtectionContract]) -> str:
    """Return a Markdown table summarising all harness contracts."""
    header = (
        "| Harness | Install Aliases | Native Approval | Browser Fallback "
        "| Resume | Event Surfaces |\n"
        "|---------|-----------------|-----------------|------------------"
        "|--------|----------------|\n"
    )
    rows: list[str] = []
    for c in contracts:
        aliases = ", ".join(f"`{a}`" for a in c.install_aliases)
        surfaces = ", ".join(c.event_surfaces) if c.event_surfaces else "—"
        rows.append(
            f"| `{c.harness}` | {aliases} | {'✅' if c.native_approval else '❌'} "
            f"| {'✅' if c.browser_fallback else '❌'} "
            f"| {'✅' if c.resume_support else '❌'} | {surfaces} |"
        )
    return header + "\n".join(rows) + "\n"
