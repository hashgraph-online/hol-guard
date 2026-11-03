"""Render the post-release trial steps included in a merged-contribution claim notice."""

from __future__ import annotations

from collections.abc import Iterable


def trial_lines(extension_ids: Iterable[str]) -> list[str]:
    """Return notice lines for turning on merged command extensions, or none.

    Only command extensions have a device control for `hol-guard command controls`,
    so other contribution kinds get no trial commands.
    """
    command_ids = sorted({extension_id for extension_id in extension_ids if extension_id.startswith("command.")})
    if not command_ids:
        return []
    return [
        "",
        "## Try it in your agent",
        "",
        (
            "Community extensions stay off until enabled on a device. Once a HOL Guard release "
            "includes yours, update with `hol-guard update` (or `pipx install hol-guard`), connect the "
            "agent you use with `hol-guard install <harness>`, and turn the extension on:"
        ),
        "",
        "```sh",
        *(
            f"hol-guard command controls apply {extension_id} --target-kind extension --state enabled"
            for extension_id in command_ids
        ),
        "```",
        "",
        (
            "Use a disposable workspace, test account, or throwaway resource for the destructive case, one "
            "that is safe to lose even if Guard does not intercept the command; never use real data. Ask the "
            "agent to run the safe counterpart and then the destructive command, compare the verdict with your "
            "fixture, deny any review it presents, and check the result with `hol-guard receipts`. "
            "A setup guide written from "
            "that run gives readers accurate steps; open a follow-up pull request if the agent experience "
            "differs from your fixture."
        ),
    ]
