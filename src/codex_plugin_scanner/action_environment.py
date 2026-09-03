"""Action-boundary environment hygiene for env-triggered external analyzers."""

from __future__ import annotations

import os

EXTERNAL_ANALYZER_SECRET_ENV_NAMES = ("MCP_SCANNER_API_KEY", "MCP_SCANNER_LLM_API_KEY")


def drop_external_analyzer_credentials(online: bool) -> tuple[str, ...]:
    """Remove env-triggered external analyzer credentials unless online opted in.

    The Cisco MCP integration deliberately passes these variables through to its
    isolated subprocess so local installs can opt into LLM/API analysis. Inside
    the GitHub Action that passthrough would let runner- or org-level secrets
    activate external analyzers even though the workflow requested an offline
    scan, so the Action boundary blanks them unless ``online`` is true.
    """
    if online:
        return ()
    dropped = tuple(name for name in EXTERNAL_ANALYZER_SECRET_ENV_NAMES if os.environ.pop(name, None) is not None)
    if dropped:
        print(
            "Note: online is disabled; removed "
            f"{', '.join(dropped)} from the scan environment so repository content "
            "cannot reach external analyzers. Set the online input to true to permit them."
        )
    return dropped
