"""Oh My Pi provider configuration that routes the agent through the live relay."""

from __future__ import annotations

import json
from pathlib import Path

from .provider import InferenceRelay

DEFAULT_MAX_TOKENS = 8192
# Pinned reasoning spends output tokens before the tool call.
REASONING_MAX_TOKENS = 32768


def write_agent_configuration(path: Path, relay: InferenceRelay) -> None:
    """Point the actual OMP provider at the transparent live relay.

    ``config.yml`` pins ``launch.enabled`` off so the bash schema stays the
    non-service variant: otherwise 18.4.12 advertises ``name``/``ready`` and the
    model materializes inert defaults that add notice lines to every output.
    """
    path.mkdir(mode=0o700)
    (path / "config.yml").write_text(json.dumps({"launch": {"enabled": False}}), encoding="utf-8")
    configuration = {
        "providers": {
            "gauntlet-live": {
                "baseUrl": relay.base_url,
                "api": "openai-completions",
                "auth": "none",
                "models": [
                    {
                        "id": "agent",
                        "name": "Guard Gauntlet live inference",
                        "reasoning": False,
                        "input": ["text"],
                        "contextWindow": 128000,
                        "maxTokens": DEFAULT_MAX_TOKENS if relay.reasoning_effort is None else REASONING_MAX_TOKENS,
                    }
                ],
            }
        }
    }
    # JSON is a YAML subset; this avoids another serialization dependency.
    (path / "models.yml").write_text(json.dumps(configuration, indent=2), encoding="utf-8")
