"""Oh My Pi provider configuration that routes the agent through the live relay."""

from __future__ import annotations

import json
from pathlib import Path

from .provider import InferenceRelay

DEFAULT_MAX_TOKENS = 8192
# Pinned reasoning spends output tokens before the tool call.
REASONING_MAX_TOKENS = 32768


def write_agent_configuration(
    path: Path, relay: InferenceRelay, *, wait_for_tasks: bool = False, memory_bank: bool = False
) -> None:
    """Point the actual OMP provider at the transparent live relay.

    ``config.yml`` pins ``launch.enabled`` off so the bash schema stays the
    non-service variant: otherwise 18.4.12 advertises ``name``/``ready`` and the
    model materializes inert defaults that add notice lines to every output.
    Synchronous task scenarios must await delegated results before print mode
    exits. Async scenarios retain the SDK default to exercise wait itself.

    The `learn` tool exists only where auto-learn is on and a memory backend is
    live, so the memory scenarios turn both on. `local` keeps the bank inside
    the disposable agent directory; every other scenario leaves memory off so
    its own tool inventory is unchanged.
    """
    path.mkdir(mode=0o700)
    # The eval scenario exercises the guarded JavaScript session-tool bridge;
    # Python/raw filesystem cells have a different admission contract.
    configuration: dict[str, object] = {
        "launch": {"enabled": False},
        "async": {"enabled": not wait_for_tasks},
        "eval": {"py": False, "js": True},
    }
    if memory_bank:
        configuration["autolearn"] = {"enabled": True, "autoContinue": False}
        configuration["memory"] = {"backend": "local"}
    (path / "config.yml").write_text(json.dumps(configuration), encoding="utf-8")
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
