"""Grok managed state and runtime hook verification."""

from .base import HarnessContext
from .grok_config import GUARD_HOOK_PRETOOL_FILE, GUARD_HOOK_PROMPT_FILE


def grok_runtime_hooks_verified(context: HarnessContext) -> bool:
    """Return whether Grok catch-all PreToolUse and prompt screening hooks are installed.

    Managed permission rules in ``managed_config.toml`` are a second layer. Missing
    that file must not fail machine-wide local protection health while hooks still
    intercept every tool.
    """

    from ..cli.install_commands import _grok_pretool_is_catchall, _grok_prompt_hook_is_observe
    from .grok import GrokHarnessAdapter

    hooks_dir = GrokHarnessAdapter._hooks_dir(context)
    return _grok_pretool_is_catchall(hooks_dir / GUARD_HOOK_PRETOOL_FILE, context) and _grok_prompt_hook_is_observe(
        hooks_dir / GUARD_HOOK_PROMPT_FILE, context
    )
