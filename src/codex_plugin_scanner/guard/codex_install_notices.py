"""User-facing scope and reload notices for managed Codex configuration."""

from __future__ import annotations


def codex_install_notices(*, active: bool) -> dict[str, object]:
    """Describe the user-level mutation independently of workspace selection."""
    scope = (
        "Codex configuration is user-wide: this affects all Codex sessions using this user's "
        "~/.codex/config.toml. --workspace selects workspace context; it does not make the installation project-only."
    )
    reload = (
        "Fully quit and reopen Codex Desktop and restart existing Codex CLI sessions to load the installed hooks."
        if active
        else "Fully quit and reopen Codex Desktop and restart existing Codex CLI sessions to discard cached hooks. "
        "Until then, cached Guard hooks may deny calls after uninstall; "
        "stopping the daemon alone does not unload hooks."
    )
    return {
        "installation_scope": "user",
        "runtime_restart_required": True,
        "notes": [scope, reload],
    }
