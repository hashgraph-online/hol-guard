"""Guard runtime embedded inside the plugin scanner package."""

from .cli.commands import run_guard_command

__all__ = ["run_guard_command"]
