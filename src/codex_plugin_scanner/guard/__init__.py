"""Guard runtime embedded inside the plugin scanner package.

`run_guard_command` resolves lazily so short-lived invocations (`--version`,
daemon lifecycle probes) do not pay for the full command-surface import.
"""

__all__ = ["run_guard_command"]


def __getattr__(name: str):
    if name == "run_guard_command":
        from .cli.commands import run_guard_command

        return run_guard_command
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
