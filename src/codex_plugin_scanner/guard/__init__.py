"""Guard runtime embedded inside the plugin scanner package."""

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .cli.commands import run_guard_command


def __getattr__(name: str) -> Any:
    """Resolve the public CLI export without importing the CLI at package load."""

    if name == "run_guard_command":
        from .cli.commands import run_guard_command

        globals()[name] = run_guard_command
        return run_guard_command
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    """Advertise the public CLI export before its lazy resolution."""

    return sorted(set(globals()) | set(__all__))


__all__ = ["run_guard_command"]
