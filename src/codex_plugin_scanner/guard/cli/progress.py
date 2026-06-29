"""Rich progress bar for hol-guard CLI flows (connect, sync).

Falls back to plain stderr prints when rich is unavailable.
All output goes to stderr so stdout stays clean for --json mode.
"""

from __future__ import annotations

import sys
from types import TracebackType
from typing import Any, cast

try:
    from rich.console import Console
    from rich.progress import (
        BarColumn,
        Progress,
        SpinnerColumn,
        TaskProgressColumn,
        TextColumn,
        TimeElapsedColumn,
    )

    _rich_available = True
except ImportError:
    Console = cast(Any, None)
    Progress = cast(Any, None)
    SpinnerColumn = cast(Any, None)
    BarColumn = cast(Any, None)
    TaskProgressColumn = cast(Any, None)
    TextColumn = cast(Any, None)
    TimeElapsedColumn = cast(Any, None)
    _rich_available = False


class GuardProgress:
    """Context manager that renders a multi-step progress bar.

    Usage::

        with GuardProgress(total=8, title="Guard Connect") as bar:
            bar.step("Preparing authorization...")
            do_prep()
            bar.step("Opening browser...")
            do_browser()
            bar.done("Connected to Guard Cloud")
    """

    def __init__(self, *, total: int, title: str = "", use_rich: bool = True) -> None:
        self._total = total
        self._completed = 0
        self._title = title
        self._use_rich = use_rich and _rich_available
        self._progress: Any | None = None
        self._task: Any | None = None

        if self._use_rich:
            self._progress = Progress(
                SpinnerColumn(spinner_name="dots"),
                BarColumn(bar_width=None, complete_style="green", finished_style="green"),
                TaskProgressColumn(),
                TextColumn("[progress.description]{task.description}"),
                TimeElapsedColumn(),
                console=Console(file=sys.stderr, soft_wrap=True),
                transient=False,
                expand=True,
            )
        else:
            self._progress = None

    # -- context manager protocol -------------------------------------------

    def __enter__(self) -> GuardProgress:
        if self._use_rich and self._progress is not None:
            self._progress.__enter__()
            label = f"{self._title} — " if self._title else ""
            self._task = self._progress.add_task(
                f"{label}Starting...",
                total=self._total,
            )
        else:
            if self._title:
                print(f"hol-guard: {self._title}", file=sys.stderr, flush=True)
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        if self._use_rich and self._progress is not None:
            self._progress.__exit__(exc_type, exc_val, exc_tb)

    # -- public API ----------------------------------------------------------

    def step(self, description: str) -> None:
        """Advance the progress bar and update the description.

        Call this *before* starting the next step so the spinner shows
        the new label while the step runs. The bar advances immediately
        so step 1 shows 1/total (not 0%) while it runs.
        """
        if self._use_rich and self._progress is not None and self._task is not None:
            self._progress.advance(self._task)
            self._progress.update(self._task, description=description)
            self._completed += 1
        else:
            self._completed += 1
            pct = int(self._completed * 100 / self._total) if self._total else 0
            print(
                f"hol-guard: [{pct:3d}%] {description}",
                file=sys.stderr,
                flush=True,
            )

    def done(self, description: str = "Complete") -> None:
        """Mark all steps as complete with a green checkmark."""
        if self._use_rich and self._progress is not None and self._task is not None:
            self._progress.update(
                self._task,
                description=f"✓ {description}",
                completed=self._total,
            )
        else:
            print(f"hol-guard: ✓ {description}", file=sys.stderr, flush=True)
