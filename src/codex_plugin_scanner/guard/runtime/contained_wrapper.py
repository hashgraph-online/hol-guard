"""Carry native authority's peel to the execution sink, and apply its output handling.

The cd prefix, output filter chain and status echo are classified once, by the
pre-tool pass. This module used to peel them a second time from its own lexer,
its own sibling-repository rule and its own filter grammar; that copy could not
read a Windows owner SID, so it accepted checkouts the classifier had refused
and handed the sandbox a core no receipt covered. The questions below are now
asked of the classifier. What stays here is the sink's own work: holding the
answer, and filtering the captured output in process.
"""

from __future__ import annotations

import contextlib
import io
import sys
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import cast

from ..native_contained_wrapper_plan import (
    ContainedWrapperPlanUnavailableError,
    native_contained_wrapper_plan,
)
from .contained_output_filters import Stage, apply_filters, keep_lines


@dataclass(frozen=True)
class OutputFilter:
    """A trailing `2>&1`, output filter chain or `; echo "<label>$?"`.

    `kind` is "head" or "tail" for one bounded filter, "pipe" for any other
    chain in `stages` (see `contained_output_filters`), else "all".
    """

    kind: str
    count: int
    merge_stderr: bool
    status_label: str | None = None
    stages: tuple[Stage, ...] = ()
    pipe_status: list[int] = field(default_factory=list, init=False, compare=False, repr=False)

    def status_line(self, exit_code: int) -> str | None:
        """The echo's output; after a pipe, `$?` is the last filter's own status."""
        if self.status_label is None:
            return None
        if self.kind == "pipe":
            exit_code = self.pipe_status[-1] if self.pipe_status else 0
        elif self.kind in {"head", "tail"}:
            exit_code = 0
        return f"{self.status_label}{exit_code}\n"


def _answer(
    command: str,
    *,
    workspace: Path,
    cwd: Path | None,
    home: Path | None,
    project_root_query: Path | None = None,
) -> Mapping[str, object]:
    """Ask native authority about one command, or raise when it cannot answer."""
    return native_contained_wrapper_plan(
        command,
        workspace=workspace,
        cwd=cwd,
        home=home,
        project_root_query=project_root_query,
    )


def _root(answer: Mapping[str, object], key: str) -> Path | None:
    value = answer.get(key)
    return Path(value) if isinstance(value, str) and value else None


def _output_filter(encoded: object) -> OutputFilter | None:
    """The sink's output handling, as native authority described it."""
    if encoded is None:
        return None
    if not isinstance(encoded, Mapping):
        raise ValueError("unsupported wrapper shape")
    fields = cast(Mapping[str, object], encoded)
    count = fields["count"]
    stages = fields.get("stages") or ()
    if not isinstance(count, int) or not isinstance(stages, Sequence):
        raise ValueError("unsupported wrapper shape")
    label = fields.get("status_label")
    return OutputFilter(
        str(fields["kind"]),
        count,
        bool(fields["merge_stderr"]),
        status_label=None if label is None else str(label),
        stages=tuple(tuple(str(word) for word in _words(stage)) for stage in stages),
    )


def _words(stage: object) -> Sequence[object]:
    if not isinstance(stage, Sequence) or isinstance(stage, (str, bytes)):
        raise ValueError("unsupported wrapper shape")
    return stage


def sibling_project_root(directory: Path, *, home: Path | None) -> Path | None:
    """The repository holding a directory outside the hook workspace, as native authority finds it.

    The nearest ancestor with a `.git` entry, strictly below home - or the
    system temporary directory, on POSIX - and owned by this user, which only
    the native runtime can establish on Windows. The sink rebases its approved
    root there, so the run is contained to that repository exactly as it would
    be from a session started in it. An unreachable runtime proves no root.
    """
    if home is None:
        return None
    try:
        answer = _answer(
            "",
            workspace=directory,
            cwd=directory,
            home=home,
            project_root_query=directory,
        )
    except ContainedWrapperPlanUnavailableError:
        return None
    return _root(answer, "project_root")


def anchored_sibling_root(command: str, *, workspace: Path, cwd: Path, home: Path | None) -> Path | None:
    """The sibling repository an absolute script or tool names, as native authority anchors it.

    One plain command whose executed path lies in a repository outside the
    workspace roots the sandbox there, as after `cd <root> &&`. A relative word
    naming a file from `cwd`, the workspace's own repository, or an untrusted
    temporary root keeps None, as does an unreachable runtime.
    """
    try:
        answer = _answer(command, workspace=workspace, cwd=cwd, home=home)
    except ContainedWrapperPlanUnavailableError:
        return None
    return _root(answer, "anchored_sibling_root")


def peel_contained_wrapper(
    command: str, *, workspace: Path, home: Path | None = None, cwd: Path | None = None
) -> tuple[str, Path, OutputFilter | None] | None:
    """Return the core command, its directory, and output filter, or None when nothing is wrapped.

    A cd target must lie in the workspace or, given `home`, in a sibling
    repository (see `sibling_project_root`). A relative target is accepted only
    when it names a sibling repository's root from `cwd`, such as a linked
    worktree beside the checkout, or, on Windows, a workspace directory joined
    by `&&`; after a cd into a sibling root, the core may be an `&&` list of
    plain commands, which is re-authorized there. Only a cd into a sibling
    repository may end in `;` or carry `2>/dev/null`: the directory is resolved
    by native authority and nothing is peeled when it is gone, so the core
    never falls back to the session directory the way the shell would after a
    failed cd.

    Raises ValueError for a wrapped shape native authority does not peel, which
    the sink answers by running the text whole in the sandbox native authority
    chose for it, and ContainedWrapperPlanUnavailableError when no classifier
    is reachable to ask.
    """
    answer = _answer(command, workspace=workspace, cwd=cwd, home=home)
    refusal = answer.get("refusal")
    if refusal is not None:
        raise ValueError(str(refusal))
    plan = answer.get("plan")
    if plan is None:
        return None
    if not isinstance(plan, Mapping):
        raise ValueError("unsupported wrapper shape")
    return str(plan["core"]), Path(str(plan["directory"])), _output_filter(plan.get("output"))


@contextlib.contextmanager
def bounded_output(output: OutputFilter | None) -> Iterator[None]:
    """Apply the output filters to the contained core's captured output.

    A bare `2>&1` is one file descriptor in the sandbox, so this wrapper does
    not buffer that full stream. Head and tail keep only the requested lines
    in-process; a grep stage runs the system grep on the captured text alone,
    with arguments that name no file (see `contained_output_filters`).
    """
    if output is None or (output.kind == "all" and not output.merge_stderr):
        yield
        return
    if output.kind == "all":
        with contextlib.redirect_stderr(sys.stdout):
            yield
        return
    destination = sys.stdout
    captured = io.StringIO()
    errors = contextlib.redirect_stderr(captured) if output.merge_stderr else contextlib.nullcontext()
    try:
        with contextlib.redirect_stdout(captured), errors:
            yield
    finally:
        if output.kind == "pipe":
            text, diagnostics, status = apply_filters(captured.getvalue(), output.stages)
            output.pipe_status.append(status)
            if diagnostics:
                sys.stderr.write(diagnostics)
                sys.stderr.flush()
        else:
            text = "".join(keep_lines(captured.getvalue().splitlines(keepends=True), output.kind, output.count))
        destination.write(text)
        destination.flush()
