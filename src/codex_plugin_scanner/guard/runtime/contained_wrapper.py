"""Peel the cd prefix, output handling and status echo that native authority classified."""

from __future__ import annotations

import contextlib
import io
import os
import re
import shlex
import sys
from collections.abc import Iterator
from dataclasses import dataclass, field, replace
from pathlib import Path

from .contained_output_filters import Stage, apply_filters, filter_chain, keep_lines
from .restricted_pytest_validation import _path_is_within

_MERGE = re.compile(r"2>&1(?=[ \t|]|\Z)")
_HOME_CD = re.compile(r"[ \t]*cd[ \t]+~(?=/|[ \t])")
_OPERATOR = frozenset("();<>|&\n")
# Characters the shell would expand; native authority only upgrades exact parses.
_UNQUOTED_EXPANSION = frozenset("$`*?[{")
_DOUBLE_QUOTED_ESCAPES = frozenset('$`"\\')
_ARGUMENT_REJECT = frozenset("<>|&;")
# A final `; echo "<label>$?"`; a label with spaces must be double-quoted.
_STATUS_ECHO = re.compile(
    r'[ \t]*;[ \t]*echo[ \t]+(?:"([A-Za-z0-9_=: -]{0,32})\$\?"|([A-Za-z0-9_=:-]{0,32})\$\?)[ \t]*\Z'
)


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


def _lex(command: str) -> tuple[list[tuple[str, bool]], bool]:
    """Split like a POSIX shell into (value, is_operator) pairs; also report exactness.

    Quoted text is never an operator, so `'|'` or `'print(1)'` stay plain words.
    """
    tokens: list[tuple[str, bool]] = []
    word: list[str] | None = None
    exact = True
    index = 0

    def finish() -> None:
        nonlocal word
        if word is not None:
            tokens.append(("".join(word), False))
            word = None

    while index < len(command):
        character = command[index]
        if character in " \t":
            finish()
            index += 1
        elif word is None and _MERGE.match(command, index):
            tokens.append(("2>&1", True))
            index += 4
        elif character in _OPERATOR:
            finish()
            end = index
            while end < len(command) and command[end] in _OPERATOR:
                end += 1
            tokens.append((command[index:end], True))
            index = end
        elif character == "'":
            end = command.find("'", index + 1)
            if end < 0:
                raise ValueError("unterminated quote")
            word = [*(word or []), command[index + 1 : end]]
            index = end + 1
        elif character == '"':
            word = word or []
            index += 1
            while True:
                if index >= len(command):
                    raise ValueError("unterminated quote")
                character = command[index]
                if character == '"':
                    index += 1
                    break
                if character == "\\" and index + 1 < len(command) and command[index + 1] in _DOUBLE_QUOTED_ESCAPES:
                    index += 1
                    character = command[index]
                elif character == "\\" and command[index + 1 : index + 2] == "\n":
                    raise ValueError("line continuation")
                elif character in "$`":
                    exact = False
                word.append(character)
                index += 1
        elif character == "\\":
            if index + 1 >= len(command) or command[index + 1] == "\n":
                raise ValueError("unsupported escape")
            word = [*(word or []), command[index + 1]]
            index += 2
        else:
            if ord(character) < 32 or character in _UNQUOTED_EXPANSION or (word is None and character in "~#"):
                exact = False
            word = [*(word or []), character]
            index += 1
    finish()
    return tokens, exact


def sibling_project_root(directory: Path, *, home: Path | None) -> Path | None:
    """The repository holding a cd target outside the hook workspace, as native authority finds it.

    The nearest ancestor with a `.git` entry, strictly below home or the system
    temporary directory and owned by this user. The sink rebases its approved
    root there, so the run is contained to that repository exactly as it would
    be from a session started in it.
    """
    if home is None:
        return None
    directory = directory.resolve(strict=True)
    for base in (home, Path("/tmp")):
        try:
            base = base.resolve(strict=True)
        except (OSError, RuntimeError):
            continue
        if directory == base or not _path_is_within(directory, base):
            continue
        candidate = directory
        while candidate != base:
            if os.path.lexists(candidate / ".git"):
                return candidate if candidate.stat().st_uid == os.getuid() else None
            candidate = candidate.parent
        return None
    return None


_DIRECTORY_FLAGS = {"bun": ("--cwd",), "yarn": ("--cwd",), "npm": ("--prefix", "-C"), "pnpm": ("--dir", "-C")}
_PLAIN_WORD = re.compile(r"[A-Za-z0-9/._@+=:,-]+")


def _names_directory_flag(word: str, flags: tuple[str, ...]) -> bool:
    return any(
        word.startswith(flag) and (word == flag or word[len(flag)] == "=" or not flag.startswith("--"))
        for flag in flags
    )


def _package_directory(tokens: list[tuple[str, bool]], base: Path) -> tuple[list[tuple[str, bool]], Path] | None:
    """`bun --cwd <dir> run build` as `bun run build` in `<dir>`, as native authority reads it.

    One directory flag, before the verb or right after `run`. The directory is
    joined to the physical working directory and normalized lexically, as the
    package manager's `path.resolve` does, then resolved on disk. Other
    spellings return None and keep the unwrapped path.
    """
    flags = _DIRECTORY_FLAGS.get(tokens[0][0]) if tokens and not tokens[0][1] else None
    if flags is None:
        return None
    end = next((index for index, (_value, operator) in enumerate(tokens) if operator), len(tokens))
    words = [value for value, _operator in tokens[1:end]]
    options = words[: words.index("--")] if "--" in words else words
    if sum(_names_directory_flag(word, flags) for word in options) != 1:
        return None
    index = 1 if words[:1] == ["run"] else 0
    flag = words[index] if index < len(words) else ""
    if flag in flags and index + 1 < len(words):
        value, consumed = words[index + 1], 2
    elif "=" in flag and flag.split("=", 1)[0] in flags and flag.startswith("--"):
        value, consumed = flag.split("=", 1)[1], 1
    else:
        return None
    rest = words[:index] + words[index + consumed :]
    if value.startswith(("-", "~")) or "//" in value or not _PLAIN_WORD.fullmatch(value) or not rest:
        return None
    # Only scripts are projected; `bun x`, `npm exec` and other runners keep
    # their own tool-runner path, as on the native side.
    if rest[0] not in ("run", "test"):
        return None
    directory = Path(os.path.realpath(os.path.normpath(os.path.join(os.path.realpath(base), value))))
    if not directory.is_dir():
        raise ValueError("package directory is not a directory")
    return [tokens[0], *((word, False) for word in rest), *tokens[end:]], directory


def _joined_list(tokens: list[tuple[str, bool]]) -> str | None:
    """`a && b && c` of plain words, rejoined, or None for any other shape."""
    segments: list[list[str]] = [[]]
    for value, operator in tokens:
        if (value, operator) == ("&&", True):
            segments.append([])
        elif operator or set(value) & _ARGUMENT_REJECT:
            return None
        else:
            segments[-1].append(value)
    if len(segments) < 2 or not all(segments):
        return None
    return " && ".join(shlex.join(segment) for segment in segments)


_INLINE_PROGRAM_FLAGS = {"node": ("-e", "--eval"), "nodejs": ("-e", "--eval"), "bun": ("-e", "--eval")}


def _inline_program_index(tokens: list[tuple[str, bool]]) -> int | None:
    """Where a bare `node -e <program>` or `python3 -c <program>` holds its program, else None.

    That word is one argument the sandbox passes to the interpreter, never to a
    shell, and the peeled core is re-authorized as quoted text. So `;` or `|`
    inside its quotes (`node -e "a(); b()"`) is code, not an operator.
    """
    if len(tokens) != 3 or any(operator for _value, operator in tokens):
        return None
    name, flag = tokens[0][0], tokens[1][0]
    flags = _INLINE_PROGRAM_FLAGS.get(name, ("-c",) if name in {"python", "python3"} else ())
    return 2 if flag in flags else None


def peel_contained_wrapper(
    command: str, *, workspace: Path, home: Path | None = None, cwd: Path | None = None
) -> tuple[str, Path, OutputFilter | None] | None:
    """Return the core command, its directory, and output filter, or None when nothing is wrapped.

    A cd target must lie in the workspace or, given `home`, in a sibling
    repository (see `sibling_project_root`). A relative target is accepted only
    when it names a sibling repository's root from `cwd`, such as a linked
    worktree beside the checkout; after a cd into a sibling root, the core may
    be an `&&` list of plain commands, which is re-authorized there. Only a cd
    into a sibling root may end in `;`: the directory is resolved here and
    nothing runs when it is gone, so the core never falls back to the
    session directory the way the shell would after a failed cd. Raises
    ValueError (or OSError for a missing cd target) for shapes native
    authority never upgrades.
    """
    status = _STATUS_ECHO.search(command)
    if status is not None:
        command = command[: status.start()]
    home_cd = home is not None and _HOME_CD.match(command) is not None
    if home_cd:
        # The cd target's leading `~` is the one expansion proved; lex it as `.`.
        tilde = command.index("~")
        command = command[:tilde] + "." + command[tilde + 1 :]
    tokens, exact = _lex(command)
    directory = workspace
    wrapped = status is not None
    output = None
    sibling_root = False
    if tokens[:1] == [("cd", False)]:
        if len(tokens) < 4 or tokens[1][1] or tokens[2] not in (("&&", True), (";", True)):
            raise ValueError("unsupported cd prefix")
        sequenced = tokens[2] == (";", True)
        spelled = tokens[1][0]
        # Only an unquoted leading `~` expands, as the native proof requires.
        # `~//x` is home/x. Joining home with a leading slash would drop home,
        # because pathlib treats an absolute right-hand side as the whole path.
        rest = spelled[2:].lstrip("/")
        target = home / rest if home_cd and home is not None else Path(spelled)
        if not exact:
            raise ValueError("relative cd target")
        inside = workspace.resolve(strict=True)
        directory = ((cwd or workspace) / target).resolve(strict=True)
        if not target.is_absolute() and (
            _path_is_within(directory, inside) or sibling_project_root(directory, home=home) != directory
        ):
            raise ValueError("relative cd target")
        if not directory.is_dir() or not (
            _path_is_within(directory, inside) or sibling_project_root(directory, home=home) is not None
        ):
            raise ValueError("cd target outside the workspace")
        sibling_root = sibling_project_root(directory, home=home) == directory and not _path_is_within(
            directory, inside
        )
        if sequenced and not sibling_root:
            raise ValueError("unsupported cd prefix")
        tokens, wrapped = tokens[3:], True
        joined = _joined_list(tokens) if sibling_root else None
        if joined is not None:
            # A filter after `a && b` applies to `b` alone, so none is peeled.
            if status is not None:
                label = status.group(1) if status.group(1) is not None else status.group(2)
                output = OutputFilter("all", 0, False, status_label=label)
            return joined, directory, output
    elif exact and (package := _package_directory(tokens, cwd or workspace)) is not None:
        tokens, directory = package
        if not (
            _path_is_within(directory, workspace.resolve(strict=True))
            or sibling_project_root(directory, home=home) is not None
        ):
            raise ValueError("package directory outside the workspace")
        wrapped = True
    if ("|", True) in tokens:
        index = tokens.index(("|", True))
        stages = filter_chain(tokens[index + 1 :])
        tokens = tokens[:index]
        merge = tokens[-1:] == [("2>&1", True)]
        if merge:
            tokens = tokens[:-1]
        if len(stages) == 1 and stages[0][0] in {"head", "tail"}:
            output = OutputFilter(stages[0][0], int(stages[0][1]), merge)
        else:
            output = OutputFilter("pipe", 0, merge, stages=stages)
        wrapped = True
    elif tokens[-1:] == [("2>&1", True)]:
        tokens = tokens[:-1]
        output = OutputFilter("all", 0, True)
        wrapped = True
    if status is not None:
        label = status.group(1) if status.group(1) is not None else status.group(2)
        output = replace(output or OutputFilter("all", 0, False), status_label=label)
    if not wrapped:
        return None
    program = _inline_program_index(tokens)
    if (
        not exact
        or not tokens
        or any(
            operator or (index != program and set(value) & _ARGUMENT_REJECT)
            for index, (value, operator) in enumerate(tokens)
        )
    ):
        raise ValueError("unsupported wrapper shape")
    return shlex.join(value for value, _operator in tokens), directory, output


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
