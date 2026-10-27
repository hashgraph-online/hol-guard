"""Find and start the runtime CLIs an install plan names.

Programs come only from absolute PATH entries, never the current directory,
then from the folders each runtime's installer is known to use.
On POSIX a folder or program every user can write to is skipped, since anyone
could have planted it. On Windows an ``.exe`` wins over a ``.cmd`` or ``.bat``
shim in the same folder, and every argument bound for a shim must stay clear
of cmd.exe's metacharacters, because cmd.exe re-parses it. Children get no
stdin, so a prompt Guard did not expect ends the command instead of hanging.
"""

from __future__ import annotations

import os
import stat
import subprocess
import sys
import threading
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, TextIO

COMMAND_TIMEOUT_SECONDS = 600.0
_WINDOWS_EXTENSIONS = (".exe", ".cmd", ".bat")
_BATCH_EXTENSIONS = (".cmd", ".bat")
_BATCH_UNSAFE = frozenset('%^&|<>"()!')


class RunnerError(RuntimeError):
    """A program could not be started safely, or did not finish."""


@dataclass(frozen=True)
class Program:
    name: str
    #: Absolute path; the plan shows it and the confirmation covers it.
    path: str
    #: False when it was found in a known install folder that is not on PATH.
    on_path: bool = True

    @property
    def batch(self) -> bool:
        return self.path.lower().endswith(_BATCH_EXTENSIONS)


@dataclass
class Lookup:
    programs: dict[str, Program] = field(default_factory=dict)
    #: One line per copy of a program Guard found and would not use.
    ignored: list[str] = field(default_factory=list)


def _world_writable(mode: int) -> bool:
    return bool(mode & stat.S_IWOTH)


def _open_ancestor(found: str) -> str | None:
    """The first folder above ``found``, or above the file it links to, that any
    user can rename entries in. A sticky folder such as /tmp only lets owners
    rename, so it does not count."""

    for start in (found, os.path.realpath(found)):
        folder = os.path.dirname(start)
        while True:
            try:
                mode = os.stat(folder).st_mode
            except OSError:
                break
            if _world_writable(mode) and not mode & stat.S_ISVTX:
                return folder
            parent = os.path.dirname(folder)
            if parent == folder:
                break
            folder = parent
    return None


def _candidate(folder: str, name: str, *, windows: bool) -> str | None:
    if windows:
        for extension in _WINDOWS_EXTENSIONS:
            candidate = os.path.join(folder, name + extension)
            if os.path.isfile(candidate):
                return candidate
        return None
    candidate = os.path.join(folder, name)
    return candidate if os.path.isfile(candidate) and os.access(candidate, os.X_OK) else None


def find_programs(
    names: Iterable[str],
    environ: Mapping[str, str] | None = None,
    *,
    windows: bool | None = None,
    known: Sequence[str] = (),
) -> Lookup:
    """Resolve each name to an absolute path Guard is willing to start: PATH
    first, then the ``known`` install folders, with the same checks."""

    environ = os.environ if environ is None else environ
    windows = os.name == "nt" if windows is None else windows
    separator = ";" if windows else ":"
    names = list(names)
    lookup = Lookup()
    seen: set[str] = set()
    folders: list[str] = []
    for entry in environ.get("PATH", "").split(separator):
        if not entry or entry in seen:
            continue
        seen.add(entry)
        reason = None
        if not os.path.isabs(entry):
            reason = "a relative PATH entry"
        else:
            try:
                info = os.stat(entry)
            except OSError:
                continue
            if not stat.S_ISDIR(info.st_mode):
                continue
            if not windows and _world_writable(info.st_mode):
                reason = "a folder every user can write to"
        if reason is None:
            folders.append(entry)
            continue
        for name in names:
            planted = _candidate(os.path.abspath(entry), name, windows=windows)
            if planted:
                lookup.ignored.append(f"Guard ignored {planted}: it is in {reason}.")
    extra: list[str] = []
    for entry in known:
        if entry in seen or not os.path.isabs(entry):
            continue
        seen.add(entry)
        try:
            info = os.stat(entry)
        except OSError:
            continue
        if stat.S_ISDIR(info.st_mode) and (windows or not _world_writable(info.st_mode)):
            extra.append(entry)
    for name in names:
        for folder in [*folders, *extra]:
            found = _candidate(folder, name, windows=windows)
            if found is None:
                continue
            if not windows:
                try:
                    mode = os.stat(found).st_mode
                except OSError:
                    continue
                if _world_writable(mode):
                    lookup.ignored.append(f"Guard ignored {found}: every user can write to it.")
                    continue
                folder_open = _open_ancestor(found)
                if folder_open is not None:
                    lookup.ignored.append(f"Guard ignored {found}: every user can change {folder_open}.")
                    continue
            lookup.programs[name] = Program(name, found, on_path=folder in folders)
            break
    return lookup


def check_arguments(program: Program, arguments: Sequence[str]) -> None:
    """Refuse arguments cmd.exe could read as commands when the program is a shim."""

    if not program.batch:
        return
    for argument in arguments:
        if not argument or any(
            character in _BATCH_UNSAFE or character.isspace() or ord(character) < 32 or ord(character) == 127
            for character in argument
        ):
            raise RunnerError(
                f"Guard will not pass {argument!a} to {program.path}: cmd.exe could read it as a command."
            )


@dataclass(frozen=True)
class Completed:
    returncode: int
    stdout: str


# A runtime's reply is a short JSON document or a few lines of text; more
# than this means something is wrong, and Guard stops reading rather than
# holding it all in memory.
OUTPUT_LIMIT_BYTES = 4 * 1024 * 1024

# How long to wait for the output reader once the command has exited. A
# background process the command started can keep the pipe open after that.
READER_GRACE_SECONDS = 5.0


def _run_capped(argv: Sequence[str], *, timeout: float, **options: Any) -> subprocess.CompletedProcess[str]:
    """Run ``argv`` with stdout piped, keeping at most OUTPUT_LIMIT_BYTES."""

    process = subprocess.Popen(list(argv), stdout=subprocess.PIPE, **options)
    stream = process.stdout
    assert stream is not None
    chunks: list[bytes] = []
    too_large = threading.Event()

    def read() -> None:
        size = 0
        fd = stream.fileno()
        with stream:
            for chunk in iter(lambda: os.read(fd, 65536), b""):
                size += len(chunk)
                if size > OUTPUT_LIMIT_BYTES:
                    too_large.set()
                    process.kill()
                    return
                chunks.append(chunk)

    reader = threading.Thread(target=read, daemon=True)
    reader.start()
    try:
        returncode = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        raise
    finally:
        reader.join(timeout=READER_GRACE_SECONDS)
        # A reader still blocked in read() holds the stream's lock, so close()
        # would wait for whatever process still has the pipe open. Leave the
        # stream to the daemon reader then; it closes the stream at EOF.
        if not reader.is_alive():
            stream.close()
    if too_large.is_set():
        name = os.path.basename(argv[0])
        raise RunnerError(f"{name} printed more than {OUTPUT_LIMIT_BYTES // (1024 * 1024)} MiB, so Guard stopped it.")
    text = b"".join(list(chunks)).decode("utf-8", errors="replace").replace("\r\n", "\n").replace("\r", "\n")
    return subprocess.CompletedProcess(list(argv), returncode, text)


def run(
    program: Program,
    arguments: Sequence[str],
    *,
    capture: bool = False,
    echo: TextIO | None = None,
    timeout: float = COMMAND_TIMEOUT_SECONDS,
) -> Completed:
    """Start ``program`` without a shell or stdin.

    ``capture`` returns its stdout instead of showing it. ``echo`` sends it
    to another stream, such as stderr when stdout must stay one JSON document.
    """

    check_arguments(program, arguments)
    piped = capture or echo is not None
    try:
        if piped:
            completed = _run_capped([program.path, *arguments], shell=False, stdin=subprocess.DEVNULL, timeout=timeout)
        else:
            completed = subprocess.run(
                [program.path, *arguments], shell=False, check=False, stdin=subprocess.DEVNULL, timeout=timeout
            )
    except subprocess.TimeoutExpired as error:
        raise RunnerError(f"{program.name} did not finish within {timeout:.0f} seconds.") from error
    except OSError as error:
        raise RunnerError(f"{program.path} could not be started.") from error
    output = completed.stdout if isinstance(completed.stdout, str) else ""
    if echo is not None and not capture and output:
        echo.write(output)
        echo.flush()
    return Completed(completed.returncode, output)


def stdin_is_terminal() -> bool:
    try:
        return sys.stdin.isatty()
    except (AttributeError, ValueError):
        return False
