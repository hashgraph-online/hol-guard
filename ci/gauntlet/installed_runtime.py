"""Resolve and classify the Guard executable the installed-acceptance lane drives.

The qualification lane imports Guard as a library from a wheel. This lane runs
an executable the way a user's machine runs it, so it first has to establish
*what* it was handed: a console script that still needs an interpreter, or the
frozen PyInstaller bundle the Desktop app installs. PR #4773 described a defect
that only appears on a frozen install, so a lane that silently accepted a wheel
would keep missing that whole class.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

#: Directory PyInstaller places beside a ``--onedir`` executable.
ONEDIR_INTERNAL = "_internal"
#: Native runtime the Desktop bundle ships inside ``_internal``.
BUNDLED_NATIVE_RUNTIME = Path("codex_plugin_scanner") / "_native" / "hol-guard-runtime"
#: Manifest sealed next to the bundled native runtime.
BUNDLED_NATIVE_MANIFEST = Path("codex_plugin_scanner") / "_native" / "runtime-manifest.json"

FROZEN_ONEDIR = "frozen-onedir"
FROZEN_ONEFILE = "frozen-onefile"
SCRIPT = "script"
#: A shell wrapper that reaches a frozen bundle it does not name literally.
SHIM = "shim"

_VERSION_TIMEOUT = 120.0


class InstalledRuntimeError(RuntimeError):
    """Raised when the executable under test cannot be accepted as-is."""


@dataclass(frozen=True)
class InstalledRuntime:
    """An executable the lane will drive, plus what the lane proved about it."""

    path: Path
    kind: str
    version: str
    native_runtime: Path | None
    interpreter_free: bool

    @property
    def frozen(self) -> bool:
        return self.kind in {FROZEN_ONEDIR, FROZEN_ONEFILE, SHIM}

    def as_evidence(self) -> dict[str, object]:
        return {
            "path": str(self.path),
            "kind": self.kind,
            "frozen": self.frozen,
            "version": self.version,
            "native_runtime": str(self.native_runtime) if self.native_runtime else None,
            "interpreter_free": self.interpreter_free,
        }


def classify(path: Path) -> tuple[str, Path | None]:
    """Name the packaging of ``path`` and the native runtime it carries.

    A onedir bundle is recognised by its sibling ``_internal`` directory with
    the sealed native runtime inside it, which is what the Desktop feed builds
    and asserts. Anything else that is not a text script is treated as a
    onefile bundle; a text script is a wheel console script.
    """

    internal = path.parent / ONEDIR_INTERNAL
    if internal.is_dir():
        # The layout, not its contents, says which bundle this is. A onedir
        # launcher whose sealed runtime went missing is a damaged onedir, and
        # calling it a onefile would skip the very artifacts this lane exists
        # to check: `resolve_runtime` refuses it by name instead.
        bundled = internal / BUNDLED_NATIVE_RUNTIME
        return FROZEN_ONEDIR, (bundled if bundled.exists() else None)
    if _shebang(path) is not None:
        return SCRIPT, None
    return FROZEN_ONEFILE, None


def _shebang(path: Path) -> str | None:
    """The interpreter line of a text script, or ``None`` for a binary."""

    try:
        with path.open("rb") as handle:
            if handle.read(2) != b"#!":
                return None
            line = handle.readline(512)
    except OSError:
        return None
    return line.decode("utf-8", "replace").strip()


def _needs_an_interpreter(path: Path) -> bool:
    """Whether the script's own shebang hands it to a language runtime.

    pip writes console scripts with an absolute shebang onto the installing
    environment's interpreter, which the kernel resolves without consulting
    ``PATH``. Such a script answers ``--version`` with an empty ``PATH`` and
    would otherwise be reclassified as a shim onto a frozen bundle, which is
    exactly the substitution ``--require-frozen`` exists to refuse. The
    Desktop wrapper chain this lane does accept is ``/bin/sh``.
    """

    shebang = _shebang(path)
    if shebang is None:
        return False
    # `_shebang` already consumed the `#!`, so this line is the interpreter.
    words = shebang.split()
    if not words:
        return False
    interpreter = Path(words[0]).name
    if interpreter == "env" and len(words) > 1:
        interpreter = Path(words[1]).name
    return not interpreter.startswith(("sh", "bash", "dash", "zsh", "ksh"))


def probe_version(path: Path, *, environment: dict[str, str] | None = None) -> str:
    """Return the executable's own reported version."""

    completed = subprocess.run(
        [str(path), "--version"],
        capture_output=True,
        text=True,
        timeout=_VERSION_TIMEOUT,
        env=environment if environment is not None else _base_environment(),
        check=False,
    )
    if completed.returncode != 0:
        raise InstalledRuntimeError(f"{path} --version exited {completed.returncode}: {completed.stderr.strip()[:400]}")
    reported = (completed.stdout or completed.stderr).strip()
    if not reported:
        raise InstalledRuntimeError(f"{path} --version printed nothing")
    return reported.splitlines()[0].strip()


def _base_environment() -> dict[str, str]:
    """A parent environment with Python's import seams removed.

    ``PYTHONPATH`` or a stray ``PYTHONHOME`` from the lane's own virtual
    environment would let a frozen bundle pick up the repository's sources, so
    nothing the lane observes afterwards would be about the bundle.
    The build interpreter's loader path is likewise outside the installed
    harness home and must not become the agent's library search path. Runtime
    resolution checks ``--version`` with this same environment before replay.
    """

    environment = dict(os.environ)
    for name in ("PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "VIRTUAL_ENV", "LD_LIBRARY_PATH"):
        environment.pop(name, None)
    return environment


def prove_interpreter_free(path: Path) -> bool:
    """Run the executable with no Python on ``PATH``.

    A frozen bundle carries its own interpreter, so it still answers. A wheel
    console script cannot, which is what stops a wheel from being presented to
    this lane as if it were the shipped bundle.
    """

    with tempfile.TemporaryDirectory(prefix="guard-installed-path-") as empty:
        environment = _base_environment()
        environment["PATH"] = empty
        try:
            probe_version(path, environment=environment)
        except (InstalledRuntimeError, OSError, subprocess.SubprocessError):
            return False
    return True


def resolve_runtime(path: Path, *, require_frozen: bool) -> InstalledRuntime:
    """Accept ``path`` as the executable under test, or explain the refusal."""

    resolved = Path(path).expanduser()
    if not resolved.is_absolute():
        located = shutil.which(str(resolved))
        # `shutil.which` hands back a path that names a directory unchanged, so
        # a relative `--runtime` can survive this. The lane runs the executable
        # with the case workspace as its working directory, where a path
        # relative to the caller's own directory no longer names anything.
        resolved = (Path(located) if located else resolved).resolve()
    if not resolved.exists():
        raise InstalledRuntimeError(f"no executable at {resolved}")
    if not os.access(resolved, os.X_OK):
        raise InstalledRuntimeError(f"{resolved} is not executable")
    kind, native_runtime = classify(resolved)
    interpreter_free = prove_interpreter_free(resolved)
    if kind == SCRIPT and interpreter_free and not _needs_an_interpreter(resolved):
        # The Desktop install is reached through two `/bin/sh` wrappers, the
        # second of which computes the bundle path from `current.json` at run
        # time. Reading the first wrapper's bytes says "console script" about a
        # genuinely frozen install, so the packaging question is settled by
        # what the executable can actually do without an interpreter, not by
        # how its first two bytes look.
        kind = SHIM
    if require_frozen and kind == SCRIPT:
        raise InstalledRuntimeError(
            f"--require-frozen was asked for, but {resolved} is a console script, not a frozen bundle"
        )
    if require_frozen and not interpreter_free:
        raise InstalledRuntimeError(
            f"{resolved} looks frozen but needs an interpreter on PATH to answer --version; "
            "a wheel console script cannot stand in for the shipped bundle"
        )
    if kind == FROZEN_ONEDIR:
        internal = resolved.parent / ONEDIR_INTERNAL
        missing = [
            internal / relative
            for relative in (BUNDLED_NATIVE_RUNTIME, BUNDLED_NATIVE_MANIFEST)
            if not (internal / relative).exists()
        ]
        if missing:
            spelled = ", ".join(str(path) for path in missing)
            raise InstalledRuntimeError(f"the onedir bundle at {resolved} is missing {spelled}")
    return InstalledRuntime(
        path=resolved,
        kind=kind,
        version=probe_version(resolved),
        native_runtime=native_runtime,
        interpreter_free=interpreter_free,
    )


def isolated_environment(*, home: Path, guard_home: Path) -> dict[str, str]:
    """Environment for driving the executable against a lane-owned home.

    Every harness path Guard writes is derived from ``HOME``, so pointing it at
    a lane-owned directory keeps the run away from the operator's real
    ``~/.claude``, ``~/.codex`` and ``~/.omp``.
    """

    environment = _base_environment()
    environment["HOME"] = str(home)
    environment["USERPROFILE"] = str(home)
    environment["HOL_GUARD_HOME"] = str(guard_home)
    environment["XDG_CONFIG_HOME"] = str(home / ".config")
    environment["XDG_STATE_HOME"] = str(home / ".local" / "state")
    environment["XDG_CACHE_HOME"] = str(home / ".cache")
    return environment


def run_guard(
    runtime: InstalledRuntime,
    arguments: list[str],
    *,
    environment: dict[str, str],
    stdin: str | None = None,
    timeout: float = 300.0,
    cwd: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    """Drive the executable exactly as a harness or a user would."""

    return subprocess.run(
        [str(runtime.path), *arguments],
        input=stdin if stdin is not None else "",
        capture_output=True,
        text=True,
        timeout=timeout,
        env=environment,
        cwd=str(cwd) if cwd is not None else None,
        check=False,
    )


def json_payload(completed: subprocess.CompletedProcess[str]) -> dict[str, object] | None:
    """Return the first JSON object the command printed, if it printed one."""

    for stream in (completed.stdout, completed.stderr):
        for line in (stream or "").splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                parsed = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(parsed, dict):
                return parsed
    return None


__all__ = [
    "FROZEN_ONEDIR",
    "FROZEN_ONEFILE",
    "SCRIPT",
    "SHIM",
    "InstalledRuntime",
    "InstalledRuntimeError",
    "classify",
    "isolated_environment",
    "json_payload",
    "probe_version",
    "prove_interpreter_free",
    "resolve_runtime",
    "run_guard",
]
