"""Cached SDK prefixes and native wheels shared by qualification driver processes.

Everything under the cache root is owned by this driver: lock-keyed SDK prefixes,
per-SHA platform wheels and one persistent build worktree whose ``rust/target``
stays warm between builds. Writers serialize on flock'd lock files.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import signal
import stat
import subprocess
import sys
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from pathlib import Path
from typing import Any

from .fixtures import digest_file, mkdir_private

REQUIRED_TOOLS = ("git", "uv", "bun", "npm", "rg", "curl")
GNU_SED_DIRS = (
    Path("/opt/homebrew/opt/gnu-sed/libexec/gnubin"),
    Path("/usr/local/opt/gnu-sed/libexec/gnubin"),
)
LOCK_DIR = "ci/pi-exact-continuation"


def _reap_group(process: subprocess.Popen[Any]) -> None:
    """SIGTERM then SIGKILL a setup process group so it cannot outlive the driver."""
    with suppress(ProcessLookupError, PermissionError):
        os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=30)
        return
    except subprocess.TimeoutExpired:
        pass
    with suppress(ProcessLookupError, PermissionError):
        os.killpg(process.pid, signal.SIGKILL)
    with suppress(subprocess.TimeoutExpired):
        process.wait(timeout=30)


def run_logged(argv: list[str], *, cwd: Path, log: Path, env: dict[str, str] | None = None) -> None:
    """Append one setup command's output to the run log; surface only its tail on failure.

    The command runs in its own process group so an interrupted driver reaps the
    whole setup tree (including the niced wheel build) before any lock releases.
    """
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("ab") as stream:
        process = subprocess.Popen(
            argv, cwd=cwd, env=env, stdout=stream, stderr=subprocess.STDOUT, start_new_session=True
        )
        try:
            returncode = process.wait(timeout=7200)
        except BaseException:
            _reap_group(process)
            raise
    if returncode:
        tail = log.read_text(encoding="utf-8", errors="replace").splitlines()[-20:]
        for line in tail:
            print("qualify: setup | " + line, file=sys.stderr)
        raise RuntimeError(f"setup command failed ({returncode}); full log at {log}")


def git(repo: Path, *args: str, check: bool = True) -> str:
    """Run Git in the trusted checkout, returning stdout."""
    result = subprocess.run(
        ["git", *args],
        cwd=repo,
        env={**os.environ, "GIT_CONFIG_NOSYSTEM": "1"},
        capture_output=True,
        text=True,
        timeout=600,
    )
    if check and result.returncode:
        raise RuntimeError(f"git {' '.join(args)} failed: {result.stderr.strip()[:400]}")
    return result.stdout.strip()


def git_show(repo: Path, sha: str, path: str) -> bytes:
    """Read one immutable blob from the candidate commit."""
    return subprocess.check_output(
        ["git", "show", f"{sha}:{path}"], cwd=repo, env={**os.environ, "GIT_CONFIG_NOSYSTEM": "1"}, timeout=120
    )


DEFAULT_CACHE_ROOT = Path.home() / ".cache" / "hol-guard-gauntlet"


def default_tmp_root() -> Path:
    """The per-user private temporary root; POSIX only (``os.getuid``)."""
    return Path("/tmp") / f"hol-guard-gauntlet-{os.getuid()}"


def driver_owned(path: Path) -> bool:
    """Whether path sits inside one of the driver's own default roots."""
    resolved = path.resolve()
    defaults = (DEFAULT_CACHE_ROOT.resolve(), default_tmp_root().resolve())
    return any(resolved.is_relative_to(root) for root in defaults)


def private_dir(path: Path, *, tighten: bool = False) -> Path:
    """Create or verify a directory only this user can enter.

    Missing components are created with mode 0o700. An existing directory with
    group or other permissions is only tightened when ``tighten`` is set (the
    driver's own default roots); every other location is verified, never
    modified, and rejected outright.
    """
    mkdir_private(path)
    info = os.lstat(path)
    if not stat.S_ISDIR(info.st_mode):
        raise RuntimeError("not a real directory: " + str(path))
    if info.st_uid != os.getuid():
        raise RuntimeError("not owned by this user: " + str(path))
    if info.st_mode & 0o077:
        if tighten:
            # An older version left group/other bits on this user's own roots.
            with suppress(OSError):
                os.chmod(path, 0o700)
        if os.lstat(path).st_mode & 0o077:
            raise RuntimeError("directory is not private to this user: " + str(path))
    return path


@contextmanager
def file_lock(path: Path) -> Iterator[None]:
    """Serialize cache writers across driver processes; POSIX flock only."""
    import fcntl

    private_dir(path.parent, tighten=driver_owned(path.parent))
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def gnu_sed_dir(*, probe=subprocess.run) -> Path | None:
    """Return the gnubin prefix when PATH lacks GNU sed, or None when it has one."""
    try:
        result = probe(["sed", "--version"], capture_output=True, text=True, timeout=15)
        gnu = result.returncode == 0 and "GNU" in result.stdout + result.stderr
    except (OSError, subprocess.SubprocessError):
        gnu = False
    if gnu:
        return None
    for candidate in GNU_SED_DIRS:
        if (candidate / "sed").is_file():
            return candidate
    raise RuntimeError("GNU sed is required on PATH or via a Homebrew gnu-sed gnubin directory")


def preflight(repo: Path) -> dict[str, Any]:
    """Check tools and record how trustworthy this checkout's own verifier is."""
    missing = [tool for tool in REQUIRED_TOOLS if shutil.which(tool) is None]
    if missing:
        raise RuntimeError("qualify prerequisites are missing: " + ", ".join(missing))
    sed_dir = gnu_sed_dir()
    verifier_sha = git(repo, "rev-parse", "HEAD")
    verifier_clean = not git(repo, "status", "--porcelain", "--untracked-files=all")
    subprocess.run(
        ["git", "fetch", "-q", "origin", "main"],
        cwd=repo,
        env={**os.environ, "GIT_CONFIG_NOSYSTEM": "1"},
        capture_output=True,
        timeout=120,
    )
    on_main = (
        subprocess.run(
            ["git", "merge-base", "--is-ancestor", "HEAD", "origin/main"],
            cwd=repo,
            env={**os.environ, "GIT_CONFIG_NOSYSTEM": "1"},
            capture_output=True,
        ).returncode
        == 0
    )
    return {
        "verifier_sha": verifier_sha,
        "verifier_clean": verifier_clean,
        "verifier_on_main": on_main,
        "independent_verifier": verifier_clean and on_main,
        "gnu_sed": sed_dir,
    }


def ensure_commit(repo: Path, sha: str) -> None:
    """Fetch the tested commit only when the trusted checkout does not already have it."""
    result = subprocess.run(
        ["git", "cat-file", "-e", f"{sha}^{{commit}}"],
        cwd=repo,
        env={**os.environ, "GIT_CONFIG_NOSYSTEM": "1"},
        capture_output=True,
    )
    if result.returncode:
        git(repo, "fetch", "-q", "origin", sha)


def ensure_sdk(cache_root: Path, repo: Path, sha: str, log: Path) -> dict[str, Any]:
    """One pinned Oh My Pi dependency tree per candidate lock digest, built under flock."""
    package = git_show(repo, sha, f"{LOCK_DIR}/package.json")
    lock = git_show(repo, sha, f"{LOCK_DIR}/package-lock.json")
    lock_digest = hashlib.sha256(lock).hexdigest()
    private_dir(cache_root / "sdk", tighten=driver_owned(cache_root / "sdk"))
    private_dir(cache_root / "locks", tighten=driver_owned(cache_root / "locks"))
    root = cache_root / "sdk" / lock_digest
    pinned = json.loads(package)["dependencies"]["@oh-my-pi/pi-coding-agent"]
    with file_lock(cache_root / "locks" / f"sdk-{lock_digest}.lock"):
        if not (root / ".complete").is_file():
            shutil.rmtree(root, ignore_errors=True)
            root.mkdir(parents=True)
            (root / "package.json").write_bytes(package)
            (root / "package-lock.json").write_bytes(lock)
            run_logged(["npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund"], cwd=root, log=log)
            installed = json.loads(
                (root / "node_modules" / "@oh-my-pi" / "pi-coding-agent" / "package.json").read_text()
            ).get("version")
            if installed != pinned:
                raise RuntimeError("installed Oh My Pi version differs from the candidate pin")
            (root / ".complete").touch()
    return {"root": str(root), "lock_sha256": lock_digest, "omp_version": pinned}


def macos_platform() -> tuple[str, str, str]:
    """Map this host to the CI wheel's platform tag, cargo target and deployment target."""
    if sys.platform != "darwin":
        raise RuntimeError("in-place wheel builds are macOS-only; pass --wheel on this platform")
    arch = platform.machine()
    if arch == "arm64":
        return "macosx_11_0_arm64", "aarch64-apple-darwin", "11.0"
    if arch == "x86_64":
        return "macosx_13_0_x86_64", "x86_64-apple-darwin", "13.0"
    raise RuntimeError(f"unsupported macOS architecture: {arch}")


def _cached_wheel(store: Path) -> dict[str, Any] | None:
    """Reuse a cached wheel only when its recorded digest matches its bytes."""
    wheels = list(store.glob("*.whl"))
    digest_record = store / "wheel.sha256"
    if len(wheels) != 1 or not digest_record.is_file():
        return None
    digest = digest_file(wheels[0])
    if digest_record.read_text(encoding="utf-8").strip() != digest:
        return None
    return {"path": str(wheels[0]), "sha256": digest, "cached": True}


def _build_wheel(store: Path, repo: Path, sha: str, tag: str, target: str, deployment: str, run_root: Path) -> None:
    """Build the tested commit's wheel in the persistent warm worktree."""
    cargo = Path.home() / ".cargo" / "bin"
    if shutil.which("cargo") is None and not (cargo / "cargo").is_file():
        raise RuntimeError("a cold wheel build requires cargo on PATH or under ~/.cargo/bin")
    if shutil.which("jq") is None:
        raise RuntimeError("a cold wheel build requires jq on PATH")
    cache_root = store.parent.parent
    setup_log = run_root / "logs" / "setup.log"
    git_env = {**os.environ, "GIT_CONFIG_NOSYSTEM": "1"}
    with file_lock(cache_root / "locks" / "build.lock"):
        cached = _cached_wheel(store)
        if cached is not None:
            return
        print("qualify: building wheel (cold builds take several minutes)", file=sys.stderr, flush=True)
        worktree = cache_root / "build-worktree"
        if not (worktree / ".git").exists():
            run_logged(
                ["git", "worktree", "add", "--detach", str(worktree), sha],
                cwd=repo,
                env=git_env,
                log=setup_log,
            )
        else:
            run_logged(["git", "checkout", "--detach", "--force", sha], cwd=worktree, env=git_env, log=setup_log)
            run_logged(
                ["git", "clean", "-ffdx", "-e", "rust/target", "-e", ".venv"],
                cwd=worktree,
                env=git_env,
                log=setup_log,
            )
        env = {name: value for name, value in os.environ.items() if name != "VIRTUAL_ENV"}
        run_logged(
            ["uv", "sync", "--frozen", "--no-dev", "--group", "ci-test", "--no-install-project", "--python", "3.12"],
            cwd=worktree,
            env=env,
            log=setup_log,
        )
        build_env = {
            **env,
            "HOL_GUARD_BUILD_SHA": sha,
            "PLATFORM_TAG": tag,
            "TARGET": target,
            "MACOSX_DEPLOYMENT_TARGET": deployment,
            "PATH": os.pathsep.join(
                [str(worktree / ".venv" / "bin"), str(cargo) if cargo.is_dir() else "", env.get("PATH", "")]
            ).strip(os.pathsep),
        }
        # nice keeps a cold Rust build from starving live Gauntlet cases on this host.
        run_logged(
            ["nice", "-n", "10", "bash", "scripts/ci/build-native-wheel-macos.sh"],
            cwd=worktree,
            env=build_env,
            log=run_root / "logs" / "wheel-build.log",
        )
        built = list((worktree / "native-dist").glob(f"hol_guard-*-{tag}.whl"))
        if len(built) != 1:
            raise RuntimeError("native wheel build did not produce exactly one platform wheel")
        for stale in store.glob("*.whl"):
            stale.unlink()
        destination = store / built[0].name
        shutil.copy2(built[0], destination)
        (store / "wheel.sha256").write_text(digest_file(destination) + "\n")


def ensure_wheel(
    cache_root: Path, repo: Path, sha: str, run_root: Path, *, wheel: Path | None = None
) -> dict[str, Any]:
    """The tested commit's platform wheel: supplied, cache-hit, or built under one host lock."""
    if wheel is not None:
        return {"path": str(wheel), "sha256": digest_file(wheel), "cached": False}
    tag, target, deployment = macos_platform()
    private_dir(cache_root / "wheels", tighten=driver_owned(cache_root / "wheels"))
    store = cache_root / "wheels" / f"{sha}-{tag}"
    store.mkdir(parents=True, exist_ok=True)
    cached = _cached_wheel(store)
    if cached is not None:
        return cached
    _build_wheel(store, repo, sha, tag, target, deployment, run_root)
    cached = _cached_wheel(store)
    if cached is None:
        raise RuntimeError("native wheel build produced no verifiable wheel")
    return {**cached, "cached": False}
