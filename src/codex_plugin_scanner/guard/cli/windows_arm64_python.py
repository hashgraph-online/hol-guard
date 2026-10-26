"""Route native Windows ARM64 Python installs to an x64 Python under emulation.

cryptography and rfc3161-client publish no Windows ARM64 wheels, so pip falls back to
building them from source, which needs a Rust and C toolchain plus OpenSSL. Guard does
not install that toolchain or make either dependency optional. When an update on native
ARM64 Python fails while building one of them, Guard stops and names the supported route:
reinstall HOL Guard with an x64 CPython, which Windows on ARM runs under emulation and
which installs the published win_amd64 wheels.

Plain ``pip install hol-guard`` runs no Guard code before pip resolves dependencies, so
that path relies on the install documentation instead of this module.
"""

from __future__ import annotations

import re
import subprocess
import sys
import sysconfig
from collections.abc import Callable, Sequence

WINDOWS_ARM64_PLATFORM = "win-arm64"
WINDOWS_X64_PLATFORM = "win-amd64"
REASON_CODE = "update_windows_arm64_x64_python_required"

_WHEEL_LESS_PACKAGES = frozenset({"cryptography", "rfc3161-client"})
# pip: "Failed building wheel for X", "Failed to build X"; uv: "Failed to build `X==1.0`".
_FAILED_BUILD_RECORD = re.compile(
    r"failed (?:building wheel for|to build|to download and build) `?([a-z0-9][a-z0-9._-]*)"
)
# pip: "Failed to build installable wheels for some pyproject.toml based projects (X, Y)".
_FAILED_BUILD_SUMMARY = re.compile(r"failed to build installable wheels[^(]*\(([^)]*)\)")
_COLLECTING_RECORD = re.compile(r"^collecting ([a-z0-9][a-z0-9._-]*)")
# pip prints "... error" on a terminal and ": finished with status 'error'" when piped.
_METADATA_FAILED = re.compile(r"^preparing metadata\b.*(?:\.\.\. error|status 'error')$")
_PROBE_TIMEOUT_SECONDS = 10
_PLATFORM_PROBE = "import sysconfig; print(sysconfig.get_platform())"

Runner = Callable[..., "subprocess.CompletedProcess[str]"]


def native_windows_arm64_python(*, os_platform: str | None = None, python_platform: str | None = None) -> bool:
    """Return True when the running interpreter is a native Windows ARM64 build."""
    current_os = sys.platform if os_platform is None else os_platform
    if current_os != "win32":
        return False
    current = sysconfig.get_platform() if python_platform is None else python_platform
    return current == WINDOWS_ARM64_PLATFORM


def _normalized_package(name: str) -> str:
    bare = re.split(r"[=<>!~;\[ ]", name.strip("`'\" "), maxsplit=1)[0]
    return bare.replace("_", "-").replace(".", "-")


def failed_build_packages(installer_output: str) -> set[str]:
    """Return the packages that installer output reports as failing to build or prepare metadata."""
    failed: set[str] = set()
    collecting: str | None = None
    for raw_line in installer_output.lower().splitlines():
        line = raw_line.strip()
        summary = _FAILED_BUILD_SUMMARY.search(line)
        if summary:
            failed.update(_normalized_package(name) for name in summary.group(1).split(","))
            continue
        record = _FAILED_BUILD_RECORD.search(line)
        if record:
            failed.add(_normalized_package(record.group(1)))
            continue
        collected = _COLLECTING_RECORD.match(line)
        if collected:
            collecting = _normalized_package(collected.group(1))
        elif collecting and _METADATA_FAILED.match(line):
            # A source build without a Rust toolchain fails while preparing metadata; pip names the
            # package only in the preceding "Collecting" line.
            failed.add(collecting)
    return failed


def wheel_less_dependency_build_failed(installer_output: str) -> bool:
    """Return True when a dependency that has no Windows ARM64 wheel failed to build."""
    return not _WHEEL_LESS_PACKAGES.isdisjoint(failed_build_packages(installer_output))


def parse_py_launcher_paths(output: str) -> list[tuple[str, str]]:
    """Parse ``py -0p`` output into (tag, interpreter path) pairs."""
    entries: list[tuple[str, str]] = []
    for raw_line in output.splitlines():
        line = raw_line.strip().lstrip("*").strip()
        if not line.startswith("-"):
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        tag, path = parts[0], parts[1].strip().lstrip("*").strip()
        if path.lower().endswith(".exe"):
            entries.append((tag, path))
    return entries


def _launcher_tag_may_be_x64(tag: str) -> bool:
    lowered = tag.lower()
    return not (lowered.endswith("-arm64") or lowered.endswith("-32"))


def x64_python_candidates(run: Runner | None = None) -> list[str]:
    """Return installed interpreters that report the win-amd64 platform.

    The py launcher's tag is only a hint, so each candidate is asked for its own
    platform before Guard labels it x64.
    """
    run = run or subprocess.run
    try:
        listing = run(
            ["py", "-0p"],
            capture_output=True,
            text=True,
            timeout=_PROBE_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    if listing.returncode != 0:
        return []
    confirmed: list[str] = []
    for tag, path in parse_py_launcher_paths(listing.stdout or ""):
        if not _launcher_tag_may_be_x64(tag) or path in confirmed:
            continue
        try:
            probe = run(
                [path, "-c", _PLATFORM_PROBE],
                capture_output=True,
                text=True,
                timeout=_PROBE_TIMEOUT_SECONDS,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            continue
        if probe.returncode == 0 and (probe.stdout or "").strip() == WINDOWS_X64_PLATFORM:
            confirmed.append(path)
    return confirmed


def _reinstall_command(installer: str, python_path: str) -> str:
    quoted = f'"{python_path}"'
    if installer == "uv":
        return f"uv tool install --force --python {quoted} hol-guard"
    if installer == "pip":
        return f"{quoted} -m pip install --upgrade hol-guard"
    return f"pipx install --force --python {quoted} hol-guard"


def x64_python_route_message(installer: str, candidates: Sequence[str]) -> str:
    """Explain why the update stopped and how to reinstall Guard on x64 Python."""
    python_path = candidates[0] if candidates else "<path-to-x64-python.exe>"
    lines = [
        "HOL Guard is running on native Windows ARM64 Python. cryptography and rfc3161-client "
        "publish no Windows ARM64 wheels, so pip tried to build them from source and failed.",
        "Reinstall HOL Guard with x64 CPython, which Windows on ARM runs under emulation:",
        f"  {_reinstall_command(installer, python_path)}",
        f'Confirm the interpreter reports {WINDOWS_X64_PLATFORM} with: "{python_path}" -c "{_PLATFORM_PROBE}"',
    ]
    if installer == "pip":
        lines.append(
            "That installs a separate HOL Guard for the x64 interpreter; the ARM64 environment is not converted. "
            "Run hol-guard from the x64 interpreter's Scripts directory."
        )
    if candidates:
        lines.append("x64 Python found on this machine: " + ", ".join(candidates))
    else:
        lines.append(
            "No x64 Python was found. Install the Windows installer (64-bit) build from python.org, "
            "not the ARM64 build."
        )
    return "\n".join(lines)
