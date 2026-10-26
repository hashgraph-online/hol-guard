"""``hol-guard plugin install|uninstall``: install a HOL listing with each runtime's own CLI.

Guard asks HOL for the listing's install spec (identifiers only), the native
Kit checks every identifier and turns the spec into argument vectors for
fixed programs, and this module prints that plan. Nothing runs unless
``--apply`` is passed, and then only after a confirmation per runtime
(``--yes`` skips the prompts for CI). Commands run without a shell.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

from ...version import __version__
from ..mdm.network import ManagedNetworkError, managed_urlopen

SPEC_URL = "https://hol.org/api/guard/plugins/install-spec"
VIA_GUARD = "hol-guard"
#: The only programs a plan may start. Each is the runtime's own CLI.
PROGRAMS = ("claude", "codex", "npx")
_SPEC_LIMIT_BYTES = 64 * 1024
_SPEC_TIMEOUT_SECONDS = 20.0
_COMMAND_TIMEOUT_SECONDS = 600.0


class PluginInstallError(RuntimeError):
    """The install could not be planned or a command failed."""


def parse_target(value: str) -> tuple[str, str | None]:
    """``owner/name[@version]`` -> slug and optional version."""

    slug, _, version = value.strip().partition("@")
    if not slug:
        raise PluginInstallError("Name a HOL listing, such as owner/plugin.")
    return slug, version or None


def fetch_spec(slug: str) -> dict[str, Any]:
    url = f"{SPEC_URL}?{urllib.parse.urlencode({'slug': slug})}"
    request = urllib.request.Request(
        url, headers={"User-Agent": f"hol-guard/{__version__}", "Accept": "application/json"}
    )
    try:
        with managed_urlopen(request, timeout=_SPEC_TIMEOUT_SECONDS) as response:
            raw = response.read(_SPEC_LIMIT_BYTES + 1)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            raise PluginInstallError(f"No plugin {slug} is listed on HOL.") from error
        if error.code == 400:
            raise PluginInstallError("Use a HOL listing slug such as owner/plugin.") from error
        raise PluginInstallError(f"HOL could not answer right now (HTTP {error.code}). Try again shortly.") from error
    except (ManagedNetworkError, urllib.error.URLError, OSError) as error:
        raise PluginInstallError("The install details could not be downloaded from HOL.") from error
    if len(raw) > _SPEC_LIMIT_BYTES:
        raise PluginInstallError("The install details from HOL were larger than expected.")
    try:
        spec = json.loads(raw)
    except ValueError as error:
        raise PluginInstallError("The install details from HOL were not valid JSON.") from error
    if not isinstance(spec, dict):
        raise PluginInstallError("The install details from HOL were not in the expected shape.")
    return spec


def read_spec_file(path: str) -> dict[str, Any]:
    try:
        spec = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise PluginInstallError("The spec file could not be read as JSON.") from error
    if not isinstance(spec, dict):
        raise PluginInstallError("The spec file is not a JSON object.")
    return spec


def available_programs(which: Callable[[str], str | None] | None = None) -> list[str]:
    # Look ``shutil.which`` up per call, not as a default bound at import.
    which = which or shutil.which
    return [program for program in PROGRAMS if which(program)]


def recorded_installs(guard_home: Path) -> dict[str, list[str]]:
    """Listings ``plugin install --apply`` installed, as ``{slug: [runtime, ...]}``.

    The record lives in the native Kit; without it nothing is marked.
    """

    from .cli import PluginKitNativeError, kit_request

    try:
        result = kit_request({"command": "installs", "guard_home": str(guard_home)})
    except PluginKitNativeError:
        return {}
    return {
        slug: [runtime for runtime in runtimes if isinstance(runtime, str)]
        for slug, runtimes in result.items()
        if isinstance(runtimes, list)
    }


def record(
    guard_home: Path, slug: str, runtime: str, *, installed: bool, spec: Mapping[str, Any] | None = None
) -> None:
    """Add a runtime to Guard's install record (``spec`` is the one installed) or drop it."""

    from .cli import PluginKitNativeError, kit_request

    request: dict[str, object] = {
        "command": "record",
        "guard_home": str(guard_home),
        "slug": slug,
        "runtime": runtime,
        "installed": installed,
    }
    if installed:
        request["spec"] = dict(spec or {})
    try:
        kit_request(request)
    except PluginKitNativeError as error:
        raise PluginInstallError(str(error)) from error


def mark_guard_installs(report: Mapping[str, Any], guard_home: Path) -> dict[str, Any]:
    """Tag report entries for listings ``plugin install --apply`` installed."""

    ledger = recorded_installs(guard_home)
    marked = dict(report)
    entries = report.get("entries")
    if isinstance(entries, list):
        marked["entries"] = [
            {**entry, "via": VIA_GUARD}
            if isinstance(entry, dict) and entry.get("runtime") in ledger.get(str(entry.get("slug")), [])
            else entry
            for entry in entries
        ]
    return marked


def _shown(argv: Sequence[str]) -> str:
    return " ".join(argv)


def write_plan(plan: Mapping[str, Any], *, apply: bool) -> None:
    action = plan.get("action")
    version = f" {plan['version']}" if plan.get("version") else ""
    print(f"{plan.get('slug')}{version}")
    if isinstance(plan.get("trust_score"), int | float):
        print(f"  HOL trust score: {plan['trust_score']:g}/100")
    print(f"  Listing: {plan.get('listing_url')}")
    steps = plan.get("steps") or []
    if not steps:
        print("\nHOL has no install Guard can run for this listing. Follow the listing's install steps.")
    for step in steps:
        state = "" if step.get("available") else f"  ({step.get('program')} not found)"
        print(f"\n{step.get('runtime')}:{state}")
        for argv in step.get("commands") or []:
            print(f"  {_shown(argv)}")
        if step.get("note"):
            print(f"  {step['note']}")
    manual = plan.get("manual") or []
    if manual:
        print(f"\nInstall by hand (see the listing): {', '.join(manual)}")
    if not apply and any(step.get("automatic") and step.get("available") for step in steps):
        verb = "install" if action == "install" else "uninstall"
        print(f"\nNothing was changed. Run with --apply to {verb}, confirming each runtime.")


def _confirm(runtime: str, action: str) -> bool:
    try:
        answer = input(f"{action.capitalize()} for {runtime}? [y/N] ")
    except EOFError:
        return False
    return answer.strip().lower() in {"y", "yes"}


def _run(argv: Sequence[str], which: Callable[[str], str | None]) -> int:
    program = argv[0] if argv else ""
    executable = which(program) if program in PROGRAMS else None
    if executable is None:
        raise PluginInstallError(f"{program or 'The command'} is not an allowed install program.")
    try:
        completed = subprocess.run([executable, *argv[1:]], shell=False, check=False, timeout=_COMMAND_TIMEOUT_SECONDS)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise PluginInstallError(f"{program} did not finish.") from error
    return completed.returncode


def apply_plan(
    plan: Mapping[str, Any],
    *,
    assume_yes: bool,
    record: Callable[[str], None],
    confirm: Callable[[str, str], bool] = _confirm,
    which: Callable[[str], str | None] | None = None,
) -> int:
    """Run each automatic step the user confirms, then ``record`` its runtime. Returns the exit code."""

    which = which or shutil.which
    action = str(plan.get("action"))
    failed = False
    for step in plan.get("steps") or []:
        runtime = str(step.get("runtime"))
        if not step.get("automatic"):
            continue
        if not step.get("available"):
            print(f"\n{runtime}: skipped, {step.get('program')} is not installed.")
            continue
        if not assume_yes and not confirm(runtime, action):
            print(f"{runtime}: skipped.")
            continue
        for argv in step.get("commands") or []:
            if str(argv[0]) != step.get("program"):
                raise PluginInstallError("The install plan was not in the expected shape.")
            print(f"$ {_shown(argv)}")
            code = _run([str(part) for part in argv], which)
            if code != 0:
                print(f"{runtime}: {argv[0]} exited with {code}.", file=sys.stderr)
                failed = True
                break
        else:
            verify = step.get("verify")
            done = "installed; start a new session to load it" if action == "install" else "removed"
            check = f" Check with: {_shown(verify)}" if verify else ""
            print(f"{runtime}: {done}.{check}")
            try:
                record(runtime)
            except PluginInstallError as error:
                print(f"{runtime}: {error} Guard's record of this listing may be out of date.", file=sys.stderr)
                failed = True
    return 1 if failed else 0
