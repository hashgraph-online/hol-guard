"""``hol-guard plugin install|uninstall``: install a HOL listing with each runtime's own CLI.

Guard asks HOL for the listing's install spec (identifiers and the scan
result), the native Kit checks every identifier, decides whether HOL's scan
lets the install go ahead, and turns the spec into argument vectors for fixed
programs; this module prints that plan. Nothing runs unless ``--apply`` is
passed, and then only after a confirmation per runtime (``--yes`` skips the
prompts for CI, but never accepts a risk or a declared command on its own).
Commands run without a shell or stdin; see ``runner``.

Exit codes: 0 done or plan shown; 1 a runtime command or check failed; 2 usage,
or no terminal to confirm in; 3 nothing Guard can install here; 4 stopped by
HOL's scan result, a commit other than the scanned one, or a declared command
that was not accepted; 5 this Guard is too old; 6 HOL unreachable; 130
interrupted.
"""

from __future__ import annotations

import json
import os
import re
import socket
import sqlite3
import ssl
import sys
import textwrap
import threading
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TextIO

from packaging.version import InvalidVersion, Version

from ...version import __version__
from ..mdm.network import ManagedNetworkError, managed_urlopen
from . import runner

SPEC_URL = "https://hol.org/api/guard/plugins/install-spec"
#: Points Guard at another install-spec endpoint, such as a local portal with
#: test listings. https anywhere; plain http only on this machine or the
#: Docker host. Listing pages must then live on the same origin.
SPEC_URL_ENV = "HOL_GUARD_PLUGIN_SPEC_URL"
VIA_GUARD = "hol-guard"
#: The only programs a plan may start. Each is the runtime's own CLI.
PROGRAMS = ("claude", "codex", "npx")
#: The newest install-spec version this Guard reads; HOL answers in it or older.
SPEC_SCHEMA = 2
_SPEC_LIMIT_BYTES = 64 * 1024
_SPEC_TIMEOUT_SECONDS = 10.0
#: One retry, after this pause, for a timeout or an HTTP 5xx answer.
_SPEC_RETRY_SECONDS = 2.0
#: How long a fetch runs before Guard says it is waiting (terminal only).
_PROGRESS_AFTER_SECONDS = 1.0
_SHA256 = re.compile(r"[0-9a-f]{64}")
_COMMIT = re.compile(r"[0-9a-f]{40}")

EXIT_FAILED = 1
EXIT_USAGE = 2
EXIT_NOTHING = 3
EXIT_STOPPED = 4
EXIT_TOO_OLD = 5
EXIT_UNREACHABLE = 6
EXIT_INTERRUPTED = 130


class PluginInstallError(RuntimeError):
    """The install could not be planned or a command failed."""

    def __init__(self, message: str, *, exit_code: int = EXIT_USAGE, code: str = "invalid") -> None:
        super().__init__(message)
        self.exit_code = exit_code
        self.code = code


def parse_target(value: str) -> tuple[str, str | None]:
    """``owner/name[@version]`` -> slug and optional version."""

    slug, _, version = value.strip().partition("@")
    if not slug:
        raise PluginInstallError("Name a HOL listing, such as owner/plugin.")
    return slug, version or None


def spec_endpoint(environ: Mapping[str, str] | None = None) -> tuple[str, str | None]:
    """The install-spec URL, and its origin when the user overrode it.

    The native Kit decides whether an override is allowed and what its origin
    is, so the CLI and the plan check listings against the same rules.
    """

    value = (os.environ if environ is None else environ).get(SPEC_URL_ENV, "").strip()
    if not value:
        return SPEC_URL, None
    from .cli import PluginKitNativeError, kit_request

    try:
        origin = kit_request({"command": "endpoint", "value": value}).get("origin")
    except PluginKitNativeError as error:
        raise PluginInstallError(str(error)) from None
    if not isinstance(origin, str):
        raise PluginInstallError(f"{SPEC_URL_ENV} could not be checked. Reinstall hol-guard.")
    return value, origin


def _unreachable(message: str) -> PluginInstallError:
    return PluginInstallError(message, exit_code=EXIT_UNREACHABLE, code="unreachable")


def _proxy_host(scheme: str) -> str | None:
    """The proxy urllib would use for ``scheme``, as host:port only (never credentials)."""

    proxy = urllib.request.getproxies().get(scheme)
    if not proxy:
        return None
    parts = urllib.parse.urlsplit(proxy if "://" in proxy else f"http://{proxy}")
    try:
        port = parts.port
    except ValueError:
        port = None
    return f"{parts.hostname}:{port}" if port else parts.hostname


def _network_failure(error: BaseException, url: str) -> PluginInstallError:
    """REM D6: say which part of the connection failed, without secrets."""

    parts = urllib.parse.urlsplit(url)
    host = parts.hostname or "HOL"
    if isinstance(error, ManagedNetworkError):
        return _unreachable(
            f"Your organization's Guard network policy did not let Guard reach {host} ({error}). "
            "Ask your administrator to allow it."
        )
    reason: object = error.reason if isinstance(error, urllib.error.URLError) else error
    proxy = _proxy_host(parts.scheme)
    if isinstance(reason, ssl.SSLCertVerificationError) or (
        isinstance(reason, ssl.SSLError) and "CERTIFICATE_VERIFY_FAILED" in str(reason)
    ):
        return _unreachable(
            f"Guard could not verify the TLS certificate {host} presented. If your network inspects TLS, "
            "add your organization's CA certificate to the system store, or set SSL_CERT_FILE to a file "
            "that contains it."
        )
    if isinstance(reason, ssl.SSLError):
        return _unreachable(f"The secure connection to {host} failed. Try again, or check your network or proxy.")
    if isinstance(reason, socket.gaierror):
        if proxy:
            return _unreachable(f"Guard could not look up {host} or your proxy {proxy}. Check your DNS settings.")
        return _unreachable(f"Guard could not look up {host}. You may be offline, or DNS is not working.")
    if isinstance(reason, (TimeoutError, socket.timeout)):
        return _unreachable(
            f"{host} did not answer within {int(_SPEC_TIMEOUT_SECONDS)} seconds, twice. Try again shortly."
        )
    if isinstance(reason, OSError) and "Tunnel connection failed" in str(reason):
        status = str(reason).split("Tunnel connection failed:", 1)[-1].strip()[:40]
        who = f"Your proxy {proxy}" if proxy else "Your proxy"
        return _unreachable(f"{who} refused the connection to {host} ({status}).")
    if isinstance(reason, ConnectionRefusedError):
        if proxy:
            return _unreachable(f"Your proxy {proxy} refused the connection. Check HTTPS_PROXY.")
        return _unreachable(f"{host} refused the connection. Try again shortly.")
    if isinstance(reason, OSError) and getattr(reason, "errno", None) in {50, 51, 65, 101, 113, 10051, 10065}:
        return _unreachable(f"Guard could not reach {host}: this machine appears to be offline.")
    return _unreachable(f"The install details could not be downloaded from {host}.")


def _http_failure(error: urllib.error.HTTPError, slug: str) -> PluginInstallError:
    if 300 <= error.code < 400:
        return PluginInstallError(f"{SPEC_URL_ENV} answered with a redirect. Set it to the final install-spec URL.")
    if error.code == 404:
        return PluginInstallError(f"No plugin {slug} is listed on HOL.", code="not_found")
    if error.code == 410:
        return PluginInstallError(f"{slug} was removed from HOL.", code="removed")
    if error.code == 400:
        return PluginInstallError("Use a HOL listing slug such as owner/plugin.")
    if error.code == 403:
        return _unreachable(
            "HOL refused the request (HTTP 403). A firewall or proxy on your network may be blocking hol.org."
        )
    if error.code == 429:
        wait = (error.headers.get("Retry-After") or "").strip() if error.headers else ""
        when = f"in {wait} seconds" if wait.isdigit() else "in a minute"
        return _unreachable(f"HOL is limiting install lookups from your network. Try again {when}.")
    return _unreachable(f"HOL could not answer right now (HTTP {error.code}). Try again shortly.")


def _retryable(error: BaseException) -> bool:
    if isinstance(error, urllib.error.HTTPError):
        return error.code >= 500
    reason = error.reason if isinstance(error, urllib.error.URLError) else error
    return isinstance(reason, (TimeoutError, socket.timeout))


def _get(request: urllib.request.Request, *, allow_redirects: bool) -> bytes:
    with managed_urlopen(request, timeout=_SPEC_TIMEOUT_SECONDS, allow_redirects=allow_redirects) as response:
        return response.read(_SPEC_LIMIT_BYTES + 1)


def fetch_spec(
    slug: str,
    endpoint: str = SPEC_URL,
    *,
    progress: TextIO | None = None,
    allow_redirects: bool | None = None,
) -> dict[str, Any]:
    """Ask HOL for the listing's install spec. ``progress`` (a terminal) gets
    one line if the answer takes longer than a second. ``allow_redirects``
    defaults to following redirects only from HOL's own endpoint."""

    url = f"{endpoint}?{urllib.parse.urlencode({'slug': slug, 'schema': SPEC_SCHEMA})}"
    request = urllib.request.Request(
        url, headers={"User-Agent": f"hol-guard/{__version__}", "Accept": "application/json"}
    )
    timer = None
    if progress is not None:
        host = urllib.parse.urlsplit(endpoint).hostname or "HOL"
        timer = threading.Timer(
            _PROGRESS_AFTER_SECONDS, lambda: print(f"Getting install details for {slug} from {host}...", file=progress)
        )
        timer.daemon = True
        timer.start()
    raw = b""
    try:
        # An override was checked as given; a redirect would leave those checks behind.
        for attempt in (1, 2):
            try:
                follow = endpoint == SPEC_URL if allow_redirects is None else allow_redirects
                raw = _get(request, allow_redirects=follow)
                break
            except (ManagedNetworkError, urllib.error.URLError, OSError) as error:
                if attempt == 1 and _retryable(error):
                    time.sleep(_SPEC_RETRY_SECONDS)
                    continue
                if isinstance(error, urllib.error.HTTPError):
                    raise _http_failure(error, slug) from error
                raise _network_failure(error, url) from error
    finally:
        if timer is not None:
            timer.cancel()
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


def check_guard_version(spec: Mapping[str, Any], running: str = __version__) -> None:
    """Refuse a listing that needs a newer Guard than this one."""

    needed = spec.get("minGuardVersion")
    if needed is None:
        return
    try:
        too_old = Version(running) < Version(str(needed))
    except InvalidVersion as error:
        raise PluginInstallError(
            "HOL asked for a Guard version this Guard cannot read. Run: hol-guard update",
            exit_code=EXIT_TOO_OLD,
            code="guard_too_old",
        ) from error
    if too_old:
        raise PluginInstallError(
            f"This listing needs hol-guard {needed} or newer; this is {running}. Run: hol-guard update",
            exit_code=EXIT_TOO_OLD,
            code="guard_too_old",
        )


#: One line on how to get each runtime CLI Guard can drive (REM D2).
GET_PROGRAM = {
    "claude": "Get Claude Code: npm install -g @anthropic-ai/claude-code",
    "codex": "Get Codex: npm install -g @openai/codex",
    "npx": "Get npx with Node.js: https://nodejs.org",
}


def known_locations(environ: Mapping[str, str] | None = None, *, windows: bool | None = None) -> list[str]:
    """Folders the runtime installers use that are often missing from PATH:
    Claude Code's own installer, the npm global prefix, bun and Homebrew."""

    environ = os.environ if environ is None else environ
    windows = os.name == "nt" if windows is None else windows
    home = environ.get("USERPROFILE" if windows else "HOME", "").strip()
    folders: list[str] = []
    if home:
        folders += [
            os.path.join(home, ".local", "bin"),
            os.path.join(home, ".claude", "local"),
            os.path.join(home, ".bun", "bin"),
            os.path.join(home, ".npm-global", "bin"),
        ]
    prefix = environ.get("NPM_CONFIG_PREFIX", "").strip()
    if prefix:
        folders.append(prefix if windows else os.path.join(prefix, "bin"))
    if windows:
        appdata = environ.get("APPDATA", "").strip()
        if appdata:
            folders.append(os.path.join(appdata, "npm"))
    else:
        folders += ["/opt/homebrew/bin", "/usr/local/bin"]
    return [folder for folder in folders if os.path.isabs(folder)]


def find_programs(environ: Mapping[str, str] | None = None) -> runner.Lookup:
    return runner.find_programs(PROGRAMS, environ, known=known_locations(environ))


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
    guard_home: Path,
    slug: str,
    runtime: str,
    *,
    installed: bool,
    spec: Mapping[str, Any] | None = None,
    listing_origin: str | None = None,
    marketplace_added: bool = False,
) -> None:
    """Add a runtime to Guard's install record (``spec`` is the one installed) or drop it.

    ``marketplace_added`` says Guard registered the marketplace for this
    install, so ``uninstall`` may remove it again when nothing else uses it.
    """

    from .cli import PluginKitNativeError, kit_request

    request: dict[str, object] = {
        "command": "record",
        "guard_home": str(guard_home),
        "slug": slug,
        "runtime": runtime,
        "installed": installed,
    }
    if listing_origin:
        request["listing_origin"] = listing_origin
    if installed:
        request["spec"] = dict(spec or {})
        request["marketplace_added"] = marketplace_added
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


def _short(commit: object) -> str:
    return commit[:7] if isinstance(commit, str) and commit else "unknown"


def _printable(text: str) -> str:
    """Escape control and format characters a runtime CLI reported."""

    return "".join(
        f"\\u{ord(character):04x}" if unicodedata.category(character) in {"Cc", "Cf"} else character
        for character in text
    )


def _verb(action: str) -> str:
    return "Install" if action == "install" else "Uninstall"


_GATE_TEXT = {
    "pass": "Passed HOL's checks.",
    "confirm": "Needs your OK before Guard installs it.",
    "block": "Blocked. Guard will not install it.",
}


_LABEL = {
    "claude-code": "Claude Code",
    "codex": "Codex",
    "agent-skills": "Other agents",
    "mcp": "MCP server",
    "cursor": "Cursor",
    "opencode": "OpenCode",
    "antigravity": "Antigravity",
}
_SCOPE = {"claude-code": "your user settings", "codex": "your user config"}
_VERSION = re.compile(r"\b(\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z.-]+)?)\b")
_VERSION_SECONDS = 5.0
_versions: dict[str, str | None] = {}


def runtime_label(runtime: str) -> str:
    return _LABEL.get(runtime, runtime)


def protected_runtimes(guard_home: Path) -> set[str] | None:
    """Harnesses Guard manages here, read without creating or changing its
    database; None when Guard cannot tell."""

    database = guard_home / "guard.db"
    if not database.is_file():
        return set()
    try:
        connection = sqlite3.connect(f"{database.resolve().as_uri()}?mode=ro", uri=True, timeout=1.0)
        try:
            rows = connection.execute("select harness from managed_installs where active = 1").fetchall()
        finally:
            connection.close()
    except (sqlite3.Error, OSError, ValueError):
        return None
    return {str(row[0]) for row in rows}


def program_version(program: runner.Program) -> str | None:
    """The version ``program --version`` prints, or None; asked once per path."""

    if program.path not in _versions:
        version = None
        try:
            completed = runner.run(program, ["--version"], capture=True, timeout=_VERSION_SECONDS)
        except runner.RunnerError:
            completed = None
        if completed is not None and completed.returncode == 0:
            match = _VERSION.search(completed.stdout or "")
            version = match.group(1) if match else None
        _versions[program.path] = version
    return _versions[program.path]


def _row(label: str, text: str, out: TextIO | None, *, width: int = 10) -> None:
    print(f"  {label:<{width}}{text}", file=out)


def write_security(security: Mapping[str, Any] | None, out: TextIO | None) -> None:
    if not security:
        return
    _row("Security", _GATE_TEXT.get(str(security.get("gate")), "Unknown."), out)
    scanned_at, scanned_ref = security.get("scanned_at"), security.get("scanned_ref")
    findings = security.get("findings")
    indent = " " * 12
    if isinstance(scanned_at, str):
        line = f"{indent}Scanned {scanned_at[:10]}"
        if isinstance(scanned_ref, str):
            line += f" at {scanned_ref[:7]}"
        if isinstance(findings, dict):
            line += f": {findings.get('critical', 0)} critical, {findings.get('high', 0)} high."
        print(line if line.endswith(".") else f"{line}.", file=out)
    for reason in security.get("reasons") or []:
        print(f"{indent}{reason}", file=out)
    for reason in security.get("hol_reasons") or []:
        print(f"{indent}HOL: {reason}", file=out)
    if security.get("report_url"):
        print(f"{indent}Report: {security['report_url']}", file=out)


def write_plan(
    plan: Mapping[str, Any],
    lookup: runner.Lookup,
    *,
    apply: bool,
    out: TextIO | None = None,
    program_name: str = "hol-guard plugin",
) -> None:
    """The plan in the REM D8 layout: security first, then per runtime the
    program, its version and scope, the commands and how to undo them."""

    out = out or sys.stdout
    action = plan.get("action")
    installing = action == "install"
    version = f" {plan['version']}" if plan.get("version") else ""
    print(f"{plan.get('slug')}{version} on HOL", file=out)
    write_security(plan.get("security"), out)
    if isinstance(plan.get("trust_score"), int | float):
        _row("Trust", f"{plan['trust_score']:g}/100", out)
    _row("Listing", str(plan.get("listing_url")), out)
    steps = plan.get("steps") or []
    if not steps:
        print("\nHOL has no install Guard can run for this listing. Follow the listing's install steps.", file=out)
    elif not apply:
        print("\nWhat Guard will run. Nothing has changed yet.", file=out)
    for step in steps:
        runtime, name = str(step.get("runtime")), str(step.get("program"))
        program = lookup.programs.get(name)
        print("", file=out)
        if not step.get("automatic"):
            _row(runtime_label(runtime), "Guard does not run this. To do it yourself:", out, width=14)
        elif program is None:
            _row(runtime_label(runtime), f"{name} not found.", out, width=14)
            if name in GET_PROGRAM:
                print(f"  {GET_PROGRAM[name]}", file=out)
        else:
            found = program.path
            program_v = program_version(program)
            if program_v:
                found += f" {program_v}"
            if runtime in _SCOPE:
                found += f", {_SCOPE[runtime]}"
            if not program.on_path:
                found += " (not on PATH)"
            _row(runtime_label(runtime), found, out, width=14)
        for argv in step.get("commands") or []:
            print(f"  {_shown(argv)}", file=out)
        if step.get("note"):
            print(textwrap.fill(str(step["note"]), 80, initial_indent="  ", subsequent_indent="  "), file=out)
        if installing and step.get("automatic"):
            print(f"  Undo: {program_name} uninstall {plan.get('slug')} --apply --runtime {runtime}", file=out)
    for runtime in plan.get("manual") or []:
        print("", file=out)
        _row(runtime_label(str(runtime)), "Add it by hand. The listing shows how:", out, width=14)
        print(f"  {plan.get('listing_url')}", file=out)
    gate = (plan.get("security") or {}).get("gate")
    runnable = any(step.get("automatic") and str(step.get("program")) in lookup.programs for step in steps)
    if not apply and runnable and gate != "block":
        print("\nRun again with --apply. Guard asks before each runtime.", file=out)


@dataclass
class Outcome:
    """What happened for one runtime; ``status`` is one of planned, skipped,
    declined, installed, removed, failed or blocked."""

    runtime: str
    status: str
    path: str | None = None
    exit_code: int | None = None
    message: str | None = None
    version: str | None = None

    def as_json(self) -> dict[str, Any]:
        return {
            "runtime": self.runtime,
            "status": self.status,
            "path": self.path,
            "exit_code": self.exit_code,
            "message": self.message,
            "version": self.version,
        }


def planned(plan: Mapping[str, Any], lookup: runner.Lookup) -> list[Outcome]:
    outcomes = []
    for step in plan.get("steps") or []:
        runtime, name = str(step.get("runtime")), str(step.get("program"))
        program = lookup.programs.get(name)
        if not step.get("automatic"):
            outcomes.append(Outcome(runtime, "skipped", message="Guard does not run this one; run it yourself."))
        elif program is None:
            outcomes.append(Outcome(runtime, "skipped", message=f"{name} was not found."))
        else:
            outcomes.append(Outcome(runtime, "planned", program.path, version=program_version(program)))
    return outcomes


def exit_code_for(outcomes: Sequence[Outcome]) -> int:
    if any(outcome.status == "blocked" for outcome in outcomes):
        return EXIT_STOPPED
    if any(outcome.status == "failed" for outcome in outcomes):
        return EXIT_FAILED
    return 0


def confirm(question: str) -> bool:
    """Ask on stderr, so stdout stays clean for ``--json``; anything but yes is no."""

    sys.stderr.write(f"{question} [y/N] ")
    sys.stderr.flush()
    try:
        answer = sys.stdin.readline()
    except (OSError, ValueError):
        return False
    return answer.strip().lower() in {"y", "yes"}


class _AlreadyDoneError(Exception):
    """The runtime already has the result this step would produce (REM D11)."""


class _StoppedError(Exception):
    def __init__(self, status: str, message: str, exit_code: int | None = None) -> None:
        super().__init__(message)
        self.status = status
        self.exit_code = exit_code


def _reply(stdout: str) -> dict[str, Any]:
    """The JSON object a runtime CLI printed with ``--json``, or ``{}``."""

    for candidate in (stdout, *reversed(stdout.strip().splitlines())):
        try:
            value = json.loads(candidate)
        except ValueError:
            continue
        if isinstance(value, dict):
            return value
    return {}


def _ran(completed: runner.Completed, argv: Sequence[str], reply: Mapping[str, Any] | None = None) -> None:
    if completed.returncode == 0:
        return
    message = (reply or {}).get("message")
    detail = f": {_printable(message)}" if isinstance(message, str) and message else "."
    raise _StoppedError("failed", f"{argv[0]} exited with {completed.returncode}{detail}", completed.returncode)


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def claude_home(environ: Mapping[str, str] | None = None) -> Path:
    configured = (os.environ if environ is None else environ).get("CLAUDE_CONFIG_DIR", "").strip()
    return Path(configured) if configured else Path.home() / ".claude"


def _claude_marketplace_source(home: Path, name: str) -> str | None:
    """The GitHub repository a known Claude Code marketplace comes from, ``""`` for
    any other source, or None when no marketplace has that name."""

    known = _read_json(home / "plugins" / "known_marketplaces.json")
    entry = known.get(name) if isinstance(known, dict) else None
    if not isinstance(entry, dict):
        return None
    source = entry.get("source")
    if not isinstance(source, dict):
        return ""
    if isinstance(source.get("repo"), str):
        return source["repo"].lower()
    url = source.get("url")
    match = re.fullmatch(r"https://github\.com/([^/]+/[^/]+?)(?:\.git)?/?", url) if isinstance(url, str) else None
    return match.group(1).lower() if match else ""


def _claude_record(home: Path) -> dict[str, Any] | None:
    """Claude Code's installed plugins by id: empty when it has no record yet,
    None when the record exists but cannot be read, so callers never mistake
    an unreadable record for "nothing installed"."""

    path = home / "plugins" / "installed_plugins.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except (OSError, ValueError):
        return None
    plugins = data.get("plugins", {}) if isinstance(data, dict) else None
    return plugins if isinstance(plugins, dict) else None


def _claude_unreadable(home: Path) -> str:
    return f"Guard could not read Claude Code's plugin record ({home / 'plugins' / 'installed_plugins.json'})"


def _claude_install(home: Path, plugin_id: str) -> tuple[bool, str | None] | None:
    """Whether Claude Code has the plugin for the user and the commit it
    installed, or None when its record cannot be read."""

    plugins = _claude_record(home)
    if plugins is None:
        return None
    entries = plugins.get(plugin_id)
    for entry in entries if isinstance(entries, list) else []:
        if isinstance(entry, dict) and entry.get("scope") == "user":
            commit = entry.get("gitCommitSha")
            return True, commit if isinstance(commit, str) else None
    return False, None


def _claude_source_command(home: Path, plugin_id: str) -> str | None:
    """The command Claude Code ran to install the plugin for the user, for a
    plugin whose marketplace declares one; such a record has no commit."""

    entries = (_claude_record(home) or {}).get(plugin_id)
    for entry in entries if isinstance(entries, list) else []:
        if isinstance(entry, dict) and entry.get("scope") == "user":
            command = entry.get("sourceCommand")
            return command if isinstance(command, str) else None
    return None


def _claude_checkout_command(home: Path, marketplace: str, plugin_id: str) -> str | None:
    """The install command Claude Code's checkout of a marketplace declares
    for a plugin, or None when it declares none or cannot be read."""

    known = _read_json(home / "plugins" / "known_marketplaces.json")
    entry = known.get(marketplace) if isinstance(known, dict) else None
    root = entry.get("installLocation") if isinstance(entry, dict) else None
    if not isinstance(root, str) or not os.path.isabs(root):
        return None
    catalog = _read_json(Path(root) / ".claude-plugin" / "marketplace.json")
    plugins = catalog.get("plugins") if isinstance(catalog, dict) else None
    name = plugin_id.rsplit("@", 1)[0]
    for plugin in plugins if isinstance(plugins, list) else []:
        if not isinstance(plugin, dict) or plugin.get("name") != name:
            continue
        source = plugin.get("source")
        if isinstance(source, dict) and source.get("source") == "command":
            command = source.get("command")
            return command if isinstance(command, str) else None
    return None


def _claude_marketplace_head(home: Path, name: str) -> str | None:
    """The commit Claude Code's checkout of a marketplace is at."""

    known = _read_json(home / "plugins" / "known_marketplaces.json")
    entry = known.get(name) if isinstance(known, dict) else None
    root = entry.get("installLocation") if isinstance(entry, dict) else None
    return git_head(Path(root)) if isinstance(root, str) and os.path.isabs(root) else None


def _claude_plugins(home: Path, *, any_scope: bool = False) -> set[str] | None:
    """Plugin ids Claude Code has installed for the user (with ``any_scope``,
    for a project or folder too), or None when its record cannot be read."""

    plugins = _claude_record(home)
    if plugins is None:
        return None
    return {
        plugin_id
        for plugin_id, entries in plugins.items()
        if isinstance(entries, list)
        and any(isinstance(e, dict) and (any_scope or e.get("scope") == "user") for e in entries)
    }


def _codex_plugins(program: runner.Program) -> set[str] | None:
    """Plugin ids Codex lists as installed, or None when it could not list them."""

    try:
        completed = runner.run(program, ["plugin", "list", "--json"], capture=True)
    except runner.RunnerError:
        return None
    installed = _reply(completed.stdout).get("installed") if completed.returncode == 0 else None
    if not isinstance(installed, list):
        return None
    return {
        entry["pluginId"]
        for entry in installed
        if isinstance(entry, dict) and isinstance(entry.get("pluginId"), str) and entry.get("installed") is not False
    }


def _installed_plugins(runtime: str, program: runner.Program, context: _Context) -> set[str] | None:
    if runtime == "claude-code":
        return _claude_plugins(context.home)
    if runtime == "codex":
        return _codex_plugins(program)
    return None


def _check_runtime_lists(step: Mapping[str, Any], plugins: set[str] | None, context: _Context) -> None:
    """Stop when the runtime reported success but its own list disagrees (REM D10)."""

    plugin_id = step.get("plugin_id")
    if not isinstance(plugin_id, str):
        return
    verify = step.get("verify")
    check = f" Check with: {_shown(verify)}" if verify else ""
    if plugins is None:
        raise _StoppedError(
            "failed",
            f"{step.get('program')} finished, but Guard could not read its plugin list to check {plugin_id}.{check}",
        )
    installing = context.action == "install"
    if (plugin_id in plugins) == installing:
        return
    said = "does not list" if installing else "still lists"
    raise _StoppedError("failed", f"{step.get('program')} finished, but it {said} {plugin_id}.{check}")


def _removed_by_hand(step: Mapping[str, Any], runtime: str, program: runner.Program, context: _Context) -> bool:
    """True when the runtime's own list shows the plugin is already gone, so
    uninstall only brings Guard's record up to date (REM D11)."""

    plugin_id = step.get("plugin_id")
    if not isinstance(plugin_id, str):
        return False
    plugins = _installed_plugins(runtime, program, context)
    return plugins is not None and plugin_id not in plugins


def _drop_marketplace(
    step: Mapping[str, Any], runtime: str, program: runner.Program, listed: set[str] | None, context: _Context
) -> str:
    """After an uninstall, remove the marketplace Guard added when it still
    comes from the same repository and no other installed plugin uses it.
    Returns what to tell the user; stops when the removal fails, so Guard's
    record keeps the marketplace and running uninstall again retries."""

    remove = step.get("remove_marketplace")
    marketplace = str(step.get("marketplace"))
    if not isinstance(remove, list) or remove[:4] != [step.get("program"), "plugin", "marketplace", "remove"]:
        return ""
    argv = [str(part) for part in remove]
    recorded = step.get("marketplace_repository")
    if runtime == "claude-code" and isinstance(recorded, str):
        current = _claude_marketplace_source(context.home, marketplace)
        if current is None:
            return ""
        if current != recorded.lower():
            where = current or "another source"
            return f" Kept the {marketplace} marketplace: it now comes from {where}, not the repository Guard added."
    # Claude Code also counts plugins installed for a project or folder.
    plugins = _claude_plugins(context.home, any_scope=True) if runtime == "claude-code" else listed
    if plugins is None:
        return (
            f" Guard could not tell whether other plugins use the {marketplace} marketplace, so it kept it."
            f" Remove it with: {_shown(argv)}"
        )
    others = sorted(plugin for plugin in plugins if plugin.endswith(f"@{marketplace}"))
    if others:
        return f" Kept the {marketplace} marketplace Guard added; other plugins still use it: {', '.join(others)}."
    print(f"$ {_shown(argv)}", file=context.out)
    undone = _undo(program, argv, context)
    if undone:
        raise _StoppedError(
            "failed",
            f"removed the plugin, but Guard could not remove the {marketplace} marketplace it added.{undone}"
            " Run uninstall again to retry.",
        )
    return f" Removed the {marketplace} marketplace Guard added."


def git_head(root: Path) -> str | None:
    """The commit a checkout is at, read from its files without running git."""

    git = root / ".git"
    try:
        if git.is_file():
            pointer = git.read_text(encoding="utf-8").strip()
            if not pointer.startswith("gitdir:"):
                return None
            git = (root / pointer[len("gitdir:") :].strip()).resolve()
        head = (git / "HEAD").read_text(encoding="utf-8").strip()
        if _COMMIT.fullmatch(head):
            return head
        if not head.startswith("ref: refs/") or ".." in head:
            return None
        ref = head[len("ref: ") :]
        loose = git / ref
        if loose.is_file():
            commit = loose.read_text(encoding="utf-8").strip()
            return commit if _COMMIT.fullmatch(commit) else None
        for line in (git / "packed-refs").read_text(encoding="utf-8").splitlines():
            commit, _, name = line.partition(" ")
            if name == ref and _COMMIT.fullmatch(commit):
                return commit
    except (OSError, UnicodeDecodeError):
        return None
    return None


@dataclass
class _Context:
    action: str
    assume_yes: bool
    accept_command: str | None
    ask: Callable[[str], bool]
    echo: TextIO | None
    out: TextIO
    home: Path


def _run_step(program: runner.Program, argv: Sequence[str], context: _Context) -> None:
    print(f"$ {_shown(argv)}", file=context.out)
    _ran(runner.run(program, argv[1:], echo=context.echo), argv)


def _undo(program: runner.Program, argv: Sequence[str], context: _Context) -> str:
    """Run a rollback command; on failure, say how to run it by hand."""

    try:
        if runner.run(program, argv[1:], echo=context.echo).returncode == 0:
            return ""
    except runner.RunnerError:
        pass
    return f" Remove it yourself with: {_shown(argv)}"


def _declared_command(reply: Mapping[str, Any], context: _Context) -> tuple[str, str]:
    shown = reply.get("shownCommand")
    command = shown.get("command") if isinstance(shown, dict) else None
    digest = shown.get("sha256") if isinstance(shown, dict) else None
    if not isinstance(command, str) or not isinstance(digest, str) or not _SHA256.fullmatch(digest):
        raise _StoppedError("blocked", "Claude Code reported an install command Guard could not read, so nothing ran.")
    print("\nclaude-code: this plugin runs a command on your machine when it installs:", file=context.out)
    print(f"  {_printable(command)}", file=context.out)
    print(f"  sha256 {digest}", file=context.out)
    return command, digest


def _install_claude(step: Mapping[str, Any], program: runner.Program, context: _Context) -> bool:
    """Install through Claude Code, show any command the plugin declares, then
    check Claude Code installed the commit HOL scanned. Returns whether Guard
    added the marketplace."""

    add, install = step["commands"]
    marketplace, plugin_id = str(step.get("marketplace")), str(step.get("plugin_id"))
    expected = step.get("expected_commit")
    remove_marketplace = ["claude", "plugin", "marketplace", "remove", marketplace]
    source = _claude_marketplace_source(context.home, marketplace)
    if source is not None and source != str(add[-1]).lower():
        raise _StoppedError(
            "blocked",
            f"Claude Code already has a marketplace named {marketplace} from another source, "
            "so Guard did not install from it.",
        )
    found = _claude_install(context.home, plugin_id)
    if found is None:
        raise _StoppedError("failed", f"{_claude_unreadable(context.home)}, so it changed nothing.")
    had_plugin, prior = found
    ran = _claude_source_command(context.home, plugin_id) if had_plugin and prior is None else None
    if ran is not None:
        # Installed earlier by running its declared command: such a record keeps
        # the command, not a commit, so the marketplace checkout it came from is
        # the only commit there is to hold against the one HOL scanned, and the
        # command it recorded has to be the one that checkout declares.
        head = _claude_marketplace_head(context.home, marketplace)
        if ran != _claude_checkout_command(context.home, marketplace, plugin_id):
            raise _StoppedError(
                "blocked",
                f"Claude Code already has {plugin_id}, installed by running a command that is not the one "
                f"the {marketplace} marketplace declares, so Guard did not change it. "
                f"To install what HOL scanned, remove it first with: claude plugin uninstall {plugin_id}",
            )
        if expected and head != expected:
            raise _StoppedError(
                "blocked",
                f"Claude Code already has {plugin_id} from the {marketplace} marketplace at commit "
                f"{_short(head)}, not the commit HOL scanned ({_short(expected)}), so Guard did not change it. "
                f"To install what HOL scanned, remove it first with: claude plugin uninstall {plugin_id}",
            )
        raise _AlreadyDoneError("already installed")
    if had_plugin and expected and prior != expected:
        raise _StoppedError(
            "blocked",
            f"Claude Code already has {plugin_id} at commit {_short(prior)}, not the commit HOL scanned "
            f"({_short(expected)}), so Guard did not change it. To install what HOL scanned, remove it first "
            f"with: claude plugin uninstall {plugin_id}",
        )
    if had_plugin:
        # Already at the scanned commit (or nothing to compare), whether or
        # not its marketplace is still registered: Guard changes nothing.
        raise _AlreadyDoneError(f"already installed at commit {_short(prior)}" if prior else "already installed")
    added = source is None
    if added:
        _run_step(program, add, context)

    def undo_marketplace() -> str:
        return _undo(program, remove_marketplace, context) if added else ""

    def run_install(arguments: Sequence[str]) -> runner.Completed:
        """Run Claude Code's install; if it never finishes, take back what
        Guard added before reporting the failure."""

        try:
            return runner.run(program, arguments, capture=True)
        except runner.RunnerError as error:
            undone = ""
            if (_claude_install(context.home, plugin_id) or (True, None))[0]:
                undone = _undo(program, ["claude", "plugin", "uninstall", plugin_id], context)
            undone += undo_marketplace()
            raise runner.RunnerError(
                f"{error}{undone}" if undone else f"{error} Guard removed what it added."
            ) from None

    arguments = [*install[1:], "--json"]
    print(f"$ {_shown(install)}", file=context.out)
    completed = run_install(arguments)
    reply = _reply(completed.stdout)
    declared: str | None = None
    if completed.returncode != 0 and reply.get("failureCode") == "command_source_refused":
        try:
            declared, digest = _declared_command(reply, context)
        except _StoppedError as stop:
            raise _StoppedError(stop.status, f"{stop}{undo_marketplace()}") from None
        accepted = context.accept_command
        if accepted is None and not context.assume_yes and context.ask("Let Claude Code run this command?"):
            accepted = digest
        if accepted != digest:
            reason = (
                "--accept-command does not match the command this plugin declares, so nothing ran."
                if accepted
                else f"The install command was not accepted, so nothing ran. To run it, add --accept-command {digest}."
            )
            raise _StoppedError("blocked", f"{reason}{undo_marketplace()}")
        # Running the command is not undoable, so hold the checkout that
        # declares it against the scanned commit before it runs; the check
        # after the install still catches a checkout moved while it ran.
        head = _claude_marketplace_head(context.home, marketplace)
        if expected and head != expected:
            raise _StoppedError(
                "blocked",
                f"Claude Code's {marketplace} checkout is at commit {_short(head)}, not the commit HOL "
                f"scanned ({_short(expected)}), so Guard did not let the install command "
                f"run.{undo_marketplace()}",
            )
        completed = run_install([*arguments, "--accept-command", digest])
        reply = _reply(completed.stdout)
    try:
        _ran(completed, install, reply)
    except _StoppedError as stop:
        raise _StoppedError(stop.status, f"{stop}{undo_marketplace()}", stop.exit_code) from None
    if declared is not None:
        # A plugin installed by running a command has no commit of its own.
        # HOL scanned the marketplace that declares the command, so check the
        # command Claude Code ran is the one shown and its checkout of that
        # marketplace is at the scanned commit.
        ran = _claude_source_command(context.home, plugin_id)
        head = _claude_marketplace_head(context.home, marketplace)
        if ran == declared and (not expected or head == expected):
            return added
        problem = (
            "ran a different install command than the one Guard showed"
            if ran != declared
            else f"installed from the {marketplace} marketplace at commit {_short(head)}, "
            f"not the commit HOL scanned ({_short(expected)})"
        )
        undone = _undo(program, ["claude", "plugin", "uninstall", plugin_id], context) + undo_marketplace()
        raise _StoppedError(
            "blocked",
            f"Claude Code {problem}. "
            + (f"Guard could not remove it.{undone}" if undone else "Guard removed it again."),
        )
    if not expected:
        return added
    found = _claude_install(context.home, plugin_id)
    if found is None:
        raise _StoppedError(
            "failed",
            f"Claude Code finished, but {_claude_unreadable(context.home)} to check which commit it installed. "
            f"Check with: claude plugin list",
        )
    commit = found[1]
    if commit == expected:
        return added
    undone = _undo(program, ["claude", "plugin", "uninstall", plugin_id], context) + undo_marketplace()
    raise _StoppedError(
        "blocked",
        f"Claude Code installed commit {_short(commit)}, not the commit HOL scanned ({_short(expected)}). "
        + (f"Guard could not remove it.{undone}" if undone else "Guard removed it again."),
    )


def _install_codex(step: Mapping[str, Any], program: runner.Program, context: _Context) -> bool:
    """Add the marketplace at the scanned commit, check Codex checked that commit
    out, then install the plugin. Returns whether Guard added the marketplace."""

    add, plugin_add = step["commands"]
    expected = step.get("expected_commit")
    print(f"$ {_shown(add)}", file=context.out)
    completed = runner.run(program, [*add[1:], "--json"], capture=True)
    reply = _reply(completed.stdout)
    _ran(completed, add, reply)
    root, already = reply.get("installedRoot"), reply.get("alreadyAdded")
    head = git_head(Path(root)) if isinstance(root, str) and os.path.isabs(root) else None
    marketplace = str(step.get("marketplace"))
    remove = ["codex", "plugin", "marketplace", "remove", marketplace]
    if expected and head != expected:
        # Only take back a marketplace Codex says it just added; one the
        # user added before, or one Codex did not say, stays.
        if already is False:
            hint = _undo(program, remove, context)
        elif already is True:
            hint = f" You added that marketplace before; to install what HOL scanned, remove it with: {_shown(remove)}"
        else:
            hint = (
                " Codex did not say whether it added that marketplace, so Guard left it. "
                f"If you did not add it, remove it with: {_shown(remove)}"
            )
        raise _StoppedError(
            "blocked",
            f"Codex has the {marketplace} marketplace at commit {_short(head)}, not the commit HOL scanned "
            f"({_short(expected)}), so Guard did not install the plugin.{hint}",
        )
    plugin_id = step.get("plugin_id")
    if already and isinstance(plugin_id, str) and plugin_id in (_codex_plugins(program) or set()):
        raise _AlreadyDoneError(f"already installed at commit {_short(head)}" if head else "already installed")
    try:
        _run_step(program, plugin_add, context)
    except (_StoppedError, runner.RunnerError) as error:
        if already is not False:
            raise
        undone = _undo(program, remove, context) or " Guard removed the marketplace it added."
        if isinstance(error, _StoppedError):
            raise _StoppedError(error.status, f"{error}{undone}", error.exit_code) from None
        raise runner.RunnerError(f"{error}{undone}") from None
    # Only a Codex that says it added the marketplace now counts; an older one
    # that does not say leaves the marketplace in place on uninstall.
    return reply.get("alreadyAdded") is False


def apply_plan(
    plan: Mapping[str, Any],
    *,
    lookup: runner.Lookup,
    assume_yes: bool,
    record: Callable[[str, bool], None],
    accept_command: str | None = None,
    ask: Callable[[str], bool] = confirm,
    json_output: bool = False,
    home: Path | None = None,
    progress: Callable[[Sequence[Outcome]], None] | None = None,
) -> list[Outcome]:
    """Run each automatic step the user confirms, check the runtime lists the
    result, then ``record`` its runtime and whether Guard added its marketplace.
    ``progress`` sees the outcomes so far after each runtime, so an interrupt
    still reports the ones that finished."""

    action = str(plan.get("action"))
    context = _Context(
        action=action,
        assume_yes=assume_yes,
        accept_command=accept_command,
        ask=ask,
        echo=sys.stderr if json_output else None,
        out=sys.stderr if json_output else sys.stdout,
        home=home or claude_home(),
    )
    outcomes: list[Outcome] = []

    def add(outcome: Outcome) -> None:
        outcomes.append(outcome)
        if progress is not None:
            progress(outcomes)

    for step in plan.get("steps") or []:
        runtime, name = str(step.get("runtime")), str(step.get("program"))
        program = lookup.programs.get(name)
        if not step.get("automatic"):
            add(Outcome(runtime, "skipped", message="Guard does not run this one; run it yourself."))
            continue
        if program is None:
            print(f"\n{runtime}: skipped, {name} is not installed.", file=context.out)
            add(Outcome(runtime, "skipped", message=f"{name} was not found."))
            continue
        commands = step.get("commands") or []
        if any(not argv or str(argv[0]) != name for argv in commands):
            raise PluginInstallError("The install plan was not in the expected shape.", exit_code=EXIT_FAILED)
        if not assume_yes and not ask(f"{_verb(action)} for {runtime} with {program.path}?"):
            print(f"{runtime}: skipped.", file=context.out)
            add(Outcome(runtime, "declined", program.path))
            continue
        added = False
        cleanup = ""
        verify = step.get("verify")
        check = f" Check with: {_shown(verify)}" if verify else ""
        try:
            if action == "uninstall" and _removed_by_hand(step, runtime, program, context):
                listed = _installed_plugins(runtime, program, context)
                cleanup = _drop_marketplace(step, runtime, program, listed, context)
                raise _AlreadyDoneError(f"already removed; Guard updated its record.{cleanup}")
            if action == "install" and runtime == "claude-code" and len(commands) == 2:
                added = _install_claude(step, program, context)
            elif action == "install" and runtime == "codex" and len(commands) == 2:
                added = _install_codex(step, program, context)
            else:
                for argv in commands:
                    _run_step(program, [str(part) for part in argv], context)
            listed = _installed_plugins(runtime, program, context)
            try:
                _check_runtime_lists(step, listed, context)
            except _StoppedError as stop:
                if not added:
                    raise
                if listed is None:
                    # The plugin may be installed; taking its marketplace away
                    # would leave it with no source and no record.
                    kept = " Guard kept the marketplace it added, because the plugin may be installed."
                    raise _StoppedError(stop.status, f"{stop}{kept}", stop.exit_code) from None
                # Take back the marketplace Guard just added, so a retry adds
                # it again and records that Guard owns it.
                remove = [name, "plugin", "marketplace", "remove", str(step.get("marketplace"))]
                undone = _undo(program, remove, context) or " Guard removed the marketplace it added."
                raise _StoppedError(stop.status, f"{stop}{undone}", stop.exit_code) from None
            if action == "uninstall":
                cleanup = _drop_marketplace(step, runtime, program, listed, context)
        except _AlreadyDoneError as done:
            print(f"{runtime}: {done}{'' if str(done).endswith('.') else '.'}{check}", file=context.out)
        except _StoppedError as stop:
            print(f"{runtime}: {stop}", file=sys.stderr)
            add(Outcome(runtime, stop.status, program.path, stop.exit_code, str(stop)))
            continue
        except runner.RunnerError as error:
            print(f"{runtime}: {error}", file=sys.stderr)
            add(Outcome(runtime, "failed", program.path, None, str(error)))
            continue
        else:
            done = "installed; start a new session to load it" if action == "install" else "removed"
            print(f"{runtime}: {done}.{cleanup}{check}", file=context.out)
        try:
            record(runtime, added)
        except PluginInstallError as error:
            message = f"{error} Guard's record of this listing may be out of date."
            print(f"{runtime}: {message}", file=sys.stderr)
            add(Outcome(runtime, "failed", program.path, 0, message))
            continue
        add(Outcome(runtime, "installed" if action == "install" else "removed", program.path, 0))
    return outcomes
