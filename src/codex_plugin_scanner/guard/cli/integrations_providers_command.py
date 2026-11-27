"""``hol-guard integrations list|status|connect|disconnect|test|settings``.

Thin glue over the daemon's provider routes (``/v1/integrations/providers``). The native daemon
owns every rule: which providers ship, what each one is sent, the one-use proofs, managed locks,
key storage and the lookup itself. This module parses arguments, reads the key without echoing it,
shows the preview the daemon returns, asks before a change, and prints the answer.

The key is never an argument. It is read with ``getpass`` from a terminal, or as one line from
standard input with ``--key-stdin``, and it is sent only in the connect request body.
"""

from __future__ import annotations

import argparse
import getpass
import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any, Protocol, TextIO

PROVIDERS_PATH = "/v1/integrations/providers"
DEFAULT_CAPABILITY = "browser.origin-reputation"
EFFECTS = ("observe", "tighten", "enforce")
PROVIDER_COMMANDS = frozenset({"list", "status", "connect", "disconnect", "test", "settings"})

_READ_TIMEOUT_S = 10.0
# Connect checks the key with the provider and test runs one lookup, so both wait on the network.
_PROVIDER_CALL_TIMEOUT_S = 45.0


class ProviderClient(Protocol):
    def _get(self, path: str, *, timeout: float) -> dict[str, object]: ...

    def _post(self, path: str, payload: dict[str, object], *, timeout: float = ...) -> dict[str, object]: ...


class ProviderCommandError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def configure_provider_subcommands(commands: argparse._SubParsersAction[Any]) -> None:
    listing = commands.add_parser("list", help="List the providers this Guard ships and their state")
    listing.add_argument("--json", action="store_true", help="Print the daemon answer as JSON")

    status = commands.add_parser("status", help="Show one provider's connection, shares and settings")
    status.add_argument("provider", help="Provider id, for example provider.exampleshield")
    status.add_argument("--json", action="store_true", help="Print the daemon answer as JSON")

    connect = commands.add_parser("connect", help="Connect a provider with your own key")
    connect.add_argument("provider", help="Provider id")
    connect.add_argument("--key-stdin", action="store_true", help="Read the key as one line from standard input")
    connect.add_argument(
        "--share",
        action="append",
        default=[],
        metavar="FACT",
        help="Also share an opt-in fact the provider offers (repeatable)",
    )
    connect.add_argument("--yes", action="store_true", help="Connect without asking after the preview")
    connect.add_argument("--json", action="store_true", help="Print the daemon answer as JSON")

    disconnect = commands.add_parser("disconnect", help="Disconnect a provider and delete its key")
    disconnect.add_argument("provider", help="Provider id")
    disconnect.add_argument("--yes", action="store_true", help="Disconnect without asking")
    disconnect.add_argument("--json", action="store_true", help="Print the daemon answer as JSON")

    test = commands.add_parser("test", help="Run one live lookup for a public origin; the answer is not stored")
    test.add_argument("provider", help="Provider id")
    test.add_argument("--origin", required=True, help="Public origin, for example https://storefront.example-org.com")
    test.add_argument("--capability", default=DEFAULT_CAPABILITY, help=f"Capability (default: {DEFAULT_CAPABILITY})")
    test.add_argument("--json", action="store_true", help="Print the daemon answer as JSON")

    settings = commands.add_parser("settings", help="Change what a connected provider's signals may do")
    settings.add_argument("provider", help="Provider id")
    settings.add_argument(
        "--effect",
        action="append",
        default=[],
        nargs=2,
        metavar=("CAPABILITY", "LEVEL"),
        help="Set a capability's effect: observe, tighten or enforce (repeatable)",
    )
    settings.add_argument(
        "--require-fresh",
        action="append",
        default=[],
        nargs=2,
        metavar=("CAPABILITY", "on|off"),
        help="Require a fresh provider answer before the action runs (repeatable)",
    )
    settings.add_argument(
        "--enforce-blocks",
        choices=("on", "off"),
        help="on: a danger answer blocks for every capability (enforce); off: lowers enforce to tighten",
    )
    settings.add_argument(
        "--share",
        action="append",
        default=None,
        metavar="FACT",
        help="Set the opt-in facts to share; repeat for each (default: keep the current set)",
    )
    settings.add_argument("--no-opt-in", action="store_true", help="Share no opt-in facts")
    settings.add_argument("--yes", action="store_true", help="Apply without asking after the preview")
    settings.add_argument("--json", action="store_true", help="Print the daemon answer as JSON")


def run_provider_command(
    args: argparse.Namespace,
    *,
    output_stream: TextIO,
    error_stream: TextIO,
    client_factory: Callable[[], ProviderClient] | None = None,
    input_stream: TextIO | None = None,
) -> int:
    from ..native_daemon_client import GuardDaemonRequestError

    as_json = bool(getattr(args, "json", False))
    session = _Session(
        args,
        client_factory or (lambda: _daemon_client(args)),
        output_stream,
        error_stream,
        input_stream if input_stream is not None else sys.stdin,
    )
    try:
        return session.run()
    except GuardDaemonRequestError as exc:
        code = exc.code or ("daemon_unavailable" if exc.status is None else "daemon_request_failed")
        return _fail(ProviderCommandError(code, str(exc)), as_json, output_stream, error_stream)
    except ProviderCommandError as exc:
        return _fail(exc, as_json, output_stream, error_stream)


def _fail(exc: ProviderCommandError, as_json: bool, output: TextIO, errors: TextIO) -> int:
    if as_json:
        print(json.dumps({"ok": False, "error": {"code": exc.code, "message": str(exc)}}), file=output)
    else:
        print(f"{exc.code}: {exc}", file=errors)
    return 2


def _daemon_client(args: argparse.Namespace) -> ProviderClient:
    from ..config import resolve_guard_home
    from ..native_daemon_client import load_guard_surface_daemon_client

    guard_home = resolve_guard_home(getattr(args, "guard_home", None) or getattr(args, "home", None))
    return load_guard_surface_daemon_client(Path(guard_home))


class _Session:
    def __init__(
        self,
        args: argparse.Namespace,
        client_factory: Callable[[], ProviderClient],
        output: TextIO,
        errors: TextIO,
        stdin: TextIO,
    ) -> None:
        self.args = args
        self.client_factory = client_factory
        self.output = output
        self.errors = errors
        self.stdin = stdin
        self.as_json = bool(getattr(args, "json", False))

    def run(self) -> int:
        command = str(self.args.integrations_command)
        if command == "list":
            return self._emit(self._client().get(PROVIDERS_PATH, timeout=_READ_TIMEOUT_S), _print_list)
        provider = _provider_id(self.args.provider)
        base = f"{PROVIDERS_PATH}/{provider}"
        if command == "status":
            return self._emit(self._client().get(base, timeout=_READ_TIMEOUT_S), _print_detail)
        if command == "test":
            payload: dict[str, object] = {
                "capability": str(self.args.capability),
                "origin": str(self.args.origin).strip(),
            }
            return self._emit(self._post(f"{base}/test", payload, _PROVIDER_CALL_TIMEOUT_S), _print_test)
        if command == "connect":
            return self._connect(base)
        if command == "disconnect":
            return self._disconnect(base)
        return self._settings(base)

    def _client(self) -> _Calls:
        return _Calls(self.client_factory())

    def _post(self, path: str, payload: dict[str, object], timeout: float = _READ_TIMEOUT_S) -> dict[str, object]:
        return self._client().post(path, payload, timeout=timeout)

    def _emit(self, answer: dict[str, object], render: Callable[[dict[str, object], TextIO], None]) -> int:
        if self.as_json:
            print(json.dumps(answer, sort_keys=True), file=self.output)
        else:
            render(answer, self.output)
        return 0

    def _connect(self, base: str) -> int:
        # The key is read before any request, so a refused read changes nothing.
        key = self._read_key()
        calls = self._client()
        preview = calls.post(f"{base}/connect/preview", {}, timeout=_READ_TIMEOUT_S)
        offered = _strings(preview.get("opt_in_facts"))
        shares = [str(fact) for fact in self.args.share]
        unknown = sorted(set(shares) - set(offered))
        if unknown:
            raise ProviderCommandError(
                "invalid_request", f"The provider does not offer {', '.join(unknown)} as an opt-in fact."
            )
        if not self.as_json:
            _print_connect_preview(preview, shares, self.output)
        self._confirm("Connect this provider?")
        payload: dict[str, object] = {
            "key": key,
            "proof": _challenge(preview),
            "enabled_opt_in_facts": shares,
        }
        answer = calls.post(f"{base}/connect", payload, timeout=_PROVIDER_CALL_TIMEOUT_S)
        return self._emit(answer, _print_connected)

    def _disconnect(self, base: str) -> int:
        calls = self._client()
        preview = calls.post(f"{base}/disconnect/preview", {}, timeout=_READ_TIMEOUT_S)
        if not self.as_json:
            provider = preview.get("provider_id")
            print(f"Disconnecting {provider} deletes its key and every cached answer.", file=self.output)
        self._confirm("Disconnect this provider?")
        answer = calls.post(f"{base}/disconnect", {"proof": _challenge(preview)}, timeout=_READ_TIMEOUT_S)
        return self._emit(answer, _print_disconnected)

    def _settings(self, base: str) -> int:
        calls = self._client()
        detail = calls.get(base, timeout=_READ_TIMEOUT_S)
        settings = _settings_rows(detail)
        capabilities = _strings(_mapping(detail.get("summary")).get("capabilities"))
        for row in settings:
            capabilities.append(str(row.get("capability")))
        if self.args.enforce_blocks is not None:
            for capability in dict.fromkeys(capabilities):
                row = _row(settings, capability)
                if self.args.enforce_blocks == "on":
                    row["effect"] = "enforce"
                elif row.get("effect") == "enforce":
                    row["effect"] = "tighten"
        for capability, level in _pairs(self.args.effect):
            if level not in EFFECTS:
                raise ProviderCommandError("invalid_request", f"{level} is not one of {', '.join(EFFECTS)}.")
            _row(settings, capability)["effect"] = level
        for capability, flag in _pairs(self.args.require_fresh):
            if flag not in {"on", "off"}:
                raise ProviderCommandError("invalid_request", "--require-fresh takes on or off.")
            _row(settings, capability)["require_fresh_check"] = flag == "on"
        if self.args.no_opt_in:
            facts: list[str] = []
        elif self.args.share is not None:
            facts = [str(fact) for fact in self.args.share]
        else:
            facts = _strings(detail.get("enabled_opt_in_facts"))
        change: dict[str, object] = {"settings": settings, "enabled_opt_in_facts": facts}
        preview = calls.post(f"{base}/settings/preview", change, timeout=_READ_TIMEOUT_S)
        if not self.as_json:
            _print_settings_preview(preview, self.output)
        self._confirm("Apply these settings?")
        apply = {**change, "proof": _challenge(preview)}
        answer = calls.post(f"{base}/settings", apply, timeout=_READ_TIMEOUT_S)
        return self._emit(answer, _print_applied)

    def _read_key(self) -> str:
        if self.args.key_stdin:
            key = self.stdin.readline().strip()
        else:
            if not self.stdin.isatty():
                raise ProviderCommandError(
                    "terminal_required",
                    "Run this in a terminal, or pass --key-stdin to read the key from standard input.",
                )
            key = getpass.getpass("Provider key (not shown): ", stream=self.errors).strip()
        if not key:
            raise ProviderCommandError("provider_key_missing", "No key was entered.")
        return key

    def _confirm(self, question: str) -> None:
        if self.args.yes:
            return
        # With --key-stdin the key used up standard input, so no answer can follow it there.
        if getattr(self.args, "key_stdin", False) or not self.stdin.isatty():
            raise ProviderCommandError("confirmation_required", "Pass --yes to apply without a terminal prompt.")
        print(f"{question} [y/N] ", end="", file=self.output, flush=True)
        if self.stdin.readline().strip().lower() not in {"y", "yes"}:
            raise ProviderCommandError("cancelled", "Nothing was changed.")


class _Calls:
    def __init__(self, client: ProviderClient) -> None:
        self.client = client

    def get(self, path: str, *, timeout: float) -> dict[str, object]:
        return self.client._get(path, timeout=timeout)

    def post(self, path: str, payload: dict[str, object], *, timeout: float) -> dict[str, object]:
        return self.client._post(path, payload, timeout=timeout)


def _provider_id(value: object) -> str:
    provider = str(value).strip()
    if not provider.startswith("provider.") or not all(ch.isalnum() or ch in ".-" for ch in provider):
        raise ProviderCommandError("not_found", "Provider ids look like provider.<name>.")
    return provider


def _challenge(preview: dict[str, object]) -> str:
    challenge = preview.get("challenge")
    if not isinstance(challenge, str) or not challenge:
        raise ProviderCommandError("daemon_schema_invalid", "The daemon did not return a proof challenge.")
    return challenge


def _strings(value: object) -> list[str]:
    return [str(item) for item in value] if isinstance(value, list) else []


def _pairs(values: list[list[str]]) -> list[tuple[str, str]]:
    return [(str(name).strip(), str(value).strip().lower()) for name, value in values]


def _mapping(value: object) -> dict[str, object]:
    return value if isinstance(value, dict) else {}


def _settings_rows(detail: dict[str, object]) -> list[dict[str, object]]:
    rows = detail.get("settings")
    return [dict(row) for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []


def _row(settings: list[dict[str, object]], capability: str) -> dict[str, object]:
    for row in settings:
        if row.get("capability") == capability:
            return row
    row: dict[str, object] = {
        "capability": capability,
        "effect": "tighten",
        "require_fresh_check": False,
        "quieted_reason_codes": [],
    }
    settings.append(row)
    return row


def _summary_line(summary: dict[str, object]) -> str:
    verified = "verified" if summary.get("verified") is True else "unverified"
    capabilities = ", ".join(_strings(summary.get("capabilities"))) or "no capabilities"
    return f"{summary.get('id')}  {summary.get('state')}  {verified}  {capabilities}"


def _print_list(answer: dict[str, object], stream: TextIO) -> None:
    providers = answer.get("providers")
    rows = [row for row in providers if isinstance(row, dict)] if isinstance(providers, list) else []
    if not rows:
        print("This Guard ships no provider integrations.", file=stream)
        return
    for row in rows:
        print(_summary_line(row), file=stream)
        print(f"    {row.get('name')}: {row.get('summary')}", file=stream)


def _print_detail(answer: dict[str, object], stream: TextIO) -> None:
    summary = answer.get("summary")
    summary = summary if isinstance(summary, dict) else {}
    print(_summary_line(summary), file=stream)
    print(f"  Shares: {', '.join(_strings(answer.get('shares'))) or 'nothing'}", file=stream)
    opt_in = _strings(answer.get("enabled_opt_in_facts"))
    print(f"  Opt-in facts shared: {', '.join(opt_in) or 'none'}", file=stream)
    for row in _settings_rows(answer):
        fresh = ", fresh check required" if row.get("require_fresh_check") is True else ""
        print(f"  {row.get('capability')}: {row.get('effect')}{fresh}", file=stream)
    verified_at = answer.get("last_verified_at_ms")
    print(f"  Key last verified: {verified_at if verified_at is not None else 'never'}", file=stream)


def _print_connect_preview(preview: dict[str, object], opt_in: list[str], stream: TextIO) -> None:
    print(f"Connecting {preview.get('provider_id')}.", file=stream)
    print(f"  Sent with each lookup: {', '.join(_strings(preview.get('shares'))) or 'nothing'}", file=stream)
    if opt_in:
        print(f"  Also sent (you opted in): {', '.join(opt_in)}", file=stream)
    print(f"  Only these hosts are called: {', '.join(_strings(preview.get('hosts')))}", file=stream)


def _print_connected(answer: dict[str, object], stream: TextIO) -> None:
    print(f"{answer.get('provider_id')} is connected.", file=stream)


def _print_disconnected(answer: dict[str, object], stream: TextIO) -> None:
    done = "disconnected" if answer.get("disconnected") is True else "was not connected"
    print(f"{answer.get('provider_id')} {done}.", file=stream)


def _print_settings_preview(preview: dict[str, object], stream: TextIO) -> None:
    print(f"New settings for {preview.get('provider_id')}:", file=stream)
    for row in _settings_rows(preview):
        fresh = ", fresh check required" if row.get("require_fresh_check") is True else ""
        print(f"  {row.get('capability')}: {row.get('effect')}{fresh}", file=stream)
    opt_in = _strings(preview.get("enabled_opt_in_facts"))
    print(f"  Opt-in facts shared: {', '.join(opt_in) or 'none'}", file=stream)


def _print_applied(answer: dict[str, object], stream: TextIO) -> None:
    print(f"Settings applied to {answer.get('provider_id')}.", file=stream)


def _print_test(answer: dict[str, object], stream: TextIO) -> None:
    signal = answer.get("signal")
    signal = signal if isinstance(signal, dict) else {}
    verdict = signal.get("verdict") or "unknown"
    reasons = ", ".join(_strings(signal.get("reason_codes"))) or "none"
    provider, capability = answer.get("provider_id"), answer.get("capability")
    print(f"{provider} answered {verdict} for {capability} (reasons: {reasons}).", file=stream)
    print("The answer was not stored and changes no later decision.", file=stream)
