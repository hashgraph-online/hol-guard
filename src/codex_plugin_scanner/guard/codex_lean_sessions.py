"""Let the user pick when Codex sums up older turns in a long session.

Codex's own ``model_auto_compact_token_limit`` setting makes it summarize the
conversation once it passes that size. A small chat is not a cheaper chat:
Codex's provider bills the part of the chat it already saw at a tenth of the
input price, and after each summary Codex reads again the files it had read,
at full price. In Guard's long-task benchmark a 30,000-token limit halved the
tokens sent but barely moved the bill. So Guard writes no
limit of its own; it writes the size the user asks for, and never touches a
value the user set themselves: Guard records the value it wrote and only
removes that exact value. A limit an earlier Guard wrote stays until the user
turns it off.
"""

from __future__ import annotations

import math
from collections.abc import Iterator, Mapping
from contextlib import ExitStack, contextmanager
from pathlib import Path
from typing import Any, TextIO

KEY = "model_auto_compact_token_limit"
BILL_NOTE = (
    "Summing up sooner keeps the chat small but can raise the bill: "
    "Codex reads again, at full price, the files it had already read."
)
SCHEMA = "guard-codex-lean-sessions.v1"


class LeanSessionsError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def config_path(home_dir: Path, environ: Mapping[str, str] | None = None) -> Path:
    """The config file Codex reads, as the native runtime names it."""

    from .native_transition_files import publication

    named = publication("lean_sessions", Path.home(), action="path", **_home_fields(home_dir, environ))
    if not isinstance(named, str):
        raise ValueError("Codex lean sessions answer is malformed")
    return Path(named)


def status(home_dir: Path, guard_home: Path, environ: Mapping[str, str] | None = None) -> dict[str, object]:
    return _ask("status", home_dir, guard_home, environ)


def check_limit(limit: object) -> int:
    """The native runtime's check of a size the user picked: there is no default."""

    from .native_transition_files import publication

    checked = publication("lean_sessions", Path.home(), action="check", limit=_wire_limit(limit))
    if isinstance(checked, Mapping):
        raise LeanSessionsError(str(checked.get("error") or "codex_lean_limit_invalid"))
    if not isinstance(checked, int) or isinstance(checked, bool):
        raise LeanSessionsError("codex_lean_limit_invalid")
    return checked


def enable(
    home_dir: Path, guard_home: Path, environ: Mapping[str, str] | None = None, *, limit: object = None
) -> dict[str, object]:
    """Write `limit` to the Codex config. There is no default size."""

    limit = check_limit(limit)
    with _locked(guard_home, config_path(home_dir, environ)):
        return _ask("enable", home_dir, guard_home, environ, limit=limit)


def disable(home_dir: Path, guard_home: Path, environ: Mapping[str, str] | None = None) -> dict[str, object]:
    with _locked(guard_home, config_path(home_dir, environ)):
        return _ask("disable", home_dir, guard_home, environ)


def render(state: dict[str, object], output: TextIO) -> None:
    limit = state["limit"]
    if state["state"] == "on":
        print(f"Guard set Codex to sum up older turns once a session passes {limit:,} tokens.", file=output)
        print(BILL_NOTE, file=output)
        print("Remove it with: hol-guard context lean off", file=output)
    elif state["state"] == "yours":
        print(f"Your Codex config already sets {KEY} = {limit}. Guard left it as it is.", file=output)
    else:
        print("Off. Codex sums up long sessions on its own schedule.", file=output)
        print(BILL_NOTE, file=output)
        print("To pick a size anyway: hol-guard context lean on --limit 100000", file=output)


def _wire_limit(limit: object) -> object:
    """A limit JSON can carry; anything else is refused as invalid natively."""

    if isinstance(limit, float) and not math.isfinite(limit):
        return str(limit)
    if limit is None or isinstance(limit, bool | int | float | str):
        return limit
    return str(limit)


def _home_fields(home_dir: Path, environ: Mapping[str, str] | None) -> dict[str, Any]:
    codex_home = (environ or {}).get("CODEX_HOME")
    if codex_home and codex_home.strip() and not codex_home.strip().startswith("~"):
        # Codex resolves a relative CODEX_HOME from the directory it runs in;
        # the runtime runs elsewhere, so send the path this process means.
        codex_home = str(Path(codex_home.strip()).absolute())
    return {"home_dir": str(Path(home_dir).absolute()), "codex_home": codex_home}


def _ask(
    action: str,
    home_dir: Path,
    guard_home: Path,
    environ: Mapping[str, str] | None,
    **fields: Any,
) -> dict[str, object]:
    from .native_transition_files import publication

    answer = publication(
        "lean_sessions",
        guard_home,
        action=action,
        **_home_fields(home_dir, environ),
        **fields,
    )
    if not isinstance(answer, Mapping):
        raise ValueError("Codex lean sessions answer is malformed")
    error = answer.get("error")
    if isinstance(error, str):
        raise LeanSessionsError(error)
    return dict(answer)


@contextmanager
def _locked(guard_home: Path, path: Path) -> Iterator[None]:
    """Hold the same lock Guard's Codex install takes, so the two never write
    the config file at the same time, and finish an interrupted hook install
    first. The runtime takes the lock and runs that recovery in one step, so
    the config is as the recovery left it before anything here reads it."""

    from .codex_hook_file_integrity import CodexHookIntegrityError
    from .native_owned import codex_install_transaction

    with ExitStack() as held:
        try:
            held.enter_context(codex_install_transaction(guard_home, path, actor="lean-sessions", recover=True))
        except CodexHookIntegrityError as error:
            raise LeanSessionsError("codex_hooks_need_recovery") from error
        yield
