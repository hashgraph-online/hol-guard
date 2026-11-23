"""MCP connector-setup cases for the benign false-positive gate.

The gate replays each MCP call through Guard's native stdio relay
(``hol-guard-runtime mcp-relay``), launched with the argv an installer writes,
against the synthetic ``echo-mcp`` servers ``write_connectors`` installs. The
relay asks the gate's resident for each decision with the real store, and the
resident writes the approval rows and receipts a person would see. Remote
``url`` servers are not wrapped by the relay, so no case can replay one.

Nothing leaves the machine: the child is a short local script that answers
``initialize`` and ``tools/list``, and answers ``tools/call`` with a fixed
text result so a call that got past Guard shows up in the response.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ci.gauntlet.approval_rows import CONNECTOR_GROUP_ID, approval_rows
from codex_plugin_scanner.guard.blocked_request_mode import SAFE_ALTERNATIVE_GUIDANCE
from codex_plugin_scanner.guard.cli.commands_mcp_relay_launch import RELAY_COMMAND, relay_argv
from codex_plugin_scanner.guard.local_cli_trust import utc_now
from codex_plugin_scanner.guard.mcp_tool_calls import RUNTIME_TOOL_CALL_CONNECTOR_SETUP_REQUIRED
from codex_plugin_scanner.guard.native_policy_snapshot_publisher import provision_native_verifier_key_for_store
from codex_plugin_scanner.guard.runtime.local_cli_commands import LocalCliCommand
from codex_plugin_scanner.guard.runtime.local_cli_identity import UnlistedCliIdentity
from codex_plugin_scanner.guard.runtime.local_mcp_stdio import McpCatalogResult
from codex_plugin_scanner.guard.runtime.mcp_protection import McpServerIdentity, build_mcp_server_identity
from codex_plugin_scanner.guard.store import GuardStore

if TYPE_CHECKING:
    from tests.benign_fp_gate_fixture import BenignFixture

SERVERS = ("echo-mcp", "echo-ready")
READY_SERVER = "echo-ready"
READY_TOOL = "lookup"
_SESSION_SECONDS = 30.0
_WARM_SECONDS = 30.0
# The answer to a call the relay could not decide yet (`mcp_relay_authority::NO_DECISION`).
_NO_DECISION = "HOL Guard could not obtain a native decision for this tool call."
# The stderr line naming why (`mcp_relay_resident_defer::DEFER_LINE_PREFIX`).
_DEFER_PREFIX = "hol-guard mcp-relay: no native decision: "
# Default mode neither links to the review nor tells the agent to ask the user for anything.
FORBIDDEN_WORDING = ("http", "inbox", "approv", "ask the user", "ask your", "ask them")
_TOOLS = [
    {
        "name": name,
        "description": f"{name} a value",
        "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}}},
    }
    for name in ("lookup", "summarize")
]
_SERVER = f"""import json
import sys

TOOLS = {_TOOLS!r}
for line in sys.stdin:
    message = json.loads(line)
    method = message.get("method")
    if method == "initialize":
        result = {{"protocolVersion": "2025-06-18", "capabilities": {{"tools": {{}}}},
                   "serverInfo": {{"name": "echo-mcp", "version": "1.0.0"}}}}
    elif method == "tools/list":
        result = {{"tools": TOOLS}}
    elif method == "tools/call":
        result = {{"content": [{{"type": "text", "text": "forwarded"}}]}}
    else:
        result = {{}}
    print(json.dumps({{"jsonrpc": "2.0", "id": message.get("id"), "result": result}}), flush=True)
"""


@dataclass(frozen=True)
class McpCase:
    case_id: str
    server: str
    tool: str
    arguments: dict[str, object]
    expect: str


def mcp_cases(document: dict[str, Any]) -> list[McpCase]:
    """The ``mcp_cases`` of the gate's case document."""
    return [
        McpCase(entry["id"], entry["server"], entry["tool"], entry["arguments"], entry["expect"])
        for entry in document["mcp_cases"]
    ]


def server_script(home: Path) -> Path:
    return home / ".echo-mcp" / "server.py"


def server_command(home: Path, server: str) -> list[str]:
    """The command a harness config launches for ``server``; the name in argv keeps each server's identity apart."""
    return [sys.executable, "-u", str(server_script(home)), server]


def mcp_config(home: Path, remote_url: str) -> str:
    """Codex ``config.toml`` naming both stdio servers and a remote one."""
    sections = []
    for server in SERVERS:
        command, *args = server_command(home, server)
        sections.append(f"[mcp_servers.{server}]\ncommand = {json.dumps(command)}\nargs = {json.dumps(args)}\n")
    sections.append(f'[mcp_servers.remote-example]\nurl = "{remote_url}"\n')
    return "\n".join(sections)


def write_server(home: Path) -> None:
    script = server_script(home)
    script.parent.mkdir(parents=True, exist_ok=True)
    script.write_text(_SERVER, encoding="utf-8")


def _identity(case: McpCase, fixture: BenignFixture) -> McpServerIdentity:
    command, *args = server_command(fixture.home, case.server)
    return build_mcp_server_identity(
        config_path=_config_path(fixture),
        command=command,
        args=tuple(args),
        transport="stdio",
        env={},
    )


def _config_path(fixture: BenignFixture) -> str:
    return str(fixture.home / ".codex" / "config.toml")


def _relay_command(case: McpCase, fixture: BenignFixture) -> list[str]:
    """The relay command an installer writes for ``case.server`` in the Codex config."""
    command, *args = server_command(fixture.home, case.server)
    options = argparse.Namespace(
        home=str(fixture.home),
        workspace=str(fixture.worktree),
        server_name=case.server,
        source_scope="global",
        config_path=_config_path(fixture),
        transport="stdio",
    )
    argv = relay_argv(
        "codex-mcp-proxy",
        options,
        guard_home=fixture.guard_home,
        server_command=command,
        server_args=args,
        server_id=None,
        server_env_keys=(),
    )
    binary = os.environ.get("HOL_GUARD_NATIVE_BINARY", "")
    return [binary, RELAY_COMMAND, sys.executable, *argv]


def allow_ready_server(store: GuardStore, identity: McpServerIdentity) -> None:
    """Record the local admin's allow for one tool of ``echo-ready`` through the store's grant API."""
    cli = UnlistedCliIdentity(
        cli_id=f"local-cli.mcp-{identity.identity_hash[:8]}",
        name=READY_SERVER,
        kind="executable",
        identity_hash=identity.identity_hash,
        example_label=READY_SERVER,
    )
    seen_at = utc_now()
    store.record_local_cli_observation(
        cli,
        seen_at=seen_at,
        surface="mcp",
        server_identity_hash=identity.identity_hash,
        server_command=identity.command,
        server_args_hash=identity.args_hash,
        help_status="ok",
    )
    definitions = tuple(_TOOLS)
    store.replace_local_cli_commands(
        cli.cli_id,
        tuple(
            LocalCliCommand(tool["name"], tool["name"], tool["name"], tool["description"])
            for tool in definitions
        ),
        mcp_catalog=McpCatalogResult(tools=definitions, complete=True),
        identity_hash=identity.identity_hash,
        seen_at=seen_at,
    )
    store.upsert_local_cli_grant(
        identity=cli,
        state="allowed",
        expected_revision=store.read_local_cli_revision(),
        updated_at=seen_at,
        command_states={READY_TOOL: "allow", "summarize": "review"},
    )


def _messages(case: McpCase) -> list[dict[str, Any]]:
    call = {"name": case.tool, "arguments": case.arguments}
    return [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"capabilities": {}}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": call},
    ]


def _session(
    command: list[str], fixture: BenignFixture, messages: list[dict[str, Any]]
) -> tuple[dict[int, Any], list[str]]:
    """Run one relay session: its responses by id and the defer codes it named on stderr.

    Stdin closes after the last answer.

    A watchdog kills the relay once the session outlives ``_SESSION_SECONDS``,
    so a relay that holds stdout open without answering fails the case instead
    of hanging the gate.
    """
    wanted = {int(message["id"]) for message in messages}
    responses: dict[int, Any] = {}
    expired = threading.Event()
    with (
        tempfile.TemporaryFile(mode="w+", encoding="utf-8") as stderr,
        subprocess.Popen(
            command,
            cwd=fixture.worktree,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=stderr,
            text=True,
        ) as session,
    ):
        assert session.stdin is not None and session.stdout is not None

        def expire() -> None:
            expired.set()
            session.kill()

        watchdog = threading.Timer(_SESSION_SECONDS, expire)
        watchdog.start()
        try:
            for message in messages:
                session.stdin.write(json.dumps(message) + "\n")
                session.stdin.flush()
                for line in session.stdout:
                    answer = json.loads(line)
                    if isinstance(answer.get("id"), int):
                        responses[answer["id"]] = answer
                    if message["id"] in responses:
                        break
                if message["id"] not in responses:
                    break
            session.stdin.close()
            session.wait(timeout=_SESSION_SECONDS)
        except BaseException:
            session.kill()
            raise
        finally:
            watchdog.cancel()
        stderr.seek(0)
        defers = [line.removeprefix(_DEFER_PREFIX).strip() for line in stderr if line.startswith(_DEFER_PREFIX)]
    if expired.is_set():
        raise TimeoutError(f"the MCP relay session did not finish within {_SESSION_SECONDS:.0f}s")
    return {key: value for key, value in responses.items() if key in wanted}, defers


def _warming(response: dict[str, Any]) -> bool:
    """Whether the relay refused the call only because its resident had no decision yet."""
    error = response.get("error")
    return isinstance(error, dict) and error.get("message") == _NO_DECISION


def replay(
    case: McpCase, fixture: BenignFixture, store: GuardStore
) -> tuple[dict[str, Any], list[dict[str, Any]], str]:
    """Run one call through the relay: its answer, the approval rows it queued and the server's identity hash."""
    provision_native_verifier_key_for_store(store)
    identity = _identity(case, fixture)
    if case.server == READY_SERVER:
        allow_ready_server(store, identity)
    command = _relay_command(case, fixture)
    known = {str(row.get("request_id")) for row in store.list_approval_requests(status=None, limit=500)}
    # The first session reports the server's catalog; a call refused while the
    # resident still records it is sent again in a later session.
    deadline = time.monotonic() + _WARM_SECONDS
    while True:
        responses, defers = _session(command, fixture, _messages(case))
        response = responses.get(3, {})
        if not _warming(response) or time.monotonic() > deadline:
            break
        time.sleep(0.25)
    if _warming(response):
        # Name why the relay never decided, so a failing case says more than the refusal.
        response = {**response, "relay_defer": defers}
    rows = approval_rows(store, known)
    return response, rows, identity.identity_hash


def mcp_failure(case: McpCase, response: dict[str, Any], rows: list[dict[str, Any]], identity: str) -> str | None:
    """Why a replayed call is not what its case expects, or None when it is."""
    error = response.get("error")
    data = error.get("data", {}) if isinstance(error, dict) else {}
    if "relay_defer" in response:
        return f"the relay never decided the call: {response['relay_defer']}"
    if case.expect == "allow":
        if "result" not in response or rows:
            return f"an allowed server was held: {response}"
        return None
    if not isinstance(error, dict):
        return f"the call must not reach the server: {response}"
    is_setup = data.get("guardReasonCode") == RUNTIME_TOOL_CALL_CONNECTOR_SETUP_REQUIRED
    groups = [CONNECTOR_GROUP_ID.fullmatch(str(row["queue_group_id"])) for row in rows]
    if case.expect != "setup":
        if is_setup or any(groups):
            return "a server with an admin decision must not be held as setup"
        # A proxy failure or an unavailable decision is an error too; only a policy
        # stop that queued one per-call review row is the ordinary review expected here.
        if data.get("transportOutcome") != "not-forwarded" or not data.get("guardPolicyAction"):
            return f"expected a Guard policy stop, got {error}"
        if len(rows) != 1 or not rows[0].get("allow_scopes"):
            return f"expected one ordinary review row, got {rows}"
        return None
    text = str(error.get("message", "")).lower()
    if not is_setup or "reviewUrl" in data:
        return f"not answered as setup: {error}"
    if f"`{case.server}` (mcp server)" not in text:
        return "setup text does not name the server"
    if SAFE_ALTERNATIVE_GUIDANCE.lower() not in text:
        return "setup lost the safe-alternative guidance"
    leaked = [word for word in FORBIDDEN_WORDING if word in text]
    if leaked:
        return f"default-mode setup text carries {leaked}"
    if len(rows) != 1 or groups[0] is None:
        return f"setup must queue one row under a connector group, got {rows}"
    if groups[0]["identity"] != identity:
        return "group names another connector"
    return None
