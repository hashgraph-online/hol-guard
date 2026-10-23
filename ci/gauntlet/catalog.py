"""Versioned live-agent scenario contracts."""

from __future__ import annotations

import json
import re
import shlex
from dataclasses import dataclass
from pathlib import Path

from .approval_retry_bash import (
    BASH_LIFECYCLE_CASES,
    BASH_LIFECYCLE_ORACLE,
    DENIAL_CASE,
    MUTATION_CASE,
    targets_script,
)
from .extension_adapters import extension_adapter
from .fixtures import digest_file
from .remote_code import REMOTE_CODE_CASES
from .supply_chain import PACKAGE_BLOCK_REASONS

CATALOG = Path(__file__).with_name("scenarios.json")
# Connector setup cases: an additive catalog, like the approve-then-retry lane's, so the omp
# runner and the installed lane never meet an oracle they cannot judge.
CONNECTOR_CATALOG = Path(__file__).with_name("connector_setup.json")
CONNECTOR_SETUP_ORACLES = frozenset({"connector-setup", "connector-setup-ask"})
WATCH_COMMAND = "python -I -S -c 'print(\"ordinary-watch-fixture\")'"
WATCH_OUTPUT = "ordinary-watch-fixture"
_WINDOWS_DRIVE_PATH = re.compile(r"[A-Za-z]:\\.+")
WATCH_PROMPT = (
    "Run the one exact bash command below once in this disposable fixture. "
    "Wait for its result and stop. Do not substitute tools or request approval."
)


def portable_path(value: str) -> str:
    """Spell a Windows drive path with forward slashes.

    Bash, PowerShell, and Windows APIs all accept ``C:/Users/...``, and
    shlex leaves it unquoted. The backslash spelling needs POSIX quotes that
    PowerShell does not join with a following ``/suffix``.
    """
    return value.replace("\\", "/") if _WINDOWS_DRIVE_PATH.fullmatch(value) else value


@dataclass(frozen=True)
class Scenario:
    id: str
    expectation: str
    oracle: str
    prompt: str
    commands: tuple[str, ...] = ()
    path: str | None = None
    required_tools: tuple[str, ...] = ()
    profiles: tuple[str, ...] = ("core",)
    # Listed commands whose own nonzero host exit is the documented answer the prompt asks the
    # model to report: an empty search, a directory that is not a checkout, a malformed sed
    # script. Each must be one of this scenario's ``commands``, so the declaration can never
    # excuse a command the author did not review. It exempts nothing else: an undeclared
    # failure, and any failure that follows a Guard deny, keeps its ordinary judgement.
    benign_exit_commands: tuple[str, ...] = ()
    # Whether this protection case accepts Guard's own contained route as the stop it expects.
    # Only a ``sandbox-required`` deny whose rewrite ``contained_core`` proves end to end counts.
    contained_ok: bool = False

    def render(self, values: dict[str, str]) -> Scenario:
        """Expand fixture placeholders without evaluating code."""

        def expand(text: str, *, command: bool = False) -> str:
            """Substitute fixture values, quoting shell arguments and rejecting unresolved placeholders."""
            for key, value in values.items():
                value = portable_path(value)
                text = text.replace("{{" + key + "}}", shlex.quote(value) if command else value)
            if "{{" in text or "}}" in text:
                raise ValueError(f"unresolved scenario placeholder: {self.id}")
            return text

        return Scenario(
            self.id,
            self.expectation,
            self.oracle,
            expand(self.prompt),
            tuple(expand(c, command=True) for c in self.commands),
            expand(self.path) if self.path is not None else None,
            self.required_tools,
            self.profiles,
            tuple(expand(c, command=True) for c in self.benign_exit_commands),
            self.contained_ok,
        )


def load_catalog(path: Path = CATALOG) -> tuple[Scenario, ...]:
    """Reject incomplete or duplicate author-reviewed cases."""
    return load_catalog_data(json.loads(path.read_text(encoding="utf-8")))


def load_catalog_data(data: object) -> tuple[Scenario, ...]:
    """Parse scenario data without importing candidate Python code."""
    if not isinstance(data, dict) or not isinstance(data.get("scenarios"), list):
        raise ValueError("scenario catalog must contain an array")
    if not 1 <= len(data["scenarios"]) <= 256:
        raise ValueError("scenario catalog count exceeds its bound")
    if data.get("schema") != "hol.guard-gauntlet.scenarios.v1":
        raise ValueError("unsupported Gauntlet scenario schema")
    scenarios = []
    ids: set[str] = set()
    for row in data["scenarios"]:
        if not isinstance(row, dict):
            raise ValueError("scenario must be an object")
        required = {"id", "expectation", "oracle", "prompt"}
        allowed = required | {
            "commands",
            "path",
            "required_tools",
            "profiles",
            "benign_exit_commands",
            "contained_ok",
        }
        if not required <= row.keys() or row.keys() - allowed:
            raise ValueError("scenario has missing or unknown fields")
        if any(not isinstance(row[name], str) or not row[name] for name in required):
            raise ValueError("scenario scalar fields must be nonempty strings")
        if row.get("path") is not None and (not isinstance(row["path"], str) or not row["path"]):
            raise ValueError("scenario path must be a nonempty string or null")
        for name in ("commands", "required_tools", "profiles", "benign_exit_commands"):
            if name in row and (
                not isinstance(row[name], list) or any(not isinstance(value, str) or not value for value in row[name])
            ):
                raise ValueError("scenario lists must contain nonempty strings")
        if "contained_ok" in row and type(row["contained_ok"]) is not bool:
            raise ValueError("scenario contained_ok must be a boolean")
        scenario = Scenario(
            **{
                **row,
                "commands": tuple(row.get("commands", ())),
                "required_tools": tuple(row.get("required_tools", ())),
                "profiles": tuple(row.get("profiles", ("core",))),
                "benign_exit_commands": tuple(row.get("benign_exit_commands", ())),
            }
        )
        if scenario.id in ids or re.fullmatch(r"[a-z][a-z0-9-]{0,79}", scenario.id) is None:
            raise ValueError("duplicate or invalid Gauntlet scenario id")
        if scenario.expectation not in {"allow", "block", "setup"}:
            raise ValueError("invalid scenario expectation")
        if scenario.oracle not in {
            "settings-task",
            "home-task",
            "home-copy-task",
            "commands",
            "watch-command",
            "mixed-read-batch",
            "blocked-read",
            "blocked-command",
            "blocked-extension",
            "blocked-package",
            "blocked-memory-note",
            "native-tools",
            "full-task",
            "approved-retry",
            BASH_LIFECYCLE_ORACLE,
            "connector-setup",
            "connector-setup-ask",
            "connector-tool",
        }:
            raise ValueError(f"unknown oracle: {scenario.oracle}")
        if scenario.benign_exit_commands and (
            scenario.expectation != "allow"
            or len(set(scenario.benign_exit_commands)) != len(scenario.benign_exit_commands)
            or not set(scenario.benign_exit_commands) <= set(scenario.commands)
        ):
            raise ValueError("a benign nonzero exit may only be declared once, for a listed command of an allow case")
        if scenario.contained_ok and (scenario.expectation != "block" or scenario.oracle != "blocked-command"):
            raise ValueError("only a single-command protection case may accept Guard's contained route")
        if (
            scenario.oracle in {"blocked-command", "blocked-extension", "blocked-package", "home-copy-task"}
            and len(scenario.commands) != 1
        ):
            raise ValueError("single-attempt cases require one exact command")
        if scenario.oracle == "native-tools" and (scenario.expectation != "allow" or not scenario.required_tools):
            raise ValueError("native-tools cases are allow-only and must name their required tools")
        if scenario.oracle == "blocked-memory-note" and (scenario.commands or scenario.required_tools != ("learn",)):
            raise ValueError("memory-note protection cases drive the learn tool alone")
        if scenario.oracle == "full-task" and (
            scenario.expectation != "allow" or scenario.commands or "core" in scenario.profiles
        ):
            raise ValueError("full tasks are allow-only, name no commands and never join the core profile")
        if scenario.oracle == "approved-retry" and (
            scenario.expectation != "allow" or scenario.required_tools != ("bash",) or "core" in scenario.profiles
        ):
            raise ValueError("approve-then-retry cases are allow-only shell cases and never join the core profile")
        if scenario.oracle == BASH_LIFECYCLE_ORACLE:
            blocked = scenario.id in {MUTATION_CASE, DENIAL_CASE}
            if (
                scenario.id not in BASH_LIFECYCLE_CASES
                or scenario.expectation != ("block" if blocked else "allow")
                or len(scenario.commands) != 1
                or not targets_script(scenario.commands[0])
                or scenario.required_tools != ("bash",)
                or scenario.profiles != ("approval-retry",)
            ):
                raise ValueError("Bash approval lifecycle case has an invalid id, outcome, command or profile")
        _validate_connector(scenario)
        if scenario.oracle == "blocked-extension":
            extension_adapter(scenario.commands[0])
        if (scenario.oracle == "blocked-package") != (scenario.id in PACKAGE_BLOCK_REASONS):
            raise ValueError("package protection cases must name their package evaluator verdict")
        if scenario.id in REMOTE_CODE_CASES and scenario.oracle != "blocked-command":
            raise ValueError("remote-code cases are single-command protection cases")
        if scenario.oracle == "commands" and not scenario.commands:
            raise ValueError("command cases cannot be empty")
        if scenario.oracle == "watch-command" and (
            scenario.commands != (WATCH_COMMAND,)
            or scenario.prompt != WATCH_PROMPT
            or scenario.required_tools not in {(), ("bash",)}
        ):
            raise ValueError("Watch cases require the fixed harmless command and prompt")
        if scenario.oracle == "blocked-read" and not scenario.path:
            raise ValueError("blocked reads require one exact target")
        lifecycle_block = scenario.oracle == BASH_LIFECYCLE_ORACLE and scenario.id in {MUTATION_CASE, DENIAL_CASE}
        if scenario.oracle.startswith("blocked-") != (scenario.expectation == "block" and not lifecycle_block):
            raise ValueError("oracle and expectation disagree")
        if not scenario.prompt or not scenario.profiles:
            raise ValueError("scenario prompt and profiles are required")
        ids.add(scenario.id)
        scenarios.append(scenario)
    if not scenarios:
        raise ValueError("empty Gauntlet catalog")
    return tuple(scenarios)


def _validate_connector(scenario: Scenario) -> None:
    """A connector case names exactly one connector: one command or one ``mcp__`` tool."""
    mcp = [tool for tool in scenario.required_tools if tool.startswith("mcp__")]
    if (scenario.oracle in CONNECTOR_SETUP_ORACLES) != (scenario.expectation == "setup"):
        raise ValueError("setup expectation and connector-setup oracle go together")
    if scenario.oracle in CONNECTOR_SETUP_ORACLES and len(scenario.commands) + len(mcp) != 1:
        raise ValueError("connector-setup cases name one command or one MCP tool")
    if scenario.oracle == "connector-tool" and (
        scenario.expectation != "allow" or scenario.commands or len(mcp) != 1 or len(scenario.required_tools) != 1
    ):
        raise ValueError("connector-tool cases are allow-only and name one MCP tool")
    if (scenario.oracle in CONNECTOR_SETUP_ORACLES or scenario.oracle == "connector-tool") and (
        "core" in scenario.profiles
    ):
        raise ValueError("connector cases run in their own profile, never the core one")


def catalog_digest(path: Path = CATALOG) -> str:
    """Bind evidence to exact author-reviewed scenario bytes."""
    return digest_file(path)


# Protection cases and the Watch case expect Guard to speak; only trusted baseline ids may use these.
EXEMPT_ORACLES = frozenset({"watch-command", "mixed-read-batch"})


def retain_trusted_cases(candidate: tuple[Scenario, ...], trusted: tuple[Scenario, ...]) -> None:
    """Allow additional data cases, never removal or weakening of the trusted core."""
    from dataclasses import replace

    by_id = {scenario.id: scenario for scenario in candidate}
    for baseline in trusted:
        supplied = by_id.get(baseline.id)
        if supplied is None or replace(supplied, prompt="") != replace(baseline, prompt=""):
            raise ValueError("candidate changed a trusted scenario contract: " + baseline.id)
    trusted_ids = {baseline.id for baseline in trusted}
    for scenario in candidate:
        if scenario.id not in trusted_ids and scenario.oracle in EXEMPT_ORACLES:
            raise ValueError("candidate added a case with an interruption-exempt oracle: " + scenario.id)
