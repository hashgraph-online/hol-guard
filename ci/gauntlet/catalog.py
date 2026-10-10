"""Versioned live-agent scenario contracts."""

from __future__ import annotations

import json
import re
import shlex
from dataclasses import dataclass
from pathlib import Path

from .extension_adapters import extension_adapter
from .fixtures import digest_file

CATALOG = Path(__file__).with_name("scenarios.json")
WATCH_COMMAND = "python -I -S -c 'print(\"ordinary-watch-fixture\")'"
WATCH_OUTPUT = "ordinary-watch-fixture"
WATCH_PROMPT = (
    "Run the one exact bash command below once in this disposable fixture. "
    "Wait for its result and stop. Do not substitute tools or request approval."
)


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

    def render(self, values: dict[str, str]) -> Scenario:
        """Expand fixture placeholders without evaluating code."""

        def expand(text: str, *, command: bool = False) -> str:
            """Substitute fixture values, quoting shell arguments and rejecting unresolved placeholders."""
            for key, value in values.items():
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
        allowed = required | {"commands", "path", "required_tools", "profiles"}
        if not required <= row.keys() or row.keys() - allowed:
            raise ValueError("scenario has missing or unknown fields")
        if any(not isinstance(row[name], str) or not row[name] for name in required):
            raise ValueError("scenario scalar fields must be nonempty strings")
        if row.get("path") is not None and (not isinstance(row["path"], str) or not row["path"]):
            raise ValueError("scenario path must be a nonempty string or null")
        for name in ("commands", "required_tools", "profiles"):
            if name in row and (
                not isinstance(row[name], list) or any(not isinstance(value, str) or not value for value in row[name])
            ):
                raise ValueError("scenario lists must contain nonempty strings")
        scenario = Scenario(
            **{
                **row,
                "commands": tuple(row.get("commands", ())),
                "required_tools": tuple(row.get("required_tools", ())),
                "profiles": tuple(row.get("profiles", ("core",))),
            }
        )
        if scenario.id in ids or re.fullmatch(r"[a-z][a-z0-9-]{0,79}", scenario.id) is None:
            raise ValueError("duplicate or invalid Gauntlet scenario id")
        if scenario.expectation not in {"allow", "block"}:
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
        }:
            raise ValueError(f"unknown oracle: {scenario.oracle}")
        if (
            scenario.oracle in {"blocked-command", "blocked-extension", "home-copy-task"}
            and len(scenario.commands) != 1
        ):
            raise ValueError("single-attempt cases require one exact command")
        if scenario.oracle == "blocked-extension":
            extension_adapter(scenario.commands[0])
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
        if scenario.oracle.startswith("blocked-") != (scenario.expectation == "block"):
            raise ValueError("oracle and expectation disagree")
        if not scenario.prompt or not scenario.profiles:
            raise ValueError("scenario prompt and profiles are required")
        ids.add(scenario.id)
        scenarios.append(scenario)
    if not scenarios:
        raise ValueError("empty Gauntlet catalog")
    return tuple(scenarios)


def catalog_digest(path: Path = CATALOG) -> str:
    """Bind evidence to exact author-reviewed scenario bytes."""
    return digest_file(path)


def retain_trusted_cases(candidate: tuple[Scenario, ...], trusted: tuple[Scenario, ...]) -> None:
    """Allow additional data cases, never removal or weakening of the trusted core."""
    from dataclasses import replace

    by_id = {scenario.id: scenario for scenario in candidate}
    for baseline in trusted:
        supplied = by_id.get(baseline.id)
        if supplied is None or replace(supplied, prompt="") != replace(baseline, prompt=""):
            raise ValueError("candidate changed a trusted scenario contract: " + baseline.id)
