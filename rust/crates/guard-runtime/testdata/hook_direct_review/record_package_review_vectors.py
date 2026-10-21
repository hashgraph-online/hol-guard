"""Record which package reviews `native_package_review_response` leaves to the queue.

The resident queues a package review only when the daemon's settle step
returns ``None`` before it probes the filesystem or runs the evaluator. Each
vector holds the payload and edge result the daemon passes it, whether it
returned ``None``, and whether it reached a filesystem probe or the
evaluator. ``PATH`` names a directory that does not exist, so a probe finds
no npm and nothing is fetched. The ``nt`` vectors run the same inputs as on
Windows, where the daemon never settles a package review.

Run from the repository root:

    .venv/bin/python rust/crates/guard-runtime/testdata/hook_direct_review/record_package_review_vectors.py
"""

from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Callable
from pathlib import Path
from unittest import mock

from codex_plugin_scanner.guard.daemon import hook_native_package_review as package_review

OUT = Path(__file__).with_name("package_review_vectors.json")
ENVIRONMENT_KEY = "guard_execution_environment"
MISSING_PATH = "/nonexistent-hol-guard-vector-bin"
INSTALL = "npm install left-pad"
REVIEW = {"reason_code": "native_package_review", "minimum_action": "review", "reason": "Review this install."}


def _environment(**fields: object) -> dict[str, object]:
    environment: dict[str, object] = {
        "path": MISSING_PATH,
        "home": "/home/agent",
        "environment_names": ["HOME", "PATH"],
    }
    environment.update(fields)
    return {key: value for key, value in environment.items() if value is not ...}


def _bash(command: object, environment: object = None) -> dict[str, object]:
    return {"tool_name": "Bash", "tool_input": {"command": command}, ENVIRONMENT_KEY: environment}


COMMANDS = [
    INSTALL,
    "pip install requests",
    "pnpm add react",
    "yarn add react",
    "npx create-react-app app",
    "NPM install left-pad",
    "/usr/local/bin/npm install left-pad",
    "npm",
    "npm|tail",
    "npm2>&1",
    "  npm install left-pad  \n",
    "npm  install   left-pad",
    "npm\tinstall left-pad",
    "npm install left-pad 2>&1",
    "npm install left-pad 2>&1 | tail -3",
    "npm install left-pad|tail -n3",
    "npm install left-pad | grep -v warn | head -n 5",
    "npm install left-pad | grep -iEc added",
    "npm install left-pad | grep -f patterns",
    "npm install left-pad | grep -iv =foo",
    "npm install left-pad | tail -3 2>&1",
    "npm install left-pad | cat",
    "npm install left-pad && rm -rf node_modules",
    "npm install left-pad; echo done",
    "npm install $(whoami)",
    "npm install ~/pkg",
    "npm install =pkg",
    "npm install left-pad@^1.3.0 @scope/pkg@~2.0.0",
    "npm install café",
    "npm install left-pad > log",
    "",
    "   ",
]

PAYLOADS: list[tuple[str, dict[str, object]]] = [
    *((f"command {command!r}", _bash(command, _environment())) for command in COMMANDS),
    ("tool input cmd", {"toolInput": {"cmd": INSTALL}, ENVIRONMENT_KEY: _environment()}),
    ("arguments shell command", {"arguments": {"shell_command": INSTALL}, ENVIRONMENT_KEY: _environment()}),
    ("top-level command", {"shellCommand": "pip install x", ENVIRONMENT_KEY: _environment()}),
    ("blank command then cmd", {"tool_input": {"command": "  ", "cmd": INSTALL}, ENVIRONMENT_KEY: _environment()}),
    ("list command then cmd", {"tool_input": {"command": ["npm"], "cmd": "pip install x"}, ENVIRONMENT_KEY: None}),
    ("tool input text", {"tool_input": INSTALL, "command": "cargo add serde", ENVIRONMENT_KEY: _environment()}),
    ("tool input wins", {"tool_input": {"command": "pip install x"}, "command": INSTALL, ENVIRONMENT_KEY: None}),
    ("no command", {"tool_name": "Bash", "tool_input": {}, ENVIRONMENT_KEY: _environment()}),
    ("environment none", _bash(INSTALL, None)),
    ("environment text", _bash(INSTALL, "PATH=/bin")),
    ("environment list", _bash(INSTALL, [])),
    ("names missing", _bash(INSTALL, _environment(environment_names=...))),
    ("names text", _bash(INSTALL, _environment(environment_names="PATH"))),
    ("names number", _bash(INSTALL, _environment(environment_names=["PATH", 3]))),
    ("names registry", _bash(INSTALL, _environment(environment_names=["NPM_CONFIG_REGISTRY"]))),
    ("names bare prefix", _bash(INSTALL, _environment(environment_names=["npm_config_"]))),
    (
        "names inert",
        _bash(
            INSTALL,
            _environment(
                environment_names=[
                    "npm_config_cache",
                    "NPM_CONFIG_UPDATE_NOTIFIER",
                    "npm_config_fund",
                    "npm_config_audit",
                    "npm_config_loglevel",
                    "npm_config_progress",
                    "npm_config_color",
                ]
            ),
        ),
    ),
    ("names update-notifier dash", _bash(INSTALL, _environment(environment_names=["npm_config_update-notifier"]))),
    ("names node options", _bash(INSTALL, _environment(environment_names=["NODE_OPTIONS"]))),
    ("names node path suffix", _bash(INSTALL, _environment(environment_names=["NODE_PATH_EXTRA"]))),
    ("names prefix", _bash(INSTALL, _environment(environment_names=["PREFIX"]))),
    ("names destdir", _bash(INSTALL, _environment(environment_names=["DestDir"]))),
    ("names tls", _bash(INSTALL, _environment(environment_names=["NODE_TLS_REJECT_UNAUTHORIZED"]))),
    ("names extra ca", _bash(INSTALL, _environment(environment_names=["NODE_EXTRA_CA_CERTS"]))),
    ("names loader", _bash(INSTALL, _environment(environment_names=["LD_LIBRARY_PATH"]))),
    ("names non-ascii", _bash(INSTALL, _environment(environment_names=["ÑPM"]))),
    ("names non-ascii then registry", _bash(INSTALL, _environment(environment_names=["Ñ", "npm_config_ca"]))),
    ("names non-ascii, path empty", _bash(INSTALL, _environment(environment_names=["Ñ"], path=""))),
    ("path empty", _bash(INSTALL, _environment(path=""))),
    ("path missing", _bash(INSTALL, _environment(path=...))),
    ("path number", _bash(INSTALL, _environment(path=7))),
    ("home missing", _bash(INSTALL, _environment(home=...))),
    ("home relative", _bash(INSTALL, _environment(home="agent"))),
]

RESULTS: list[tuple[str, dict[str, object]]] = [
    ("package review", REVIEW),
    ("package reapproval", {**REVIEW, "minimum_action": "require-reapproval"}),
    ("package block", {**REVIEW, "minimum_action": "block"}),
    ("other review", {**REVIEW, "reason_code": "native_review"}),
    ("no reason code", {"minimum_action": "review"}),
]


def _spy(probes: list[str], name: str, original: Callable[..., object]) -> Callable[..., object]:
    def spy(*args: object, **kwargs: object) -> object:
        probes.append(name)
        if name == "_evaluate":
            # Never fetch from a registry while recording.
            return None
        return original(*args, **kwargs)

    return spy


def _record(platform: str, payload: dict[str, object], result: dict[str, object], workspace: Path) -> dict[str, object]:
    probes: list[str] = []
    spies = {
        name: _spy(probes, name, getattr(package_review, name))
        for name in ("_loader_paths_outside", "_resolve_executable", "_filters_outside_workspace", "_evaluate")
    }
    with mock.patch.multiple(package_review, **spies):
        if platform == "nt":
            with mock.patch.object(os, "name", "nt"):
                settled = _settle(payload, result, workspace)
        else:
            settled = _settle(payload, result, workspace)
    return {"python_none": settled is None, "probed": bool(probes)}


def _settle(payload: dict[str, object], result: dict[str, object], workspace: Path) -> object:
    return package_review.native_package_review_response(
        None,
        harness="claude-code",
        payload=payload,
        native_result=result,
        workspace=workspace,
        guard_home=workspace / ".hol-guard",
        home_dir=workspace,
    )


def main() -> None:
    if os.name == "nt":
        raise SystemExit("Record these vectors on a POSIX host.")
    vectors = []
    with tempfile.TemporaryDirectory() as directory:
        workspace = Path(directory).resolve()
        for platform in ("posix", "nt"):
            # Windows returns before reading the result, so two results show it.
            for result_name, result in RESULTS if platform == "posix" else RESULTS[:2]:
                for payload_name, payload in PAYLOADS:
                    vectors.append(
                        {
                            "name": f"{platform}: {result_name}: {payload_name}",
                            "windows": platform == "nt",
                            "payload": payload,
                            "result": result,
                            **_record(platform, payload, result, workspace),
                        }
                    )
    # One vector per line keeps the file small and its diffs readable.
    lines = ",\n".join(json.dumps(vector, sort_keys=True, ensure_ascii=False) for vector in vectors)
    OUT.write_text('{"vectors": [\n' + lines + "\n]}\n", encoding="utf-8")


if __name__ == "__main__":
    main()
