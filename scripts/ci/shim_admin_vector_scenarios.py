"""Scenario builders for the package-shim admin parity vectors (install and status)."""

from __future__ import annotations

import copy
import json
from collections.abc import Callable

from shim_admin_vector_support import FIXED_NOW

Step = dict[str, object]
Scenario = dict[str, object]

SHIM_BIN = "{root}/guard/package-shims/bin"
MANAGERS = (
    "brew", "bun", "bunx", "bundle", "cargo", "composer", "go", "gradle", "mvn", "npm",
    "npx", "pip", "pip3", "pipenv", "pipx", "pnpm", "poetry", "uv", "uvx", "yarn",
)  # fmt: skip


def base_facts(**override: object) -> dict[str, object]:
    facts: dict[str, object] = {
        "environ": {"HOME": "{root}/home", "PATH": "{root}/real1:{root}/real2", "SHELL": "/bin/zsh"},
        "home": "{root}/home",
        "cwd": "{root}/work",
        "executable": "{root}/py/python3",
        "frozen": False,
        "frozen_cli": "{root}/frozen/hol-guard",
        "trusted_frozen_cli_paths": ["{root}/py/python3", "{root}/frozen/hol-guard"],
        "python_version": [3, 12],
        "import_root": "{root}/src",
        "argv0": "/usr/local/bin/hol-guard",
        "windows": False,
        "sqlite_connect_timeout_seconds": 30.0,
        "now": FIXED_NOW,
    }
    facts.update(override)
    return facts


def env(shell: str | None = "/bin/zsh", path: str | None = "{root}/real1:{root}/real2", **extra: str) -> dict[str, str]:
    values = {"HOME": "{root}/home"}
    if shell is not None:
        values["SHELL"] = shell
    if path is not None:
        values["PATH"] = path
    values.update(extra)
    return values


def write(path: str, text: str, executable: bool = False) -> Step:
    return {"op": "write", "path": path, "text": text, "exec": executable}


def mkdir(path: str) -> Step:
    return {"op": "mkdir", "path": path}


def symlink(path: str, target: str) -> Step:
    return {"op": "symlink", "path": path, "target": target}


def remove(path: str) -> Step:
    return {"op": "remove", "path": path}


def call(subop: str, **args: object) -> Step:
    return {"op": "call", "subop": subop, "args": args}


def real_binary(directory: str, command: str) -> Step:
    return write(f"{directory}/{command}", "#!/bin/sh\nexit 0\n", executable=True)


def setup_steps() -> list[Step]:
    return [
        mkdir("work"),
        mkdir("home"),
        mkdir("src"),
        write("py/python3", "#!/bin/sh\nexit 0\n", executable=True),
        write("frozen/hol-guard", "#!/bin/sh\nexit 0\n", executable=True),
    ]


def scenario(
    name: str,
    steps: list[Step],
    *,
    facts: dict[str, object] | None = None,
    guard_home: str = "{root}/guard",
    home_dir: str | None = "{root}/home",
    workspace_dir: str | None = None,
    durable: bool = False,
) -> Scenario:
    return {
        "name": name,
        "durable_root": durable,
        "facts": facts if facts is not None else base_facts(),
        "context": {"guard_home": guard_home, "home_dir": home_dir, "workspace_dir": workspace_dir},
        "steps": [*setup_steps(), *copy.deepcopy(steps)],
    }


def manifest_text(payload: object) -> str:
    return payload if isinstance(payload, str) else json.dumps(payload, sort_keys=True)


def manifest_step(payload: object, guard_home: str = "guard") -> Step:
    return write(f"{guard_home}/package-shims/manifest.json", manifest_text(payload))


def supported_and_install_scenarios() -> list[Scenario]:
    scenarios = [scenario("supported-managers", [call("supported_managers")])]
    scenarios += [
        scenario("install-all", [call("install"), call("status")]),
        scenario("install-empty-list", [call("install", managers=[])]),
        scenario("install-mixed-case-dupes-unknown", [call("install", managers=["NPM", " pip ", "npm", "bogus", "Yarn"])]),
        scenario("install-unknown-only", [call("install", managers=["bogus"]), call("status")]),
    ]
    scenarios += [scenario(f"install-{name}", [call("install", managers=[name])]) for name in MANAGERS]
    scenarios += [
        scenario("install-incremental", [call("install", managers=["npm"]), call("install", managers=["pip", "npm"]), call("status")]),
        scenario(
            "install-extends-existing-manifest",
            [
                manifest_step(
                    {
                        "content_hashes": {"cargo": "a" * 64, "npm": 7, "bogus": "b" * 64},
                        "installed_managers": ["cargo", "bogus"],
                        "last_test_at": {"cargo": "2025-01-01T00:00:00+00:00", "x": 3},
                        "shim_dir": "elsewhere",
                    }
                ),
                call("install", managers=["npm"]),
                call("status"),
            ],
        ),
    ]
    for label, text in (
        ("not-json", "{nope"),
        ("json-list", "[1, 2]"),
        ("empty-managers", {"installed_managers": []}),
        ("non-list-managers", {"installed_managers": "npm"}),
        ("non-string-manager", {"installed_managers": ["npm", 4]}),
        ("unknown-manager", {"installed_managers": ["npm", "bogus"]}),
        ("empty-file", ""),
    ):
        scenarios.append(scenario(f"install-over-invalid-manifest-{label}", [manifest_step(text), call("install", managers=["npm"]), call("status")]))
    scenarios.append(scenario("install-repeat-idempotent", [call("install", managers=["npm"]), call("install", managers=["npm"])]))
    scenarios.append(scenario("install-with-path-env", [real_binary("real1", "npm"), call("install", managers=["npm", "pip"], path_env=f"{SHIM_BIN}:{{root}}/real1")]))
    return scenarios


def interpreter_scenarios() -> list[Scenario]:
    scenarios: list[Scenario] = []
    base_steps: list[Step] = [call("install", managers=["npm", "pip"]), call("status")]
    scenarios.append(scenario("interp-space-in-executable", base_steps, facts=base_facts(executable="{root}/py bin/python 3")))
    scenarios.append(
        scenario(
            "interp-space-executable-runnable",
            [write("py bin/python 3", "#!/bin/sh\n", executable=True), *base_steps, call("repair")],
            facts=base_facts(executable="{root}/py bin/python 3"),
        )
    )
    scenarios.append(scenario("interp-appimage-executable", base_steps, facts=base_facts(executable="/tmp/.mount_HOLabc123/usr/bin/python3")))
    exact_lists = (
        ("default", None),
        ("only-frozen-cli-trusted", ["{root}/frozen/hol-guard"]),
        ("nothing-trusted", []),
        ("alias-trusted", ["{root}/py/python3", "{root}/frozen/../frozen/hol-guard"]),
    )
    for label, trusted in exact_lists:
        scenarios.append(
            scenario(
                f"interp-frozen-{label}",
                [*base_steps, call("repair"), call("uninstall", managers=["pip"])],
                facts=base_facts(frozen=True, **({} if trusted is None else {"trusted_frozen_cli_paths": trusted})),
            )
        )
    scenarios.append(scenario("interp-frozen-cli-missing", base_steps, facts=base_facts(frozen=True, frozen_cli="{root}/frozen/missing", trusted_frozen_cli_paths=["{root}/py/python3", "{root}/frozen/missing"])))
    scenarios.append(scenario("interp-frozen-symlink-cli", [symlink("frozen/link", "{root}/frozen/hol-guard"), *base_steps], facts=base_facts(frozen=True, frozen_cli="{root}/frozen/link", trusted_frozen_cli_paths=["{root}/py/python3", "{root}/frozen/hol-guard"])))
    scenarios.append(scenario("interp-windows", [*base_steps, call("uninstall")], facts=base_facts(windows=True, environ=env(path="{root}/real1"))))
    for version in ([3, 9], [3, 10], [3, 11], [3, 12], [3, 13], [4, 0]):
        scenarios.append(scenario(f"interp-python-{version[0]}-{version[1]}", [call("install", managers=["npm"])], facts=base_facts(python_version=version)))
    for index, argv0 in enumerate((None, "", "   ", "/usr/bin/hol-guard", "hol-guard.exe", "/opt/x y/guard cli", "python -m", "ä/güard")):
        scenarios.append(scenario(f"install-argv0-{index}", [call("install", managers=["npm"])], facts=base_facts(argv0=argv0)))
    for index, seconds in enumerate((30.0, 5.0, 0.1, 1e-05, 1e22, 120.5, 0.0, 3.0, 1e16, 123456789.125, 0.30000000000000004)):
        scenarios.append(scenario(f"install-sqlite-timeout-{index}", [call("install", managers=["npm"])], facts=base_facts(sqlite_connect_timeout_seconds=seconds)))
    return scenarios


def path_variant_scenarios() -> list[Scenario]:
    shim = SHIM_BIN
    layouts: list[tuple[str, str | None, list[Step]]] = [
        ("shim-first", f"{shim}:{{root}}/real1:{{root}}/real2", [real_binary("real1", "npm"), real_binary("real2", "pip")]),
        ("real-first", f"{{root}}/real1:{shim}", [real_binary("real1", "npm"), real_binary("real1", "pip")]),
        ("only-real", "{root}/real1", [real_binary("real1", "npm")]),
        ("only-shim", shim, []),
        ("empty", "", []),
        ("unset", None, [real_binary("work", "npm")]),
        ("shim-twice", f"{shim}:{{root}}/real1:{shim}", [real_binary("real1", "npm")]),
        ("empty-entries", f":{shim}::{{root}}/real1:", [real_binary("work", "npm"), real_binary("real1", "pip")]),
        ("tilde", f"~/bin:{shim}", [real_binary("home/bin", "npm")]),
        ("trailing-slash-and-dotdot", f"{shim}/:{{root}}/real1/../real1:{{root}}/real2/", [real_binary("real1", "npm")]),
        ("relative-entry", f"rel:{shim}", [real_binary("work/rel", "npm")]),
        ("foreign-first", f"{{root}}/foreign/package-shims/bin:{shim}:{{root}}/real1", [write("foreign/package-shims/bin/npm", "#!/bin/sh\n", True), real_binary("real1", "npm")]),
        ("foreign-after", f"{shim}:{{root}}/foreign/package-shims/bin:{{root}}/real1", [write("foreign/package-shims/bin/npm", "#!/bin/sh\n", True), real_binary("real1", "npm")]),
        ("foreign-no-shim-dir", "{root}/foreign/package-shims/bin:{root}/real1", [write("foreign/package-shims/bin/npm", "#!/bin/sh\n", True), real_binary("real1", "npm")]),
        ("not-bin-layout", f"{{root}}/foreign/package-shims/sbin:{shim}", [write("foreign/package-shims/sbin/npm", "x", True)]),
        ("npm-is-directory", f"{{root}}/real1:{shim}", [mkdir("real1/npm"), real_binary("real2", "pip")]),
        ("non-executable-real", f"{shim}:{{root}}/real1", [write("real1/npm", "data")]),
        ("symlinked-real", f"{{root}}/real1:{shim}", [real_binary("real2", "npm"), symlink("real1/npm", "{root}/real2/npm")]),
        ("symlink-into-shim-dir", f"{{root}}/linkdir:{shim}", [symlink("linkdir", "{root}/guard/package-shims/bin")]),
        ("symlinked-shim-dir-in-path", "{root}/shimlink:{root}/real1", [symlink("shimlink", "{root}/guard/package-shims/bin"), real_binary("real1", "npm")]),
        ("broken-symlink-real", f"{{root}}/real1:{shim}", [symlink("real1/npm", "{root}/nowhere")]),
        ("unicode-and-space-dirs", f"{{root}}/réal dir:{shim}", [real_binary("réal dir", "npm")]),
        ("many-real", f"{shim}:{{root}}/real1:{{root}}/real2", [real_binary("real1", name) for name in MANAGERS] + [real_binary("real2", "npm")]),
    ]
    scenarios: list[Scenario] = []
    for label, path, extra in layouts:
        environ = env(path=path)
        scenarios.append(
            scenario(
                f"path-{label}",
                [
                    *extra,
                    call("install", managers=["npm", "pip"]),
                    call("path_order", manager="npm"),
                    call("path_order", manager="pip"),
                    call("path_order", manager="bogus"),
                    call("status"),
                    call("dashboard_status"),
                    call("cloud_coverage", generated_at="2026-01-01T00:00:00+00:00"),
                ],
                facts=base_facts(environ=environ),
            )
        )
        scenarios.append(
            scenario(
                f"path-override-{label}",
                [
                    *extra,
                    call("install", managers=["npm"]),
                    call("status", path_env=path if path is not None else ""),
                    call("status", path_env=""),
                ],
                facts=base_facts(environ=env(path="{root}/nothing")),
            )
        )
    return scenarios


def all_install_status_scenarios() -> list[Scenario]:
    builders: list[Callable[[], list[Scenario]]] = [supported_and_install_scenarios, interpreter_scenarios, path_variant_scenarios]
    return [item for builder in builders for item in builder()]
