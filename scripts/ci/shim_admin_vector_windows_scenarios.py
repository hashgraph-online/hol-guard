"""Windows scenarios for the package-shim admin parity vectors.

The POSIX builders describe their paths with ``/`` and ``:``. This module reuses
those scenarios for the Windows flavour by rewriting only the path-bearing fields
(facts, context and call arguments) into ``ntpath`` spellings, drops what a
Windows host cannot or does not exercise (symlinks need a privilege, shell
profiles are POSIX-only, and the probe runs POSIX shell shims), and adds scenarios
that only make sense with Windows paths: drive-case and slash-style variations,
``PATHEXT`` resolution and the ``.cmd`` launchers.

They must be recorded on a real Windows host (``os.name == "nt"``): pathlib's
``WindowsPath`` cannot be instantiated elsewhere, and a patched ``os.name`` on a
POSIX host would record POSIX path semantics under a Windows label.
"""

from __future__ import annotations

import copy

from shim_admin_vector_profile_scenarios import all_profile_scenarios
from shim_admin_vector_scenarios import (
    Scenario,
    Step,
    all_install_status_scenarios,
    base_facts,
    call,
    mkdir,
    real_binary,
    scenario,
    write,
)
from shim_admin_vector_state_scenarios import all_state_scenarios

PATHEXT = ".COM;.EXE;.BAT;.CMD"
# Scenarios that depend on POSIX-only behaviour (quoting in file names, shell
# profiles, the shell-script probe) or on symlinks.
SKIPPED_NAME_FRAGMENTS = (
    "probe-",
    "transient-env",
    "profile-",
    "guard-home-quote",
    "home-dir-quote",
    "dashboard-projection-",
)
PROFILE_KEEP = ("profile-transient-guard-home",)


def nt(text: str) -> str:
    return text.replace("/", "\\")


def nt_path_list(text: str) -> str:
    return ";".join(nt(entry) for entry in text.split(":")) if ":" in text or text == "" else nt(text)


def nt_environ(environ: dict[str, str]) -> dict[str, str]:
    converted: dict[str, str] = {"PATHEXT": PATHEXT}
    for key, value in environ.items():
        if key == "HOME":
            converted["USERPROFILE"] = nt(value)
        elif key == "PATH":
            converted["PATH"] = nt_path_list(value)
        elif key == "SHELL":
            continue
        else:
            converted[key] = nt(value)
    return converted


def nt_facts(facts: dict[str, object]) -> dict[str, object]:
    converted = copy.deepcopy(facts)
    converted["windows"] = True
    converted["environ"] = nt_environ(facts["environ"])  # type: ignore[arg-type]
    for key in ("home", "cwd", "executable", "frozen_cli", "import_root"):
        converted[key] = nt(str(facts[key]))
    converted["trusted_frozen_cli_paths"] = [nt(str(item)) for item in facts["trusted_frozen_cli_paths"]]  # type: ignore[attr-defined]
    return converted


def nt_step(step: Step) -> Step:
    if step["op"] != "call":
        return step
    args = dict(step["args"])  # type: ignore[arg-type]
    if isinstance(args.get("path_env"), str):
        args["path_env"] = nt_path_list(args["path_env"])
    if isinstance(args.get("workspace_dir"), str):
        args["workspace_dir"] = nt(args["workspace_dir"])
    return {"op": "call", "subop": step["subop"], "args": args}


def portable(item: Scenario) -> bool:
    name = str(item["name"])
    if name in PROFILE_KEEP:
        return True
    if any(fragment in name for fragment in SKIPPED_NAME_FRAGMENTS):
        return False
    return not any(step["op"] == "symlink" for step in item["steps"])  # type: ignore[attr-defined]


def to_windows(item: Scenario) -> Scenario:
    context = dict(item["context"])  # type: ignore[arg-type]
    for key in ("guard_home", "home_dir", "workspace_dir"):
        if isinstance(context.get(key), str):
            context[key] = nt(str(context[key]))
    return {
        "name": f"win-{item['name']}",
        "durable_root": False,
        "facts": nt_facts(item["facts"]),  # type: ignore[arg-type]
        "context": context,
        "steps": [nt_step(step) for step in item["steps"]],  # type: ignore[attr-defined]
    }


def win_facts(**override: object) -> dict[str, object]:
    return nt_facts(base_facts(**override))


def cmd_binary(directory: str, command: str) -> list[Step]:
    """A real manager the way Windows installs one: an extensionless script and a ``.cmd``."""

    return [real_binary(directory, command), write(f"{directory}/{command}.cmd", "@echo off\r\n")]


def native_scenarios() -> list[Scenario]:
    shim = "{root}\\guard\\package-shims\\bin"
    install = call("install", managers=["npm", "pip"])
    layouts: list[tuple[str, str | None, list[Step]]] = [
        ("cmd-only", "{root}\\real1", [write("real1/npm.cmd", "@echo off\r\n")]),
        ("cmd-and-bare", "{root}\\real1;{root}\\real2", [*cmd_binary("real1", "npm"), *cmd_binary("real2", "pip")]),
        ("forward-slashes", "{root}/real1;" + shim.replace("\\", "/"), cmd_binary("real1", "npm")),
        ("mixed-case-shim-dir", "{root}\\GUARD\\Package-Shims\\BIN;{root}\\real1", cmd_binary("real1", "npm")),
        ("mixed-case-real", "{root}\\REAL1;" + shim, cmd_binary("real1", "npm")),
        ("trailing-backslash", shim + "\\;{root}\\real1\\", cmd_binary("real1", "npm")),
        ("dotdot-and-dot", "{root}\\real1\\..\\real1\\.;" + shim, cmd_binary("real1", "npm")),
        ("quoted-entry", '"{root}\\real1";' + shim, cmd_binary("real1", "npm")),
        ("relative-entry", "rel;" + shim, cmd_binary("work/rel", "npm")),
        ("current-dir-entry", ".;" + shim, [write("work/npm.cmd", "@echo off\r\n")]),
        ("home-relative", "~\\bin;" + shim, cmd_binary("home/bin", "npm")),
        ("empty-entries", ";" + shim + ";;{root}\\real1;", cmd_binary("real1", "npm")),
        (
            "exe-and-bat",
            "{root}\\real1;" + shim,
            [write("real1/npm.exe", "MZ"), write("real1/pip.bat", "@echo off\r\n")],
        ),
        (
            "foreign-first",
            "{root}\\foreign\\package-shims\\bin;" + shim + ";{root}\\real1",
            [write("foreign/package-shims/bin/npm", "x"), *cmd_binary("real1", "npm")],
        ),
        (
            "foreign-after",
            shim + ";{root}\\foreign\\package-shims\\bin;{root}\\real1",
            [write("foreign/package-shims/bin/npm", "x"), *cmd_binary("real1", "npm")],
        ),
        ("unicode-and-space", "{root}\\réal dir;" + shim, cmd_binary("réal dir", "npm")),
        ("npm-is-directory", "{root}\\real1;" + shim, [mkdir("real1/npm"), mkdir("real1/npm.cmd")]),
    ]
    scenarios: list[Scenario] = []
    for label, path, extra in layouts:
        facts = win_facts()
        facts["environ"] = {**facts["environ"], "PATH": path}  # type: ignore[dict-item]
        steps: list[Step] = [
            *extra,
            install,
            call("path_order", manager="npm"),
            call("path_order", manager="pip"),
            call("status"),
            call("dashboard_status"),
            call("cloud_coverage", generated_at="2026-01-01T00:00:00+00:00"),
            call("uninstall", managers=["pip"]),
            call("status"),
        ]
        scenarios.append(scenario(f"win-native-path-{label}", steps, facts=facts))
    for label, pathext in (
        ("unset", None),
        ("empty", ""),
        ("lower", ".exe;.cmd"),
        ("dotted", ".CMD.;.EXE"),
        ("exe-only", ".EXE"),
    ):
        facts = win_facts()
        environ = {key: value for key, value in facts["environ"].items() if key != "PATHEXT"}  # type: ignore[attr-defined]
        if pathext is not None:
            environ["PATHEXT"] = pathext
        facts["environ"] = environ
        scenarios.append(
            scenario(
                f"win-native-pathext-{label}",
                [
                    *cmd_binary("real1", "npm"),
                    write("real1/pip.exe", "MZ"),
                    call("status"),
                    call("install", managers=["npm"]),
                    call("status"),
                ],
                facts=facts,
            )
        )
    facts = win_facts()
    facts["environ"] = {**facts["environ"], "NoDefaultCurrentDirectoryInExePath": "1"}  # type: ignore[dict-item]
    scenarios.append(
        scenario("win-native-no-current-dir", [write("work/npm.cmd", "@echo off\r\n"), call("status")], facts=facts)
    )
    facts = win_facts()
    scenarios.append(
        scenario(
            "win-native-current-dir-binary",
            [
                write("work/npm.cmd", "@echo off\r\n"),
                write("work/pip.cmd", "@echo off\r\n"),
                call("status"),
                call("install", managers=["npm"]),
                call("status"),
            ],
            facts=facts,
        )
    )
    for index, executable in enumerate(
        (
            "{root}\\py bin\\python.exe",
            "C:\\tmp\\.mount_HOLabc123\\usr\\bin\\python.exe",
            "{root}\\Py\\PYTHON.EXE",
            "{root}/py/python.exe",
        )
    ):
        scenarios.append(
            scenario(
                f"win-native-interpreter-{index}",
                [
                    write("py bin/python.exe", "MZ"),
                    call("install", managers=["npm", "pip"]),
                    call("status"),
                    call("repair"),
                ],
                facts=win_facts(executable=executable),
            )
        )
    for index, argv0 in enumerate(
        (
            "C:\\Program Files\\hol-guard\\hol-guard.exe",
            "hol-guard.exe",
            "D:/tools/hol-guard",
            "\\\\server\\share\\hol-guard.exe",
            "C:",
        )
    ):
        scenarios.append(
            scenario(f"win-native-argv0-{index}", [call("install", managers=["npm"])], facts=win_facts(argv0=argv0))
        )
    for label, guard_home in (
        ("drive-relative-case", "{root}\\Guard"),
        ("forward-slash", "{root}/guard"),
        ("dotdot", "{root}\\a\\..\\guard"),
        ("space-unicode", "{root}\\gärd 中"),
        ("trailing", "{root}\\guard\\"),
    ):
        scenarios.append(
            scenario(
                f"win-native-guard-home-{label}",
                [
                    call("install", managers=["npm", "pip"]),
                    call("status"),
                    call("repair"),
                    call("uninstall", managers=["npm"]),
                ],
                guard_home=guard_home,
                facts=win_facts(),
            )
        )
    scenarios.append(
        scenario(
            "win-native-profile-noop",
            [
                call("ensure_package_shim_profile"),
                call("remove_guard_profile_blocks"),
                call("activate", managers=["npm"]),
                call("status"),
            ],
            facts=win_facts(),
        )
    )
    other = win_facts()
    other["environ"] = {**other["environ"], "USERNAME": "tester"}  # type: ignore[dict-item]
    scenarios.append(
        scenario(
            "win-native-expanduser-other-user",
            [
                mkdir("bin"),
                call("status", path_env="~tester\\bin;~other\\bin"),
                call("status", path_env="~\\bin"),
                call("install", managers=["npm"]),
            ],
            facts=other,
        )
    )
    return scenarios


def all_windows_scenarios() -> list[Scenario]:
    posix = [*all_install_status_scenarios(), *all_state_scenarios(), *all_profile_scenarios()]
    derived = [to_windows(item) for item in posix if portable(item)]
    names = {str(item["name"]) for item in derived}
    native = [item for item in native_scenarios() if item["name"] not in names]
    return [*derived, *native]
