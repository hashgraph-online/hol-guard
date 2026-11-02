#!/usr/bin/env python3
"""Record OpenCode pretool plugin vectors from the ORIGINAL Python renderer.

Run against a checkout that still renders the plugin template in Python
(the base of the commit that introduced the native `opencode_plugin_render`
runner-authority kind), never from Rust output:

    cd <base-worktree>
    PYTHONPATH=$PWD/src python3 <this-file> <output plugin_render_vectors.json>

Each case stubs the Guard CLI attestation, the bounded native hook argv and
the Windows taskkill lookup, renders the plugin with the original
`pretool_plugin_source` and records both the arguments the native kind
receives and the exact source Python wrote.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

from codex_plugin_scanner.guard.adapters import guard_cli_attestation as attestation
from codex_plugin_scanner.guard.adapters import opencode_pretool as old
from codex_plugin_scanner.guard.adapters.bounded_cli_hook_native import NATIVE_BOUNDED_HOOK_COMMAND
from codex_plugin_scanner.guard.adapters.hook_python import HookPythonExecutableIdentity, HookPythonFileMetadata

if not hasattr(old, "_PLUGIN_TEMPLATE"):
    sys.exit("refusing to record: the original Python plugin renderer is gone")


def metadata(seed: int, mtime_ns: int | None = None) -> HookPythonFileMetadata:
    return HookPythonFileMetadata(
        device=16777220 + seed,
        inode=9000000 + seed,
        mode=0o100755,
        size=51000 + seed,
        mtime_ns=1767225600123456789 + seed if mtime_ns is None else mtime_ns,
    )


def identity(
    invocation: str,
    target: str,
    *,
    link: str | None = None,
    mtime_ns: int | None = None,
) -> HookPythonExecutableIdentity:
    return HookPythonExecutableIdentity(
        invocation_path=Path(invocation),
        invocation_type="symlink" if link is not None else "file",
        invocation_link_target=link,
        invocation_stat=metadata(1, mtime_ns),
        target_path=Path(target),
        target_stat=metadata(2, mtime_ns),
        target_sha256="ab" * 32,
    )


def bridge_argv(config: dict[str, object], runtime: str = "/opt/guard/bin/hol-guard-runtime") -> list[str]:
    return [
        runtime,
        NATIVE_BOUNDED_HOOK_COMMAND,
        "--harness",
        "opencode",
        "--bootstrap",
        "/opt/guard/libexec/bootstrap.py",
        json.dumps(config, ensure_ascii=True, separators=(",", ":")),
    ]


BRIDGE_CONFIG: dict[str, object] = {
    "python_executable": "/opt/guard/venv/bin/python3",
    "package_root": "/opt/guard/venv/lib/python3.12/site-packages",
    "guard_home": "/home/dev/.hol-guard",
    "cli_args": [],
    "harness": "opencode",
    "timeout_seconds": 25,
}


CASES: list[dict[str, object]] = [
    {
        "name": "attested_python_with_native_bridge",
        "guard_home": "/guard-vectors/dev/.hol-guard",
        "identity": identity("/opt/guard/venv/bin/python3", "/usr/local/bin/python3.12"),
        "frozen": False,
        "import_roots": ["/opt/guard/venv/lib/python3.12/site-packages"],
        "argv": bridge_argv(BRIDGE_CONFIG),
        "taskkill": None,
    },
    {
        "name": "python_launcher_when_the_argv_is_not_the_native_bridge",
        "guard_home": "/guard-vectors/dev/.hol-guard",
        "identity": identity("/opt/guard/venv/bin/python3", "/usr/local/bin/python3.12"),
        "frozen": False,
        "import_roots": ["/opt/guard/site", "/opt/guard/extra"],
        "argv": ["/opt/guard/venv/bin/python3", "-m", "codex_plugin_scanner.cli"],
        "taskkill": None,
    },
    {
        "name": "bridge_argv_with_a_different_subcommand",
        "guard_home": "/guard-vectors/dev/.hol-guard",
        "identity": identity("/opt/guard/venv/bin/python3", "/usr/local/bin/python3.12"),
        "frozen": False,
        "import_roots": [],
        "argv": ["/opt/guard/bin/hol-guard-runtime", "other", "a", "b", "c", "d", "{}"],
        "taskkill": None,
    },
    {
        "name": "frozen_cli_has_no_bridge_and_no_import_roots",
        "guard_home": "/guard-vectors/dev/.hol-guard",
        "identity": identity(
            "/Applications/HOL Guard.app/Contents/MacOS/hol-guard",
            "/Applications/HOL Guard.app/Contents/MacOS/hol-guard",
        ),
        "frozen": True,
        "import_roots": [],
        "argv": None,
        "taskkill": None,
    },
    {
        "name": "non_ascii_paths_roots_and_config",
        "guard_home": "/guard-vectors/d\u00e9v/\u4e2d\u6587/.hol-guard",
        "identity": identity(
            "/home/d\u00e9v/\U0001f600/bin/python3", "/usr/bin/python3\u00e9", link="../\u00e9/python3"
        ),
        "frozen": False,
        "import_roots": ["/home/d\u00e9v/site-\u4e2d", "/tmp/\U0001f680/roots"],
        "argv": bridge_argv(
            {**BRIDGE_CONFIG, "guard_home": "/home/d\u00e9v/\u4e2d\u6587/.hol-guard", "cli_args": ["\U0001f600", "x"]},
            runtime="/home/d\u00e9v/runtime",
        ),
        "taskkill": None,
    },
    {
        "name": "values_spelling_later_placeholders_are_replaced_in_order",
        "guard_home": "/guard-vectors/dev/__GUARD_FROZEN__/__INTERCEPT_TOOLS__",
        "identity": identity("/opt/__GUARD_HOOK_ENV__/python3", "/opt/__GUARD_HOME__/python3"),
        "frozen": False,
        "import_roots": ["/opt/__GUARD_TASKKILL_PATH__", "/opt/__GUARD_INHERIT_ENV_KEYS__"],
        "argv": bridge_argv(
            {**BRIDGE_CONFIG, "guard_home": "/x/__GUARD_HOOK_LAUNCHER__"}, runtime="/r/__GUARD_PYTHON__"
        ),
        "taskkill": "C:\\__INTERCEPT_TOOLS__\\taskkill.exe",
    },
    {
        "name": "windows_paths_quotes_and_control_characters",
        "guard_home": "/guard-vectors/dev/.hol-guard",
        "identity": identity("C:\\Program Files\\Python312\\python.exe", 'C:\\Py "quoted"\\python.exe'),
        "frozen": False,
        "import_roots": ["C:\\Users\\dev\\site\tpackages", "C:\\with\nnewline\r\x0c\x08\x01\x7f"],
        "argv": bridge_argv(
            {**BRIDGE_CONFIG, "guard_home": "C:\\Users\\dev\\.hol-guard", "nested": {"list": [1, 2.5, None, True]}},
            runtime="C:\\Program Files\\HOL Guard\\hol-guard-runtime.exe",
        ),
        "taskkill": "C:\\Windows\\System32\\taskkill.exe",
    },
    {
        "name": "extreme_stat_values",
        "guard_home": "/guard-vectors/dev/.hol-guard",
        "identity": identity("/opt/python3", "/opt/python3", mtime_ns=-1),
        "frozen": False,
        "import_roots": ["/opt/site"],
        "argv": None,
        "taskkill": None,
    },
    {
        "name": "large_stat_values",
        "guard_home": "/guard-vectors/dev/.hol-guard",
        "identity": identity("/opt/python3", "/opt/python3", mtime_ns=2**64 - 1),
        "frozen": False,
        "import_roots": ["/opt/site"],
        "argv": bridge_argv({**BRIDGE_CONFIG, "big": 2**70, "float": 1e300, "small": 5e-324}),
        "taskkill": None,
    },
]


def record(case: dict[str, object]) -> dict[str, object]:
    ident = case["identity"]
    assert isinstance(ident, HookPythonExecutableIdentity)
    frozen = bool(case["frozen"])
    import_roots = case["import_roots"]
    assert isinstance(import_roots, list)
    argv = case["argv"]
    python = (
        None
        if frozen
        else SimpleNamespace(
            executable=ident.invocation_path, identity=ident, import_roots=[Path(r) for r in import_roots]
        )
    )
    guard_cli = attestation.GuardCliAttestation(
        command=("hol-guard",), python=python, frozen_identity=ident if frozen else None
    )
    old.resolve_attested_guard_cli = lambda _context: guard_cli
    old.bounded_cli_hook_command = lambda **_kwargs: list(argv) if argv is not None else []
    taskkill = case["taskkill"]
    old.os = SimpleNamespace(name="nt" if taskkill is not None else "posix")
    old.windows_system_executable_path = lambda _name: taskkill
    guard_home = Path(str(case["guard_home"]))
    source = old.pretool_plugin_source(SimpleNamespace(guard_home=guard_home))
    return {
        "name": case["name"],
        "args": {
            "guard_home": str(guard_home.resolve()),
            "python": attestation._executable_identity_payload(ident),
            "frozen": frozen,
            "native_bridge_argv": None if frozen else (list(argv) if argv is not None else []),
            "import_roots": [str(Path(r)) for r in import_roots],
            "taskkill_path": taskkill,
        },
        "source": source,
    }


def main() -> None:
    cases = [record(case) for case in CASES]
    document = {"schema": "guard-opencode-plugin-render-vectors.v1", "cases": cases}
    Path(sys.argv[1]).write_text(json.dumps(document, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
