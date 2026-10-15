"""Freeze original Python helper outcomes without allowing native requests."""

from __future__ import annotations

import ast
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from types import ModuleType

BASE = "225df27eac6b8291eebd00f6722540cd33dbd872"
ROOT = Path(__file__).resolve().parents[2]
SERVICE = "src/codex_plugin_scanner/guard/runtime/secret_file_request_services/"


def main() -> None:
    sys.path.insert(0, str(ROOT / "src"))
    from codex_plugin_scanner.guard import native_resident_client

    def forbid_native(*args, **kwargs):
        raise AssertionError("Original parity recording cannot use a native request")

    native_resident_client.native_resident_client_request = forbid_native
    namespaces, hashes = {}, {}
    for filename in ("developer_inspection.py", "source_edit_context.py"):
        source = subprocess.check_output(["git", "show", f"{BASE}:{SERVICE}{filename}"], cwd=ROOT)
        hashes[SERVICE + filename] = hashlib.sha256(source).hexdigest()
        module = ModuleType("pinned_" + filename.removesuffix(".py"))
        module.__package__ = "codex_plugin_scanner.guard.runtime.secret_file_request_services"
        sys.modules[module.__name__] = module
        namespace = module.__dict__
        exec(compile(source, filename, "exec"), namespace)
        namespaces.update(
            {node.name: namespace[node.name] for node in ast.parse(source).body if isinstance(node, ast.FunctionDef)}
        )
    cases = []

    def record(name, *args, **kwargs):
        result = namespaces[name](*args, **kwargs)
        cases.append({"call": name, "args": args, "kwargs": kwargs, "result": result})

    for value in (
        "",
        "plain",
        "$HOME",
        "$?",
        "$(pwd)",
        "`pwd`",
        "é",
        "s/a/b/",
        "s#a#b#g",
        "s/a/b/e",
        "s/a/b/;d",
        "s/[a]/b/",
        "s/a/\\1/",
        "s/a/&/",
        "s/a/b/2",
        "s/a/b/\n",
    ):
        for name in (
            "_static_shell_arg_is_safe",
            "_literal_sed_script_is_safe",
            "_literal_sed_substitution_is_safe",
            "_split_literal_sed_commands",
        ):
            record(name, value)
        record("_sed_pattern_is_literal", value, delimiter="/")
        record("_sed_replacement_is_literal", value, delimiter="/")
    for args in (
        [],
        ["-u"],
        ["+%Y"],
        ["+%Y", "+%m"],
        ["--set", "now"],
        ["-f", "pattern"],
        ["--file=pattern"],
        ["--no-config", "needle"],
        ["-e", "needle"],
        ["--", "-f"],
        ["{}"],
        ["-n", "{}"],
        ["-exec", "ls", "{}", ";"],
        ["-delete"],
        ["-exec", "sh", "-c", "x", ";"],
    ):
        for name in (
            "_read_only_lookup_date_args_are_safe",
            "_ripgrep_config_is_disabled",
            "_find_exec_ls_args_are_read_only",
            "_find_args_use_write_or_unsafe_exec_action",
            "_static_shell_segment_is_safe",
        ):
            record(name, args)
        for command in ("grep", "rg"):
            record("_read_only_lookup_search_uses_file_input", command, args)
    for command in ("python", "python3", "python3.12", "pythonw.exe", "python3x", "node"):
        record("_is_read_only_observer_interpreter_command", command)
    for delimiter in ("", "/", "::", "雪"):
        for value in ("literal", r"a\:", r"a\/", r"a\雪", r"a\$", r"a\&"):
            record("_sed_pattern_is_literal", value, delimiter=delimiter)
            record("_sed_replacement_is_literal", value, delimiter=delimiter)
    fixtures = {}
    for path in sorted((ROOT / "rust/crates/guard-command/tests/fixtures/sfrs").glob("*.json.gz")):
        fixtures[str(path.relative_to(ROOT))] = hashlib.sha256(path.read_bytes()).hexdigest()
    output = ROOT / "rust/crates/guard-command/tests/fixtures/developer_inspection_authority.json"
    output.write_text(
        json.dumps(
            {
                "source_commit": BASE,
                "source_sha256": hashes,
                "retained_original_fixture_sha256": fixtures,
                "cases": cases,
            },
            ensure_ascii=True,
            sort_keys=True,
            indent=2,
        )
        + "\n"
    )
    print(f"Frozen {len(cases)} original native-free helper outcomes and {len(fixtures)} fixture hashes")


if __name__ == "__main__":
    main()
