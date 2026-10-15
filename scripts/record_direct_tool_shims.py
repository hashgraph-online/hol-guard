"""Record current Python-generated Bun shims for native trust regression tests."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from types import SimpleNamespace

from codex_plugin_scanner.guard import package_shim_frozen, shims


def record() -> dict[str, object]:
    root = "/__DIRECT_TOOL_FIXTURE__"
    home = f"{root}/home/caller"
    context = SimpleNamespace(guard_home=Path(home) / ".hol-guard", home_dir=Path(home))
    cases = []
    original_executable = sys.executable
    original_frozen = getattr(sys, "frozen", None)
    for name, frozen, executable in [
        ("ordinary", False, f"{root}/runtime/python"),
        ("space", False, f"{root}/runtime/python spaced"),
        ("frozen", True, f"{root}/runtime/versions/one/hol-guard"),
    ]:
        interpreter = f"{root}/runtime/current-hol-guard" if frozen else executable
        sys.executable = executable
        sys.frozen = frozen  # type: ignore[attr-defined]
        shims.package_shim_interpreter = lambda value=interpreter: value
        package_shim_frozen.package_shim_interpreter = lambda value=interpreter: value
        shims._trusted_import_root = lambda: Path(f"{root}/import-root")
        shims._trusted_python_flags = lambda: ["-I", "-P"]
        source = shims._build_package_manager_python_shim(context, "bun")
        wrapper = package_shim_frozen.expected_package_shim_executable_bytes(
            source, context.guard_home / "package-shims/bin", "bun"
        ).decode()
        cases.append(
            {
                "name": name,
                "launcher": {
                    "python_executable": executable,
                    "interpreter": interpreter,
                    "import_root": f"{root}/import-root",
                    "frozen": frozen,
                    "python_version": [3, 12],
                },
                "source": source,
                "wrapper": wrapper,
            }
        )
    sys.executable = original_executable
    if original_frozen is None:
        del sys.frozen  # type: ignore[attr-defined]
    else:
        sys.frozen = original_frozen  # type: ignore[attr-defined]
    sources = {
        p.name: hashlib.sha256(p.read_bytes()).hexdigest()
        for p in [Path(shims.__file__), Path(package_shim_frozen.__file__)]
    }
    result = {"schema": "direct-tool-python-shims.v1", "sources": sources, "cases": cases}
    return json.loads(json.dumps(result).replace(root, "{ROOT}"))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    args.output.write_text(json.dumps(record(), sort_keys=True, indent=2) + "\n")
    print("recorded three current Python shim layouts")


if __name__ == "__main__":
    main()
