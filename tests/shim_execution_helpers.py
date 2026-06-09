"""Shared helpers for package-shim intercept and execution proofs."""

from __future__ import annotations

import json
from pathlib import Path

from codex_plugin_scanner.guard.shim_probe import (
    package_shim_probe_args,
    parse_protect_json_stdout,
    protect_evaluator_evidence,
)

__all__ = [
    "manager_probe_args",
    "parse_protect_json_output",
    "protect_evaluator_evidence",
    "write_fake_manager_script",
]


def write_fake_manager_script(
    *,
    fake_bin: Path,
    manager: str,
    marker_path: Path,
    exit_code: int,
    stdout_text: str | None = None,
    stderr_text: str | None = None,
) -> Path:
    """Write a fake package manager that records argv/cwd when invoked."""

    script_path = fake_bin / manager
    script_path.write_text(
        "\n".join(
            [
                "#!/usr/bin/env python3",
                "from __future__ import annotations",
                "import json",
                "import os",
                "import sys",
                f"marker_path = {str(marker_path)!r}",
                "payload = {",
                "    'argv': sys.argv,",
                "    'cwd': os.getcwd(),",
                "    'path': os.environ.get('PATH', ''),",
                "    'shim_var': os.environ.get('SHIM_TEST_VAR'),",
                "}",
                "with open(marker_path, 'w', encoding='utf-8') as handle:",
                "    json.dump(payload, handle)",
                f"if {stdout_text!r} is not None:",
                f"    print({stdout_text!r})",
                f"if {stderr_text!r} is not None:",
                f"    print({stderr_text!r}, file=sys.stderr)",
                f"raise SystemExit({exit_code})",
                "",
            ]
        ),
        encoding="utf-8",
    )
    script_path.chmod(script_path.stat().st_mode | 0o755)
    return script_path


def parse_protect_json_output(stdout: str):
    """Backward-compatible alias for protect stdout parsing."""

    return parse_protect_json_stdout(stdout)


def manager_probe_args(manager: str) -> tuple[str, ...]:
    """Backward-compatible alias for install-shaped probe args."""

    return package_shim_probe_args(manager)
