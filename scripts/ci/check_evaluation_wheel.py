"""Exercise evaluator and interpreter regressions against an installed wheel.

The fixtures are synthetic. Passing this check does not establish installed
agent enforcement or authenticate caller-supplied evaluation evidence.
"""

from __future__ import annotations

import argparse
import importlib.metadata
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-version", required=True)
    args = parser.parse_args()
    if not sys.flags.isolated:
        parser.error("run with the Python -I flag")
    if sys.prefix == sys.base_prefix:
        parser.error("run inside the wheel virtual environment")

    from codex_plugin_scanner.guard import evaluation_cli, evaluation_preflight

    prefix = Path(sys.prefix).resolve()
    for module in (evaluation_cli, evaluation_preflight):
        if module.__file__ is None or not Path(module.__file__).resolve().is_relative_to(prefix):
            raise RuntimeError("evaluator import did not originate in the wheel virtual environment")
    if importlib.metadata.version("hol-guard") != args.expected_version:
        raise RuntimeError("installed distribution version differs from the expected wheel version")

    console = Path(sys.executable).parent / "hol-guard-eval"
    try:
        version = subprocess.run([str(console), "--version"], check=True, capture_output=True, text=True, timeout=30)
    except FileNotFoundError:
        raise RuntimeError("installed evaluator console script is missing") from None
    if version.stdout.strip() != f"hol-guard-eval {args.expected_version}":
        raise RuntimeError("installed evaluator console reports an unexpected version")

    repo = Path(__file__).resolve().parents[2]
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    environment.pop("PYTEST_ADDOPTS", None)
    environment.pop("PYTEST_PLUGINS", None)
    environment["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    with tempfile.TemporaryDirectory(prefix="guard-evaluation-wheel-") as temporary:
        root = Path(temporary)
        test_root = root / "tests"
        test_root.mkdir()
        for name in (
            "__init__.py",
            "evaluation_cli_fixtures.py",
            "test_guard_evaluation_cli.py",
            "test_guard_evaluation_cli_package.py",
            "test_guard_evaluation_preflight.py",
            "test_opencode_hook_python.py",
            "test_opencode_hook_python_isolation.py",
        ):
            shutil.copy2(repo / "tests" / name, test_root / name)
        configuration = root / "pytest.ini"
        configuration.write_text("[pytest]\naddopts = --strict-markers\n", encoding="utf-8")
        result = subprocess.run(
            [
                sys.executable,
                "-I",
                "-m",
                "pytest",
                "-c",
                str(configuration),
                "--confcutdir",
                str(root),
                "--rootdir",
                str(root),
                "--import-mode=importlib",
                "-q",
                str(root),
            ],
            env=environment,
            timeout=180,
            check=False,
        )
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
