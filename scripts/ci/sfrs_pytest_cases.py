"""Record parity vectors for the pytest target and config safety checks.

Usage: ``sfrs_pytest_cases.py FIXTURE_DIR``. A fixed directory tree (a pytest
config corpus plus project layouts) is built under a fresh root; each case
calls a Python helper and stores the result. Paths carry the ``{ROOT}`` token
so the Rust port can rebuild the same tree and replay every case. A case whose
Python path reached the inline-Python AST analysis is tagged ``approx``: the
Rust port answers those with a lexical over-approximation. This script depends
on the Python implementation and is retired with it.
"""

from __future__ import annotations

import gzip
import json
import os
import sys
import tempfile
import time
from collections.abc import Callable
from pathlib import Path

from codex_plugin_scanner.guard.runtime import pytest_config as pc
from codex_plugin_scanner.guard.runtime.secret_file_request_services import (
    interpreter_observers as obs,
)
from codex_plugin_scanner.guard.runtime.secret_file_request_services import (
    pytest_binary_safety as pbs,
)
from codex_plugin_scanner.guard.runtime.secret_file_request_services import (
    pytest_config_safety as pcs,
)
from codex_plugin_scanner.guard.runtime.secret_file_request_services import (
    pytest_target_detection as ptd,
)
from codex_plugin_scanner.guard.runtime.secret_file_request_services.shell_tokenization import (
    _iter_shell_command_segments,
    _shell_segment_primary_command,
    _split_shell_parts,
)

TOKEN = "{ROOT}"

CONFIGS: list[tuple[str, str, str, dict[str, object]]] = [
    # (case id, file name, content, options)
    ("ini_empty", "pytest.ini", "", {}),
    ("ini_section", "pytest.ini", "[pytest]\n", {}),
    ("ini_safe", "pytest.ini", "[pytest]\naddopts = -q --maxfail=2\n", {}),
    ("ini_dot", ".pytest.ini", "[pytest]\naddopts = -q\n", {}),
    ("ini_plugin", "pytest.ini", "[pytest]\naddopts = -p evil\n", {}),
    ("ini_plugin_attached", "pytest.ini", "[pytest]\naddopts = -pevil -q\n", {}),
    ("ini_rootdir", "pytest.ini", "[pytest]\naddopts = --rootdir=/tmp\n", {}),
    ("ini_cfile", "pytest.ini", "[pytest]\naddopts = -c other.ini\n", {}),
    ("ini_override", "pytest.ini", "[pytest]\naddopts = -ofoo=1\n", {}),
    ("ini_override_sep", "pytest.ini", "[pytest]\naddopts = -o foo=1\n", {}),
    ("ini_log_file", "pytest.ini", "[pytest]\nlog_file = out.log\n", {}),
    ("ini_log_blank", "pytest.ini", "[pytest]\nlog_file =\n", {}),
    ("ini_pythonpath", "pytest.ini", "[pytest]\npythonpath = src\n", {}),
    ("ini_required", "pytest.ini", "[pytest]\nrequired_plugins = foo\n", {}),
    ("ini_quote_open", "pytest.ini", "[pytest]\naddopts = '-q\n", {}),
    ("ini_dup_section", "pytest.ini", "[pytest]\na = 1\n[pytest]\nb = 2\n", {}),
    ("ini_dup_option", "pytest.ini", "[pytest]\na = 1\na = 2\n", {}),
    ("ini_dup_case", "pytest.ini", "[pytest]\nA = 1\na = 2\n", {}),
    ("ini_garbage", "pytest.ini", "garbage\n", {}),
    ("ini_no_value", "pytest.ini", "[pytest]\nflag\n", {}),
    ("ini_continuation", "pytest.ini", "[pytest]\naddopts =\n    -q\n    -x\n", {}),
    ("ini_blank_continuation", "pytest.ini", "[pytest]\naddopts = -q\n\n  -x\n", {}),
    ("ini_comment", "pytest.ini", "# c\n; d\n[pytest]\naddopts = -q # tail\n", {}),
    ("ini_inline_hash", "pytest.ini", "[pytest]\naddopts = -k 'a # b'\n", {}),
    ("ini_colon", "pytest.ini", "[pytest]\naddopts: -q\n", {}),
    ("ini_upper_key", "pytest.ini", "[pytest]\nADDOPTS = -p x\n", {}),
    ("ini_percent", "pytest.ini", "[pytest]\naddopts = -k 100%\n", {}),
    ("ini_default_section", "pytest.ini", "[DEFAULT]\naddopts = -p x\n[pytest]\n", {}),
    ("ini_unicode", "pytest.ini", "[pytest]\nmarkers = caf\u00e9\n\u00e9 = 1\n", {}),
    ("ini_bom", "pytest.ini", "\ufeff[pytest]\naddopts = -q\n", {}),
    ("ini_crlf", "pytest.ini", "[pytest]\r\naddopts = -q\r\n", {}),
    ("ini_missing_header", "pytest.ini", "a = 1\n[pytest]\n", {}),
    ("ini_empty_section_name", "pytest.ini", "[]\n[pytest]\n", {}),
    ("ini_section_trailing", "pytest.ini", "[pytest] x\n", {}),
    ("ini_indented_section", "pytest.ini", "  [pytest]\naddopts = -q\n", {}),
    ("ini_indent_first", "pytest.ini", "[pytest]\n  addopts = -q\n", {}),
    ("setup_section", "setup.cfg", "[tool:pytest]\naddopts = -p x\n", {}),
    ("setup_plain", "setup.cfg", "[pytest]\naddopts = -p x\n", {}),
    ("setup_empty", "setup.cfg", "", {}),
    ("tox_section", "tox.ini", "[pytest]\naddopts = -q\n", {}),
    ("tox_none", "tox.ini", "[tox]\nenvlist = py\n", {}),
    ("toml_empty", "pytest.toml", "", {}),
    ("toml_section", "pytest.toml", "[pytest]\naddopts = '-q'\n", {}),
    ("toml_list", "pytest.toml", "[pytest]\naddopts = ['-q', '-p', 'x']\n", {}),
    ("toml_dot", ".pytest.toml", "[pytest]\nlog_file = 'x'\n", {}),
    ("toml_addopts_int", "pytest.toml", "[pytest]\naddopts = 1\n", {}),
    ("toml_list_int", "pytest.toml", "[pytest]\naddopts = ['-q', 1]\n", {}),
    ("toml_pytest_int", "pytest.toml", "pytest = 1\n", {}),
    ("toml_log_int", "pytest.toml", "[pytest]\nlog_file = 5\n", {}),
    ("toml_dup_key", "pytest.toml", "a = 1\na = 2\n", {}),
    ("toml_dup_table", "pytest.toml", "[pytest]\n[pytest]\n", {}),
    ("toml_dup_table_key", "pytest.toml", "[pytest]\na = 1\n[pytest]\nb = 2\n", {}),
    ("toml_redefine_dotted", "pytest.toml", "pytest.a = 1\n[pytest]\nb = 2\n", {}),
    ("toml_scalar_then_header", "pytest.toml", "pytest = 1\n[pytest]\n", {}),
    ("toml_table_then_array", "pytest.toml", "[pytest]\n[[pytest]]\n", {}),
    ("toml_array_then_table", "pytest.toml", "[[pytest]]\n[pytest]\n", {}),
    ("toml_static_array_header", "pytest.toml", "pytest = [1]\n[[pytest]]\n", {}),
    ("toml_inline_then_header", "pytest.toml", "pytest = {}\n[pytest]\n", {}),
    ("toml_scalar_subtable", "pytest.toml", "[pytest]\nb = 1\n[pytest.b]\n", {}),
    ("toml_dotted_dup", "pytest.toml", "pytest.a = 1\npytest.a = 2\n", {}),
    ("toml_overwrite_value", "pytest.toml", "pytest = 1\n[pytest]\n", {}),
    ("toml_array_of_tables", "pytest.toml", "[[pytest]]\na = 1\n", {}),
    ("toml_syntax", "pytest.toml", "[pytest\n", {}),
    ("toml_bad_value", "pytest.toml", "[pytest]\na = \n", {}),
    ("toml_bom", "pytest.toml", "\ufeff[pytest]\naddopts = '-q'\n", {}),
    ("toml_bool_float", "pytest.toml", "[pytest]\na = true\nb = 1.5\nc = 1e20\nd = 1_000\n", {}),
    ("toml_dates", "pytest.toml", "[pytest]\na = 1979-05-27\nb = 07:32:00\nc = 1979-05-27T07:32:00Z\n", {}),
    ("toml_unicode", "pytest.toml", "[pytest]\nmarkers = 'caf\u00e9 \U0001f600'\n", {}),
    ("toml_nested", "pytest.toml", "[pytest]\nmarkers = [['a', 'b'], ['c']]\n", {}),
    ("toml_table_value", "pytest.toml", "[pytest]\nt = {a = 1, b = 'x'}\n", {}),
    ("toml_pythonpath", "pytest.toml", "[pytest]\npythonpath = ['src']\n", {}),
    ("toml_empty_pythonpath", "pytest.toml", "[pytest]\npythonpath = ''\n", {}),
    ("toml_unsafe_marker", "pytest.toml", "[pytest]\naddopts = '--junit-xml=x.xml'\n", {}),
    ("py_empty", "pyproject.toml", "", {}),
    ("py_none", "pyproject.toml", "[project]\nname = 'x'\n", {}),
    ("py_ini", "pyproject.toml", "[tool.pytest.ini_options]\naddopts = '-q'\n", {}),
    ("py_ini_plugin", "pyproject.toml", "[tool.pytest.ini_options]\naddopts = '-p x'\n", {}),
    ("py_native", "pyproject.toml", "[tool.pytest]\naddopts = ['-q']\n", {}),
    ("py_native_plugin", "pyproject.toml", "[tool.pytest]\naddopts = ['-p', 'x']\n", {}),
    ("py_conflict", "pyproject.toml", "[tool.pytest]\nx = 1\n[tool.pytest.ini_options]\ny = 2\n", {}),
    ("py_tool_int", "pyproject.toml", "tool = 1\n", {}),
    ("py_pytest_int", "pyproject.toml", "[tool]\npytest = 1\n", {}),
    ("py_ini_int", "pyproject.toml", "[tool.pytest]\nini_options = 1\n", {}),
    ("py_ini_addopts_int", "pyproject.toml", "[tool.pytest.ini_options]\naddopts = 1\n", {}),
    ("py_ini_addopts_listint", "pyproject.toml", "[tool.pytest.ini_options]\naddopts = ['a', 2]\n", {}),
    (
        "py_ini_scalars",
        "pyproject.toml",
        "[tool.pytest.ini_options]\na = 1\nb = 1.5\nc = true\nd = 'x'\ne = 1979-05-27\nf = 1e20\ng = 1e-7\n",
        {},
    ),
    ("py_ini_list", "pyproject.toml", "[tool.pytest.ini_options]\nmarkers = ['a', 'b']\npythonpath = ['x']\n", {}),
    ("py_ini_nested_list", "pyproject.toml", "[tool.pytest.ini_options]\nmarkers = [1, 'a', [2.5, true]]\n", {}),
    ("py_ini_log", "pyproject.toml", "[tool.pytest.ini_options]\nlog_file = ' x '\n", {}),
    ("py_ini_log_int", "pyproject.toml", "[tool.pytest.ini_options]\nlog_file = 5\n", {}),
    ("py_ini_empty_pythonpath", "pyproject.toml", "[tool.pytest.ini_options]\npythonpath = ''\n", {}),
    ("py_ini_empty_list_pythonpath", "pyproject.toml", "[tool.pytest.ini_options]\npythonpath = []\n", {}),
    ("py_ini_ws_required", "pyproject.toml", "[tool.pytest.ini_options]\nrequired_plugins = '  '\n", {}),
    ("py_ini_empty_table", "pyproject.toml", "[tool.pytest.ini_options]\n", {}),
    ("py_ini_quote_open", "pyproject.toml", '[tool.pytest.ini_options]\naddopts = "\'-q"\n', {}),
    ("py_ini_comment", "pyproject.toml", "[tool.pytest.ini_options]\naddopts = '-q # hi'\n", {}),
    ("py_syntax", "pyproject.toml", "[tool\n", {}),
    ("py_dup", "pyproject.toml", "[tool.pytest]\na = 1\n[tool.pytest]\nb = 2\n", {}),
    ("py_dup_key", "pyproject.toml", "[tool.pytest.ini_options]\na = 1\na = 2\n", {}),
    ("py_inline_overwrite", "pyproject.toml", "tool = {pytest = {}}\n[tool.pytest.ini_options]\n", {}),
    ("py_bom", "pyproject.toml", "\ufeff[tool.pytest.ini_options]\naddopts = '-q'\n", {}),
    ("py_crlf", "pyproject.toml", "[tool.pytest.ini_options]\r\naddopts = '-q'\r\n", {}),
    ("py_upper_suffix", "pyproject.TOML", "[tool.pytest.ini_options]\naddopts = '-p x'\n", {}),
    ("custom_toml", "custom.toml", "[pytest]\naddopts = '-p x'\n", {}),
    ("custom_ini", "custom.ini", "[pytest]\naddopts = -p x\n", {}),
    ("custom_noext", "custom", "[pytest]\naddopts = -q\n", {}),
]

BINARY_FILES = {
    "bin_utf8_invalid": ("pytest.ini", "5b7079746573745d0a6164646f707473203d20ff0a"),
    "bin_toml_invalid": ("pytest.toml", "ff"),
    "bin_nul": ("pytest.ini", "5b7079746573745d00"),
}

TREE_DIRS = [
    "proj/pkg/sub",
    "proj/tests",
    "proj/pyshadow",
    "proj/ruffmod/ruff",
    "proj/dist/foo.dist-info",
    "proj/dist2/foo.egg-info",
    "proj/dist3/foo.egg-info",
    "proj/dirpy.py",
    "proj/bin",
    "proj/empty",
    "proj/pkgcfg/inner",
    "proj/pkgcfg2",
    "proj/dircfg/pytest.ini",
    "proj/dircfg2",
    "outside",
    "empty",
]
TREE_FILES = {
    "proj/script.py": "print(1)\n",
    "proj/bin/run.py": "print(2)\n",
    "proj/notpy.txt": "x\n",
    "proj/tests/test_a.py": "def test_a(): pass\n",
    "proj/pkg/test_b.py": "def test_b(): pass\n",
    "proj/pkg/sub/test_c.py": "def test_c(): pass\n",
    "proj/pyshadow/pytest.py": "",
    "proj/ruffmod/ruff/__init__.py": "",
    "proj/dist/foo.dist-info/entry_points.txt": "[console_scripts]\n",
    "proj/dist3/foo.egg-info/PKG-INFO": "x\n",
    "proj/pkgcfg/pytest.ini": "[pytest]\naddopts = -p evil\n",
    "proj/pkgcfg/inner/test_d.py": "",
    "proj/pkgcfg2/pyproject.toml": "[project]\nname = 'x'\n",
    "proj/pkgcfg2/tox.ini": "[pytest]\naddopts = -q\n",
    "proj/pyproject.toml": "[project]\nname = 'x'\n",
    "proj/pkg/pytest.ini": "[pytest]\naddopts = -q\n",
    "proj/safe.ini": "[pytest]\naddopts = -q\n",
    "proj/unsafe.ini": "[pytest]\naddopts = -p evil\n",
    "proj/broken.ini": "garbage\n",
    "proj/dircfg2/setup.cfg": "[tool:pytest]\nlog_file = x\n",
    "outside/out.py": "print(3)\n",
    "outside/pytest.ini": "[pytest]\naddopts = -p evil\n",
    "proj/big.ini": {"repeat": "#", "count": 1000001},
    "proj/exact.ini": {"repeat": "#", "count": 1000000},
    "proj/ruff_target.py": "x = 1\n",
}
TREE_LINKS = {
    "proj/link_cfg.ini": "safe.ini",
    "proj/esc.py": "../outside/out.py",
    "proj/ok_link.py": "script.py",
    "proj/dangling.py": "missing.py",
    "proj/linkdir": "pkg",
    "proj/outside_cfg.ini": "../outside/pytest.ini",
}

TEXTS = [
    "pytest",
    "pytest -q",
    "py.test tests",
    "pytest.exe",
    "py.test.exe -x",
    "/usr/bin/pytest",
    "./pytest",
    "'pytest' -q",
    '"pytest" -q',
    "p'y'test",
    "pytest; ls",
    "ls && pytest",
    "ls | pytest",
    "echo pytest",
    "echo hi",
    "python -m pytest",
    "python3 -m pytest -q",
    "python3.12 -m pytest tests",
    "python -mpytest",
    "python -m pytest.main",
    "python -m pytest_cov",
    "python -W error -m pytest",
    "python -X dev -m pytest",
    "python -Werror -m pytest",
    "python -c 'import pytest; pytest.main()'",
    "python -c 'print(1)'",
    "python -c 'x=1'",
    "python -c",
    "python -c ''",
    "python -cprint(1)",
    "python --command='print(1)'",
    "python --command 'print(1)'",
    "python -c 'import os; os.system(\"pytest\")'",
    "python -c 'import os; os.system(\"ls\")'",
    "python -c 'import subprocess; subprocess.run([\"pytest\"])'",
    "python -c 'import subprocess; subprocess.run([\"ls\"])'",
    "python -c 'from pytest import main; main()'",
    "python -c 'import importlib; importlib.import_module(\"pytest\").main()'",
    "python -c 'import runpy; runpy.run_module(\"pytest\")'",
    "python -c 'exec(\"import pytest; pytest.main()\")'",
    "python -c 'eval(\"1\")'",
    "python -c 'print(\"pytest\")'",
    "python -c 'import pytest; print(pytest.__version__)'",
    'python -c \'print("p" "ytest")\'',
    "python -c 'print(\"\\x70ytest\")'",
    "python -c 'import os\nos.popen(\"py.test\")'",
    "python script.py",
    "python script.py -c x",
    "python -",
    "python",
    "python -u",
    "bash -c 'pytest'",
    'sh -c "pytest -q"',
    "bash -c 'ls'",
    "bash -lc 'pytest'",
    "zsh -c 'echo $(pytest)'",
    "bash -c 'bash -c pytest'",
    "echo $(pytest)",
    "echo `pytest`",
    'echo "$(pytest -q)"',
    "echo '$(pytest)'",
    "eval pytest",
    "eval 'ls; pytest'",
    "eval ls",
    "xargs pytest",
    "xargs -n1 pytest",
    "xargs echo",
    "parallel pytest ::: a b",
    "watch pytest",
    "find . -exec pytest {} \\;",
    "find . -name x",
    "find . -execdir python -m pytest {} +",
    "find . -ok pytest",
    "fd -x pytest",
    "fd --exec pytest {}",
    "fd -X pytest",
    "fd x",
    "uvx pytest",
    "uvx ruff",
    "uvx --from pytest pytest",
    "uv run pytest",
    "uv run --with x pytest -q",
    "uv run --python 3.12 pytest",
    "uv run -p 3.12 pytest",
    "uv run",
    "uv run --with",
    "uv run -- pytest",
    "uv run FOO=1 pytest",
    "uv run python -m pytest",
    "uv run python -c 'import pytest; pytest.main()'",
    "uv sync",
    "poetry run pytest",
    "poetry run --directory x pytest",
    "poetry run python -m pytest",
    "pdm run pytest",
    "pipenv run pytest",
    "pipx run pytest",
    "pixi run pytest",
    "rye run pytest",
    "hatch run pytest",
    "hatch run --env x pytest",
    "conda run -n x pytest",
    "conda run --name x pytest",
    "mise exec -- pytest",
    "mise x pytest",
    "direnv exec . pytest",
    "direnv exec pytest",
    "direnv exec . echo",
    "direnv exec",
    "env pytest",
    "env FOO=1 pytest",
    "env -i pytest",
    "env -S 'pytest -q'",
    "env -S pytest",
    "env -C /tmp pytest",
    "env --chdir=/tmp pytest",
    "env --chdir /tmp python -m pytest",
    "env -u X pytest",
    "env -- pytest",
    "sudo pytest",
    "sudo -D /tmp pytest",
    "sudo -D/tmp pytest",
    "sudo --chdir=/tmp pytest",
    "sudo --chdir /tmp pytest",
    "sudo -u root pytest",
    "sudo -n pytest",
    "sudo -E -D x python -m pytest",
    "sudo env --chdir x pytest",
    "env -S 'a b' pytest",
    "nohup pytest",
    "time pytest",
    "command pytest",
    "exec pytest",
    "timeout 5 pytest",
    "nice pytest",
    "FOO=1 pytest",
    "PATH=/x pytest",
    "PYTHONPATH=. pytest",
    "PYTEST_ADDOPTS=-p pytest",
    "PYTEST_PLUGINS=x pytest",
    "PYTHONHOME=x pytest",
    "PYTHONUSERBASE=x pytest",
    "env PYTHONPATH=. python -m pytest",
    "PYTHONPATH=. python -m pytest",
    "PYTHONPATH=. python -m ruff check",
    "PYTHONPATH=pyshadow python -m ruff check",
    "PYTHONPATH=ruffmod python -m ruff check",
    "PYTHONPATH= python -m pytest",
    "PYTHONPATH+=x python -m pytest",
    "env -u PYTHONPATH python -m pytest",
    "env -i PYTHONPATH=x python -m pytest",
    "export PATH=/x; pytest",
    "export PATH; pytest",
    "export FOO=1; pytest",
    "export PYTEST_ADDOPTS; pytest",
    "export PYTEST_ADDOPTS=-p; pytest",
    "export PYTEST_ADDOPTS; PYTEST_ADDOPTS=-p pytest",
    "export PYTHONPATH=x; pytest",
    "declare -x PATH=/x; pytest",
    "declare -x PATH; PATH=y pytest",
    "declare PATH=/x; pytest",
    "declare -- -x; pytest",
    "typeset -x PYTEST_PLUGINS=x; pytest",
    "typeset +x PATH=1; pytest",
    "set -a; PATH=x; pytest",
    "set -k; pytest",
    "set -o allexport; pytest",
    "set -o keyword; pytest",
    "set -o noglob; pytest",
    "set +o allexport; pytest",
    "set +o; pytest",
    "set -ex; pytest",
    "set -e; pytest",
    "set -- -a; pytest",
    "set allexport; pytest",
    "set keyword; pytest",
    "set --; pytest",
    "set -o; pytest",
    "cd /tmp; pytest",
    "cd /tmp && pytest",
    "cd $(pwd); pytest",
    "cd -P /tmp; pytest",
    "cd -; pytest",
    "cd -- /tmp; pytest",
    "cd; pytest",
    "pushd /tmp; pytest",
    "pushd -n x; pytest",
    "popd; pytest",
    "popd $(x); pytest",
    "cd /tmp >/dev/null; pytest",
    "cd /tmp 2>&1; pytest",
    "cd /tmp | pytest",
    "pytest <(echo x)",
    "pytest >(cat)",
    "cat <(pytest)",
    "diff <(python -m pytest) x",
    "echo <(ls)",
    "pytest -q tests",
    "pytest -q --maxfail=2 tests/test_a.py::t",
    "pytest -k expr -m mark",
    "pytest -k",
    "pytest -p evil",
    "pytest -pevil",
    "pytest -c other.ini",
    "pytest -cother.ini",
    "pytest -c=other.ini",
    "pytest --config-file other.ini",
    "pytest --config-file=other.ini",
    "pytest --rootdir=/x",
    "pytest --rootdir /x",
    "pytest -o addopts=x",
    "pytest --override-ini=x=1",
    "pytest --basetemp=/x",
    "pytest --junitxml=x.xml",
    "pytest --debug",
    "pytest --",
    "pytest -- -p x",
    "pytest -- tests",
    "pytest --tb=short",
    "pytest --tb short",
    "pytest --quiet --verbose --disable-warnings",
    "pytest -qsvx",
    "pytest -x -s",
    "pytest tests/ pkg/",
    "pytest /abs/path",
    "pytest ../escape",
    "pytest tests/test_a.py::test_a",
    "pytest ::x",
    "pytest ''",
    "pytest tests >out.txt",
    "pytest tests 2>&1",
    "pytest tests | tee x",
    "pytest tests &> out",
    "pytest tests > out",
    "pytest -q 2>/dev/null",
    "python -m pytest -q",
    "python -m pytest -p x",
    "python -m pytest --basetemp /x",
    "python -m pytest --basetemp=/x",
    "python -m pytest --debug",
    "python -m pytest --junitxml=a",
    "python -m pytest -c x.ini",
    "python -m ruff check .",
    "python -m ruff format .",
    "python -m ruff format ruff_target.py",
    "python -m ruff format script.py extra",
    "python -m ruff format ../outside/out.py",
    "python -m ruff format /abs.py",
    "python -m ruff format $X",
    "python -m ruff format `x`",
    "python -m ruff format linkdir",
    "python -m ruff check --add-noqa",
    "python -m ruff check --add-noqa=x",
    "python -m ruff --config x.toml check",
    "python -m ruff --config=x.toml format",
    "python -m ruff --cache-dir x format",
    "python -m ruff --color always check",
    "python -m ruff -- format x",
    "python -m mypy x",
    "python -m mypy --install-types",
    "python -m pip install x",
    "python -m http.server",
    "python -m pytest.__main__",
    "python -m",
    "python -m ''",
    "python -m .pytest",
    "python -m ruff.x check",
    "python -m pytest\n",
    "python -m pytest;ls",
    "python -c 'x' -m pytest",
    "python -- -m pytest",
    "python -B -m pytest",
    "python -I -m pytest",
    "python -E -s -m pytest",
    "python -Wd -m pytest",
    "python -Xutf8 -m pytest",
    "python --check-hash-based-pycs always -m pytest",
    "python --version",
    "python3.12 script.py",
    "python script.py && python -m pytest",
    "python -m pytest && python script.py",
    "python script.py; cd /tmp",
    "python ruff_target.py",
    "python ./script.py",
    "python bin/run.py",
    "python ../outside/out.py",
    "python esc.py",
    "python ok_link.py",
    "python dangling.py",
    "python dirpy.py",
    "python notpy.txt",
    "python /abs/x.py",
    "python ~/x.py",
    "python $(x).py",
    "python script.py arg1",
    "python script.py >out",
    "python -W ignore script.py",
    "python -Wignore script.py",
    "python -- script.py",
    "python -u -- script.py",
    "python -m script",
    "python script.py; python script.py",
    "cd bin; python run.py",
    "cd bin && python run.py",
    "cat x | python -m pytest",
    "head -n 5 x | python -m pytest",
    "echo x | pytest",
    "cat x; pytest",
    "grep x y | pytest",
    "sed -n 1p x; pytest",
    "tail -n 3 x; python -m pytest",
    "ls; pytest",
    "pwd; pytest",
    "true; pytest",
    "false || pytest",
    "(pytest)",
    "{ pytest; }",
    "pytest &",
    "pytest\npytest",
    "echo a\npytest -q",
    "x=$(pytest)",
    "pytest # comment",
    "# pytest",
    "",
    " ",
    ";",
    "&&",
    "pytest \u00e9",
    "pytest \u2028",
    "pytest -k '\u00e9'",
    "pytest " + "a" * 5000,
    "echo " + "x " * 3000 + "; pytest",
    "pytest " + " ".join(f"t{i}.py" for i in range(500)),
    "(" * 20 + "pytest" + ")" * 20,
    "$(" * 12 + "pytest" + ")" * 12,
    "bash -c '" + "bash -c " * 10 + "pytest'",
    "eval " * 12 + "pytest",
    "pytest 'unterminated",
    'pytest "unterminated',
    "pytest \\",
    "echo `unterminated",
    "echo $(unterminated",
    "cat <<EOF\nhello\nEOF",
    "cat <<'EOF'\nhello\nEOF",
    "cat <<-EOF\n\thello\n\tEOF",
    "cat - <<EOF\nx\nEOF",
    "cat <<EOF\nx\nEOF\nls",
    "cat <<EOF\nx\nEOF\n",
    "cat <<EOF > out\nx\nEOF",
    "cat <<EOF | grep x\nx\nEOF",
    "echo a; cat <<EOF\nx\nEOF",
    "cat -n <<EOF\nx\nEOF",
    "cat <<EOF\nx\nEOF\n<<EOF2\ny\nEOF2",
    "cat <<EOF\nx",
    "cat <<EOF\nx\nEOF\n\n  \n",
    "cat <<'E O F'\nx\nE O F",
    "tee <<EOF\nx\nEOF",
    'cat <<"EOF"\nx\nEOF',
    "cat <<EOF; ls\nx\nEOF",
    "cat <<EOF\n$(pytest)\nEOF",
    "cat '<<EOF'",
    "cat <<E\\\nOF\nx\nEOF",
    "cat <<EOF\r\nx\r\nEOF\r\n",
    "cat <<\u00e9\nx\n\u00e9",
]

TOKENS = [
    "a*",
    "a?",
    "a[b]",
    "'a*'",
    '"a*"',
    "a\\*",
    "a'*'",
    "'a'*",
    "a\\",
    "'a",
    '"a',
    "*",
    "?",
    "[",
    "",
    "plain",
    "\u00e9*",
    "a\\?b",
    "'x\"*\"'",
    "\"x'*'\"",
    "\\*\\?",
    "[a-z]",
    "a]",
    "$(*)",
    "'' *",
    "a\\\\*",
    "'\\*'",
    '"\\*"',
]

REDIRECTION_TOKENS = [
    "|",
    "|&",
    ">",
    ">>",
    "2>",
    "2>&1",
    "1>",
    "0>",
    "&>",
    "&>>",
    ">&2",
    ">/dev/null",
    "2>/dev/null",
    "<",
    "<<",
    "<<<",
    "3>",
    "12>",
    ">file",
    "2>file",
    ">&",
    "2>&",
    ">|",
    "x",
    "",
    "a>b",
    "2>a b",
    "2> x",
    "1>&2",
    "0>&1",
    "2>>x",
    "2>&-",
    ">\u00e9",
    "<in",
    "<&3",
    "1<",
    "2>\t",
    "\u0662>",
    "0>&0",
    "|x",
    "||",
    "&",
    ";",
]

ARG_LISTS = [
    [],
    ["-q"],
    ["-m", "pytest"],
    ["-mpytest"],
    ["-m", "pytest.x"],
    ["-m"],
    ["-mruff", "check"],
    ["-m", "ruff", "check"],
    ["-c", "x"],
    ["--command", "x"],
    ["--command=x"],
    ["-cx"],
    ["--"],
    ["--", "-m", "pytest"],
    ["-W", "e", "-m", "pytest"],
    ["-Werror", "-m", "pytest"],
    ["-X", "dev", "-m", "pytest"],
    ["-Xdev", "-m", "pytest"],
    ["-W"],
    ["-W", "e"],
    ["--check-hash-based-pycs", "always", "-m", "pytest"],
    ["-u", "-m", "pytest"],
    ["x.py"],
    ["-", "-m", "pytest"],
    ["-m", "pytest", "-q"],
    ["-m", "pytest", ">", "out"],
    ["-m", "pytest", "2>&1"],
    ["-m", "pytest", "|", "tee"],
    ["-m", "ruff", "format", "ruff_target.py"],
    ["-m", "ruff", "format"],
    ["-m", "ruff", "--config", "x", "format", "a"],
    ["-m", "ruff", "--config=x", "format", "a"],
    ["-m", "ruff", "--cache-dir", "x"],
    ["-m", "ruff", "--add-noqa"],
    ["-m", "ruff", "--add-noqa=1"],
    ["-m", "ruff", "--color", "x", "check"],
    ["-m", "mypy"],
    ["-m", "pytest", "--", "x"],
    ["-m", "pytest", "-p", "x"],
    ["-m", "pytest", "-c", "x.ini"],
    ["-m", "pytest", "--basetemp=x"],
    ["-m", "pytest", "--basetemp", "x"],
    ["-m", "pytest", "tests"],
    ["-m", "pytest", "-k", "x", "tests"],
    ["-m", "pytest", "-qk", "x"],
    ["-m", "pytest", "--maxfail=1"],
    ["-m", "pytest", "--maxfail", "1"],
    ["-m", "pytest", "--tb"],
    ["-m", "pytest", "-k"],
    ["-m", "pytest", "--debug=x"],
    ["-m", "pytest", "--junitxml"],
    ["-m", "pytest", "--junitxml=x"],
    ["-m", "", "x"],
    ["-m", ".x"],
    ["-m", "pytest\u00e9"],
    ["-\u00e9"],
]

PYTEST_ARG_LISTS = [
    [],
    ["-q"],
    ["tests"],
    ["-q", "tests", "pkg"],
    ["tests/test_a.py::t"],
    ["-k", "x"],
    ["-k", "x", "tests"],
    ["-m", "x", "t"],
    ["--maxfail", "2", "tests"],
    ["--maxfail=2", "tests"],
    ["--tb", "short"],
    ["--tb=short", "x"],
    ["--"],
    ["--", "x"],
    ["-p", "x"],
    ["-pxx"],
    ["-c", "x.ini"],
    ["-c"],
    ["-cx.ini"],
    ["-c=x.ini"],
    ["-c", "x.ini", "-c", "y.ini"],
    ["--config-file", "x.ini"],
    ["--config-file=x.ini"],
    ["--config-file"],
    ["--config-file=", "tests"],
    ["-c", ""],
    ["--rootdir=/x"],
    ["--rootdir", "x"],
    ["-o", "x=1"],
    ["--override-ini=x"],
    ["-v", "-s", "-x", "--quiet", "--verbose"],
    ["--disable-warnings", "-q"],
    ["-qq"],
    ["../x"],
    ["tests/../x"],
    ["/x"],
    [""],
    ["::x"],
    ["pkg/sub"],
    ["pkg/sub/test_c.py"],
    ["pkg/test_b.py", "tests/test_a.py"],
    ["pkg", "tests"],
    ["tests", "tests"],
    ["pkg", "pkg/sub"],
    ["pkg/sub", "pkg/test_b.py"],
    ["nonexistent"],
    ["nonexistent/x.py"],
    ["pkgcfg"],
    ["pkgcfg/inner"],
    ["pkgcfg/inner/test_d.py"],
    ["pkgcfg2"],
    ["dircfg"],
    ["dircfg2"],
    ["linkdir"],
    ["linkdir/test_b.py"],
    ["pkg/./sub"],
    ["./pkg"],
    ["pkg/"],
    ["pkg//sub"],
    ["-c", "safe.ini"],
    ["-c", "unsafe.ini"],
    ["-c", "broken.ini"],
    ["-c", "missing.ini"],
    ["-c", "big.ini"],
    ["-c", "exact.ini"],
    ["-c", "link_cfg.ini"],
    ["-c", "outside_cfg.ini"],
    ["-c", "../outside/pytest.ini"],
    ["-c", "/abs.ini"],
    ["-c", "pkg"],
    ["-c", "dircfg/pytest.ini"],
    ["-c", "pkg/pytest.ini", "tests"],
    ["-csafe.ini"],
    ["--config-file=safe.ini"],
    ["--config-file", "unsafe.ini", "-c", "safe.ini"],
    ["-c", "safe.ini", "-c", "unsafe.ini"],
    ["-c", "linkdir/pytest.ini"],
    ["-c", "pyproject.toml"],
    ["-c", "pkgcfg2/pyproject.toml"],
    ["-c", "pkgcfg2/tox.ini"],
    ["-c", "dircfg2/setup.cfg"],
    ["-c", "::x"],
    ["-c", "x::y"],
    ["tests::x", "pkg::y"],
    ["-k"],
    ["-m"],
    ["--tb"],
    ["x", "-c"],
    ["-q", "-c", "safe.ini", "tests"],
    ["--junitxml=x", "tests"],
    ["-\u00e9"],
    ["\u00e9"],
    ["pkg/\u00e9"],
    ["a" * 300],
    ["pkg/" * 40 + "x"],
]

MODULE_ROOTS = ["pytest", "ruff", "mypy", "", "pytest.x", "ruff.y", "PYTEST", "pip"]
CWDS = [
    None,
    "proj",
    "proj/pkg",
    "proj/pkg/sub",
    "proj/tests",
    "proj/pyshadow",
    "proj/ruffmod",
    "proj/dist",
    "proj/dist2",
    "proj/dist3",
    "proj/empty",
    "proj/missing",
    "proj/script.py",
    "proj/linkdir",
    "proj/pkgcfg",
    "proj/pkgcfg/inner",
    "proj/pkgcfg2",
    "proj/dircfg",
    "proj/dircfg2",
    "outside",
    "empty",
    "",
]
ABS_CWDS = [
    None,
    "proj",
    "proj/pkg",
    "proj/pkgcfg",
    "proj/pyshadow",
    "proj/dist",
    "proj/empty",
    "empty",
    "outside",
    "proj/missing",
]

SEGMENTS = [
    ["python", "-m", "pytest"],
    ["PYTHONPATH=pyshadow", "python", "-m", "pytest"],
    ["PYTHONPATH=.", "python", "-m", "pytest"],
    ["PYTHONPATH=ruffmod", "python", "-m", "ruff"],
    ["PYTHONPATH=empty", "python", "-m", "ruff"],
    ["PYTHONPATH=a:b", "python", "-m", "ruff"],
    ["PYTHONPATH=", "python"],
    ["PYTHONPATH=pkg:", "python"],
    ["PYTHONPATH= pkg ", "python"],
    ["pythonpath=pkg", "python"],
    ["PYTHONPATH+=pkg", "python"],
    ["env", "PYTHONPATH=pkg", "python"],
    ["env", "-i", "PYTHONPATH=pkg", "python"],
    ["env", "-u", "PYTHONPATH", "PYTHONPATH=pkg", "python"],
    ["env", "PYTHONPATH=pkg", "env", "-u", "PYTHONPATH", "python"],
    ["env", "-S", "PYTHONPATH=pkg", "python"],
    ["env", "-C", "x", "PYTHONPATH=pkg", "python"],
    ["env", "-Z", "python"],
    ["env", "--", "python"],
    ["sudo", "python"],
    ["python"],
    ["FOO=1", "PYTHONPATH=/abs", "python"],
    ["PYTHONPATH=../x", "python"],
    ["PYTHONPATH=pkg", "PYTHONPATH=other", "python"],
    ["PYTHONPATH=\u00e9", "python"],
    ["PYTHONPATH=" + "a:" * 100, "python"],
]


def _rel(value: str | None, root: Path) -> str | None:
    return None if value is None else str(root / value) if value else str(root)


def _text(root: Path, value: object) -> object:
    if isinstance(value, str):
        return value.replace(str(root), TOKEN)
    if isinstance(value, (list, tuple)):
        return [_text(root, item) for item in value]
    if isinstance(value, (set, frozenset)):
        return sorted(_text(root, item) for item in value)
    if isinstance(value, Path):
        return _text(root, str(value))
    if isinstance(value, dict):
        return {key: _text(root, item) for key, item in value.items()}
    return value


def _value(value: pc.PytestConfigValue | None) -> object:
    if value is None:
        return None
    return {
        "addopts": list(value.addopts),
        "log_file": value.log_file,
        "execution_options": [list(item) for item in value.execution_options],
        "unsafe": value.unsafe,
    }


def _result(result: pc.PytestConfigParseResult) -> dict[str, object]:
    return {
        "source_path": result.source_path,
        "present": result.present,
        "value": _value(result.value),
        "complete": result.complete,
        "reason_code": result.reason_code,
        "content_sha256": result.content_sha256,
    }


def _assessment(assessment: pc.PytestConfigAssessment) -> dict[str, object]:
    return {
        "results": [_result(item) for item in assessment.results],
        "complete": assessment.complete,
        "unsafe": assessment.unsafe,
        "reason_codes": list(assessment.reason_codes),
        "identity_sha256": assessment.identity_sha256,
    }


class _Probe:
    """Detect whether the inline-Python AST analysis ran during a call."""

    def __init__(self) -> None:
        self.hit = False
        self.original = ptd._inline_python_payload_runs_pytest

    def install(self) -> None:
        def wrapped(*args: object, **kwargs: object) -> bool:
            self.hit = True
            return self.original(*args, **kwargs)

        ptd._inline_python_payload_runs_pytest = wrapped

    def restore(self) -> None:
        ptd._inline_python_payload_runs_pytest = self.original


def _build(root: Path) -> dict[str, object]:
    files: dict[str, object] = {}
    hexfiles: dict[str, str] = {}
    for case_id, name, content, _options in CONFIGS:
        files[f"cfg/{case_id}/{name}"] = content
    for case_id, (name, hexed) in BINARY_FILES.items():
        hexfiles[f"cfg/{case_id}/{name}"] = hexed
    for name in ("pytest.ini", "pytest.toml"):
        files[f"cfg/oversize_{name}/{name}"] = {"repeat": "#", "count": 1000001}
        files[f"cfg/maxsize_{name}/{name}"] = {"repeat": "#", "count": 1000000}
    files.update(TREE_FILES)
    dirs = [*list(TREE_DIRS), "cfg/dir_ini/pytest.ini", "cfg/dir_toml/pytest.toml", "cfg/dir_link_target"]
    links = dict(TREE_LINKS)
    links["cfg/symlink_ini/pytest.ini"] = "../ini_section/pytest.ini"
    links["cfg/symlink_dangling/pytest.ini"] = "../missing/pytest.ini"
    links["cfg/symlink_dir"] = "ini_safe"
    links["cfg/symlink_dir_user/placeholder"] = "x"
    del links["cfg/symlink_dir_user/placeholder"]
    tree = {"dirs": dirs, "files": files, "hexfiles": hexfiles, "links": links}
    for name in dirs:
        (root / name).mkdir(parents=True, exist_ok=True)
    for name, content in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, dict):
            path.write_bytes(content["repeat"].encode() * content["count"])
        else:
            path.write_bytes(str(content).encode("utf-8"))
    for name, hexed in hexfiles.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(bytes.fromhex(hexed))
    for name, target in links.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        os.symlink(target, path)
    (root / "cfg/symlink_dir_user").mkdir(exist_ok=True)
    tree["dirs"].append("cfg/symlink_dir_user")
    os.symlink("../ini_safe/pytest.ini", root / "cfg/symlink_dir_user/pytest.ini")
    tree["links"]["cfg/symlink_dir_user/pytest.ini"] = "../ini_safe/pytest.ini"
    return tree


def _cases(root: Path) -> list[dict[str, object]]:
    cases: list[dict[str, object]] = []
    probe = _Probe()

    def add(function: str, args: list[object], thunk: Callable[[], object]) -> None:
        probe.hit = False
        started = time.monotonic()
        try:
            result = thunk()
        except (RecursionError, ValueError, OSError):
            return
        if time.monotonic() - started > 1.0:
            print("slow", function, str(args)[:80], file=sys.stderr)
        entry: dict[str, object] = {"fn": function, "args": _text(root, args), "result": _text(root, result)}
        if probe.hit:
            entry["approx"] = True
        cases.append(entry)

    probe.install()
    cwd_args = lambda cwd: _rel(cwd, root)  # noqa: E731
    cwd_path = lambda cwd: None if cwd is None else Path(_rel(cwd, root))  # noqa: E731

    # Config parsing and assessment.
    config_ids = [item[0] for item in CONFIGS]
    for case_id, name, _content, _options in CONFIGS:
        workspace = root / "cfg" / case_id
        for relative in (name, f"./{name}"):
            add(
                "parse_pytest_config",
                [str(workspace), relative],
                lambda w=workspace, r=relative: _result(pc.parse_pytest_config(w, r)),
            )
    for case_id in [
        *list(BINARY_FILES),
        "oversize_pytest.ini",
        "oversize_pytest.toml",
        "maxsize_pytest.ini",
        "maxsize_pytest.toml",
        "dir_ini",
        "dir_toml",
        "symlink_ini",
        "symlink_dangling",
        "symlink_dir",
        "symlink_dir_user",
    ]:
        workspace = root / "cfg" / case_id
        for relative in ("pytest.ini", "pytest.toml", ".pytest.ini", "missing.ini"):
            add(
                "parse_pytest_config",
                [str(workspace), relative],
                lambda w=workspace, r=relative: _result(pc.parse_pytest_config(w, r)),
            )
    for relative in [
        "",
        ".",
        "..",
        "../x",
        "/abs",
        "a/../b",
        "pytest.ini/",
        "x\x00y",
        "\u00e9.ini",
        "a" * 400,
        "link_cfg.ini",
        "linkdir/pytest.ini",
        "pkg/pytest.ini",
        "pkg/missing.ini",
        "missing/dir/pytest.ini",
        "script.py/x",
        "dircfg/pytest.ini",
        "big.ini",
        "exact.ini",
        "safe.ini",
        "unsafe.ini",
        "broken.ini",
        "outside_cfg.ini",
        "esc.py",
    ]:
        for workspace in (root / "proj", root / "missing", root / "proj" / "script.py"):
            add(
                "parse_pytest_config",
                [str(workspace), relative],
                lambda w=workspace, r=relative: _result(pc.parse_pytest_config(w, r)),
            )
    rel_sets = [
        ["pytest.ini"],
        ["pytest.ini", "pytest.ini"],
        ["pytest.toml", ".pytest.toml", "pytest.ini", ".pytest.ini", "pyproject.toml", "tox.ini", "setup.cfg"],
        ["pyproject.toml", "tox.ini"],
        ["setup.cfg", "pytest.ini"],
        ["missing.ini"],
        [],
        ["pytest.ini", "custom.toml", "custom.ini", "custom"],
        ["pyproject.toml", "pytest.ini"],
        ["tox.ini", "setup.cfg"],
    ]
    for case_id in [*config_ids, "dir_ini", "dir_toml", "symlink_ini", "bin_utf8_invalid"]:
        workspace = root / "cfg" / case_id
        for rels in rel_sets:
            for require in (False, True):
                add(
                    "assess_pytest_configs",
                    [str(workspace), rels, require],
                    lambda w=workspace, r=rels, q=require: _assessment(
                        pc.assess_pytest_configs(w, r, require_present=q)
                    ),
                )
            add(
                "assess_selected_pytest_config",
                [str(workspace), rels],
                lambda w=workspace, r=rels: _assessment(pc.assess_selected_pytest_config(w, r)),
            )
    for workspace in (root / "proj", root / "proj" / "pkg", root / "outside", root / "missing"):
        for rels in (
            ["safe.ini", "unsafe.ini"],
            ["broken.ini"],
            ["pyproject.toml", "tox.ini"],
            ["link_cfg.ini", "safe.ini"],
            ["pytest.ini", "pyproject.toml"],
            ["big.ini"],
        ):
            for require in (False, True):
                add(
                    "assess_pytest_configs",
                    [str(workspace), rels, require],
                    lambda w=workspace, r=rels, q=require: _assessment(
                        pc.assess_pytest_configs(w, r, require_present=q)
                    ),
                )
            add(
                "assess_selected_pytest_config",
                [str(workspace), rels],
                lambda w=workspace, r=rels: _assessment(pc.assess_selected_pytest_config(w, r)),
            )
    sample = [
        pc.assess_pytest_configs(root / "cfg" / "ini_safe", ["pytest.ini"]),
        pc.assess_pytest_configs(root / "cfg" / "ini_plugin", ["pytest.ini"]),
        pc.assess_pytest_configs(root / "cfg" / "ini_garbage", ["pytest.ini"]),
        pc.assess_pytest_configs(root / "cfg" / "ini_empty", ["missing.ini"]),
        pc.assess_pytest_configs(root / "cfg" / "ini_empty", ["missing.ini"], require_present=True),
        pc.assess_selected_pytest_config(root / "cfg" / "py_none", ["pyproject.toml"]),
        pc.assess_selected_pytest_config(root / "cfg" / "py_ini", ["pyproject.toml"]),
    ]
    sample_sets = [
        [0],
        [1],
        [0, 1],
        [2, 0],
        [3],
        [4],
        [3, 4],
        [5],
        [6],
        [5, 6],
        [0, 1, 2, 3, 4, 5, 6],
        [],
        [3, 3],
        [4, 0],
    ]
    for indexes in sample_sets:
        picked = [sample[i] for i in indexes]
        add(
            "combine_pytest_config_assessments",
            [
                {
                    "workspaces": [
                        str(root / "cfg" / n)
                        for n in (
                            "ini_safe",
                            "ini_plugin",
                            "ini_garbage",
                            "ini_empty",
                            "ini_empty",
                            "py_none",
                            "py_ini",
                        )
                    ],
                    "rels": [
                        ["pytest.ini"],
                        ["pytest.ini"],
                        ["pytest.ini"],
                        ["missing.ini"],
                        ["missing.ini"],
                        ["pyproject.toml"],
                        ["pyproject.toml"],
                    ],
                    "modes": ["all", "all", "all", "all", "require", "selected", "selected"],
                    "indexes": indexes,
                }
            ],
            lambda p=picked: _assessment(pc.combine_pytest_config_assessments(p)),
        )

    # Config safety: pure helpers.
    for args in ARG_LISTS:
        add("python_module_root_from_args", [args], lambda a=args: pcs._python_module_root_from_args(a))
        add(
            "shell_args_without_trailing_redirections",
            [args],
            lambda a=args: pcs._shell_args_without_trailing_redirections(a),
        )
        add(
            "python_segment_runs_safe_module_nocwd",
            [args],
            lambda a=args: pcs._python_segment_runs_safe_module(a, cwd=None),
        )
    for root_name in [*MODULE_ROOTS, None]:
        add("python_module_unsafe_env_keys", [root_name], lambda r=root_name: pcs._python_module_unsafe_env_keys(r))
    for token in REDIRECTION_TOKENS:
        add("is_shell_redirection_token", [token], lambda t=token: pcs._is_shell_redirection_token(t))
    for args in PYTEST_ARG_LISTS + ARG_LISTS:
        add("pytest_positional_args", [args], lambda a=args: list(pcs._pytest_positional_args(a)))
        add("pytest_module_args_are_safe", [args], lambda a=args: pcs._pytest_module_args_are_safe(a))
        for module_root in MODULE_ROOTS:
            add(
                "python_module_subcommand",
                [module_root, args],
                lambda m=module_root, a=args: pcs._python_module_subcommand(m, a),
            )
    for text in [
        "",
        ".",
        "a",
        "a/b",
        "a/b/c",
        "./a",
        "a/./b",
        "a//b",
        "../a",
        "a/..",
        "é/ü",
        "a" * 50 + "/" + "b" * 50,
    ]:
        add("pytest_config_ancestor_dirs", [text], lambda t=text: list(pcs._pytest_config_ancestor_dirs(Path(t))))

    # Config safety: filesystem helpers.
    for cwd in ABS_CWDS:
        for args in PYTEST_ARG_LISTS:
            if cwd is None:
                continue
            path = Path(_rel(cwd, root))
            add(
                "pytest_explicit_config_paths",
                [args, _rel(cwd, root)],
                lambda a=args, p=path: (
                    pcs._pytest_explicit_config_paths(a, cwd=p) and list(pcs._pytest_explicit_config_paths(a, cwd=p))
                    if pcs._pytest_explicit_config_paths(a, cwd=p) is not None
                    else None
                ),
            )
            add(
                "pytest_config_search_dirs",
                [args, _rel(cwd, root)],
                lambda a=args, p=path: (
                    None
                    if pcs._pytest_config_search_dirs(a, cwd=p) is None
                    else list(pcs._pytest_config_search_dirs(a, cwd=p))
                ),
            )
            add(
                "pytest_config_assessment",
                [_rel(cwd, root), args],
                lambda a=args, p=path: _assessment(pcs._pytest_config_assessment(p, a)),
            )
        for args in PYTEST_ARG_LISTS:
            add(
                "pytest_config_may_add_unsafe_options",
                [cwd_args(cwd), args],
                lambda a=args, c=cwd: pcs._pytest_config_may_add_unsafe_options(cwd_path(c), a),
            )
    for arg in [
        "",
        "tests",
        "tests::x",
        "::x",
        "/x",
        "../x",
        "a/../b",
        "a//b",
        "./a",
        ".",
        "a/",
        "//",
        str(root),
        str(root / "proj"),
        str(root / "proj" / "tests"),
        str(root / "proj" / "tests") + "/x::y",
        str(root) + "/",
        str(root / "proj" / ".." / "x"),
        str(root.parent),
        "\u00e9",
        "x::y::z",
        "a/./b",
        str(root / "proj") + "//pkg",
        str(root / "proj") + "/./pkg",
        str(root / "proj") + "/..",
        str(root) + "x",
        "~",
        "~/x",
    ]:
        for cwd in ("proj", "proj/pkg", ""):
            add(
                "pytest_selected_relative_path",
                [arg, _rel(cwd, root)],
                lambda a=arg, c=cwd: pcs._pytest_selected_relative_path(a, cwd=Path(_rel(c, root))),
            )

    for module_root in ("pytest", "ruff", "mypy", "x", ""):
        for cwd in CWDS:
            add(
                "python_module_may_be_shadowed",
                [module_root, cwd_args(cwd)],
                lambda m=module_root, c=cwd: obs._python_module_may_be_shadowed(m, cwd_path(c)),
            )
    for module in ["pytest", "pytest.x", "ruff", "mypy", "", "x", "PYTEST", "ruff.y"]:
        for args in [
            [],
            ["-q"],
            ["tests"],
            ["-p", "x"],
            ["--basetemp", "x"],
            ["-c", "safe.ini"],
            ["--debug"],
            ["--junitxml=x"],
            ["format", "ruff_target.py"],
            ["format", "script.py"],
            ["check", "."],
            ["--add-noqa"],
            ["--config", "x", "format", "ruff_target.py"],
            ["format"],
            ["format", "x", "y"],
            ["format", "../outside/out.py"],
            ["format", "linkdir"],
            ["format", "$X"],
            ["--", "format", "a"],
            ["--cache-dir", "x", "check"],
            ["--color=x", "check"],
            ["-k"],
            ["pkg"],
            ["pkgcfg"],
            ["-q", "pkg/sub"],
            ["format", "dirpy.py"],
            ["format", "ok_link.py"],
            ["format", "esc.py"],
            ["format", "dangling.py"],
            ["format", "notpy.txt"],
        ]:
            for cwd in ABS_CWDS:
                add(
                    "python_module_args_are_safe",
                    [module, args, cwd_args(cwd)],
                    lambda m=module, a=args, c=cwd: pcs._python_module_args_are_safe(m, a, cwd=cwd_path(c)),
                )
    for args in ARG_LISTS:
        for cwd in ABS_CWDS:
            add(
                "python_segment_runs_safe_module",
                [args, cwd_args(cwd)],
                lambda a=args, c=cwd: pcs._python_segment_runs_safe_module(a, cwd=cwd_path(c)),
            )
    for args in [
        [],
        ["format"],
        ["format", "ruff_target.py"],
        ["format", "script.py"],
        ["format", "a", "b"],
        ["check", "x"],
        ["format", "dirpy.py"],
        ["format", "linkdir"],
        ["format", "ok_link.py"],
        ["format", "esc.py"],
        ["format", "../outside/out.py"],
        ["format", "/abs.py"],
        ["format", "$X"],
        ["format", "`x`"],
        ["format", "."],
        ["format", "pkg/.."],
        ["format", "\u00e9.py"],
        ["format", ""],
    ]:
        for cwd in ABS_CWDS:
            add(
                "ruff_format_target_is_bounded",
                [args, cwd_args(cwd)],
                lambda a=args, c=cwd: pcs._ruff_format_target_is_bounded(a, cwd=cwd_path(c)),
            )
    for segment in SEGMENTS:
        command_index = (
            len(segment) - 1 if segment[-1] == "python" else next(i for i, t in enumerate(segment) if t == "python")
        )
        for module_root in ("pytest", "ruff", None, "mypy"):
            for cwd in ABS_CWDS:
                add(
                    "python_module_may_be_shadowed_from_execution_context",
                    [module_root, cwd_args(cwd), segment, command_index],
                    lambda m=module_root, c=cwd, s=segment, i=command_index: (
                        pcs._python_module_may_be_shadowed_from_execution_context(
                            m, cwd=cwd_path(c), segment=s, command_index=i
                        )
                    ),
                )
                add(
                    "pythonpath_search_roots",
                    [cwd_args(cwd), segment, command_index],
                    lambda c=cwd, s=segment, i=command_index: [
                        str(item)
                        for item in pcs._pythonpath_search_roots_from_segment(s, command_index=i, cwd=cwd_path(c))
                    ],
                )

    # Environment helpers.
    for token in [
        "A=1",
        "a=1",
        "A+=1",
        "A=b+=c",
        "A+=b=c",
        "=1",
        "+=1",
        "A",
        "",
        "=",
        "A==",
        "path=x",
        "\u00e9=1",
        "a b=1",
        "x+=",
        "PATH+=:x",
        "A=+=",
        "+==",
        "a+b=c",
    ]:
        add("shell_env_assignment_key", [token], lambda t=token: obs._shell_env_assignment_key(t))
    env_segments = [
        ["python"],
        ["PYTHONPATH=x", "python"],
        ["pythonpath=x", "python"],
        ["PYTHONPATH+=x", "python"],
        ["env", "PYTHONPATH=x", "python"],
        ["env", "-i", "PYTHONPATH=x", "python"],
        ["env", "-u", "PYTHONPATH", "python"],
        ["env", "-u", "pythonpath", "PYTHONPATH=x", "python"],
        ["env", "PYTHONPATH=x", "-u", "PYTHONPATH", "python"],
        ["env", "-S", "PYTHONPATH=x python"],
        ["env", "-S", "python"],
        ["env", "-C", "d", "python"],
        ["env", "--unknown", "python"],
        ["env", "-", "PYTHONPATH=x", "python"],
        ["env", "PYTHONPATH=a", "env", "PYTHONPATH=b", "python"],
        ["FOO=1", "env", "PYTHONPATH=x", "python"],
        ["PYTHONPATH=a", "env", "-i", "python"],
        ["PYTHONPATH=a", "env", "--ignore-environment", "python"],
        ["env", "--", "PYTHONPATH=x", "python"],
        ["env", "--unset=PYTHONPATH", "python"],
        ["env", "--unset", "PYTHONPATH", "python"],
        ["env"],
        ["env", "PYTHONPATH=x"],
        ["PYTHONPATH=x"],
        ["env", "-u"],
        ["sudo", "PYTHONPATH=x", "python"],
        ["(PYTHONPATH=x", "python"],
        ["PYTHONPATH=x>out", "python"],
        ["env>x", "PYTHONPATH=y", "python"],
        ["PYTHONPATH=", "python"],
        ["PYTHONPATH=a=b", "python"],
        ["env", "PYTHONPATH=a=b", "python"],
        ["env", "-S", "'A=1 python'", "python"],
        ["env", "-i", "-u", "X", "PYTHONPATH=1", "python"],
        ["env", "-0", "python"],
        ["env", "-Pfoo", "python"],
    ]
    for segment in env_segments:
        indexes = sorted({len(segment) - 1, 0, len(segment)})
        for command_index in indexes:
            for key in ("PYTHONPATH", "pythonpath", "PATH", "PYTEST_ADDOPTS", "X"):
                add(
                    "shell_segment_sets_env_key",
                    [segment, command_index, key],
                    lambda s=segment, i=command_index, k=key: obs._shell_segment_sets_env_key(s, i, k),
                )
                add(
                    "shell_segment_explicit_env_value",
                    [segment, command_index, key],
                    lambda s=segment, i=command_index, k=key: list(obs._shell_segment_explicit_env_value(s, i, k)),
                )
    return cases + _command_cases(root, add)


def _command_cases(
    root: Path, add: Callable[[str, list[object], Callable[[], object]], None]
) -> list[dict[str, object]]:
    extra: list[dict[str, object]] = []
    cwd_args = lambda cwd: _rel(cwd, root)  # noqa: E731
    cwd_path = lambda cwd: None if cwd is None else Path(_rel(cwd, root))  # noqa: E731
    for token in TOKENS:
        add("shell_token_has_active_glob", [token], lambda t=token: ptd._shell_token_has_active_glob(t))
    for text in TEXTS:
        parts = _split_shell_parts(text)
        add("shell_command_targets_pytest", [text], lambda t=text: ptd._shell_command_targets_pytest(t))
        add("is_literal_cat_heredoc_to_stdout", [text], lambda t=text: pbs._is_literal_cat_heredoc_to_stdout(t))
        add(
            "contains_pytest_process_substitution",
            [text],
            lambda t=text, p=parts: pbs._contains_pytest_process_substitution(t, p),
        )
        add(
            "contains_prior_pytest_state_mutation", [text], lambda p=parts: pbs._contains_prior_pytest_state_mutation(p)
        )
        add(
            "contains_unsafe_pytest_environment_wrapper",
            [text],
            lambda p=parts: pbs._contains_unsafe_pytest_environment_wrapper(p, cwd=None),
        )
        add("python_inline_script_runs_pytest_parts", [parts], lambda p=parts: ptd._python_inline_script_runs_pytest(p))
        add("pytest_args_from_argument_sequence", [parts], lambda p=parts: ptd._pytest_args_from_argument_sequence(p))
        add("argument_sequence_targets_pytest", [parts], lambda p=parts: ptd._argument_sequence_targets_pytest(p))
        for index in range(min(len(parts), 6)):
            add(
                "pytest_args_from_command_position",
                [parts, index],
                lambda p=parts, i=index: ptd._pytest_args_from_command_position(p, i),
            )
        for name in ("uv", "poetry", "direnv", "conda", "mise", "hatch", "pipx", "unknown"):
            add(
                "pytest_args_from_runner_argument_sequence",
                [name, parts],
                lambda n=name, p=parts: ptd._pytest_args_from_runner_argument_sequence(n, p),
            )
        add(
            "pytest_args_from_argument_sequence_ignoring",
            [parts, [0]],
            lambda p=parts: ptd._pytest_args_from_argument_sequence_ignoring(p, ignored_indices=frozenset({0})),
        )
        add(
            "pytest_args_from_argument_sequence_ignoring",
            [parts, [1, 2]],
            lambda p=parts: ptd._pytest_args_from_argument_sequence_ignoring(p, ignored_indices=frozenset({1, 2})),
        )
        for segment in _iter_shell_command_segments(parts):
            name, index = _shell_segment_primary_command(segment)
            if name is None or index is None:
                continue
            add(
                "segment_targets_pytest",
                [segment, name, index],
                lambda s=segment, n=name, i=index: ptd._segment_targets_pytest(s, n, i),
            )
            for fn_name, fn in (
                ("shell_segment_uses_env_split_string_wrapper", pbs._shell_segment_uses_env_split_string_wrapper),
                ("shell_segment_uses_env_chdir", pbs._shell_segment_uses_env_chdir),
                ("shell_segment_uses_sudo_chdir", pbs._shell_segment_uses_sudo_chdir),
                ("shell_segment_uses_cwd_changing_wrapper", pbs._shell_segment_uses_cwd_changing_wrapper),
            ):
                add(fn_name, [segment, index], lambda f=fn, s=segment, i=index: f(s, i))
            add(
                "shell_directory_setup_segment_is_safe",
                [name, segment[index + 1 :]],
                lambda n=name, s=segment, i=index: pbs._shell_directory_setup_segment_is_safe(n, s[i + 1 :]),
            )
            if name in {"export", "declare", "typeset", "set"}:
                for token in segment[index + 1 :]:
                    add("shell_declared_env_key", [token], lambda t=token: pbs._shell_declared_env_key(t))
                add(
                    "shell_declaration_exports_env",
                    [segment[index + 1 :]],
                    lambda s=segment, i=index: pbs._shell_declaration_exports_env(s[i + 1 :]),
                )
                add(
                    "shell_set_exports_assignments",
                    [segment[index + 1 :]],
                    lambda s=segment, i=index: pbs._shell_set_exports_assignments(s[i + 1 :]),
                )
        for cwd in ABS_CWDS:
            add(
                "looks_like_safe_python_module_invocation",
                [text, cwd_args(cwd)],
                lambda p=parts, c=cwd: pbs._looks_like_safe_python_module_invocation(p, cwd=cwd_path(c)),
            )
            add(
                "looks_like_bounded_python_script_invocation",
                [text, cwd_args(cwd)],
                lambda p=parts, c=cwd: pbs._looks_like_bounded_python_script_invocation(p, cwd=cwd_path(c)),
            )
            add(
                "looks_like_supported_python_invocation",
                [text, cwd_args(cwd)],
                lambda p=parts, c=cwd: pbs._looks_like_supported_python_invocation(p, cwd=cwd_path(c)),
            )
            add(
                "looks_like_safe_pytest_binary_invocation",
                [text, cwd_args(cwd)],
                lambda p=parts, c=cwd: pbs._looks_like_safe_pytest_binary_invocation(p, cwd=cwd_path(c)),
            )
    for args in ARG_LISTS + [[t] for t in TOKENS[:6]]:
        add("python_inline_script_runs_pytest", [args], lambda a=args: ptd._python_inline_script_runs_pytest(a))
        for cwd in ABS_CWDS:
            if cwd is None:
                continue
            add(
                "bounded_python_script_path",
                [args, cwd_args(cwd)],
                lambda a=args, c=cwd: pbs._bounded_python_script_path(a, cwd=cwd_path(c)),
            )
    for operand in [
        "script.py",
        "./script.py",
        "bin/run.py",
        "../outside/out.py",
        "esc.py",
        "ok_link.py",
        "dangling.py",
        "dirpy.py",
        "notpy.txt",
        "/abs/x.py",
        "-",
        "$(x).py",
        "`x`.py",
        "ruff_target.py",
        "\u00e9.py",
        "a" * 300 + ".py",
        "missing.py",
        "linkdir/test_b.py",
        "pkg/test_b.py",
        "script.py/",
        ".py",
    ]:
        for prefix in (
            [],
            ["--"],
            ["-u"],
            ["-W", "x"],
            ["-Wx"],
            ["-X", "y"],
            ["-"],
            ["-c"],
            ["-m"],
            ["-mx"],
            ["--command=x"],
            ["-cx"],
            ["--check-hash-based-pycs", "z"],
        ):
            for suffix in ([], [">", "out"], ["2>&1"], ["arg"]):
                args = [*prefix, operand, *suffix]
                for cwd in ("proj", "proj/bin", "outside", "empty", "proj/missing"):
                    add(
                        "bounded_python_script_path",
                        [args, cwd_args(cwd)],
                        lambda a=args, c=cwd: pbs._bounded_python_script_path(a, cwd=cwd_path(c)),
                    )
    for _token_name, token in [("a", "pytest"), ("b", "/x/pytest"), ("c", "x\\pytest"), ("d", "pytest.exe"), ("e", "")]:
        for args in PYTEST_ARG_LISTS[:40]:
            for cwd in ABS_CWDS:
                add(
                    "pytest_binary_segment_is_safe",
                    [token, args, cwd_args(cwd)],
                    lambda t=token, a=args, c=cwd: pbs._pytest_binary_segment_is_safe(t, a, cwd=cwd_path(c)),
                )
    for command in ("cd", "pushd", "popd", "ls", "echo", "cat", ""):
        for args in [
            [],
            ["-"],
            ["--"],
            ["-P"],
            ["x"],
            ["x", "y"],
            ["$(x)"],
            ["`x`"],
            ["x", ">", "o"],
            ["x", "2>&1"],
            ["-", "x"],
            ["--", "-x"],
            ["-n"],
            [">"],
            ["$(x)", ">o"],
            ["\u00e9"],
            ["a;b"],
        ]:
            add(
                "shell_directory_setup_segment_is_safe",
                [command, args],
                lambda c=command, a=args: pbs._shell_directory_setup_segment_is_safe(c, a),
            )
    for token in ["PATH", "path", "PATH=/x", "PATH+=x", "A=b", "", "=x", "-x", "--", "x=", "pytest_addopts"]:
        add("shell_declared_env_key", [token], lambda t=token: pbs._shell_declared_env_key(t))
    for args in [
        [],
        ["-x"],
        ["-xr"],
        ["-rx"],
        ["-r"],
        ["--"],
        ["-x", "--"],
        ["--", "-x"],
        ["+x"],
        ["-"],
        ["--x"],
        ["-p"],
        ["x"],
        ["A=1", "-x"],
        ["---x"],
        ["-\u00e9x"],
    ]:
        add("shell_declaration_exports_env", [args], lambda a=args: pbs._shell_declaration_exports_env(a))
    for args in [
        [],
        ["-a"],
        ["-k"],
        ["allexport"],
        ["keyword"],
        ["-o"],
        ["-o", "allexport"],
        ["-o", "keyword"],
        ["-o", "x"],
        ["+o"],
        ["+o", "allexport"],
        ["+o", "x", "-a"],
        ["-ex"],
        ["-e"],
        ["-ak"],
        ["--"],
        ["--", "-a"],
        ["-e", "-a"],
        ["--ak"],
        ["+a"],
        ["-"],
        ["-x", "-o"],
        ["x", "-k"],
        ["--allexport"],
        ["-\u00e9a"],
    ]:
        add("shell_set_exports_assignments", [args], lambda a=args: pbs._shell_set_exports_assignments(a))
    # Inline payloads (lexical over-approximation); every case is approximate.
    for payload in [
        "",
        "1",
        "print(1)",
        "import pytest",
        "import pytest\npytest.main()",
        "pytest.main()",
        "import pytest as p\np.main()",
        "from pytest import main\nmain()",
        "from pytest import main as m\nm()",
        "from pytest import console_main\nconsole_main()",
        "import importlib\nimportlib.import_module('pytest').main()",
        "from importlib import import_module\nimport_module('pytest').main()",
        "import runpy\nrunpy.run_module('pytest')",
        "from runpy import run_module\nrun_module('pytest')",
        "import os\nos.system('pytest')",
        "import os\nos.system('ls')",
        "from os import popen\npopen('py.test')",
        "import subprocess\nsubprocess.run(['pytest'])",
        "import subprocess\nsubprocess.run(args=['pytest'])",
        "import subprocess as sp\nsp.call('pytest -q', shell=True)",
        "from subprocess import Popen\nPopen(['python', '-m', 'pytest'])",
        "eval('1')",
        "exec('import pytest\\npytest.main()')",
        "exec('print(1)')",
        "def f(:",
        "print('pytest')",
        "x = 'pytest'",
        'print("py" "test")',
        "print('\\x70ytest')",
        "pytest",
        "(pytest)",
        "\u0070ytest()",
        "\uff50ytest.main()",
        "# pytest main()",
        "a = pytest.main",
        "1 +",
        "\x00",
        "print(1)" * 100,
        "exec('exec(\"exec(1)\")')",
        "exec(" * 12 + "'pytest.main()'" + ")" * 12,
        "import os, subprocess\nsubprocess.check_output('py.test')",
        "__import__('pytest').main()",
        "getattr(__import__('pytest'), 'main')()",
        "print(1)\n" * 400,
        "pytest.console_main()",
        "import pytest; pytest.main()",
    ]:
        add("inline_python_payload_runs_pytest", [payload], lambda p=payload: ptd._inline_python_payload_runs_pytest(p))
        extra.append({"fn": "__approx_marker__", "args": [], "result": None}) if False else None
    return extra


def main() -> None:
    out_dir = Path(sys.argv[1])
    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw).resolve()
        tree = _build(root)
        cases = _cases(root)
    for case in cases:
        if case["fn"] == "inline_python_payload_runs_pytest":
            case["approx"] = True
    document = {"tree": tree, "cases": cases}
    out_dir.mkdir(parents=True, exist_ok=True)
    target = out_dir / "pytest_helpers.json.gz"
    with gzip.GzipFile(target, "wb", mtime=0) as handle:
        handle.write(json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode())
    print(f"{len(cases)} cases")


if __name__ == "__main__":
    main()
