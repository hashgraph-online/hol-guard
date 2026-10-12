"""Record parity vectors for the interpreter launch, identity, trust and observer helpers.

Usage: ``sfrs_interpreter_cases.py FIXTURE_DIR``. The pytest recorder's tree and
command corpus are reused and extended. Host-dependent behavior is recorded as
facts: ``build_runtime_executable_identity`` (a native worker call) is replaced
by a deterministic stub whose calls are stored with each case, ``sys.executable``
and the environment are fixed, and the reuse nonce is constant. Paths carry the
``{ROOT}`` token so the Rust port can rebuild the tree and replay every case.
This script depends on the Python implementation and is retired with it.
"""

from __future__ import annotations

import gzip
import json
import os
import re
import secrets
import shlex
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import sfrs_pytest_cases as pcases

from codex_plugin_scanner.guard.runtime.secret_file_request_services import (
    destructive_shell_detection as dsd,
)
from codex_plugin_scanner.guard.runtime.secret_file_request_services import (
    developer_inspection as devi,
)
from codex_plugin_scanner.guard.runtime.secret_file_request_services import (
    github_pr_body_safety as gpb,
)
from codex_plugin_scanner.guard.runtime.secret_file_request_services import (
    interpreter_identity as iid,
)
from codex_plugin_scanner.guard.runtime.secret_file_request_services import (
    interpreter_launch as ilaunch,
)
from codex_plugin_scanner.guard.runtime.secret_file_request_services import (
    interpreter_observers as obs,
)
from codex_plugin_scanner.guard.runtime.secret_file_request_services import (
    interpreter_trust as itrust,
)
from codex_plugin_scanner.guard.runtime.secret_file_request_services.shell_tokenization import (
    _iter_shell_command_segments,
    _shell_segment_primary_command,
    _split_shell_parts,
)

NONCE = "ab" * 16
PATHS = [
    "/opt/zz/bin:/opt/yy/bin",
    "/opt/t_unres/bin",
    "/opt/t_loose/bin:/opt/yy/bin",
    "venv/bin:/opt/zz/bin",
    "",
    "$X:/opt/zz/bin",
]

INTERP_TEXTS = [
    "rg foo",
    "rg -n foo src",
    "rg --hidden foo",
    "rg -uu foo",
    "rg -u foo",
    "RIPGREP_CONFIG_PATH= rg foo",
    "RIPGREP_CONFIG_PATH=x rg foo",
    "RIPGREP_CONFIG_PATH= rg --no-config foo",
    "RIPGREP_CONFIG_PATH= ls",
    "A=1 rg foo",
    "rg --no-config foo",
    "grep -r x . | head",
    "ls | head -5",
    "cat a && ls",
    "cat a 2>/dev/null",
    "cat a 2>&1",
    "cat a 2> /dev/null",
    "cat a 2>/dev/null | head",
    "cat a 1>/dev/null",
    "cat a 2>/dev/null; ls",
    "cat a >/dev/null",
    "git status",
    "fd x",
    "find . -name x | sort",
    "head -n1 ~/x",
    "cat ~/.ssh/id_rsa",
    "cat $HOME/x",
    "ls /etc",
    "rg x | rg y",
    "rg x |& head",
    "rg x; ls",
    "rg x || ls",
    "rg x & ls",
    "sed -n 1p x | tr a b",
    "echo `x`",
    "wc -l x | sort | uniq",
    "cat x | xargs rm",
    "cat /usr/bin/x 2> /dev/null",
    "ls -la 2>/dev/null",
    "ls &&",
    "&& ls",
    "ls | | head",
    "| ls",
    "ls && | head",
    "/bin/ls",
    "./ls",
    "ls \\x",
    "cat x | head -n 5 | tail -n 2",
    "cat x | grep y | sort",
    "cat x | sort | head && ls",
    "ls 2>'/dev/null'",
    'ls 2>"/dev/null")',
    "ls 2>/dev/null)",
    "ls 2>/dev/null;",
    "ls 2>/dev/NULL",
    "ls 2>/dev/null,",
    "ls 2>/dev/zero",
    "ls 2>x",
    "ls 3>/dev/null",
    "ls a2>/dev/null",
    "python - <<'EOF'\nprint(1)\nEOF",
    "python3 <<EOF\nimport os\nos.listdir('.')\nEOF",
    "python - <<EOF\nopen('x','w')\nEOF",
    "python3 - <<'PY'\nimport json\nprint(json.dumps({}))\nPY",
    "python3 - x <<EOF\nprint(1)\nEOF",
    "python3 -u - <<EOF\nprint(1)\nEOF",
    "python3 -c 'print(1)' <<EOF\nprint(2)\nEOF",
    "node <<EOF\nconsole.log(1)\nEOF",
    "ruby <<EOF\nputs 1\nEOF",
    "perl <<EOF\nprint 1\nEOF",
    "bash <<EOF\nls\nEOF",
    "sh <<EOF\nrm x\nEOF",
    "cat <<EOF | python3 -\nprint(1)\nEOF",
    "python3 <<EOF\nprint(1)\nEOF\nls",
    "python3 <<EOF\nprint(1)\nEOF && ls",
    "python3 <<EOF\nEOF",
    "python3 <<EOF\n\nEOF",
    "python3 <<'EOF'\nimport subprocess\nsubprocess.run(['ls'])\nEOF",
    "python3 <<-EOF\n\tprint(1)\n\tEOF",
    "python3 << EOF\nprint(1)\nEOF",
    "python3 <<EOF >out\nprint(1)\nEOF",
    "python3 <<EOF\nprint(1)\nEOF\npython3 <<EOF\nprint(2)\nEOF",
    "python3 -m json.tool x",
    "python3 -m json.tool <<EOF\n{}\nEOF",
    "python -c 'print(1)'",
    "python3 -c 'import os; os.remove(\"x\")'",
    "python -m json.tool x",
    "python -c 'import time; time.sleep(3)'",
    "python3 -c 'import time; time.sleep(3)' && echo done",
    "sleep 3 && python -c 'print(1)'",
    "node -e 'console.log(1)'",
    "ruby -e 'puts 1'",
    "perl -e 'print 1'",
    "python -c 'print(1)' | head",
    "python -c 'print(1)'; ls",
    "ls && python -c 'print(1)' && ls",
    "cat x && python3 -c 'import json; json.load(open(\"x\"))'",
    "echo done && python -c 'print(1)'",
    "python -m pytest && python -c 'print(1)'",
    "python -c 'print(1)' && python -c 'print(2)'",
    "python -c 'print(1)' && python -m x",
    "python3 -c \"import time; time.sleep(2); print('ok')\"",
    "python3 -c 'import time; time.sleep(1)' && echo done && echo ok",
    "python3 -c 'import time; time.sleep(1)' && echo done; ls",
    "python3 -c 'import time; time.sleep(1)' && echo done | tee x",
    "python3 -c 'import time; time.sleep(1)' && echo $(x)",
    "python3 -c 'import time; time.sleep(1)' && true",
    "echo x && python3 -c 'import time; time.sleep(1)'",
    "python3 -c 'import time; time.sleep(1)' && python3 -c 'import time; time.sleep(1)'",
    "python3 -c 'import time; time.sleep(1)'",
    "python3 -c 'import time; time.sleep(1)' && echo done >out",
    "python3 -c 'import time; time.sleep(1)' && printf done",
    "python3 -c 'print(1)' && cat x",
    "python3 -c 'print(1)' && cat x | head",
    "python3 -c 'print(1)' && rg x",
    "python3 -c 'print(1)'\nrg x",
    "python3 -c 'print(1)' && python3 -c 'import os; os.listdir()' && ls",
    "python3 -c 'x' && rg x && ls",
    "rg x && python3 -c 'print(1)'",
    "python3 -E -c 'print(1)'",
    "python3 -m x -c 'print(1)'",
    "python3 x.py",
    "python3 -I x.py",
    "python3 -Bm x",
    "python3 -Wm x",
    "python3 -W e -m x",
    "python3 -X dev -mx",
    "python3 -Xdev -m x",
    "python3 --check-hash-based-pycs always -m x",
    "python3 -- -m x",
    "python3 -bm x",
    "python3 -qm x",
    "python3 -xm x",
    "python3 -mm",
    "python3 -m",
    "python3 -c",
    "python3 --command=x",
    "python3 -cx",
    "python3 -",
    "python3 -uX",
    "python3 -OOm x",
    "python3 -hm x",
    "python3 -bBdEhiIOPqRsSuvVm x",
    "python3 -bBdEhiIOPqRsSuvVxm x",
    "python3 -m x; python3 -c 'print(1)'",
    "python3 -c 'print(1)' && python3 -m x",
    "python3 -m pytest",
    "uv run python -m x",
    "python3 -m x\npython3 -c 'print(1)'",
    "python3 --version",
    "/opt/zz/bin/python3 -V",
    "./venv/bin/python3 x.py",
    "venv/bin/python3 x.py",
    "env python3 x",
    "env -i python3 x",
    "env PATH=/opt/yy/bin python3 x",
    "env PATH=$X python3 x",
    "env PATH=`x` python3 x",
    "env -u PATH python3 x",
    "env -S 'python3 x'",
    "env -C proj python3 x",
    "env -C missing python3 x",
    "env -C '$X' python3 x",
    "env --unknown python3 x",
    "env -",
    "env",
    "env FOO=1",
    "sudo python3 x",
    "sudo -D proj python3 x.py",
    "sudo -D sudo_missing python3",
    "sudo -D sudo_file python3",
    "sudo -D sudo_link python3",
    "sudo -D sudo_d python3",
    "sudo -Dsudo_d python3",
    "sudo --chdir=sudo_d python3",
    "sudo --chdir sudo_d python3",
    "sudo -D",
    "sudo -D '' python3",
    "sudo -D '$X' python3",
    "sudo -R x python3",
    "sudo --chroot=x python3",
    "sudo -Rx python3",
    "sudo -- python3",
    "sudo -u root python3",
    "sudo -E python3",
    "sudo -D ~ python3",
    "sudo -D ~/x python3",
    "sudo",
    "sudo -u",
    "sudo env python3",
    "env sudo python3",
    "sudo sudo python3",
    "nohup python3 x",
    "command -p python3",
    "command python3",
    "command -v python3",
    "command -pv python3",
    "command",
    "time python3",
    "time -p python3",
    "nice python3",
    "nice -n 5 python3",
    "stdbuf -o0 python3",
    "timeout 5 python3",
    "exec python3",
    "xargs python3",
    "builtin python3",
    "setsid python3",
    "bash -c 'python3 x'",
    "sh -c \"bash -c 'python3 x'\"",
    "bash -lc 'python3 x'",
    "bash -c",
    "bash -c ''",
    "sh -c 'echo $(python3 -V)'",
    "dash -c 'python3 x; python x'",
    "echo $(python3 -V)",
    "echo `python3 -V`",
    "echo $(echo $(python3 -V))",
    "python3 x; python x; python3 x",
    "FOO=1 python3 x",
    "PATH=/opt/yy/bin python3 x",
    "PATH+=:/x python3",
    "PATH=$X python3",
    "PATH+=$X python3",
    "PATH=/opt/t_unres/bin python3",
    "PATH=/opt/t_loose/bin python3",
    "PATH= python3",
    "FOO+=1 python3",
    "python3 >out x",
    ">out python3 x",
    "2>&1 python3",
    "<in python3 x",
    "python3>out",
    "python3 2>/dev/null",
    "cd proj/pkg && python3 x",
    "cd missing && python3 x",
    "cd $X && python3 x",
    "cd proj; python3 x",
    "cd proj && cd .. && python3 x",
    "pushd proj && python3 x",
    "(python3 x)",
    "{ python3 x; }",
    "python3.12 x",
    "python3.1.2 x",
    "pythonw x",
    "python.exe x",
    "python3.exe x",
    "pythonw3.exe x",
    "python3. x",
    "py x",
    "pypy x",
    "C:\\python\\python.exe x",
    "c:python.exe x",
    "//server/python x",
    "/opt/t_unres/python3 x",
    "/opt/t_nonexec/python3 x",
    "/opt/t_unread/python3 x",
    "/opt/t_foreign/python3 x",
    "/opt/t_invalid/python3 x",
    "/opt/t_changed/python3 x",
    "/opt/t_weird/python3 x",
    "/opt/t_nopath/python3 x",
    "/opt/t_loose/python3 x",
    "/opt/t_nochain/python3 x",
    "/opt/t_boolmode/python3 x",
    "/opt/t_guard/python3 x",
    "/opt/t_guardsib/python3 x",
    "/opt/t_guardreal/python3 x",
    "/usr/local/t_stable/bin/python3 x",
    "/usr/local/t_loose/bin/python3 x",
    "/opt/homebrew/bin/python3 x",
    "/opt/hostedtoolcache/Python/3.12/x64/bin/python3 x",
    "/home/linuxbrew/.linuxbrew/bin/python3 x",
    "~/py/python3 x",
    "~/.venv/bin/python3 x",
    "proj/t_ws/python3 x",
    "./t_ws/python3 x",
    "t_home/python3 x",
    "python3 x && /opt/t_unres/python3 y",
    "/opt/t_unres/python3 x | /opt/t_loose/python3 y",
    "sudo /opt/zz/bin/python3 x",
    "sudo -D sudo_d /opt/zz/bin/python3",
    "env python3 x | python3 y",
    "echo x | python3 -",
    "python3 x $(python3 y)",
    "python3 -c 'import os'",
    "echo ok",
    "ls",
    "",
    "   ",
    "python3 \u00e9",
]

SUDO_ARGS = [
    ["python3"],
    ["-D", "sudo_d", "python3"],
    ["-D", "sudo_link", "python3"],
    ["-D", "sudo_file", "python3"],
    ["-D", "sudo_missing", "python3"],
    ["-D"],
    ["-D", ""],
    ["-D", "$X", "python3"],
    ["-D", "a`b`", "python3"],
    ["-D", "a\x00b", "python3"],
    ["-Dsudo_d", "python3"],
    ["-D", "~", "python3"],
    ["-D", "~/x", "python3"],
    ["--chdir=sudo_d", "python3"],
    ["--chdir", "sudo_d", "python3"],
    ["--chdir"],
    ["--chdir="],
    ["-R", "x", "python3"],
    ["--chroot=x", "python3"],
    ["-Rx", "python3"],
    ["--chroot", "x", "python3"],
    ["-R"],
    ["--", "python3"],
    ["-D", "sudo_d", "--", "python3"],
    ["-u", "root", "python3"],
    ["-E", "python3"],
    ["-E", "-D", "sudo_d", "-R", "x", "python3"],
    ["-R", "x", "-D", "sudo_d", "python3"],
    ["-D", "sudo_d", "-D", "sudo_missing", "python3"],
    ["-D", "sudo_missing", "-D", "sudo_d", "python3"],
    ["-Z", "python3"],
    ["-"],
    ["--"],
    [],
    ["-D", "../sudo/sudo_d", "python3"],
    ["-D", "sudo_d/..", "python3"],
    ["-D", "sudo_d/.", "python3"],
    ["-D", "sudo_d/missing/..", "python3"],
    ["-D", "/", "python3"],
    ["-D", "sudo_d", "x", "-D", "sudo_missing"],
    ["-D", "\u00e9", "python3"],
    ["-D", " ", "python3"],
    ["--chdir=$X", "python3"],
    ["-D", "sudo_d\n", "python3"],
    ["-i", "python3"],
    ["-g", "wheel", "python3"],
    ["-Dsudo_missing", "python3"],
    ["-D", "sudo_d", "-u", "x", "python3"],
    ["--user=x", "--chdir=sudo_d", "python3"],
]

CHAIN_VARIANTS: list[object] = [
    None,
    [],
    {},
    "x",
    1,
    [{"mode": 0o100755}],
    [{"mode": 0o100777}],
    [{"mode": 0o100775}],
    [{"mode": 0o100757}],
    [{"mode": 0o100752}],
    [{"mode": 0o100755}, {"mode": 0o100777}],
    [{"mode": 0o100755}, {"mode": 0o100755}],
    [{"mode": True}],
    [{"mode": False}],
    [{"mode": 1.5}],
    [{"mode": "755"}],
    [{"mode": None}],
    [{}],
    [{"path": "x"}],
    ["x"],
    [None],
    [1],
    [[]],
    [{"mode": 0}],
    [{"mode": -1}],
    [{"mode": -23}],
    [{"mode": 2**63}],
    [{"mode": 2**64 + 0o022}],
    [{"mode": 2**64}],
    [{"mode": 18446744073709551615}],
    [{"mode": 0o022}],
    [{"mode": 0o020}],
    [{"mode": 0o002}],
    [{"mode": 0o700}, {"mode": 0o755}, {"mode": 0o644}],
    [{"mode": 0o100755}, "x"],
    [{"mode": 0o100755}, None],
    [{"mode": 0o100755}, {}],
    [{"mode": 0o100755}, {"mode": None}],
    [{"mode": 1e3}],
    [{"mode": [1]}],
]


def _fake_identity_factory(guard: Path, calls: list[list[object]]) -> Callable[..., dict[str, object]]:
    def fake(command: str, *, search_path: str | None = None, cwd: Path | str | None = None) -> dict[str, object]:
        cwd_text = str(cwd)
        if False:
            raise AssertionError
        pathlike = "/" in command or "\\" in command or re.match(r"^[A-Za-z]:", command) or command.startswith("//")
        launch: str | None
        if pathlike:
            if "\\" in command or re.match(r"^[A-Za-z]:", command) or command.startswith("//"):
                launch = None
                identity: dict[str, object] = {"command": command, "status": "foreign_platform_path"}
            else:
                launch = os.path.normpath(os.path.join(cwd_text, os.path.expanduser(command)))
        else:
            launch = None
            identity = {"command": command, "status": "unresolved"}
            for entry in (search_path or "").split(":"):
                if not entry or "$" in entry:
                    continue
                base = entry if os.path.isabs(entry) else os.path.join(cwd_text, entry)
                launch = os.path.normpath(os.path.join(base, command))
                break
        if launch is None:
            result = identity
        else:
            tags = {part[2:] for part in launch.split("/") if part.startswith("t_")}
            canonical = launch
            if "guard" in tags:
                launch = str(guard)
                canonical = os.path.realpath(guard)
            elif "guardsib" in tags:
                launch = str(guard.parent / "python3.99")
                canonical = os.path.realpath(guard)
            elif "guardreal" in tags:
                launch = os.path.realpath(guard)
                canonical = launch
            result = {
                "command": command,
                "launch_path": launch,
                "path": canonical,
                "path_chain": [{"mode": 0o100755, "path": launch, "uid": 0}],
                "sha256": "00" * 32,
                "status": "verified",
            }
            for tag, status in (
                ("unres", "unresolved"),
                ("nonexec", "not_executable"),
                ("unread", "unreadable"),
                ("foreign", "foreign_platform_path"),
                ("invalid", "invalid_path"),
                ("changed", "path_changed"),
                ("weird", "weird_status"),
            ):
                if tag in tags:
                    result["status"] = status
            if "nopath" in tags:
                del result["path"]
            if "loose" in tags:
                result["path_chain"] = [{"mode": 0o100777, "path": launch, "uid": 0}]
            if "nochain" in tags:
                del result["path_chain"]
            if "boolmode" in tags:
                result["path_chain"] = [{"mode": True, "path": launch}]
        calls.append([command, search_path, cwd_text, result])
        return result

    return fake


def _extra_tree(root: Path, tree: dict[str, object]) -> None:
    dirs = ["home", "home/.ssh", "sudo/sudo_d", "sudo/sudo_d/sub", "guard/bin", "proj/venv/bin", "proj/t_ws"]
    for name in dirs:
        (root / name).mkdir(parents=True, exist_ok=True)
        tree["dirs"].append(name)  # type: ignore[union-attr]
    (root / "sudo/sudo_file").write_text("x")
    tree["files"]["sudo/sudo_file"] = "x"  # type: ignore[index]
    (root / "guard/bin/python3.11").write_text("x")
    tree["files"]["guard/bin/python3.11"] = "x"  # type: ignore[index]
    os.symlink("sudo_d", root / "sudo/sudo_link")
    tree["links"]["sudo/sudo_link"] = "sudo_d"  # type: ignore[index]
    os.symlink("python3.11", root / "guard/bin/python")
    tree["links"]["guard/bin/python"] = "python3.11"  # type: ignore[index]


class _Segment:
    """Stand-in for a modeled shell segment (the real model is a native call)."""

    def __init__(self, tokens: list[str]) -> None:
        self.tokens = tuple(tokens)
        self.directory_operation = None


class _Context:
    def __init__(self, segments: list[_Segment], cwd: Path | None) -> None:
        self.segments = tuple(segments)
        self.cwd = cwd


def _stand_in_model(
    command_text: str, *, cwd: Path | None = None, workspace_root: Path | None = None, **_kw: object
) -> _Context:
    return _Context([_Segment(segment) for segment in _segments(command_text)], cwd)


def _stand_in_validate(context: _Context, _segment: object) -> tuple[Path | None, str | None]:
    return context.cwd, None


# The stand-in model above is exact only for flat, literal command lines.
CD_WORD = re.compile(r"\b(cd|pushd|popd|eval)\b|^\s*[({]|[{}]|''|\"\"|\(\(")


def _deep_shell(depth: int, inner: str) -> str:
    text = inner
    for _ in range(depth):
        text = "sh -c " + shlex.quote(text)
    return text


def _segments(text: str) -> list[list[str]]:
    return _iter_shell_command_segments(_split_shell_parts(text))


def main() -> None:
    out_dir = Path(sys.argv[1]).resolve()
    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw).resolve()
        tree = pcases._build(root)
        _extra_tree(root, tree)
        guard = root / "guard/bin/python"
        env = {"HOME": str(root / "home"), "LANG": "C", "PATH": "/opt/zz/bin:/opt/yy/bin"}
        os.environ.clear()
        os.environ.update(env)
        os.chdir(root)
        sys.executable = str(guard)
        secrets.token_hex = lambda *_a, **_k: NONCE  # type: ignore[assignment]
        calls: list[list[object]] = []
        iid.model_shell_execution_context = _stand_in_model  # type: ignore[assignment]
        iid.validate_shell_execution_segment = _stand_in_validate  # type: ignore[assignment]
        itrust.validate_shell_execution_segment = _stand_in_validate  # type: ignore[assignment]
        ilaunch.build_runtime_executable_identity = _fake_identity_factory(guard, calls)  # type: ignore[assignment]
        probe = pcases._Probe()
        probe.install()
        cases: list[dict[str, object]] = []
        skipped = {"n": 0}

        def add(function: str, args: list[object], thunk: Callable[[], object]) -> None:
            probe.hit = False
            calls.clear()
            try:
                result = thunk()
            except (RecursionError, ValueError, OSError, RuntimeError):
                skipped["n"] += 1
                return
            entry: dict[str, object] = {
                "fn": function,
                "args": pcases._text(root, args),
                "result": pcases._text(root, result),
            }
            if calls:
                seen: list[list[object]] = []
                for call in calls:
                    if call not in seen:
                        seen.append(call)
                entry["calls"] = pcases._text(root, seen)
            if probe.hit:
                entry["approx"] = True
            cases.append(entry)

        rel = lambda value: pcases._rel(value, root)  # noqa: E731
        path = lambda value: None if value is None else Path(rel(value))  # noqa: E731
        home = str(root / "home")
        texts = pcases.TEXTS + INTERP_TEXTS
        record_observers(add, texts, home)
        record_trust(add, root, texts, rel, path, home, guard)
        record_launch(add, root, texts, rel, path, home)
        record_identities(add, root, texts, rel, path, home)
        probe.restore()
    for case in cases:
        if "calls" in case:
            case["calls"] = case["calls"]
    document = {
        "tree": tree,
        "env": pcases._text(root, env),
        "guard": pcases._text(root, str(guard)),
        "nonce": NONCE,
        "cases": cases,
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    target = out_dir / "interpreter.json.gz"
    with gzip.GzipFile(target, "wb", mtime=0) as handle:
        handle.write(json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode())
    counts: dict[str, int] = {}
    for case in cases:
        counts[str(case["fn"])] = counts.get(str(case["fn"]), 0) + 1
    for name, count in sorted(counts.items()):
        print(f"{name}: {count}")
    print(f"{len(cases)} cases, {skipped['n']} skipped")


def record_observers(add: Callable[..., None], texts: list[str], home: str) -> None:
    for text in texts:
        parts = _split_shell_parts(text)
        names = []
        for segment in _iter_shell_command_segments(parts):
            name, index = _shell_segment_primary_command(segment)
            if name is not None and index is not None:
                names.append(name)
        for home_dir in (None, home):
            add(
                "looks_like_safe_read_only_lookup_command",
                [text, parts, home_dir],
                lambda t=text, p=parts, h=home_dir: obs._looks_like_safe_read_only_lookup_command(
                    t, p, home_dir=None if h is None else Path(h)
                ),
            )
            add(
                "looks_like_read_only_interpreter_compound",
                [text, parts, home_dir],
                lambda t=text, p=parts, h=home_dir: obs._looks_like_read_only_interpreter_compound(
                    t, p, home_dir=None if h is None else Path(h)
                ),
            )
        add("read_only_lookup_segments", [parts], lambda p=parts: obs._read_only_lookup_segments(p))
        add(
            "contains_pytest_env_shell_script_wrapper",
            [parts],
            lambda p=parts: obs._contains_pytest_env_shell_script_wrapper(p),
        )
        add("parts_use_python_module_mode", [parts], lambda p=parts: obs._parts_use_python_module_mode(p))
        add(
            "looks_like_benign_interpreter_wait_chain",
            [text, parts],
            lambda t=text, p=parts: obs._looks_like_benign_interpreter_wait_chain(t, p),
        )
        for name_list in (names, [], names + names[:1], names[:1]):
            add(
                "looks_like_benign_interpreter_wait",
                [text, parts, name_list],
                lambda t=text, p=parts, n=name_list: obs._looks_like_benign_interpreter_wait(t, p, n),
            )
            add(
                "looks_like_read_only_interpreter_command",
                [text, parts, name_list],
                lambda t=text, p=parts, n=name_list: obs._looks_like_read_only_interpreter_command(t, p, n),
            )
        add("single_interpreter_heredoc_script", [text], lambda t=text: dsd._single_interpreter_heredoc_script(t))
        add(
            "single_interpreter_heredoc_interpreter",
            [text],
            lambda t=text: obs._single_interpreter_heredoc_interpreter(t),
        )
        add("single_interpreter_heredoc_args", [text], lambda t=text: obs._single_interpreter_heredoc_args(t))
        add("shell_heredoc_payloads", [text], lambda t=text: list(gpb._shell_heredoc_payloads(t)))
        add("shell_script_targets_pytest", [text], lambda t=text: dsd._shell_script_targets_pytest(t))
        add("normalized_redirect_target", [text], lambda t=text: dsd._normalized_redirect_target(t))
        add(
            "is_read_only_observer_interpreter_command",
            [text],
            lambda t=text: devi._is_read_only_observer_interpreter_command(t),
        )
    for token in [
        *pcases.REDIRECTION_TOKENS,
        "2>/dev/null",
        "2>/dev/null)",
        "2>'/dev/null'",
        '2>"/dev/null"',
        "2>/dev/null;",
        "2>/dev/null,",
        "2>/DEV/NULL",
        "2>/dev/null\n",
        " 2>/dev/null",
        "2>&1",
        "2>&-",
        "2>>/dev/null",
        "2>|/dev/null",
        "x2>/dev/null",
        "12>/dev/null",
        "2>/dev/null x",
        "&>/dev/null",
        "2>/dev//null",
        "2>./x",
        "2>",
        "",
        "2>é",
    ]:
        add(
            "read_only_lookup_token_is_safe_stderr_discard",
            [token],
            lambda t=token: obs._read_only_lookup_token_is_safe_stderr_discard(t),
        )
    for args in [
        *pcases.ARG_LISTS,
        ["-m"],
        ["-bm"],
        ["-Bm", "x"],
        ["-bBdEhiIOPqRsSuvVm"],
        ["-bBdEhiIOPqRsSuvVxm"],
        ["-c"],
        ["--"],
        ["-Wm"],
        ["-W", "-m"],
        ["-X", "-m"],
        ["-Xm"],
        ["-Wmx"],
        ["--check-hash-based-pycs"],
        ["--check-hash-based-pycsm"],
        ["-um"],
        ["-u", "x", "-m"],
        ["--x", "-m"],
        ["-", "-m"],
        ["-mé"],
        ["ém"],
        ["-ém"],
        ["-mm"],
        ["-1m"],
        ["+m"],
        ["-m", "-m"],
        ["-ccm"],
    ]:
        add("python_args_use_module_mode", [args], lambda a=args: obs._python_args_use_module_mode(a))
    for name in [
        "python",
        "python3",
        "node",
        "nodejs",
        "ruby",
        "perl",
        "php",
        "bash",
        "sh",
        "deno",
        "bun",
        "lua",
        "Rscript",
        "node.exe",
        "/usr/bin/python",
        "",
        "pythonx",
        "tsx",
        "ts-node",
        "osascript",
        "awk",
        "jq",
    ]:
        add(
            "is_read_only_observer_interpreter_command",
            [name],
            lambda n=name: devi._is_read_only_observer_interpreter_command(n),
        )
    for token in [
        "",
        "x",
        ")",
        "'x'",
        '"x"',
        "'x;'",
        ";x;",
        "(x)",
        " x ",
        ",x,",
        "\"'x'\"",
        "'\"x\"'",
        "\u00e9",
        "/dev/null)",
        "'/dev/null';",
        "\t/dev/null\n",
        "''",
        "')'",
    ]:
        add("normalized_redirect_target", [token], lambda t=token: dsd._normalized_redirect_target(t))


def record_trust(
    add: Callable[..., None],
    root: Path,
    texts: list[str],
    rel: Callable[..., object],
    path: Callable[..., object],
    home: str,
    guard: Path,
) -> None:
    for token in [
        "python",
        "/usr/bin/python",
        "./python",
        "python\\x",
        "C:python",
        "c:\\python",
        "//x",
        "/",
        "\\",
        ":",
        "a:",
        "1:",
        "ab:",
        " /x ",
        "\t",
        "",
        "python3.12",
        "~/p",
        "./",
        "C:",
        "z:/x",
        "\u00e9/x",
        "x//y",
    ]:
        add("interpreter_token_has_path", [token], lambda t=token: itrust._interpreter_token_has_path(t))
    for chain in CHAIN_VARIANTS:
        identity: dict[str, object] = {"status": "verified"}
        if chain is not None:
            identity["path_chain"] = chain
        add(
            "interpreter_identity_path_chain_is_stable",
            [identity],
            lambda i=identity: itrust._interpreter_identity_path_chain_is_stable(i),
        )
    add(
        "interpreter_identity_path_chain_is_stable", [{}], lambda: itrust._interpreter_identity_path_chain_is_stable({})
    )
    for candidate in [
        "proj/x",
        "proj",
        "proj/pkg/x",
        "outside/x",
        "",
        "/opt/zz/x",
        "/",
        "/usr/local/bin/python3",
        "/usr/local",
        "/usr/localx",
        "/usr/local/",
        "../x",
        "./proj/x",
        "proj/../x",
        "/opt/homebrew/bin/python3",
    ]:
        for base in [
            "proj",
            "",
            "outside",
            "/usr/local",
            "/",
            "/opt/homebrew",
            "/opt/zz",
            "/usr/local/bin",
            "x",
            "proj/pkg",
        ]:
            c = (
                rel(candidate)
                if candidate and not candidate.startswith("/") and not candidate.startswith(".")
                else candidate
            )
            b = rel(base) if base and not base.startswith("/") else (base if base else str(root))
            if candidate == "":
                c = ""
            add(
                "interpreter_path_is_within",
                [c, b],
                lambda c=c, b=b: itrust._interpreter_path_is_within(Path(c), Path(b)),
            )
    guard_text = str(guard)
    guard_real = os.path.realpath(guard)
    for token in ["python3", "/opt/zz/bin/python3", "./venv/bin/python3", "x/python3", "\\python", "C:py", "//s/p"]:
        for reason in (None, "env_chdir"):
            for status in [
                "verified",
                "unresolved",
                "unreadable",
                "path_unreadable",
                "not_executable",
                "foreign_platform_path",
                "invalid_path",
                "path_changed",
                "other",
                "",
                None,
                1,
            ]:
                add(
                    "python_interpreter_trust",
                    [
                        token,
                        {"status": status, "launch_path": "/opt/zz/bin/python3", "path": "/opt/zz/bin/python3"},
                        rel("proj"),
                        None,
                        reason,
                    ],
                    lambda t=token, s=status, r=reason: itrust._python_interpreter_trust(
                        t,
                        identity={"status": s, "launch_path": "/opt/zz/bin/python3", "path": "/opt/zz/bin/python3"},
                        workspace_root=Path(rel("proj")),
                        home_dir=None,
                        resolution_reason=r,
                    ),
                )
    chain_ok = [{"mode": 0o100755}]
    chain_bad = [{"mode": 0o100777}]
    launches = [
        (guard_text, guard_real),
        (guard_text, guard_text),
        (guard_real, guard_real),
        (str(Path(guard_text).parent / "python3.99"), guard_real),
        (str(root / "guard/other/python"), guard_real),
        (guard_text, "/x/other"),
        (str(root / "proj/venv/bin/python3"), str(root / "proj/venv/bin/python3")),
        (str(root / "home/py/bin/python3"), str(root / "home/py/bin/python3")),
        ("/usr/local/bin/python3", "/usr/local/bin/python3"),
        ("/opt/homebrew/bin/python3", "/opt/homebrew/Cellar/python3"),
        ("/opt/hostedtoolcache/Python/3.12/x64/bin/python3", "/x"),
        ("/home/linuxbrew/.linuxbrew/bin/python3", "/x"),
        ("/usr/localx/python3", "/usr/localx/python3"),
        ("/opt/zz/bin/python3", "/opt/zz/bin/python3"),
        ("/opt/zz/nonexistent/python3", "/opt/zz/nonexistent/python3"),
        ("relative/python3", "relative/python3"),
        ("", ""),
        ("/", "/"),
        (str(root / "proj"), str(root / "proj")),
        (str(root / "proj/venv/../venv/bin/python3"), "/x"),
        (str(root / "home"), "/x"),
        ("/usr/local", "/usr/local"),
    ]
    for launch, canonical in launches:
        for chain in (chain_ok, chain_bad, None):
            for workspace, home_dir in (
                (rel("proj"), None),
                (rel("proj"), home),
                (rel("home"), home),
                ("/usr/local/bin", None),
                (str(root / "guard"), home),
            ):
                identity = {"status": "verified", "launch_path": launch, "path": canonical}
                if chain is not None:
                    identity["path_chain"] = chain
                add(
                    "python_interpreter_trust",
                    ["/x/python3", identity, workspace, home_dir, None],
                    lambda i=identity, w=workspace, h=home_dir: itrust._python_interpreter_trust(
                        "/x/python3",
                        identity=i,
                        workspace_root=Path(w),
                        home_dir=None if h is None else Path(h),
                        resolution_reason=None,
                    ),
                )
    for bad in [
        {"status": "verified"},
        {"status": "verified", "launch_path": 1, "path": "/x"},
        {"status": "verified", "launch_path": "/x", "path": None},
        {"status": "verified", "launch_path": None, "path": None},
    ]:
        add(
            "python_interpreter_trust",
            ["/x/python3", bad, rel("proj"), None, None],
            lambda i=bad: itrust._python_interpreter_trust(
                "/x/python3", identity=i, workspace_root=Path(rel("proj")), home_dir=None, resolution_reason=None
            ),
        )
    for text in texts:
        for segment in _segments(text):
            name, index = _shell_segment_primary_command(segment)
            if name is None or index is None:
                continue
            add(
                "pytest_args_from_segment",
                [segment, index],
                lambda s=segment, i=index: itrust._pytest_args_from_segment(s, i),
            )
    for text in texts:
        if CD_WORD.search(text) or "$(" in text:
            continue
        for cwd in ("proj", "proj/pkg", "outside", "empty", None):
            cwd_value = None if cwd is None else Path(rel(cwd))
            add(
                "pytest_config_assessment_for_command",
                [text, rel(cwd) if cwd else None],
                lambda t=text, c=cwd_value: pcases._assessment(
                    itrust._pytest_config_assessment_for_command(
                        t, cwd=c, execution_context=_stand_in_model(t, cwd=c, workspace_root=c)
                    )
                ),
            )


def record_launch(
    add: Callable[..., None],
    root: Path,
    texts: list[str],
    rel: Callable[..., object],
    path: Callable[..., object],
    home: str,
) -> None:
    for cwd in [
        None,
        "proj",
        "proj/pkg/../tests",
        "",
        "proj/missing",
        "~",
        "~/x",
        "x/y",
        "/",
        "/opt/zz",
        "proj/linkdir",
        "proj/script.py",
        "sudo/sudo_link",
        ".",
    ]:
        value = None if cwd is None else (rel(cwd) if cwd and not cwd.startswith(("/", "~", ".")) else cwd)
        if cwd == "":
            value = ""
        add(
            "normalized_interpreter_cwd",
            [value],
            lambda v=value: str(ilaunch._normalized_interpreter_cwd(None if v is None else Path(v))),
        )
    for args in SUDO_ARGS:
        for cwd in ("sudo", "proj", "/", "sudo/sudo_d"):
            for start in (0, 1, len(args)):
                if start > len(args):
                    continue
                c = rel(cwd) if not cwd.startswith("/") else cwd
                add(
                    "consume_sudo_wrapper_for_interpreter",
                    [args, start, c],
                    lambda a=args, s=start, c=c: [
                        (r := ilaunch._consume_sudo_wrapper_for_interpreter(a, s, cwd=Path(c)))[0],
                        str(r[1]),
                        r[2],
                    ],
                )
    environments = [
        {},
        {"PATH": "/opt/zz/bin:/opt/yy/bin"},
        {"PATH": "venv/bin:/opt/zz/bin", "FOO": "1"},
        {"PATH": "$X:/opt/zz/bin"},
        {"PATH": "`x`"},
        {"PATH": ""},
    ]
    for text in texts:
        for segment in _segments(text):
            for env in environments[:2] if len(segment) > 8 else environments:
                add(
                    "shell_launch_candidate",
                    [segment, rel("proj"), env, 0, None],
                    lambda s=segment, e=env: _candidate(
                        ilaunch._shell_launch_candidate(s, cwd=Path(rel("proj")), environment=e)
                    ),
                )
            add(
                "shell_launch_candidate",
                [segment, rel("sudo"), environments[1], 0, "seed"],
                lambda s=segment: _candidate(
                    ilaunch._shell_launch_candidate(
                        s, cwd=Path(rel("sudo")), environment=environments[1], resolution_reason="seed"
                    )
                ),
            )
    for depth in (7, 8, 9, 10):
        add(
            "shell_launch_candidate",
            [["env", "python3"], rel("proj"), environments[1], depth, None],
            lambda d=depth: _candidate(
                ilaunch._shell_launch_candidate(
                    ["env", "python3"], cwd=Path(rel("proj")), environment=environments[1], depth=d
                )
            ),
        )
        add(
            "shell_launch_candidate",
            [["python3"], rel("proj"), environments[1], depth, None],
            lambda d=depth: _candidate(
                ilaunch._shell_launch_candidate(
                    ["python3"], cwd=Path(rel("proj")), environment=environments[1], depth=d
                )
            ),
        )
    nested_env = ["env"] * 9 + ["python3"]
    add(
        "shell_launch_candidate",
        [nested_env, rel("proj"), environments[1], 0, None],
        lambda: _candidate(
            ilaunch._shell_launch_candidate(nested_env, cwd=Path(rel("proj")), environment=environments[1])
        ),
    )
    for tokens in (
        [],
        [""],
        ["x", "y"],
        ["python3", "x"],
        ["python3>out"],
        [">out", "python3"],
        ["2>&1", "python3"],
        ["A=1", "B+=2", "python3"],
        ["A=1"],
        ["sudo"],
        ["sudo", "-D", "sudo_d"],
        ["command", "-p"],
        ["command", "-p", "python3"],
        ["command", "-pv", "python3"],
        ["command", "-v", "python3"],
        ["nohup", "-", "python3"],
        ["time", "-p", "python3"],
        ["env", "-i", "python3"],
        ["env", "-u", "PATH", "python3"],
        ["env", "PATH=$X", "python3"],
        ["env", "-S", "PATH=$X python3"],
        ["env", "-C", "sudo_d", "python3"],
        ["env", "-C", "sudo_missing", "python3"],
        ["env"],
        ["env", "A=1"],
        ["sudo", "sudo", "python3"],
        ["exec", "-a", "x", "python3"],
        ["nice", "-n", "5", "python3"],
        ["nice", "-n"],
        ["nice", "-5", "python3"],
        ["timeout", "5", "python3"],
        ["timeout", "-k", "1", "5", "python3"],
        ["stdbuf", "-o0", "python3"],
        ["xargs", "-n", "1", "python3"],
    ):
        for env in environments[:3]:
            add(
                "shell_launch_candidate",
                [tokens, rel("sudo"), env, 0, None],
                lambda t=tokens, e=env: _candidate(
                    ilaunch._shell_launch_candidate(t, cwd=Path(rel("sudo")), environment=e)
                ),
            )
    for tokens in (
        [],
        ["python3"],
        ["x", "python3", "y"],
        ["/opt/zz/python3", "python", "python3.12"],
        ["python3>out", ">out", "'python3'", '"python3"'],
        ["py", "python.exe", "pythonw", "C:\\py\\python.exe"],
        ["/opt/t_unres/python3", "/opt/t_loose/python3", "/usr/local/t_stable/bin/python3"],
        [" python3 ", "\tpython3\n"],
        ["python3", "python3"],
    ):
        for reason in ("seed", "nested_shell_depth_exceeded", "interpreter_wrapper_unresolved"):
            for env in environments[:3]:
                add(
                    "ambiguous_python_evidence_from_tokens",
                    [tokens, rel("proj"), env, rel("proj"), None, reason],
                    lambda t=tokens, r=reason, e=env: list(
                        ilaunch._ambiguous_python_evidence_from_tokens(
                            t,
                            cwd=Path(rel("proj")),
                            environment=e,
                            workspace_root=Path(rel("proj")),
                            home_dir=None,
                            reason=r,
                        )
                    ),
                )
    for token in [
        "python3",
        "/opt/zz/bin/python3",
        "./venv/bin/python3",
        "venv/bin/python3",
        "python.exe",
        "/opt/t_unres/python3",
        "/opt/t_loose/python3",
        "/opt/t_guard/python3",
        "/opt/t_guardsib/python3",
        "/opt/t_guardreal/python3",
        "/usr/local/t_stable/bin/python3",
        "t_ws/python3",
        "~/p/python3",
        "C:\\py\\python.exe",
        "py",
        "python3\u00e9",
        "/opt/t_nonexec/python3",
        "/opt/t_weird/python3",
    ]:
        for reason in (None, "env_reason", "sudo_chroot_unresolved"):
            for env in environments:
                for h in (None, home):
                    add(
                        "python_interpreter_executable_identity",
                        [token, rel("proj"), env, rel("proj"), h, reason],
                        lambda t=token, r=reason, e=env, h=h: ilaunch._python_interpreter_executable_identity(
                            t,
                            cwd=Path(rel("proj")),
                            environment=e,
                            workspace_root=Path(rel("proj")),
                            home_dir=None if h is None else Path(h),
                            resolution_reason=r,
                        ),
                    )
    for value in [
        None,
        1,
        "x",
        [],
        {},
        {"reuse_nonce": "a"},
        {"a": {"reuse_nonce": 1, "b": 2}},
        [{"reuse_nonce": 1}, {"x": [{"reuse_nonce": 2, "y": 3}]}],
        {"reuse_nonce": {"reuse_nonce": 1}},
        {1: {"reuse_nonce": 2}},
        {"k": ({"reuse_nonce": 1},)},
        True,
        1.5,
        {"REUSE_NONCE": 1},
        {"a": None},
        [[[]]],
        {"": {"reuse_nonce": ""}},
    ]:
        add("without_interpreter_reuse_nonces", [value], lambda v=value: ilaunch._without_interpreter_reuse_nonces(v))


def _candidate(candidate: object) -> object:
    if candidate is None:
        return None
    return {
        "tokens": list(candidate.tokens),
        "command_index": candidate.command_index,
        "effective_cwd": str(candidate.effective_cwd),
        "environment": dict(candidate.environment),
        "resolution_reason": candidate.resolution_reason,
    }


def record_identities(
    add: Callable[..., None],
    root: Path,
    texts: list[str],
    rel: Callable[..., object],
    path: Callable[..., object],
    home: str,
) -> None:
    env_variants: list[dict[str, str] | None] = [
        None,
        {"PATH": "/opt/zz/bin:/opt/yy/bin"},
        {"PATH": "venv/bin:/opt/zz/bin", "FOO": "1"},
        {"PATH": "$X"},
        {},
    ]
    for text in (t for t in texts if not CD_WORD.search(t)):
        for cwd in ("proj", "sudo", None):
            for env in env_variants[:2] if cwd != "proj" else env_variants:
                for workspace in (None,):
                    add(
                        "python_interpreter_executable_identities",
                        [text, rel(cwd) if cwd else None, home, env, rel(workspace) if workspace else None, 0],
                        lambda t=text, c=cwd, e=env, w=workspace: [
                            dict(item)
                            for item in iid._python_interpreter_executable_identities(
                                t,
                                cwd=None if c is None else Path(rel(c)),
                                home_dir=Path(home),
                                environment=e,
                                workspace_root=None if w is None else Path(rel(w)),
                            )
                        ],
                    )
        add(
            "python_interpreter_executable_identities",
            [text, rel("proj"), None, env_variants[1], None, 0],
            lambda t=text: [
                dict(item)
                for item in iid._python_interpreter_executable_identities(
                    t, cwd=Path(rel("proj")), home_dir=None, environment=env_variants[1]
                )
            ],
        )
    for depth in (7, 8, 9, 10):
        for text in ("python3 x", "sh -c 'python3 x'", "python3 x | python y", ""):
            add(
                "python_interpreter_executable_identities",
                [text, rel("proj"), home, env_variants[1], None, depth],
                lambda t=text, d=depth: [
                    dict(item)
                    for item in iid._python_interpreter_executable_identities(
                        t, cwd=Path(rel("proj")), home_dir=Path(home), environment=env_variants[1], depth=d
                    )
                ],
            )
    for levels in range(1, 12):
        for inner in ("python3 x", "python3 x; python y", "echo $(python3 -V)", "env python3 x"):
            text = _deep_shell(levels, inner)
            add(
                "python_interpreter_executable_identities",
                [text, rel("proj"), home, env_variants[1], None, 0],
                lambda t=text: [
                    dict(item)
                    for item in iid._python_interpreter_executable_identities(
                        t, cwd=Path(rel("proj")), home_dir=Path(home), environment=env_variants[1]
                    )
                ],
            )
    for text in (
        "python3 x && sh -c 'python3 y'",
        "sh -c 'sudo -D sudo_d python3 x'",
        "sh -c 'env PATH=/opt/t_unres/bin python3 x'",
        "bash -c 'echo $(python3 -V)'",
        'sh -c "echo `python3 x`"',
        "echo $(sh -c 'python3 x') $(python y)",
        "echo $(echo $(echo $(python3 x)))",
    ):
        add(
            "python_interpreter_executable_identities",
            [text, rel("proj"), home, None, None, 0],
            lambda t=text: [
                dict(item)
                for item in iid._python_interpreter_executable_identities(
                    t, cwd=Path(rel("proj")), home_dir=Path(home), environment=None
                )
            ],
        )


if __name__ == "__main__":
    main()
