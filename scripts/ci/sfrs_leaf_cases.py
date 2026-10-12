"""Record parity vectors for the secret-file-request leaf checks.

Usage: ``sfrs_leaf_cases.py FIXTURE_DIR``. Covers the read-only Git ancestry
audit, origin-shaped fetch recognition, Guard self-approval detection, routine
``mv``, and the read-only Perl filter. A
fixed tree is built under a fresh root; paths are stored with the ``{ROOT}``
token so the Rust port can rebuild the same tree and replay every case.

Needs ``HOL_GUARD_NATIVE=force``, ``HOL_GUARD_NATIVE_BINARY`` and
``HOL_GUARD_HOME`` for the shell context model (provisioned the way
``sfrs_graph_cases.py`` does). The process-environment secret request is only
a transport of the native classifier and is unit tested in Rust. The resident's Git trust
services are replaced by the deterministic stand-ins below, which the Rust
replay host mirrors. This script depends on the Python implementation and is
retired with it.
"""

# ruff: noqa: E501, B007, B023 - recorded case tables; recorder lambdas run synchronously inside the loop.

from __future__ import annotations

import gzip
import json
import os
import sys
import tempfile
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path

from codex_plugin_scanner.guard.runtime import git_origin_refresh as origin
from codex_plugin_scanner.guard.runtime import read_only_git_audit as audit
from codex_plugin_scanner.guard.runtime import self_approval as approval
from codex_plugin_scanner.guard.runtime.secret_file_request_services import perl_read_only as perl
from codex_plugin_scanner.guard.runtime.secret_file_request_services import routine_move as move
from codex_plugin_scanner.guard.runtime.secret_file_request_services import shell_tokenization as tokens

TOKEN = "{ROOT}"
GIT = "{ROOT}/home/bin/git"

TREE = {
    "dirs": [
        "home/proj/.git",
        "home/proj/src",
        "home/proj/build",
        "home/proj/dist",
        "home/proj/.cache",
        "home/proj/.ssh",
        "home/proj/.aws",
        "home/proj/.x.lock.d",
        "home/proj/.bad.lock.d",
        "home/proj/.crlf.lock.d",
        "home/proj/.big.lock.d",
        "home/proj/.empty.lock.d",
        "home/proj/.link.lock.d",
        "home/proj/plain.lock.d",
        "home/bin",
        "home/untrusted/proj",
        "home/badconfig/proj",
        "elsewhere",
        "tmp",
    ],
    "files": {
        "home/proj/src/a.txt": "alpha\n",
        "home/proj/src/b.txt": "beta\n",
        "home/proj/notes.log": "line\n",
        "home/proj/build/out.js": "x\n",
        "home/proj/.env": "TOKEN=1\n",
        "home/proj/.ssh/config": "Host x\n",
        "home/proj/.x.lock.d/pid": "12345\n",
        "home/proj/.bad.lock.d/pid": "abc\n",
        "home/proj/.crlf.lock.d/pid": "123\r\n",
        "home/proj/.big.lock.d/pid": "1" * 40,
        "home/proj/.empty.lock.d/pid": "",
        "home/proj/plain.lock.d/pid": "1\n",
        "home/proj/reader.py": "import os\nprint(os.environ)\n",
        "home/proj/quiet.py": "print('hi')\n",
        "elsewhere/out.txt": "out\n",
        "home/bin/git": "#!/bin/sh\n",
        "home/bin/perl": "#!/bin/sh\n",
    },
    "executables": ["home/bin/git", "home/bin/perl"],
    "links": {
        "home/proj/link.txt": "src/a.txt",
        "home/proj/outside.txt": "../../elsewhere/out.txt",
        "home/proj/dangling.txt": "src/missing.txt",
        "home/proj/dirlink": "src",
        "home/proj/.link.lock.d/pid": "../src/a.txt",
        "home/proj/.dangling.lock.d": "missing-dir",
    },
}

AUDIT_LOOP = (
    "for commit in abc1234 DEF5678; do git merge-base --is-ancestor $commit HEAD 2>/dev/null"
    ' && echo "$commit YES" || echo "$commit NO"; done'
)
AUDIT_TEXTS = [
    f"cd {{P}} && {AUDIT_LOOP}",
    f"cd {{P}} && {AUDIT_LOOP};",
    f"cd {{P}} && echo start && {AUDIT_LOOP}",
    f"cd {{P}} && echo start && {AUDIT_LOOP}; echo ---; git log -1 --oneline; echo ---; cat .x.lock.d/pid 2>/dev/null || echo none",
    f"cd {{P}} && {AUDIT_LOOP}; git log -1 --oneline; cat .x.lock.d/pid 2>/dev/null || echo none",
    f"cd {{P}} && {AUDIT_LOOP}; echo ---; git log -1 --oneline; cat .x.lock.d/pid 2>/dev/null || echo none",
    f"cd {{P}} && {AUDIT_LOOP}; git log -1 --oneline; echo ---; cat .x.lock.d/pid 2>/dev/null || echo none",
    f"cd {{P}} && {AUDIT_LOOP}; git log -1 --oneline; cat .missing.lock.d/pid 2>/dev/null || echo none",
    f"cd {{P}} && {AUDIT_LOOP}; git log -1 --oneline; cat .bad.lock.d/pid 2>/dev/null || echo none",
    f"cd {{P}} && {AUDIT_LOOP}; git log -1 --oneline; cat .crlf.lock.d/pid 2>/dev/null || echo none",
    f"cd {{P}} && {AUDIT_LOOP}; git log -1 --oneline; cat .big.lock.d/pid 2>/dev/null || echo none",
    f"cd {{P}} && {AUDIT_LOOP}; git log -1 --oneline; cat .empty.lock.d/pid 2>/dev/null || echo none",
    f"cd {{P}} && {AUDIT_LOOP}; git log -1 --oneline; cat .link.lock.d/pid 2>/dev/null || echo none",
    f"cd {{P}} && {AUDIT_LOOP}; git log -1 --oneline; cat plain.lock.d/pid 2>/dev/null || echo none",
    f"cd {{P}} && {AUDIT_LOOP}; git log -1 --oneline; cat /etc/passwd 2>/dev/null || echo none",
    f"cd {{P}} && {AUDIT_LOOP}; git log -1 --oneline; cat ../.x.lock.d/pid 2>/dev/null || echo none",
    f"cd {{P}} && {AUDIT_LOOP}; git log -1 --oneline; cat .x.lock.d/pid 2>/dev/null || echo $HOME",
    f"cd {{P}} && {AUDIT_LOOP}; git log -1 --oneline; cat .x.lock.d/pid 2>/dev/null || echo `id`",
    f"cd {{P}} && {AUDIT_LOOP}; git log -1 --oneline; cat .x.lock.d/pid 2>/dev/null",
    f"cd {{P}} && {AUDIT_LOOP}; git log -1 --oneline; cat .x.lock.d/pid 2>/dev/null || echo a || echo b",
    f"cd {{P}} && {AUDIT_LOOP}; git log -2 --oneline; cat .x.lock.d/pid 2>/dev/null || echo none",
    f"cd {{P}} && {AUDIT_LOOP}; git log -1 --oneline --ext-diff; cat .x.lock.d/pid 2>/dev/null || echo none",
    f"cd {{P}} && {AUDIT_LOOP}; echo 'HEAD: $(git log -1 --oneline)'; echo hi",
    f'cd {{P}} && {AUDIT_LOOP}; echo "HEAD: $(git log -1 --oneline)"; if [ -f .x.lock.d/pid ]; then echo "LOCK: $(cat .x.lock.d/pid)"; else echo none; fi',
    f'cd {{P}} && {AUDIT_LOOP}; echo "HEAD: $(git log -1 --oneline)"; if [ -f .missing.lock.d/pid ]; then echo "LOCK: $(cat .missing.lock.d/pid)"; else echo none; fi',
    f'cd {{P}} && {AUDIT_LOOP}; echo "HEAD: $(git log -1 --oneline)"; if [ -f .bad.lock.d/pid ]; then echo "LOCK: $(cat .bad.lock.d/pid)"; else echo none; fi',
    f'cd {{P}} && {AUDIT_LOOP}; echo "HEAD: $(git log -1 --oneline)"; if [ -f .x.lock.d/pid ]; then echo "LOCK: $(cat .x.lock.d/pid)"; else echo "$HOME"; fi',
    f'cd {{P}} && {AUDIT_LOOP}; echo "HEAD: $(git log -1 --oneline)"; if [ -d .x.lock.d/pid ]; then echo "LOCK: $(cat .x.lock.d/pid)"; else echo none; fi',
    f'cd {{P}} && {AUDIT_LOOP}; echo "HEAD: $(git log -1 --oneline)"; if [ -f .x.lock.d/pid ]; then echo "LOCK: $(cat .y.lock.d/pid)"; else echo none; fi',
    f'cd {{P}} && {AUDIT_LOOP}; echo "HEAD: $(git log -1 --oneline)"; if [ -f .x.lock.d/pid ]; then echo "LOCK: $(cat .x.lock.d/pid)"; else echo none; fi; echo more',
    "cd {P} && git merge-base --is-ancestor abc1234 HEAD",
    'for commit in abc1234; do git merge-base --is-ancestor $commit HEAD 2>/dev/null && echo "$commit YES" || echo "$commit NO"; done',
    "cd {P}",
    "",
    "   ",
    "cd {P} && echo é",
    'cd {P} && for commit in ÀÀÀÀÀÀÀ; do git merge-base --is-ancestor $commit HEAD 2>/dev/null && echo "$commit YES" || echo "$commit NO"; done',
    'cd {P} && for ref in abc1234; do git merge-base --is-ancestor $ref HEAD 2>/dev/null && echo "$ref YES" || echo "$ref NO"; done; echo x; echo y',
    'cd {P} && for x in abc1234; do git merge-base --is-ancestor $x HEAD 2>/dev/null && echo "$x YES" || echo "$x NO"; done; echo x; echo y',
    'cd {P} && for sha in abc123; do git merge-base --is-ancestor $sha HEAD 2>/dev/null && echo "$sha YES" || echo "$sha NO"; done; echo x; echo y',
    "cd {P} && for sha in "
    + " ".join(f"abc12{i:02d}" for i in range(33))
    + '; do git merge-base --is-ancestor $sha HEAD 2>/dev/null && echo "$sha YES" || echo "$sha NO"; done; echo x; echo y',
    "cd {P} && for sha in "
    + " ".join(f"abc12{i:02d}" for i in range(32))
    + '; do git merge-base --is-ancestor $sha HEAD 2>/dev/null && echo "$sha YES" || echo "$sha NO"; done; echo x; echo y',
    'cd {P} && for sha in abc1234 -c; do git merge-base --is-ancestor $sha HEAD 2>/dev/null && echo "$sha YES" || echo "$sha NO"; done; echo x; echo y',
    'cd {P} && for sha in abc1234; do git -c core.pager=evil merge-base --is-ancestor $sha HEAD 2>/dev/null && echo "$sha YES" || echo "$sha NO"; done; echo x; echo y',
    'cd {P} && for sha in abc1234; do git merge-base --is-ancestor $sha HEAD && echo "$sha YES" || echo "$sha NO"; done; echo x; echo y',
    'cd {P} && for sha in abc1234; do git merge-base --is-ancestor $sha origin/main 2>/dev/null && echo "$sha YES" || echo "$sha NO"; done; echo x; echo y',
    'cd {P} && for sha in abc1234; do git merge-base --is-ancestor $sha HEAD 2>/dev/null && echo "$sha YES" || echo "$sha NO" | sh; done; echo x; echo y',
    'cd {P} && for sha in abc1234; do git merge-base --is-ancestor $sha HEAD 2>/dev/null && echo "$sha MAYBE" || echo "$sha NO"; done; echo x; echo y',
    'cd {P}/src && for sha in abc1234; do git merge-base --is-ancestor $sha HEAD 2>/dev/null && echo "$sha YES" || echo "$sha NO"; done; echo x; echo y',
    'cd {ROOT}/elsewhere && for sha in abc1234; do git merge-base --is-ancestor $sha HEAD 2>/dev/null && echo "$sha YES" || echo "$sha NO"; done; echo x; echo y',
    'cd ~/proj && for sha in abc1234; do git merge-base --is-ancestor $sha HEAD 2>/dev/null && echo "$sha YES" || echo "$sha NO"; done; echo x; echo y',
    'cd {P}; for sha in abc1234; do git merge-base --is-ancestor $sha HEAD 2>/dev/null && echo "$sha YES" || echo "$sha NO"; done; echo x; echo y',
]
AUDIT_CWDS = [
    "{P}",
    "{ROOT}/home",
    "{ROOT}/elsewhere",
    "{ROOT}/home/untrusted/proj",
    "{ROOT}/home/badconfig/proj",
    None,
]

FETCH_ARGS = [
    [],
    ["origin"],
    ["origin", "main"],
    ["origin", "main", "dev", "feature/x.y-z_1"],
    ["-q", "origin"],
    ["--quiet", "--no-tags", "--prune", "-p", "origin", "main"],
    ["origin", "-q", "main"],
    ["origin", "--prune"],
    ["--all"],
    ["origin", "--all"],
    ["upstream"],
    ["upstream", "origin"],
    ["https://example.com/repo.git"],
    ["origin", "https://example.com/repo.git"],
    ["origin", "refs/heads/*:refs/remotes/origin/*"],
    ["origin", "+main"],
    ["origin", "main:main"],
    ["origin", "-main"],
    ["origin", "main", "--upload-pack=evil"],
    ["--upload-pack=evil", "origin"],
    ["-u", "origin"],
    ["origin", ""],
    ["", "origin"],
    ["origin", "é"],
    ["origin", "a" * 256],
    ["origin", "a" * 257],
    ["origin", "_x"],
    ["origin", ".x"],
    ["origin", "x y"],
    ["origin"] + [f"r{i}" for i in range(12)],
    ["origin"] + [f"r{i}" for i in range(13)],
    ["-q"] * 15 + ["origin"],
    ["-q"] * 16 + ["origin"],
    ["-q"] * 17,
    ["origin", "origin"],
    ["Origin"],
    ["-q", "-p"],
]
FETCH_TEXTS = [
    "git fetch origin",
    "git fetch origin main",
    "git fetch --prune origin",
    "git fetch -q origin main dev",
    "git fetch",
    "git fetch --all",
    "git fetch upstream",
    "git fetch https://example.com/x.git",
    "git fetch origin --upload-pack=evil",
    "git fetch --upload-pack=evil origin",
    "git -c core.sshCommand=evil fetch origin",
    "git -ccore.sshCommand=evil fetch origin",
    "git --config-env=core.sshCommand=X fetch origin",
    "git --exec-path=/x fetch origin",
    "git --exec-path fetch origin",
    "git -C /tmp fetch origin",
    "git -C fetch origin",
    "git -C",
    "git --git-dir=.git fetch origin",
    "git --git-dir= fetch origin",
    "git --git-dir .git fetch origin",
    "git --work-tree=/x --git-dir=/y fetch origin",
    "git --namespace=x fetch origin",
    "git --super-prefix=x/ fetch origin",
    "git --no-pager fetch origin",
    "git --no-pager --no-optional-locks fetch origin",
    "git --paginate --bare --literal-pathspecs fetch origin",
    "git -P fetch origin",
    "git -p fetch origin",
    "git --no-replace-objects --no-lazy-fetch --no-advice fetch origin",
    "git --unknown fetch origin",
    "git --unknown=value fetch origin",
    "git pull origin",
    "git status",
    "git",
    "git -c",
    "git fetch --",
    "git fetch origin; git fetch origin main",
    "git fetch origin && git fetch origin main",
    "git fetch origin | cat",
    "git fetch origin && git pull",
    "git fetch origin; echo done",
    "FOO=1 git fetch origin",
    "env git fetch origin",
    "env -i git fetch origin",
    "env -S 'git fetch origin'",
    "command git fetch origin",
    "sudo git fetch origin",
    "time git fetch origin",
    "nohup git fetch origin",
    "git fetch origin >/dev/null 2>&1",
    ">/dev/null git fetch origin",
    "/usr/bin/git fetch origin",
    "GIT_SSH_COMMAND=evil git fetch origin",
    "git alias-fetch origin",
    "git -c alias.fetch='!evil' fetch origin",
    "git fetch origin main é",
    "",
    "   ",
    ";",
    "é fetch origin",
]

APPROVAL_TEXTS = [
    "hol-guard approvals approve abc",
    "hol-guard approvals allow abc",
    "hol-guard approvals deny abc",
    "hol-guard approvals block abc",
    "hol-guard approvals clear-history",
    "hol-guard approvals unlock",
    "hol-guard approvals list",
    "hol-guard approvals show abc",
    "hol-guard approvals",
    "hol-guard requests approve abc",
    "hol-guard requests list",
    "hol-guard guard approvals approve abc",
    "hol-guard guard requests allow abc",
    "hol-guard guard status",
    "hol-guard approvals --json approve abc",
    "hol-guard approvals --json list",
    "hol-guard approvals -- approve abc",
    "hol-guard --home /x approvals approve abc",
    "hol-guard approve abc",
    "plugin-guard approvals approve abc",
    "plugin-guard guard approvals unlock",
    "/usr/local/bin/hol-guard approvals approve abc",
    "./HOL-GUARD approvals approve abc",
    "~/bin/plugin-guard approvals deny abc",
    "FOO=1 hol-guard approvals approve abc",
    "FOO=1 BAR+=2 hol-guard approvals approve abc",
    "_X=1 hol-guard approvals approve abc",
    "1X=1 hol-guard approvals approve abc",
    "=1 hol-guard approvals approve abc",
    "+=1 hol-guard approvals approve abc",
    "é=1 hol-guard approvals approve abc",
    "X-Y=1 hol-guard approvals approve abc",
    "'' hol-guard approvals approve abc",
    '"hol-guard" approvals approve abc',
    "'hol-guard' 'approvals' 'approve' abc",
    "hol-guard approvals 'approve' abc",
    'hol-guard approvals "app"rove abc',
    "hol-guard approvals app\\rove abc",
    "hol-guard\\ approvals approve abc",
    "echo hi; hol-guard approvals approve abc",
    "echo hi && hol-guard approvals approve abc",
    "echo hi || hol-guard approvals approve abc",
    "echo hi | hol-guard approvals approve abc",
    "echo hi |& hol-guard approvals approve abc",
    "echo hi & hol-guard approvals approve abc",
    "echo hi\nhol-guard approvals approve abc",
    "echo hi\n\nhol-guard approvals approve abc",
    "echo 'hol-guard approvals approve abc'",
    "echo hol-guard approvals approve abc",
    "# hol-guard approvals approve abc",
    "echo hi # hol-guard approvals approve abc",
    "echo hi #; hol-guard approvals approve abc",
    "hol-guard approvals approve abc #",
    'echo "unterminated; hol-guard approvals approve abc',
    "echo 'unterminated; hol-guard approvals approve abc",
    "hol-guard approvals approve 'abc",
    "hol-guard approvals approve abc\\",
    "env hol-guard approvals approve abc",
    "sudo hol-guard approvals approve abc",
    "time hol-guard approvals approve abc",
    "nohup hol-guard approvals approve abc",
    "bash -c 'hol-guard approvals approve abc'",
    'sh -c "hol-guard approvals approve abc"',
    "(hol-guard approvals approve abc)",
    "{ hol-guard approvals approve abc; }",
    "$(hol-guard approvals approve abc)",
    "`hol-guard approvals approve abc`",
    "xargs hol-guard approvals approve abc",
    "python -m codex_plugin_scanner approvals approve abc",
    "python -m codex_plugin_scanner.cli approvals approve abc",
    "python -m codex_plugin_scanner guard approvals approve abc",
    "python3 -m codex_plugin_scanner.cli requests unlock",
    "python3.12 -m codex_plugin_scanner.cli requests unlock",
    "python3.12.1 -m codex_plugin_scanner.cli requests unlock",
    "pythonw -m codex_plugin_scanner approvals deny x",
    "py -m codex_plugin_scanner approvals deny x",
    "py3 -m codex_plugin_scanner approvals deny x",
    "py3.11 -m codex_plugin_scanner approvals deny x",
    "pytest -m codex_plugin_scanner approvals deny x",
    "/usr/bin/python -m codex_plugin_scanner approvals deny x",
    "PYTHONPATH=src python -m codex_plugin_scanner approvals deny x",
    "python -m codex_plugin_scanner approvals list",
    "python -m codex_plugin_scanner",
    "python -m other approvals approve abc",
    "python -m  codex_plugin_scanner approvals approve abc",
    "python -m ' codex_plugin_scanner ' approvals approve abc",
    "python -m",
    "python -c 'import x' approvals approve abc",
    "python -c",
    "python -W ignore -m codex_plugin_scanner approvals approve abc",
    "python -X dev -m codex_plugin_scanner approvals approve abc",
    "python --check-hash-based-pycs always -m codex_plugin_scanner approvals approve abc",
    "python -W=ignore -m codex_plugin_scanner approvals approve abc",
    "python -X=dev -m codex_plugin_scanner approvals approve abc",
    "python --check-hash-based-pycs=always -m codex_plugin_scanner approvals approve abc",
    "python -W",
    "python -W -m codex_plugin_scanner approvals approve abc",
    "python -B -s -E -m codex_plugin_scanner approvals approve abc",
    "python -u -m codex_plugin_scanner approvals approve abc",
    "python script.py -m codex_plugin_scanner approvals approve abc",
    "python",
    "uv run hol-guard approvals approve abc",
    "uv run -- hol-guard approvals approve abc",
    "uv run --with x hol-guard approvals approve abc",
    "uv tool run hol-guard approvals approve abc",
    "uv tool run -- hol-guard approvals approve abc",
    "uv tool install hol-guard approvals approve abc",
    "uv pip install hol-guard",
    "uv run",
    "uv",
    "uv -- run hol-guard approvals approve abc",
    "uv run python -m codex_plugin_scanner approvals approve abc",
    "uvx hol-guard approvals approve abc",
    "uvx --from x hol-guard approvals approve abc",
    "uvx",
    "uvx uvx uvx uvx uvx hol-guard approvals approve abc",
    "uv run uv run uv run uv run hol-guard approvals approve abc",
    "uv run uv run uv run hol-guard approvals approve abc",
    "pipx run hol-guard approvals approve abc",
    "pipx run --spec x hol-guard approvals approve abc",
    "pipx install hol-guard",
    "poetry run hol-guard approvals approve abc",
    "poetry run -- hol-guard approvals approve abc",
    "hatch run hol-guard approvals approve abc",
    "hatch run env:hol-guard approvals approve abc",
    "mise exec -- hol-guard approvals approve abc",
    "mise exec node@20 -- hol-guard approvals approve abc",
    "mise run hol-guard approvals approve abc",
    "nix develop --command hol-guard approvals approve abc",
    'nix develop --command="hol-guard approvals approve abc"',
    "nix develop --command 'hol-guard approvals approve abc'",
    "nix develop --command",
    "nix develop --command='unterminated",
    "nix develop --command 'unterminated",
    "nix develop --command x 'unterminated hol-guard approvals approve abc",
    "nix develop -c hol-guard approvals approve abc",
    "nix run x",
    "npx hol-guard approvals approve abc",
    "approve",
    "",
    "   ",
    ";;",
    "; ;",
    "&&",
    "é approvals approve",
    "hol-guard approvals approve é",
    "hol-guard approvals ‮approve abc",
    "HOL-GUARD approvals approve abc",
    "Hol-Guard Approvals approve abc",
    "hol-guard approvals APPROVE abc",
    "hol-guard approvals --approve abc",
    "hol-guard approvals -x approve abc",
    "hol-guard requests -a -b clear-history",
    "hol-guard requests --flag",
    "hol-guard approvals list approve",
    "hol-guard guard guard approvals approve abc",
    "hol-guard approvals approvals approve",
    "hol-guard x approvals approve abc",
    "hol-guard -v approvals approve abc",
]
APPROVAL_ENVS = [
    {},
    {"HOL_GUARD_HOOK_ARGV": "x"},
    {"HOL_GUARD_HOOK_ARGV": ""},
    {"HOL_GUARD_HOOK_ARGV": "   "},
    {"HOL_GUARD_HOOK_ARGV": "　"},
    {"CLAUDECODE": "1"},
    {"CURSOR_TRACE_ID": " x "},
    {"CODEX_SANDBOX": "seatbelt"},
    {"OPENCODE_CONFIG_CONTENT": "{}"},
    {"HOL_GUARD_MANAGED_CURSOR_HOOK": "1"},
    {"HOL_GUARD_CURSOR_APPROVAL_BINDING": "1"},
    {"HOL_GUARD_CURSOR_AFTER_SHELL_PROOF": "1"},
    {"CURSOR_SESSION_ID": "1"},
    {"CURSOR_TRANSCRIPT_PATH": "/x"},
    {"OTHER": "1"},
    {"claudecode": "1"},
    {"CLAUDECODE": "é"},
]
APPROVAL_LISTS = [
    [],
    [""],
    ["", "hol-guard", "approvals", "approve"],
    ["A=1", "B=2"],
    ["A=1", "python", "-m", "codex_plugin_scanner", "approvals", "approve"],
    ["hol-guard", "guard"],
    ["hol-guard", "guard", "approvals"],
    ["hol-guard", "approvals", "-x", "-y"],
    ["hol-guard", "approvals", "-x", "unlock"],
    ["python", "-m", "codex_plugin_scanner", "-m", "x"],
    ["uv", "run", "--", "run", "hol-guard", "approvals", "approve"],
    ["uv", "tool", "run", "--", "hol-guard", "approvals", "approve"],
    ["uv", "tool"],
    ["uv", "tool", "run"],
    ["uvx", "hol-guard", "requests", "block"],
    ["nix", "--command"],
    ["nix", "--command", "hol-guard", "approvals", "approve"],
    ["nix", "--command=hol-guard approvals approve"],
    ["nix", "x", "--command="],
    ["nix", "--command", "a b", "c'd"],
    ["mise", "exec", "--"],
    ["mise", "exec", "--", "--", "hol-guard", "approvals", "approve"],
    ["hatch", "run"],
    ["poetry", "x"],
    ["pipx", "--", "run", "hol-guard"],
    ["python", "-W", "-W", "-m", "codex_plugin_scanner", "approvals", "approve"],
    ["python", "-X", "dev", "-W", "x", "-m", "codex_plugin_scanner.cli", "approvals", "allow"],
    ["sudo", "hol-guard", "approvals", "approve"],
]

MOVE_TEXTS = [
    "mv src/a.txt src/c.txt",
    "mv src/a.txt src/b.txt",
    "mv -- src/a.txt src/c.txt",
    "mv -- -src/a.txt src/c.txt",
    "mv -- src/a.txt -c.txt",
    "mv -n src/a.txt src/c.txt",
    "mv -f src/a.txt src/c.txt",
    "mv src/a.txt src/c.txt -f",
    "mv src/a.txt",
    "mv src/a.txt src/c.txt src/d.txt",
    "mv",
    "mv --",
    "mv -- --",
    "mv src/a.txt src",
    "mv src/a.txt src/",
    "mv src src2",
    "mv src/a.txt ./c.txt",
    "mv ./src/a.txt ./src/c.txt",
    "mv src//a.txt src//c.txt",
    "mv src/a.txt src/../c.txt",
    "mv src/a.txt ../c.txt",
    "mv src/a.txt ../../elsewhere/c.txt",
    "mv src/a.txt {ROOT}/elsewhere/c.txt",
    "mv src/a.txt {P}/c.txt",
    "mv {P}/src/a.txt {P}/src/c.txt",
    "mv {ROOT}/elsewhere/out.txt src/c.txt",
    "mv src/a.txt .",
    "mv src/a.txt ..",
    "mv . src/c",
    "mv .. src/c",
    "mv src/a.txt .hidden",
    "mv .hidden src/a.txt",
    "mv notes.log notes.old",
    "mv *.log old/",
    "mv src/*.txt dest",
    "mv src/a.txt src/c?.txt",
    "mv src/a.txt src/[c].txt",
    "mv src/a.txt src/{c,d}.txt",
    "mv src/a.txt $HOME/c.txt",
    "mv src/a.txt `pwd`/c.txt",
    "mv src/a.txt $(pwd)/c.txt",
    "mv 'src/a b.txt' src/c.txt",
    "mv src/a.txt 'src/c d.txt'",
    "mv src/a.txt src/c...txt",
    "mv ... src/c.txt",
    "mv src/a.txt ''",
    "mv '' src/c.txt",
    "mv .env .env.bak",
    "mv src/a.txt .env",
    "mv src/a.txt .ssh/id_rsa",
    "mv .ssh/config src/config",
    "mv .ssh src/ssh",
    "mv .aws src/aws",
    "mv src/a.txt .ssh/c.txt",
    "mv src/a.txt .aws/c.txt",
    "mv src/a.txt .Codex/c.txt",
    "mv src/a.txt .SSH/c.txt",
    "mv src/a.txt .kube/c.txt",
    "mv src/a.txt .docker/c.txt",
    "mv src/a.txt .hol-guard/c.txt",
    "mv ~/.ssh/config src/c",
    "mv ~ src/c",
    "mv ~/proj/src/a.txt ~/proj/src/c.txt",
    "mv ~/proj/src/a.txt src/c.txt",
    "mv ~/missing src/c.txt",
    "mv ~root/x src/c.txt",
    "mv link.txt link2.txt",
    "mv link.txt src/c.txt",
    "mv outside.txt src/c.txt",
    "mv src/a.txt link2.txt",
    "mv src/a.txt dangling.txt",
    "mv dangling.txt src/c.txt",
    "mv dirlink/a.txt src/c.txt",
    "mv src/a.txt dirlink/c.txt",
    "mv src/missing.txt src/c.txt",
    "mv src/a.txt missing/c.txt",
    "mv src/a.txt missing/../c.txt",
    "mv build {ROOT}/tmp/build",
    "mv build {ROOT}/tmp/build2",
    "mv dist {ROOT}/tmp/dist",
    ".cache {ROOT}/tmp/cache",
    "mv .cache {ROOT}/tmp/cache",
    "mv coverage {ROOT}/tmp/coverage",
    "mv build/out.js {ROOT}/tmp/out.js",
    "mv src {ROOT}/tmp/src",
    "mv build {ROOT}/elsewhere/build",
    "mv build ../build",
    "mv build build2",
    "mv build src/build",
    "mv dist dist2",
    "mv BUILD build3",
    "mv .next {ROOT}/tmp/next",
    "mv build {ROOT}/tmp",
    "mv build {ROOT}/tmp/",
    "mv build /tmp/sfrs-leaf-missing-dir/x",
    "mv build /",
    "mv src/a.txt /",
    "mv / src/c",
    "mv src/a.txt //x",
    "mv src/a.txt src/c.txt && echo done",
    "mv src/a.txt src/c.txt; mv src/b.txt src/d.txt",
    "mv src/a.txt src/c.txt | cat",
    "echo hi && mv src/a.txt src/c.txt",
    "FOO=1 mv src/a.txt src/c.txt",
    "env mv src/a.txt src/c.txt",
    "env -i mv src/a.txt src/c.txt",
    "env -S 'mv src/a.txt src/c.txt'",
    "sudo mv src/a.txt src/c.txt",
    "command mv src/a.txt src/c.txt",
    "nohup mv src/a.txt src/c.txt",
    "time mv src/a.txt src/c.txt",
    "nice mv src/a.txt src/c.txt",
    "/bin/mv src/a.txt src/c.txt",
    "mv src/a.txt src/c.txt > log",
    "mv src/a.txt src/c.txt 2>&1",
    "> log mv src/a.txt src/c.txt",
    "mv src/a.txt > log src/c.txt",
    "mv src/a.txt src/c.txt\n",
    "mv src/a.txt\nsrc/c.txt",
    "mv src/a.txt src/é.txt",
    "mv src/é.txt src/c.txt",
    "mv src/a.txt src/c.txt # comment",
    "cp src/a.txt src/c.txt",
    "rm src/a.txt",
    "git mv src/a.txt src/c.txt",
    "",
    "   ",
    ";",
]
MOVE_CWDS = ["{P}", "{P}/src", "{ROOT}/home", "{ROOT}/elsewhere", "{P}/missing", None, "{P}/dirlink"]
MOVE_HOMES = ["{ROOT}/home", None]

PERL_PREFIXES = [
    "perl -ne ",
    "perl -n -e ",
    "/usr/bin/perl -ne ",
    "PERL -ne ",
    "./perl -ne ",
    "{ROOT}/home/bin/perl -ne ",
]
PERL_TEXTS = [
    "perl -ne 'print if /foo/' src/a.txt",
    "perl -ne 'print if /foo/i' src/a.txt",
    "perl -ne 'print if /foo/imsx' src/a.txt",
    "perl -ne 'print if /foo/g' src/a.txt",
    "perl -ne 'print if /foo/ix ' src/a.txt",
    "perl -ne 'print if /foo/\n' src/a.txt",
    "perl -ne 'print if /foo' src/a.txt",
    "perl -ne 'print if //' src/a.txt",
    "perl -ne 'print if /a\\/b/' src/a.txt",
    "perl -ne 'print if /a\\\\/' src/a.txt",
    "perl -ne 'print if /a\\' src/a.txt",
    "perl -ne 'print if /a|b/' src/a.txt",
    "perl -ne 'print if /^a$/' src/a.txt",
    "perl -ne 'print if /a$|b/' src/a.txt",
    "perl -ne 'print if /(a$)/' src/a.txt",
    "perl -ne 'print if /a$b/' src/a.txt",
    "perl -ne 'print if /a\\$b/' src/a.txt",
    "perl -ne 'print if /a\\\\$b/' src/a.txt",
    "perl -ne 'print if /a$\n/' src/a.txt",
    "perl -ne 'print if /a$\nb/' src/a.txt",
    "perl -ne 'print if /a@b/' src/a.txt",
    "perl -ne 'print if /a\\@b/' src/a.txt",
    "perl -ne 'print if /a\\\\@b/' src/a.txt",
    "perl -ne 'print if /a${x}b/' src/a.txt",
    "perl -ne 'print if /(?{system(\"id\")})/' src/a.txt",
    "perl -ne 'print if /(??{system(\"id\")})/' src/a.txt",
    "perl -ne 'print if /`id`/' src/a.txt",
    "perl -ne 'print if /é/' src/a.txt",
    "perl -ne 'print if /" + "a" * 4096 + "/' src/a.txt",
    "perl -ne 'print if /" + "a" * 4097 + "/' src/a.txt",
    "perl -ne 'print if /foo/' src/a.txt src/b.txt",
    "perl -ne 'print if /foo/'",
    "perl -ne 'print if /foo/' -",
    "perl -ne 'print if /foo/' -x",
    "perl -ne 'print if /foo/' ~/x",
    "perl -ne 'print if /foo/' $HOME/x",
    "perl -ne 'print if /foo/' $(id)",
    "perl -ne 'print if /foo/' `id`",
    "perl -ne 'print if /foo/' 'a|b'",
    "perl -ne 'print if /foo/' 'a<b'",
    "perl -ne 'print if /foo/' 'a>b'",
    "perl -ne 'print if /foo/' 'a\nb'",
    "perl -ne 'print if /foo/' ''",
    "perl -ne 'print if /foo/' .",
    "perl -ne 'print if /foo/' src",
    "perl -ne 'print if /foo/' missing.txt",
    "perl -ne 'print if /foo/' link.txt",
    "perl -ne 'print if /foo/' dirlink/a.txt",
    "perl -ne 'print if /foo/' outside.txt",
    "perl -ne 'print if /foo/' dangling.txt",
    "perl -ne 'print if /foo/' ../elsewhere/out.txt",
    "perl -ne 'print if /foo/' {ROOT}/elsewhere/out.txt",
    "perl -ne 'print if /foo/' {P}/src/a.txt",
    "perl -ne 'print if /foo/' ./src/a.txt",
    "perl -ne 'print if /foo/' src/../src/a.txt",
    "perl -ne 'print if /foo/' .env",
    "perl -ne 'print if /foo/' .ssh/config",
    "perl -ne 'print if /foo/' /etc/passwd",
    "perl -ne 'print if /foo/' notes.log",
    "perl -ne 'print if /foo/' src/é.txt",
    "perl -ne 'print if /foo/' src/a.txt > out",
    "perl -ne 'print if /foo/' src/a.txt | sh",
    "perl -ne 'print if /foo/' src/a.txt; id",
    "perl -ne 'print if /foo/' src/a.txt && id",
    "perl -ne 'print if /foo/' src/a.txt --",
    "perl -ne 'print if /foo/' -- src/a.txt",
    "perl -ne 'print;' src/a.txt",
    "perl -ne 'print' src/a.txt",
    "perl -ne 'system(\"id\")' src/a.txt",
    "perl -ne 'print if /foo/; system(\"id\")' src/a.txt",
    "perl -ne 'print if /foo/ and system(\"id\")' src/a.txt",
    "perl -ne 'print `id`' src/a.txt",
    "perl -ne 'print if `id`' src/a.txt",
    "perl -ne 'print if /foo/ ' src/a.txt",
    "perl -ne ' print if /foo/' src/a.txt",
    "perl -ne 'Print if /foo/' src/a.txt",
    "perl -ne 'print if /foo/' src/a.txt extra",
    "perl -pe 's/a/b/' src/a.txt",
    "perl -pe 'print if /foo/' src/a.txt",
    "perl -i -pe 's/a/b/' src/a.txt",
    "perl -i -ne 'print if /foo/' src/a.txt",
    "perl -pi -e 's/a/b/' src/a.txt",
    "perl -i.bak -ne 'print if /foo/' src/a.txt",
    "perl -e 'print if /foo/' src/a.txt",
    "perl -e 'system(\"id\")' src/a.txt",
    "perl -e 'print `id`' src/a.txt",
    "perl -n -e 'print if /foo/' src/a.txt",
    "perl -n -e 'print if /foo/'",
    "perl -n -e 'system(\"id\")' src/a.txt",
    "perl -n -i -e 'print if /foo/' src/a.txt",
    "perl -ne -e 'print if /foo/' src/a.txt",
    "perl -ne 'print if /foo/' -e 'system(\"id\")' src/a.txt",
    "perl -Mstrict -ne 'print if /foo/' src/a.txt",
    "perl -w -ne 'print if /foo/' src/a.txt",
    "perl -I/tmp -ne 'print if /foo/' src/a.txt",
    "perl -MEvil -ne 'print if /foo/' src/a.txt",
    "perl -l -ne 'print if /foo/' src/a.txt",
    "perl",
    "perl -ne",
    "perl -ne 'print if /foo/",
    'perl -ne "print if /foo/" src/a.txt',
    "perl -ne print\\ if\\ /foo/ src/a.txt",
    "PERL5OPT=-Mx perl -ne 'print if /foo/' src/a.txt",
    "env perl -ne 'print if /foo/' src/a.txt",
    "sudo perl -ne 'print if /foo/' src/a.txt",
    "python -ne 'print if /foo/' src/a.txt",
    "perl6 -ne 'print if /foo/' src/a.txt",
    "perl5 -ne 'print if /foo/' src/a.txt",
    "",
    "   ",
    "é",
]
PERL_ENVS = [
    {},
    {"PERL5DB": "x"},
    {"PERL5LIB": "/x"},
    {"PERL5OPT": "-Mx"},
    {"PERLIO": ":raw"},
    {"PERLIO_DEBUG": "/x"},
    {"PERLLIB": "/x"},
    {"PERLLIB": "   "},
    {"PERLLIB": ""},
    {"PERL_UNRELATED": "x"},
]
PERL_CWDS = ["{P}", "{P}/src", "{ROOT}/home/untrusted/proj", "{ROOT}/home", "{P}/missing", None, "{P}/link.txt"]
PERL_PATHS = ["{ROOT}/home/bin", "{ROOT}/elsewhere", "{ROOT}/home/bin:{ROOT}/elsewhere", "", "bin", "{ROOT}/missing"]


def _build(root: Path) -> None:
    for name in TREE["dirs"]:
        (root / name).mkdir(parents=True, exist_ok=True)
    for name, text in TREE["files"].items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    for name in TREE["executables"]:
        (root / name).chmod(0o755)
    for name, target in TREE["links"].items():
        os.symlink(target, root / name)
    # "bin" is a relative PATH entry resolved from the working directory.
    (root / "home" / "proj" / "bin").mkdir(exist_ok=True)
    (root / "home" / "proj" / "bin" / "perl").write_text("#!/bin/sh\n", encoding="utf-8")
    (root / "home" / "proj" / "bin" / "perl").chmod(0o755)


def _text(root: Path, value: object) -> object:
    if isinstance(value, str):
        return value.replace(str(root), TOKEN)
    if isinstance(value, (list, tuple)):
        return [_text(root, item) for item in value]
    if isinstance(value, dict):
        return {key: _text(root, item) for key, item in value.items()}
    return value


def _bind(root: Path, value: str | None) -> str | None:
    if value is None:
        return None
    return value.replace(TOKEN, str(root)).replace("{P}", str(root / "home" / "proj"))


@contextmanager
def _environment(root: Path, extra: dict[str, str], path: str | None = None) -> Iterator[None]:
    saved = dict(os.environ)
    for key in list(os.environ):
        if key.startswith("PERL"):
            del os.environ[key]
    os.environ["PATH"] = path if path is not None else str(root / "home" / "bin")
    os.environ.update(extra)
    try:
        yield
    finally:
        os.environ.clear()
        os.environ.update(saved)


def _stand_ins(root: Path) -> list[Callable[[], None]]:
    """Replace the resident's Git trust answers with the replay host's rules."""

    git = root / "home" / "bin" / "git"
    originals = (
        audit.trusted_git_binary_for_cwd,
        audit.git_log_has_execution_free_config,
        perl.git_binary_path_is_trusted,
    )

    def trusted_for_cwd(cwd: Path) -> Path | None:
        return None if "untrusted" in str(cwd) else git

    def log_config(cwd: Path, *, git_binary: Path, pager_key: str = "pager.log") -> bool:
        return "badconfig" not in str(cwd)

    def binary_trusted(git_path: Path, *, cwd: Path) -> bool:
        return "untrusted" not in str(cwd)

    audit.trusted_git_binary_for_cwd = trusted_for_cwd
    audit.git_log_has_execution_free_config = log_config
    perl.git_binary_path_is_trusted = binary_trusted

    def restore() -> None:
        audit.trusted_git_binary_for_cwd, audit.git_log_has_execution_free_config, perl.git_binary_path_is_trusted = (
            originals
        )

    return [restore]


def _parts(text: str) -> list[str]:
    return tokens._split_shell_parts(text) if hasattr(tokens, "_split_shell_parts") else text.split()


def _cases(root: Path) -> list[dict[str, object]]:
    proj = root / "home" / "proj"
    home = root / "home"
    cases: list[dict[str, object]] = []

    def add(function: str, args: list[object], result: object) -> None:
        cases.append({"fn": function, "args": _text(root, args), "result": _text(root, result)})

    def call(function: str, args: list[object], run: Callable[[], object], env: dict[str, str] | None = None) -> None:
        with _environment(root, env or {}):
            add(function, args, run())

    for template in AUDIT_TEXTS:
        text = _bind(root, template)
        for cwd_template in AUDIT_CWDS:
            cwd = _bind(root, cwd_template)
            for home_dir in (str(home),):
                args = [text, cwd, home_dir]
                call(
                    "read_only_git_audit",
                    args,
                    lambda: audit.is_read_only_git_ancestry_audit(
                        text, cwd=None if cwd is None else Path(cwd), home_dir=Path(home_dir)
                    ),
                )
        for home_dir in (str(root / "elsewhere"),):
            call(
                "read_only_git_audit",
                [text, str(proj), home_dir],
                lambda: audit.is_read_only_git_ancestry_audit(text, cwd=proj, home_dir=Path(home_dir)),
            )
    for argv in FETCH_ARGS:
        add("origin_shaped_git_fetch_args", [argv], origin.origin_shaped_git_fetch_args(tuple(argv)))
    for text in FETCH_TEXTS:
        parts = _parts(text)
        segments = tokens._iter_shell_command_segments(parts)
        add(
            "git_fetch_operands_text",
            [text],
            [
                None if (operands := origin.git_fetch_operands(tuple(segment))) is None else list(operands)
                for segment in segments
            ],
        )
        add(
            "command_is_origin_shaped_git_fetch",
            [text],
            origin.command_is_origin_shaped_git_fetch(tuple(tuple(segment) for segment in segments)),
        )
        for segment in segments:
            operands = origin.git_fetch_operands(tuple(segment))
            add("git_fetch_operands", [segment], None if operands is None else list(operands))
    add("command_is_origin_shaped_git_fetch", [""], origin.command_is_origin_shaped_git_fetch(()))

    for text in APPROVAL_TEXTS:
        add("is_guard_approval_mutation_command", [text], approval.is_guard_approval_mutation_command(text))
        parts = approval._split_shell_parts(text)
        add("approval_split_shell_parts", [text], parts)
        segments = approval._shell_segments(parts)
        add("approval_shell_segments", [parts], segments)
        for segment in segments:
            for depth in (0, 3, 4):
                add(
                    "approval_segment",
                    [segment, depth],
                    approval._segment_is_guard_approval_mutation(segment, depth=depth),
                )
            add("approval_first_executable_index", [segment], approval._first_executable_index(segment))
            add("approval_python_args", [segment], approval._python_module_args_mutate_approvals(segment))
            add("approval_guard_args", [segment], approval._guard_args_mutate_approvals(segment))
            add("approval_tail_mutation", [segment], approval._approval_tail_has_mutation(segment))
            for name in ("hatch", "mise", "nix", "pipx", "poetry", "uv", "uvx", "python", "other"):
                add("approval_runner_tail", [name, segment], approval._runner_wrapper_tail(name, segment))
            add("approval_tail_after_subcommand", [segment, ["run"]], approval._tail_after_subcommand(segment, {"run"}))
            add(
                "approval_tail_after_subcommand",
                [segment, ["exec", "run"]],
                approval._tail_after_subcommand(segment, {"exec", "run"}),
            )
            add("approval_tail_after_flag", [segment, "--command"], approval._tail_after_flag(segment, "--command"))
            for token in segment[:3]:
                add("approval_looks_env_assignment", [token], approval._looks_env_assignment(token))
                add("approval_is_python", [token.lower()], approval._is_python_interpreter(token.lower()))
    for argv in APPROVAL_LISTS:
        add("approval_segment", [argv, 0], approval._segment_is_guard_approval_mutation(argv, depth=0))
        add("approval_first_executable_index", [argv], approval._first_executable_index(argv))
        add("approval_python_args", [argv], approval._python_module_args_mutate_approvals(argv))
        add("approval_guard_args", [argv], approval._guard_args_mutate_approvals(argv))
        add("approval_tail_mutation", [argv], approval._approval_tail_has_mutation(argv))
        add("approval_tail_after_flag", [argv, "--command"], approval._tail_after_flag(argv, "--command"))
        add("approval_tail_after_subcommand", [argv, ["run"]], approval._tail_after_subcommand(argv, {"run"}))
        for name in ("hatch", "mise", "nix", "pipx", "poetry", "uv", "uvx", "other"):
            add("approval_runner_tail", [name, argv], approval._runner_wrapper_tail(name, argv))
    for token in (
        "",
        "A",
        "A=",
        "=",
        "A=1",
        "A+=1",
        "+=",
        "++=1",
        "_=1",
        "1=1",
        "a-b=1",
        "é=1",
        "٣=1",
        "a1_=x",
        "A B=1",
        "A",
    ):
        add("approval_looks_env_assignment", [token], approval._looks_env_assignment(token))
    for name in (
        "python",
        "py",
        "python3",
        "pythonw",
        "py3",
        "py3.11",
        "pyx",
        "pypy",
        "",
        "ipython",
        "pytest",
        "Python",
    ):
        add("approval_is_python", [name], approval._is_python_interpreter(name))
    for env in APPROVAL_ENVS:
        add("approval_from_agent", [env], approval.approval_resolution_invoked_from_agent(env))

    for text in MOVE_TEXTS:
        for cwd_template in MOVE_CWDS:
            for home_template in MOVE_HOMES[:1] if cwd_template != "{P}" else MOVE_HOMES:
                cwd = _bind(root, cwd_template)
                home_dir = _bind(root, home_template)
                bound = _bind(root, text)
                args = [bound, cwd, home_dir]
                call(
                    "routine_move",
                    args,
                    lambda: move._looks_like_safe_routine_move(
                        _parts(bound),
                        cwd=None if cwd is None else Path(cwd),
                        home_dir=None if home_dir is None else Path(home_dir),
                    ),
                )

    for prefix in PERL_PREFIXES[:1]:
        for template in PERL_TEXTS:
            bound = _bind(root, template)
            for cwd_template in PERL_CWDS[:1]:
                cwd = _bind(root, cwd_template)
                call(
                    "perl_read_only",
                    [bound, cwd, str(home), {}],
                    lambda: perl._looks_like_read_only_perl_filter(bound, cwd=Path(cwd), home_dir=home),
                )
    base = "perl -ne 'print if /foo/' src/a.txt"
    for prefix in PERL_PREFIXES:
        text = _bind(root, prefix + "'print if /foo/' src/a.txt")
        for cwd_template in PERL_CWDS:
            cwd = _bind(root, cwd_template)
            call(
                "perl_read_only",
                [text, cwd, str(home), {}],
                lambda: perl._looks_like_read_only_perl_filter(
                    text, cwd=None if cwd is None else Path(cwd), home_dir=home
                ),
            )
    for env in PERL_ENVS:
        call(
            "perl_read_only",
            [base, str(proj), str(home), env],
            lambda: perl._looks_like_read_only_perl_filter(base, cwd=proj, home_dir=home),
            env,
        )
        with _environment(root, env):
            add("perl_environment_safe", [env], perl._perl_execution_environment_is_safe())
    for path_template in PERL_PATHS:
        path = _bind(root, path_template)
        with _environment(root, {}, path):
            for prefix in PERL_PREFIXES:
                text = _bind(root, prefix + "'print if /foo/' src/a.txt")
                add(
                    "perl_read_only",
                    [text, str(proj), str(home), {"PATH": path}],
                    perl._looks_like_read_only_perl_filter(text, cwd=proj, home_dir=home),
                )
            for command in (
                "perl",
                "./bin/perl",
                "bin/perl",
                "{ROOT}/home/bin/perl",
                "{ROOT}/missing/perl",
                "perl/",
                "./perl",
            ):
                for cwd_template in ("{P}", "{ROOT}/home/untrusted/proj", "{ROOT}/home"):
                    command_text = _bind(root, command)
                    cwd = _bind(root, cwd_template)
                    add(
                        "perl_trusted_command",
                        [command_text, cwd, {"PATH": path}],
                        perl._trusted_perl_command(command_text, cwd=Path(cwd)),
                    )
    for script in (
        "print if /foo/",
        "print if /foo/i",
        "print if /foo/z",
        "print if /foo/ix",
        "print if /foo",
        "print if /",
        "print if //",
        "print if /a\\/b/",
        "print if /a\\\\/",
        "print if /a\\\\\\/",
        "print if /a\\",
        "print if /é/i",
        "print if /a/\n",
        "print if /a/ ",
        "print if /é/é",
        "print  if /foo/",
        "print if",
        "",
        "x",
        "print if /a//",
        "print if /a/i/",
        "print if /\\//",
        "print if /[/]/",
    ):
        add("perl_print_if_pattern", [script], perl._perl_print_if_pattern(script))
    return cases


def main() -> None:
    fixture_dir = Path(sys.argv[1])
    saved_cwd = os.getcwd()
    with tempfile.TemporaryDirectory(prefix="sfrs-leaf-") as scratch:
        root = Path(scratch).resolve()
        _build(root)
        os.chdir(root / "home" / "proj")
        tempfile.tempdir = str(root / "tmp")
        restore = _stand_ins(root)
        try:
            document = {"schema": "sfrs-leaf.v1", "tree": TREE, "cases": _cases(root)}
        finally:
            for undo in restore:
                undo()
            tempfile.tempdir = None
            os.chdir(saved_cwd)
    out = fixture_dir / "sfrs_leaf.json.gz"
    out.write_bytes(gzip.compress(json.dumps(document, sort_keys=True).encode("utf-8"), mtime=0))
    print(f"{len(document['cases'])} cases -> {out}")


if __name__ == "__main__":
    main()
