"""Record parity vectors for the PR body-file, ephemeral-body and Actions read checks.

Usage: ``SFRS_GH_CLASSIFIER=<guard-command-source binary> sfrs_github_body_cases.py
FIXTURE_DIR`` with the repository ``src`` on ``PYTHONPATH``. GitHub CLI
classification is answered by the Rust classifier, as in production. A fixed tree is built under a fresh root; every case runs with a
recorded environment (``PATH``, ``TMPDIR``, ``HOME``, ...) and stores the result
with the ``{ROOT}`` token so the Rust port can rebuild the tree and replay it.
Secret-content classification and executable trust are replaced by fixed stubs
that the replay host mirrors. Retired with the Python implementation.
"""

# ruff: noqa
from __future__ import annotations

import base64
import gzip
import json
import os
import sys
import tempfile
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "tests"))

from native_github_offline import install_offline_github_classifier  # noqa: E402

from codex_plugin_scanner.guard.runtime import github_pr_body_file as bf
from codex_plugin_scanner.guard.runtime.secret_file_request_services import shell_quote_tokens as sqt
from codex_plugin_scanner.guard.runtime.shell_structure import extract_heredocs, mask_complete_heredocs

TOKEN = "{ROOT}"
SECRET_MARKER = "SECRET"
OVERSIZE = 131073
LIMIT = 131072

TREE: dict[str, object] = {
    "dirs": {
        "home": 0o700,
        "home/proj": 0o700,
        "home/proj/docs": 0o700,
        "home/proj/open": 0o777,
        "home/proj/open/inner": 0o700,
        "home/proj/.ssh": 0o700,
        "home/proj/real": 0o700,
        "home/CascadeProjects": 0o700,
        "home/CascadeProjects/app": 0o700,
        "home/.omp": 0o700,
        "home/.omp/agent": 0o700,
        "home/.omp/agent/sessions": 0o700,
        "home/.omp/agent/sessions/s1": 0o700,
        "home/.omp/agent/sessions/s1/s2": 0o700,
        "home/.omp/agent/sessions/s1/s2/local": 0o700,
        "tmp": 0o700,
        "tmp/work": 0o700,
        "stk": 0o1777,
        "stk/work": 0o700,
        "bin": 0o755,
        "badbin": 0o755,
        "tmp/lib": 0o755,
        "pr-body.md": 0o700,
    },
    "files": {},
    "links": {
        "home/proj/link-pr-body.md": "pr-body.md",
        "home/proj/dirlink": "real",
        "home/proj/dangling-pr-body.md": "missing.md",
        "bin2": "bin",
        "badbin/gh-link": "../bin/gh",
    },
    "hardlinks": {"home/proj/hard-pr-body.md": "home/proj/pr-body.md"},
}


def _file(text: str | bytes = "hello\n", mode: int = 0o600, age: float = 5.0) -> dict[str, object]:
    raw = text.encode("utf-8") if isinstance(text, str) else text
    return {"b64": base64.b64encode(raw).decode("ascii"), "mode": mode, "age": age}


def _tree_files() -> dict[str, dict[str, object]]:
    files = {
        "home/proj/pr-body.md": _file(),
        "home/proj/PR-BODY.MD": _file(),
        "home/proj/pr-body.markdown": _file(),
        "home/proj/pr_body_x.md": _file(),
        "home/proj/x-pr-body.md": _file(),
        "home/proj/docs/a-pr-body.md": _file("docs \u00e9\u4e2d\n"),
        "home/proj/real/pr-body.md": _file(),
        "home/proj/secret-pr-body.md": _file("token " + SECRET_MARKER + "\n"),
        "home/proj/empty-pr-body.md": _file(""),
        "home/proj/big-pr-body.md": _file(b"a" * OVERSIZE),
        "home/proj/limit-pr-body.md": _file(b"a" * LIMIT),
        "home/proj/bad-pr-body.md": _file(b"\xff\xfe\x00"),
        "home/proj/gw-pr-body.md": _file(mode=0o660),
        "home/proj/ow-pr-body.md": _file(mode=0o602),
        "home/proj/ro-pr-body.md": _file(mode=0o400),
        "home/proj/old-pr-body.md": _file(age=172800.0),
        "home/proj/day-pr-body.md": _file(age=82800.0),
        "home/proj/future-pr-body.md": _file(age=-120.0),
        "home/proj/soon-pr-body.md": _file(age=-10.0),
        "home/proj/credentials-pr-body.md": _file(),
        "home/proj/token-pr-body.md": _file(),
        "home/proj/.ssh/pr-body.md": _file(),
        "home/proj/notes.txt": _file(),
        "home/proj/pr-body.md.bak": _file(),
        "home/proj/pr-body": _file(),
        "home/proj/open/pr-body.md": _file(),
        "home/proj/open/inner/pr-body.md": _file(),
        "home/proj/pr-b\u00f6dy.md": _file(),
        "home/proj/sp ace-pr-body.md": _file(),
        "home/CascadeProjects/app/pr-body.md": _file(),
        "home/.omp/agent/sessions/s1/s2/local/pr-body.md": _file(),
        "home/.omp/agent/sessions/s1/pr-body.md": _file(),
        "tmp/pr-body.md": _file(),
        "tmp/work/pr-body.md": _file(),
        "stk/pr-body.md": _file(),
        "stk/work/pr-body.md": _file(),
        "bin/gh": _file("#!/bin/sh\n", 0o755),
        "bin/grep": _file("#!/bin/sh\n", 0o755),
        "bin/rg": _file("#!/bin/sh\n", 0o755),
        "bin/sort": _file("#!/bin/sh\n", 0o755),
        "bin/head": _file("#!/bin/sh\n", 0o755),
        "bin/tail": _file("#!/bin/sh\n", 0o755),
        "bin/echo": _file("#!/bin/sh\n", 0o755),
        "bin/plain": _file("x", 0o644),
        "badbin/gh": _file("#!/bin/sh\n", 0o755),
        "badbin/grep": _file("#!/bin/sh\n", 0o755),
        "badbin/rg": _file("#!/bin/sh\n", 0o755),
        "badbin/sort": _file("#!/bin/sh\n", 0o755),
        "badbin/head": _file("#!/bin/sh\n", 0o755),
        "badbin/tail": _file("#!/bin/sh\n", 0o755),
        "tmp/lib/libx.so": _file("x", 0o755),
    }
    return files


TREE["files"] = _tree_files()
TREE["dirs"].pop("pr-body.md")  # type: ignore[union-attr]
TREE["dirs"]["home/proj/dirpr-body.md"] = 0o700  # type: ignore[index]
TREE["dirs"]["home/proj/a-pr-body.md"] = 0o700  # type: ignore[index]


def _build(root: Path) -> None:
    dirs: dict[str, int] = TREE["dirs"]  # type: ignore[assignment]
    for name in sorted(dirs, key=lambda item: item.count("/")):
        (root / name).mkdir(parents=True, exist_ok=True)
    for name, spec in TREE["files"].items():  # type: ignore[union-attr]
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(base64.b64decode(spec["b64"]))
        os.chmod(path, spec["mode"])
        stamp = time.time() - spec["age"]
        os.utime(path, (stamp, stamp))
    for name, target in TREE["links"].items():  # type: ignore[union-attr]
        os.symlink(target, root / name)
    for name, target in TREE["hardlinks"].items():  # type: ignore[union-attr]
        os.link(root / target, root / name)
    for name, mode in dirs.items():
        os.chmod(root / name, mode)


def _text(root: Path, value: object) -> object:
    if isinstance(value, str):
        return value.replace(str(root), TOKEN)
    if isinstance(value, (list, tuple)):
        return [_text(root, item) for item in value]
    if isinstance(value, dict):
        return {key: _text(root, item) for key, item in value.items()}
    if isinstance(value, Path):
        return str(value).replace(str(root), TOKEN)
    return value


def _fake_secret(content: str, *, suppress_samples: bool = True) -> list[str]:
    return ["secret"] if SECRET_MARKER in content else []


def _env_base(root: Path) -> dict[str, str]:
    return {"PATH": str(root / "bin"), "TMPDIR": str(root / "tmp"), "HOME": str(root / "home")}
