#!/usr/bin/env python3
"""Record parity vectors for custom-extension suggestion ranking.

Usage: GUARD_PY_SNAPSHOT=<path to src dir of the reference snapshot> \
    python scripts/record_custom_extension_suggestion_vectors.py [snapshot_src]

The reference snapshot must predate the move of suggestion ranking to the
native runtime. Each vector is one observed tool and the reference answer.
The Rust tests in rust/crates/guard-runtime replay them. Deterministic output.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

snapshot = os.environ.get("GUARD_PY_SNAPSHOT") or (sys.argv[1] if len(sys.argv) > 1 else "")
if not snapshot:
    sys.exit("set GUARD_PY_SNAPSHOT or pass the snapshot src directory")
sys.path.insert(0, snapshot)

from codex_plugin_scanner.guard.runtime import custom_extension_suggestion as reference  # noqa: E402

OUT = Path(__file__).resolve().parent.parent / "rust/crates/guard-runtime/tests/fixtures"

NAMES = [
    "deploy-tool",
    "mytool",
    "abc",
    "ab-c",
    "abcd-e",
    "x_y",
    "long_name",
    "release.sh",
    "rel.py",
    "ab.py",
    "build.sh",
    "main.py",
    "rg",
    "RG.EXE",
    "  jq  ",
    "grep.cmd",
    "whoami",
    "asciinema",
    "script",
    "script.py",
    "hol-guard",
    "Guard",
    "vitest",
    "py.test",
    "pytest.py",
    "test_api.py",
    "api.test.ts",
    "api.spec.js",
    "api_test.rb",
    "api_spec.sh",
    "api.test.txt",
    "notes.test",
    "kubectl",
    "terraform",
    "Ünïcode-tool",
    "İstanbul",
    "\u00a0padded\u2003",
    "",
    ".",
    ".hidden",
    "tool.exe.cmd",
    "deploy",
    "[",
    "a.b.c",
    "cli.mjs",
    "Tools",
]
PATHS = [
    None,
    "",
    "unknown",
    "package-store",
    "system-bin",
    "user-tool",
    "project-tool",
    "registry-package",
    "/usr/local/bin/tool",
    "/usr/bin/tool",
    "/usr/bin",
    "/bin",
    "/sbin/x",
    "/home/a/node_modules/.bin/x",
    "C:\\Users\\a\\node_modules\\x\\cli.js",
    "node_modules",
    "node_modules/x",
    "/x/.pnpm/y",
    "/x/.venv/bin/y",
    "/x/venv/bin/y",
    "/x/site-packages/y",
    "/x/__pycache__/y",
    "/home/a/.nvm/versions/node/bin/x",
    "/opt/nvm/versions/x",
    "C:\\Windows\\System32\\cmd.exe",
    "c:/windows/syswow64/x.exe",
    "\\\\?\\C:\\Windows\\System\\x",
    "//?/c:/windows/system32/x",
    "windows/system32/x",
    "D:\\Tools\\deploy.exe",
    "/USR/BIN/Tool",
    "/home/a/bin/tool",
    "relative/tool",
]
SAMPLES = [
    ("executable", 0, None, "cli"),
    ("script", 1, "ok", "cli"),
    ("script", 2, "ok", "cli"),
    ("executable", 5, "ok", "cli"),
    ("executable", 7, "failed", "cli"),
    ("executable", -3, None, "mcp"),
    ("script", 0, None, "package-scripts"),
    ("weird", 9, "ok", "other"),
]


def _vector(name: str, kind: str, source_path: str | None, count: int, help_status: str | None, surface: str):
    score = reference.suggestion_score(
        name=name,
        kind=kind,  # type: ignore[arg-type]
        source_path=source_path,
        observed_count=count,
        help_status=help_status,
        surface=surface,
    )
    return {
        "tool": {
            "name": name,
            "kind": kind,
            "source_path": source_path,
            "observed_count": count,
            "help_status": help_status,
            "surface": surface,
        },
        "expected": {
            "score": score,
            "suggestable": reference.is_suggestable_custom_tool(
                name=name,
                kind=kind,  # type: ignore[arg-type]
                source_path=source_path,
                observed_count=count,
                help_status=help_status,
                surface=surface,
            ),
            "path_class": reference.observation_path_class(source_path),
            "common_utility": reference.is_common_shell_utility(name),
            "reject_message": reference.common_utility_reject_message(name),
        },
    }


def main() -> None:
    vectors = []
    for index, name in enumerate(NAMES):
        for sample_index, (kind, count, help_status, surface) in enumerate(SAMPLES):
            source_path = PATHS[(index * len(SAMPLES) + sample_index) % len(PATHS)]
            vectors.append(_vector(name, kind, source_path, count, help_status, surface))
    for source_path in PATHS:
        vectors.append(_vector("deploy-tool", "script", source_path, 3, "ok", "cli"))
    OUT.mkdir(parents=True, exist_ok=True)
    target = OUT / "custom_extension_suggestion_vectors.json"
    target.write_text(json.dumps(vectors, indent=1, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {len(vectors)} vectors to {target}")


if __name__ == "__main__":
    main()
