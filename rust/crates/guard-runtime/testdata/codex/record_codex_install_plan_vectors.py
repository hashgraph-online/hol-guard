#!/usr/bin/env python3
"""Record `codex_install_plan` replay vectors from the ORIGINAL Python helpers.

Run against a checkout that still removes Codex shell blocks and recognizes
Guard MCP proxies in Python (the base of the commit that introduced the
native `codex_install_plan` runner-authority kind), never from Rust output:

    cd <base-worktree>
    PYTHONPATH=$PWD/src python3 <this-file> <output codex_install_plan_vectors.json>

`shell_blocks` cases pin a file's bytes (as Latin-1 text, the way the request
carries them) and the bytes the helper left. `guard_proxies` cases pin one
launch and whether the helper recognized it as a Guard proxy.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from codex_plugin_scanner.guard.adapters.codex import _remove_managed_shell_guard_blocks
from codex_plugin_scanner.guard.adapters.mcp_servers import is_guard_proxy_command

BEGIN = b"# >>> HOL Guard Codex shell guard >>>"
END = b"# <<< HOL Guard Codex shell guard <<<"
BLOCK = BEGIN + b"\nexport HOL_GUARD=1\n" + END

SHELL_CASES: list[bytes] = [
    b"",
    b"export PATH=/bin\n",
    BLOCK,
    BLOCK + b"\n",
    b"export A=1\n\n" + BLOCK + b"\n",
    b"export A=1\n\n" + BLOCK + b"\nexport B=2\n",
    b"export A=1\r\n\r\n" + BLOCK.replace(b"\n", b"\r\n") + b"\r\nexport B=2\r\n",
    b"export A=1\n" + BLOCK + b"\nexport B=2\n",
    b"export A=1\n\n\n" + BLOCK + b"\n",
    b"\n" + BLOCK + b"\n",
    b"\n\n" + BLOCK + b"\n",
    BLOCK + b"\n" + BLOCK + b"\n",
    b"a\n\n" + BLOCK + b"\n\n" + BLOCK + b"\nz\n",
    b"a\n\n" + BLOCK + b"\n" + BLOCK + b"\n",
    BEGIN + b"\nunterminated\n",
    b"x" + BLOCK + b"\n",
    BEGIN + b" trailing\n" + END + b"\n",
    BEGIN + b"\n" + END + b" trailing\n" + END + b"\nrest\n",
    BEGIN + b"\n" + END + b"\rrest\n",
    BEGIN + b"\n" + BEGIN + b"\n" + END + b"\n",
    END + b"\n" + BLOCK + b"\n",
    b"caf\xe9\n\n" + BLOCK + b"\n\xff\xfe\n",
    b"a\n" + BEGIN + b"\n" + END,
    b"keep\n\n" + BLOCK + b"\n\n" + BLOCK,
]

PROXY_CASES: list[tuple[str | None, list[str]]] = [
    (None, ["codex-mcp-proxy"]),
    ("hol-guard", ["codex-mcp-proxy", "--server", "x"]),
    ("/opt/bin/hol-guard", ["guard", "codex-mcp-proxy"]),
    ("C:\\Tools\\HOL-GUARD.EXE", ["cursor-mcp-proxy"]),
    ("current-hol-guard.cmd", ["mcp-proxy"]),
    ("hol-guard.bat", ["-m", "codex_plugin_scanner.cli", "guard", "hermes-mcp-proxy"]),
    ("hol-guard", ["mcp-relay", "/usr/bin/python3", "-m", "codex_plugin_scanner.cli", "guard", "codex-mcp-proxy"]),
    ("hol-guard", ["mcp-relay", "/usr/bin/python3", "codex-mcp-proxy"]),
    ("hol-guard", ["serve"]),
    ("hol-guard", []),
    ("hol-guard-extra", ["codex-mcp-proxy"]),
    ("hol-guard/", ["codex-mcp-proxy"]),
    ("/usr/bin/python3", ["-m", "codex_plugin_scanner.cli", "guard", "codex-mcp-proxy"]),
    ("/usr/bin/python3", ["-I", "-m", "codex_plugin_scanner.cli", "guard", "opencode-mcp-proxy", "--x"]),
    ("/usr/bin/python3", ["codex_plugin_scanner.cli", "copilot-mcp-proxy"]),
    ("/usr/bin/python3", ["guard", "codex-mcp-proxy"]),
    ("/usr/bin/python3", ["-m", "codex_plugin_scanner.cli", "guard", "scan"]),
    ("npx", ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]),
    ("/runtime/hol-guard-runtime", ["mcp-relay", "/usr/bin/python3", "-m", "codex_plugin_scanner.cli", "guard"]),
    (
        "/runtime/hol-guard-runtime",
        ["mcp-relay", "/usr/bin/python3", "-m", "codex_plugin_scanner.cli", "guard", "cline-mcp-proxy"],
    ),
]


def main(output: Path) -> None:
    shell = [
        {
            "content": content.decode("latin-1"),
            "cleaned": _remove_managed_shell_guard_blocks(content).decode("latin-1"),
        }
        for content in SHELL_CASES
    ]
    proxies = [
        {"command": command, "args": args, "guard": is_guard_proxy_command(command, tuple(args))}
        for command, args in PROXY_CASES
    ]
    document = {"schema": "guard-codex-install-plan-vectors.v1", "shell_blocks": shell, "guard_proxies": proxies}
    output.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
