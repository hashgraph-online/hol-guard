#!/usr/bin/env python3
"""Record parity vectors for memory pattern fingerprints and lookup candidates.

Usage: GUARD_PY_SNAPSHOT=<path to src dir of the reference snapshot> \
    python scripts/record_memory_pattern_vectors.py [snapshot_src]

The reference snapshot must predate the move of memory pattern fingerprints
and remembered-decision lookup candidates to the native runtime (base commit
``BASE_COMMIT``). Each vector is one request for the ``memory_pattern`` context
digest kind and the reference fingerprint, exact-command ids and memory-pattern
id. The Rust tests replay the request; the Python tests check the transport
still decodes the same answer. Deterministic output.
"""

from __future__ import annotations

import ast
import gzip
import hashlib
import importlib
import json
import os
import sys
from collections.abc import Sequence
from pathlib import Path

snapshot = os.environ.get("GUARD_PY_SNAPSHOT") or (sys.argv[1] if len(sys.argv) > 1 else "")
if not snapshot:
    sys.exit("set GUARD_PY_SNAPSHOT or pass the snapshot src directory")
sys.path.insert(0, snapshot)

# The module exists only in the snapshot, so it is loaded by name from there.
fingerprints = importlib.import_module("codex_plugin_scanner.guard." + "memory_pattern_fingerprint")

# store_policy imports the whole store stack; load only the candidate helpers
# from the snapshot's source so the reference stays the old Python.
_HELPERS = ("_memory_artifact_is_shell_command", "_distinct_non_null", "memory_lookup_candidates")


def _load_lookup_helpers() -> dict[str, object]:
    source = (Path(snapshot) / "codex_plugin_scanner/guard/store_policy.py").read_text(encoding="utf-8")
    module = ast.parse(source)
    body = [node for node in module.body if isinstance(node, ast.FunctionDef) and node.name in _HELPERS]
    assert sorted(node.name for node in body) == sorted(_HELPERS), "store_policy helpers moved"
    namespace: dict[str, object] = {
        "Sequence": Sequence,
        "build_exact_command_memory_artifact_id": fingerprints.build_exact_command_memory_artifact_id,
        "build_exact_shell_command_memory_artifact_id": fingerprints.build_exact_shell_command_memory_artifact_id,
        "build_memory_pattern_fingerprint": fingerprints.build_memory_pattern_fingerprint,
    }
    exec(compile(ast.Module(body=body, type_ignores=[]), "store_policy.py", "exec"), namespace)
    return namespace


_LOOKUP = _load_lookup_helpers()

BASE_COMMIT = "11f9e30d08"
OUT = Path(__file__).resolve().parent.parent / "rust/crates/guard-runtime/tests/fixtures"
FIELDS = ("command", "artifact_type", "artifact_id", "artifact_name", "harness")
LONG_PATH = "/".join(f"segment{index}" for index in range(30))


def case(name: str, command: object = None, **fields: object) -> tuple[str, dict[str, object]]:
    request: dict[str, object] = {"command": command, "harness": "codex"}
    request.update(fields)
    return name, {key: request.get(key) for key in FIELDS}


def cases() -> list[tuple[str, dict[str, object]]]:
    out = [
        # Package installs.
        case("npm-install", "npm install lodash"),
        case("npm-i-alias", "npm i lodash"),
        case("npm-flag-before-package", "npm install -g pm2"),
        case("npm-only-flags", "npm install --save-dev"),
        case("npm-no-package", "npm install"),
        case("npm-version-pin", "npm install lodash@4.17.21"),
        case("npm-scoped", "npm install @types/node"),
        case("npm-scoped-version", "npm install @types/node@20.1.0"),
        case("npm-scoped-only-at", "npm install @"),
        case("npm-quoted-package", "npm install 'Lodash'"),
        case("npm-quoted-empty", "npm install ''"),
        case("npm-uppercase-manager", "NPM INSTALL Express"),
        case("pnpm-add", "pnpm add react"),
        case("yarn-add", "yarn add vue"),
        case("bun-add", "bun add zod"),
        case("npm-ci", "npm ci left-pad"),
        case("npm-run-not-install", "npm run build"),
        case("pip-install-pin", "pip install requests==2.31.0"),
        case("pip3-install-range", "pip3 install 'django>=4,<5'"),
        case("pip-install-compatible", "pip install numpy~=1.26"),
        case("pip-install-not-equal", "pip install flask!=2.0"),
        case("pip-install-lt", "pip install urllib3<2"),
        case("pip-install-upgrade-flag", "pip install -U requests"),
        case("uv-add", "uv add httpx"),
        case("uv-pip-install", "uv pip install httpx"),
        case("poetry-add", "poetry add black"),
        case("cargo-add", "cargo add serde"),
        case("cargo-install", "cargo install ripgrep"),
        case("go-add", "go add example.com/mod"),
        case("go-get-not-install", "go get example.com/mod"),
        case("gem-install", "gem install rails"),
        case("brew-install", "brew install jq"),
        case("brew-upgrade", "brew upgrade jq"),
        case("npm-in-alias", "npm in lodash"),
        case("npm-up-alias", "npm up lodash"),
        case("package-no-harness", "npm install lodash", harness=None),
        case("package-blank-harness", "npm install lodash", harness="   "),
        case("package-harness-case", "npm install lodash", harness="  Claude-Code "),
        case("package-long-name", "npm install " + "a" * 120),
        # MCP tools.
        case("mcp-command", "call mcp__GitHub__create_issue now"),
        case("mcp-command-dashes", "mcp__my-server__list_items"),
        case("mcp-command-nested-separators", "mcp__my_server__extra__tool_name"),
        case("mcp-command-no-tool", "mcp__server__"),
        case("mcp-command-kelvin", "mcp__\u212aube__list"),
        case("mcp-command-long-s", "mcp__\u017fearch__find"),
        case("mcp-command-dotted-i", "mcp__\u0130ndex__get"),
        case("mcp-command-dotless-i", "mcp__\u0131ndex__get"),
        case("mcp-command-micro-stops", "mcp__ab\xb5c__get"),
        case("mcp-artifact-id", None, artifact_id="MCP:Linear:Create_Issue:extra"),
        case("mcp-artifact-id-short", None, artifact_id="mcp:linear"),
        case("mcp-artifact-id-empty-parts", None, artifact_id="mcp::"),
        case("mcp-artifact-id-padded", None, artifact_id="  mcp:srv:tool  "),
        # File reads.
        case("file-read-cat", "cat /etc//hosts", artifact_type="file"),
        case("file-read-head", "head ./src/app/main.py", artifact_type="path"),
        case("file-read-config", "tail -f /var/log/app.log", artifact_type="config"),
        case("file-read-flag-path", "less -N notes.txt", artifact_type="file_read"),
        case("file-read-type-case", "view Docs/Readme.md", artifact_type="FILE_READ_REQUEST"),
        case("file-read-type-padded", "cat a/b", artifact_type=" file "),
        case("file-read-not-file-type", "cat /etc/hosts", artifact_type="tool"),
        case("file-read-no-type", "cat /etc/hosts"),
        case("file-read-unknown-verb", "open /etc/hosts", artifact_type="file"),
        case("file-read-verb-only", "cat", artifact_type="file"),
        case("file-read-hash", "cat /tmp/0123456789abcdef0123/out.txt", artifact_type="file"),
        case("file-read-short-hex", "cat /tmp/deadbeef/out.txt", artifact_type="file"),
        case("file-read-hash-joined", "cat /tmp/x0123456789abcdef0123/out", artifact_type="file"),
        case("file-read-hash-suffix-word", "cat /tmp/0123456789abcdef0123g/out", artifact_type="file"),
        case(
            "file-read-uuid",
            "cat /runs/123e4567-e89b-12d3-a456-426614174000/log.txt",
            artifact_type="file",
        ),
        case("file-read-env", "cat $HOME/.config/app/settings.toml", artifact_type="file"),
        case("file-read-env-braced", "cat ${XDG_DATA}/app/x", artifact_type="file"),
        case("file-read-env-brace-no-word", "cat ${/x/y", artifact_type="file"),
        case("file-read-env-dollar-alone", "cat $/x/y", artifact_type="file"),
        case("file-read-numbers", "cat logs/2024/05/run7.log", artifact_type="file"),
        case("file-read-unicode-digits", "cat logs/\u0663\u0664/x", artifact_type="file"),
        case("file-read-unicode-letter-boundary", "cat d\xe9123/x", artifact_type="file"),
        case("file-read-combining-mark-boundary", "cat a\u0301123/x", artifact_type="file"),
        case("file-read-only-slashes", "cat ///", artifact_type="file"),
        case("file-read-quoted-path", "cat '\"/Etc/Hosts\"'", artifact_type="file"),
        case("file-read-long-path", "cat " + LONG_PATH, artifact_type="file"),
        # Shell commands.
        case("shell-git-status", "git status"),
        case("shell-git-target", "git push --force origin"),
        case("shell-git-dashed-target", "git log --oneline"),
        case("shell-docker-target", "docker run -it ubuntu"),
        case("shell-gh-target", "gh pr view 12"),
        case("shell-kubectl", "kubectl get pods"),
        case("shell-curl", "curl -sSL https://example.com"),
        case("shell-other-no-target", "make test all"),
        case("shell-bare-verb", "ls -la"),
        case("shell-echo", "echo hello"),
        case("shell-single-token", "pytest"),
        case("shell-only-dashes", "make --"),
        case("shell-target-only-dashes", "git -- --"),
        case("shell-uppercase", "GIT Status Origin"),
        case("shell-no-harness", "git status", harness=None),
        case("shell-long", "git commit " + "x" * 120),
        case("shell-long-colons", "git " + ":" * 100),
        # Control operators.
        case("control-and", "git status && rm -rf /"),
        case("control-semicolon", "git status; ls"),
        case("control-pipe", "git log | head"),
        case("control-newline", "git status\nls"),
        case("control-background", "sleep 1 &"),
        case("control-quoted-double", 'git commit -m "a;b"'),
        case("control-quoted-single", "git commit -m 'a|b'"),
        case("control-escaped", "git commit -m a\\;b"),
        case("control-escaped-in-single", "echo 'a\\'; ls"),
        case("control-escaped-in-double", 'git commit -m "a\\";b"'),
        case("control-unterminated-quote", "git commit -m 'a;b"),
        case("control-mixed-quotes", 'git commit -m "it\'s;" x'),
        # Generic artifacts and tool actions.
        case("generic-artifact-id", None, artifact_id="Codex:Project:Deploy", artifact_type="Skill"),
        case("generic-artifact-name", None, artifact_name="Deploy Script", artifact_type=None),
        case("generic-artifact-label", None, artifact_id="read"),
        case("generic-artifact-label-name", None, artifact_name=" Pi:Project:Read "),
        case("generic-artifact-blank", None, artifact_id="   ", artifact_name=""),
        case("generic-artifact-blank-id-name", None, artifact_id="  ", artifact_name="deployer"),
        case("generic-artifact-no-harness", None, artifact_id="x:y", harness=None),
        case(
            "tool-action-uses-artifact",
            "npm install lodash",
            artifact_type="tool_action_request",
            artifact_id="codex:tool:bash",
            artifact_name="Bash",
        ),
        case(
            "tool-output-uses-artifact",
            "git status && rm",
            artifact_type=" TOOL_OUTPUT ",
            artifact_name="Read Output",
        ),
        case("tool-action-generic", "git status", artifact_type="tool_action_request", artifact_id="bash"),
        case("tool-action-empty", "git status", artifact_type="tool_action_request"),
        case("generic-long-artifact", None, artifact_id="artifact:" + "z" * 120),
        case("generic-long-unicode", None, artifact_id="\xe9" * 120),
        # Generic-label filter on the final fingerprint.
        case("command-none-all-none", None, artifact_type=None, harness=None),
        case("command-empty", ""),
        case("command-whitespace", " \t\n "),
        case("command-python-space", "\x1cgit\x1fstatus\x1d"),
        case("command-nbsp-splits", "git\xa0status"),
        case("command-zero-width-not-space", "git\u200bstatus x"),
        # Unicode lowercasing.
        case("unicode-final-sigma", "git \u039f\u0394\u039f\u03a3"),
        case("unicode-sigma-medial", "git \u03a3\u039f"),
        case("unicode-dotted-capital-i", "git \u0130stanbul"),
        case("unicode-harness-sigma", "git status", harness="\u039f\u03a3"),
        case("unicode-sharp-s", "git STRASSE stra\xdfe"),
        # Shell-domain exact-command ids.
        case("exact-bash-type", "ls -la", artifact_type="bash"),
        case("exact-shell-type-case", "ls -la", artifact_type=" SHELL "),
        case("exact-shell-command-type", "rm -rf build", artifact_type="shell_command"),
        case("exact-long-s-type", "ls", artifact_type="\u017fhell"),
        case("exact-tool-action-bash", "ls", artifact_type="tool_action_request", artifact_name="Bash"),
        case(
            "exact-tool-action-bash-prefix",
            "ls",
            artifact_type="tool_action_request",
            artifact_name="bash ls -la",
        ),
        case("exact-tool-action-shell-prefix", "ls", artifact_type="tool_action_request", artifact_name="Shell: x"),
        case("exact-tool-action-other", "ls", artifact_type="tool_action_request", artifact_name="Read"),
        case("exact-tool-action-no-name", "ls", artifact_type="tool_action_request"),
        case("exact-blank-command", "   ", artifact_type="bash"),
        case("exact-none-command", None, artifact_type="bash"),
        case("exact-preserves-bytes", "  ls\t-la \xe9 ", artifact_type="bash"),
        case(
            "exact-excludes-artifact-id",
            "ls",
            artifact_type="bash",
            artifact_id="memory:exact-command:" + hashlib.sha256(b"ls").hexdigest(),
        ),
        case("exact-non-shell-type", "ls -la", artifact_type="file"),
        # Memory id equals the artifact id.
        case("memory-id-equals-artifact", "git status", artifact_id="placeholder"),
    ]
    names = [name for name, _ in out]
    assert len(names) == len(set(names)), "duplicate case names"
    return out


def expected(request: dict[str, object]) -> dict[str, object]:
    pattern = fingerprints.build_memory_pattern_fingerprint(
        command=request["command"],
        artifact_type=request["artifact_type"],
        artifact_id=request["artifact_id"],
        artifact_name=request["artifact_name"],
        harness=request["harness"],
    )
    harness = request["harness"]
    exact_ids, memory_id = _LOOKUP["memory_lookup_candidates"](  # type: ignore[operator]
        harness if isinstance(harness, str) else "",
        request["artifact_id"],
        memory_command=request["command"],
        memory_artifact_type=request["artifact_type"],
        memory_artifact_name=request["artifact_name"],
    )
    if not isinstance(harness, str):
        # Lookups always carry a harness; without one there is no memory id.
        memory_id = None
    return {
        "pattern": None
        if pattern is None
        else {
            "fingerprint": pattern.fingerprint,
            "kind": pattern.kind,
            "components": [[key, value] for key, value in pattern.components.items()],
        },
        "exact_artifact_ids": list(exact_ids),
        "memory_artifact_id": memory_id,
    }


def main() -> None:
    vectors = [{"name": name, "request": request, "expected": expected(request)} for name, request in cases()]
    # The memory id must equal the artifact id for this case to exercise the exclusion.
    for vector in vectors:
        if vector["name"] == "memory-id-equals-artifact":
            pattern = vector["expected"]["pattern"]
            assert pattern is not None
            vector["request"]["artifact_id"] = f"memory:codex:{pattern['kind']}:{pattern['fingerprint']}"
            vector["expected"] = expected(vector["request"])
            assert vector["expected"]["memory_artifact_id"] is None
    document = {"base_commit": BASE_COMMIT, "cases": vectors}
    path = OUT / "memory_pattern_vectors.json.gz"
    encoded = (json.dumps(document, separators=(",", ":"), ensure_ascii=False) + "\n").encode()
    path.write_bytes(gzip.compress(encoded, compresslevel=9, mtime=0))
    print(f"recorded {len(vectors)} vectors to {path.name}")


if __name__ == "__main__":
    main()
