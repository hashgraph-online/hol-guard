#!/usr/bin/env python3
"""Record Copilot detection vectors from the ORIGINAL Python implementation.

Run against a checkout that still holds `CopilotHarnessAdapter._hook_artifacts`
and `_mcp_artifacts` (the base of the commit that introduced the native
`copilot_detect` runner-authority kind), never from Rust output:

    cd <base-worktree>
    PYTHONPATH=$PWD/src python3 <this-file> <output vectors.json>

Each case materializes a fixture tree under a temporary root, runs the
original `detect` over it (optionally with captured config contents) and
records the artifacts and config paths plus the arguments the native facade
sends. `<ROOT>` stands for the fixture root.
"""

from __future__ import annotations

import dataclasses
import json
import shutil
import sys
import tempfile
from pathlib import Path

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.copilot import CopilotHarnessAdapter
from codex_plugin_scanner.guard.models import GuardArtifact

if not hasattr(CopilotHarnessAdapter, "_hook_artifacts"):
    sys.exit("refusing to record: the original Python Copilot discovery is gone")

HOME, WORK = "home", "work"
CONFIG = f"{HOME}/.copilot/config.json"
MCP_CONFIG = f"{HOME}/.copilot/mcp-config.json"
WS_MCP = f"{WORK}/.mcp.json"
VSCODE_MCP = f"{WORK}/.vscode/mcp.json"
HOOKS = f"{WORK}/.github/hooks"


def file(path: str, text: str = "{}", mode: int = 0o644) -> dict:
    return {"path": path, "text": text, "mode": mode}


def raw(path: str, data: bytes) -> dict:
    return {"path": path, "hex": data.hex(), "mode": 0o644}


def doc(path: str, value: object) -> dict:
    return file(path, json.dumps(value))


def link(path: str, target: str) -> dict:
    return {"path": path, "target": target}


def case(
    name: str,
    files: list[dict] | None = None,
    symlinks: list[dict] | None = None,
    *,
    dirs: list[str] | None = None,
    dir_modes: dict[str, int] | None = None,
    captured: dict[str, str | None] | None = None,
    no_workspace: bool = False,
    workspace_is_home: bool = False,
) -> dict:
    return {
        "name": name,
        "files": files or [],
        "symlinks": symlinks or [],
        "dirs": dirs or [],
        "dir_modes": dir_modes or {},
        "captured": captured,
        "no_workspace": no_workspace,
        "workspace_is_home": workspace_is_home,
    }


HOOK_MATRIX = {
    "preToolUse": [
        {"command": "pre-cmd", "bash": "pre-bash", "powershell": "pre-ps"},
        5,
        {"bash": 1, "powershell": "only-ps"},
        {"type": "command"},
    ],
    "sessionStart": [{"command": "start"}],
    "sessionEnd": [{"bash": "end"}],
    "userPromptSubmitted": [{"command": "prompt"}],
    "postToolUse": [{"command": "post"}],
    "permissionRequest": [{"command": "perm"}],
    "permissionRequestV2": [{"command": "perm2"}],
    "errorOccurred": [{"command": "err"}],
    "PreToolUse": [{"command": "wrong-case"}],
    "stop": [{"command": "unknown"}],
    "agentStop": {"command": "not-a-list"},
}

SERVERS = {
    "plain": {"command": "node", "args": ["server.js", 3, None, "--flag", True]},
    "listed": {"command": ["uvx", 7, "tool", "--x"], "args": ["--y"]},
    "empty-list": {"command": [1, None], "args": ["a"]},
    "numeric": {"command": 5},
    "remote": {"url": "https://example.test/mcp", "env": {"TOKEN": "t"}},
    "url-not-text": {"url": 9, "command": "x"},
    "env-mixed": {"command": "e", "env": {"A": "1", "B": 2, "C": None, "D": "4"}},
    "environment-only": {"command": "e2", "environment": {"Z": "z", "Y": "y"}},
    "env-not-dict": {"command": "e3", "env": ["A"], "environment": {"Q": "q"}},
    "env-wins": {"command": "e4", "env": {"E": "env"}, "environment": {"F": "environment"}},
    "env-neither": {"command": "e5", "env": "x", "environment": [1]},
    "not-a-dict": ["command"],
    "launcher-proxy": {"command": "/opt/bin/hol-guard", "args": ["copilot-mcp-proxy", "--server", "x"]},
    "launcher-guard-proxy": {"command": "HOL-GUARD.EXE", "args": ["guard", "mcp-proxy"]},
    "launcher-module-proxy": {
        "command": "current-hol-guard",
        "args": ["-m", "codex_plugin_scanner.cli", "guard", "codex-mcp-proxy"],
    },
    "launcher-not-proxy": {"command": "hol-guard", "args": ["scan"]},
    "python-proxy": {"command": "python3", "args": ["-m", "codex_plugin_scanner.cli", "guard", "copilot-mcp-proxy"]},
    "python-no-guard": {"command": "python3", "args": ["-m", "codex_plugin_scanner.cli", "copilot-mcp-proxy"]},
    "list-proxy": {"command": ["hol-guard", "copilot-mcp-proxy"]},
}

JSONC = """{
  // leading comment
  "mcpServers": {
    /* block
       comment */
    "commented": {"command": "c", "args": ["http://x//y", "/* kept */"]},
    "quoted": {"command": "q\\"//", "url": "https://z/*"}
  },
  "hooks": {"preToolUse": [{"command": "jsonc-hook"}]} // trailing
}
"""


def config_cases() -> list[dict]:
    return [
        case("nothing"),
        case("hooks_nested_matrix", [doc(CONFIG, {"hooks": HOOK_MATRIX, "mcpServers": SERVERS})]),
        case("hooks_top_level", [doc(CONFIG, {"version": 1, **HOOK_MATRIX})]),
        case("hooks_key_not_object", [doc(CONFIG, {"hooks": [1], "postToolUse": [{"command": "top"}]})]),
        case("hooks_object_shadows_top_level", [doc(CONFIG, {"hooks": {}, "preToolUse": [{"command": "top"}]})]),
        case("config_without_hooks_is_found", [doc(CONFIG, {"model": "x"})]),
        case("config_empty_object", [doc(CONFIG, {})]),
        case("config_top_level_list", [doc(CONFIG, [{"hooks": {}}])]),
        case("config_top_level_string", [doc(CONFIG, "text")]),
        case("config_invalid_json", [file(CONFIG, "{not json")]),
        case("config_empty_file", [file(CONFIG, "")]),
        case("config_trailing_comma", [file(CONFIG, '{"a": 1,}')]),
        case("config_invalid_utf8", [raw(CONFIG, b'{"a": "\xc3\x28"}')]),
        case("config_utf8_bom", [raw(CONFIG, b'\xef\xbb\xbf{"preToolUse": [{"command": "x"}]}')]),
        case("config_integer_over_limit", [file(CONFIG, '{"a": ' + "9" * 5000 + "}")]),
        case("config_integer_over_limit_in_comment_fallback", [file(CONFIG, '{"a": 1} // ' + "\n" + "9" * 5000)]),
        case(
            "config_lone_surrogate_unused_value",
            [file(CONFIG, '{"note": "\\ud800", "preToolUse": [{"command": "x"}]}')],
        ),
        case("config_nan_and_floats", [file(CONFIG, '{"x": NaN, "y": 1e999, "preToolUse": [{"command": "n"}]}')]),
        case("config_unreadable", [file(CONFIG, '{"preToolUse": [{"command": "x"}]}', mode=0o000)]),
        case("config_is_directory", dirs=[CONFIG]),
        case(
            "config_symlink",
            [doc("real/config.json", {"sessionStart": [{"command": "linked"}]})],
            [link(CONFIG, "<ROOT>/real/config.json")],
        ),
        case("config_dangling_symlink", symlinks=[link(CONFIG, "<ROOT>/missing.json")]),
        case("config_jsonc", [file(CONFIG, JSONC)]),
        case("mcp_config_jsonc", [file(MCP_CONFIG, JSONC)]),
        case("mcp_config_comment_ended_by_cr", [file(MCP_CONFIG, '{// c\r"mcpServers": {"cr": {"command": "x"}}}')]),
        case(
            "mcp_config_comment_ended_by_crlf", [file(MCP_CONFIG, '{// c\r\n"mcpServers": {"crlf": {"command": "x"}}}')]
        ),
        case(
            "mcp_config_unterminated_block_comment",
            [file(MCP_CONFIG, '{"mcpServers": {"a": {"command": "x"}}} /* open')],
        ),
        case(
            "mcp_config_matrix", [doc(MCP_CONFIG, {"mcpServers": SERVERS, "hooks": {"preToolUse": [{"command": "h"}]}})]
        ),
        case("mcp_config_servers_only", [doc(MCP_CONFIG, {"servers": {"s": {"command": "x"}}})]),
        case(
            "mcp_config_both_keys_prefers_mcp_servers",
            [doc(MCP_CONFIG, {"servers": {"s": {"command": "s"}}, "mcpServers": {"m": {"command": "m"}}})],
        ),
        case(
            "mcp_config_both_keys_fallback", [doc(MCP_CONFIG, {"servers": {"s": {"command": "s"}}, "mcpServers": None})]
        ),
        case("mcp_config_neither_object", [doc(MCP_CONFIG, {"servers": [1], "mcpServers": "x"})]),
        case(
            "mcp_config_duplicate_keys",
            [
                file(
                    MCP_CONFIG,
                    '{"mcpServers": {"a": {"command": "1"}}, "x": 1, "mcpServers": {"b": {"command": "2"}, "a": {"command": "3"}, "b": {"command": "4"}}}',
                )
            ],
        ),
        case(
            "workspace_mcp_json",
            [doc(WS_MCP, {"servers": {"w": {"command": "w"}}, "mcpServers": {"m": {"command": "m"}}})],
        ),
        case(
            "workspace_vscode_mcp_both_keys",
            [doc(VSCODE_MCP, {"servers": {"v": {"command": "v"}}, "mcpServers": {"m": {"command": "m"}}})],
        ),
        case(
            "workspace_vscode_mcp_fallback",
            [doc(VSCODE_MCP, {"servers": 1, "mcpServers": {"m": {"url": "https://m"}}})],
        ),
        case("workspace_mcp_with_hooks", [doc(WS_MCP, {"hooks": {"preToolUse": [{"command": "wh"}]}})]),
        case(
            "workspace_is_home",
            [doc(CONFIG, {"preToolUse": [{"command": "c"}]}), doc(MCP_CONFIG, {"mcpServers": {"g": {"command": "g"}}})],
            workspace_is_home=True,
        ),
        case(
            "no_workspace",
            [
                doc(MCP_CONFIG, {"mcpServers": {"g": {"command": "g"}}}),
                doc(WS_MCP, {"mcpServers": {"w": {"command": "w"}}}),
            ],
            no_workspace=True,
        ),
    ]


def hook_dir_cases() -> list[dict]:
    hooks = {"version": 1, "hooks": {"preToolUse": [{"command": "dir-hook", "bash": "dir-bash"}]}}
    return [
        case(
            "hooks_dir_matrix",
            [
                doc(f"{HOOKS}/b.json", hooks),
                doc(f"{HOOKS}/A.json", {"postToolUse": [{"powershell": "ps"}]}),
                doc(f"{HOOKS}/no-hooks.json", {"version": 1}),
                file(f"{HOOKS}/invalid.json", "{"),
                doc(f"{HOOKS}/notes.txt", hooks),
                doc(f"{HOOKS}/hol-guard-copilot.json", hooks),
                doc(f"{HOOKS}/multi.dot.json", hooks),
                doc(f"{HOOKS}/.json", hooks),
                doc(f"{HOOKS}/nested/inner.json", hooks),
                file(f"{HOOKS}/jsonc.json", '{"hooks": {"sessionStart": [{"command": "s"}]}} // c'),
            ],
            dirs=[f"{HOOKS}/folder.json"],
        ),
        case(
            "hooks_dir_symlinked_file",
            [doc("real/h.json", hooks)],
            [link(f"{HOOKS}/linked.json", "<ROOT>/real/h.json")],
        ),
        case("hooks_dir_symlinked_dir", [doc("real/h.json", hooks)], [link(HOOKS, "<ROOT>/real")]),
        case(
            "hooks_dir_dangling_symlink", [doc(f"{HOOKS}/ok.json", hooks)], [link(f"{HOOKS}/gone.json", "<ROOT>/gone")]
        ),
        case("hooks_dir_is_file", [file(HOOKS, "{}")]),
        case("hooks_dir_invalid_utf8", [raw(f"{HOOKS}/bad.json", b"\xff")]),
        case("hooks_dir_without_workspace", [doc(f"{HOOKS}/x.json", hooks)], no_workspace=True),
        case(
            "everything_together",
            [
                doc(CONFIG, {"hooks": {"sessionStart": [{"command": "global"}]}}),
                doc(MCP_CONFIG, {"mcpServers": {"g": {"command": "g"}}}),
                doc(WS_MCP, {"mcpServers": {"w": {"command": "w"}}}),
                doc(VSCODE_MCP, {"servers": {"v": {"command": "v"}}}),
                doc(f"{HOOKS}/team.json", hooks),
            ],
        ),
    ]


def captured_cases() -> list[dict]:
    hooks = json.dumps({"hooks": {"preToolUse": [{"command": "captured-hook"}]}}).encode()
    disk = [
        doc(CONFIG, {"preToolUse": [{"command": "disk"}]}),
        doc(MCP_CONFIG, {"mcpServers": {"disk": {"command": "disk"}}}),
        doc(f"{HOOKS}/disk.json", {"preToolUse": [{"command": "disk-hook"}]}),
    ]
    return [
        case(
            "captured_overrides_disk",
            disk,
            captured={
                CONFIG: json.dumps({"sessionStart": [{"command": "captured"}]}).encode().hex(),
                MCP_CONFIG: None,
                WS_MCP: json.dumps({"mcpServers": {"cap": {"command": "c"}}}).encode().hex(),
                f"{HOOKS}/z.json": hooks.hex(),
                f"{HOOKS}/a.json": hooks.hex(),
                f"{HOOKS}/none.json": None,
                f"{HOOKS}/skip.txt": hooks.hex(),
                f"{HOOKS}/nested/deep.json": hooks.hex(),
                f"{WORK}/other/x.json": hooks.hex(),
            },
        ),
        case("captured_empty_mapping", disk, captured={}),
        case(
            "captured_jsonc_cr_not_translated",
            captured={MCP_CONFIG: b'{// c\r"mcpServers": {"cr": {"command": "x"}}}'.hex()},
        ),
        case("captured_jsonc", captured={CONFIG: JSONC.encode().hex(), WS_MCP: JSONC.encode().hex()}),
        case("captured_invalid_utf8", captured={WS_MCP: b"\xc3\x28".hex()}),
        case("captured_hook_invalid_utf8", captured={f"{HOOKS}/bad.json": b"\xff".hex()}),
    ]


def cases() -> list[dict]:
    return config_cases() + hook_dir_cases() + captured_cases()


def artifact_dict(artifact: GuardArtifact) -> dict:
    payload = dataclasses.asdict(artifact)
    payload.pop("runtime_private_metadata", None)
    payload["args"] = list(artifact.args)
    return payload


def materialize(root: Path, spec: dict) -> None:
    (root / WORK).mkdir(parents=True)
    (root / HOME).mkdir()
    locked: list[tuple[Path, int]] = []
    for entry in spec["files"]:
        target = root / entry["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        if "hex" in entry:
            target.write_bytes(bytes.fromhex(entry["hex"]))
        else:
            target.write_bytes(entry["text"].encode("utf-8"))
        locked.append((target, entry["mode"]))
    for relative in spec["dirs"]:
        (root / relative).mkdir(parents=True, exist_ok=True)
    for entry in spec["symlinks"]:
        target = root / entry["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.symlink_to(entry["target"].replace("<ROOT>", str(root)))
    for path, mode in locked:
        path.chmod(mode)
    for relative, mode in spec["dir_modes"].items():
        (root / relative).chmod(mode)


def release(root: Path) -> None:
    for path in sorted(root.rglob("*"), reverse=True):
        if not path.is_symlink():
            path.chmod(0o755)
    shutil.rmtree(root, ignore_errors=True)


def scrub(value: object, root: Path) -> object:
    return json.loads(json.dumps(value, ensure_ascii=False).replace(str(root), "<ROOT>"))


def facade_args(
    adapter: CopilotHarnessAdapter, context: HarnessContext, contents: dict[Path, bytes | None] | None
) -> dict:
    """The request the native facade sends for this context."""

    sources = [
        (context.home_dir / ".copilot" / "config.json", "config"),
        (context.home_dir / ".copilot" / "mcp-config.json", "mcp"),
        *((path, "mcp") for path in adapter._workspace_mcp_paths(context)),
    ]
    wire = [{"path": str(path), "scope": adapter._scope_for(context, path), "kind": kind} for path, kind in sources]
    if context.workspace_dir is not None:
        hooks_dir = context.workspace_dir / ".github" / "hooks"
        if hooks_dir.is_dir() or contents is not None:
            hook_paths = (
                sorted(path for path in contents if path.parent == hooks_dir and path.suffix == ".json")
                if contents is not None
                else sorted(path for path in hooks_dir.glob("*.json") if path.is_file())
            )
            wire.extend({"path": str(path), "scope": "project", "kind": "hooks"} for path in hook_paths)
    request: dict[str, object] = {"harness": "copilot", "sources": wire}
    if contents is not None:
        request["contents"] = {
            entry["path"]: None if (data := contents.get(Path(entry["path"]))) is None else data.hex() for entry in wire
        }
    return request


def run_case(spec: dict) -> dict:
    root = Path(tempfile.mkdtemp(prefix="copilot-vec-")).resolve()
    try:
        materialize(root, spec)
        home_dir = root / HOME
        workspace = home_dir if spec["workspace_is_home"] else root / WORK
        context = HarnessContext(
            home_dir=home_dir,
            workspace_dir=None if spec["no_workspace"] else workspace,
            guard_home=root / "guard-home",
        )
        contents = (
            None
            if spec["captured"] is None
            else {root / path: None if data is None else bytes.fromhex(data) for path, data in spec["captured"].items()}
        )
        adapter = CopilotHarnessAdapter()
        args = facade_args(adapter, context, contents)
        try:
            detection = adapter.detect(context, config_contents=contents)
            outcome: dict = {
                "artifacts": [artifact_dict(item) for item in detection.artifacts],
                "found_paths": list(detection.config_paths),
            }
        except (ValueError, RecursionError, OSError):
            outcome = {"refused": True}
        record = {key: spec[key] for key in ("name", "files", "symlinks", "dirs", "dir_modes", "no_workspace")}
        record["workspace_is_home"] = spec["workspace_is_home"]
        record["args"] = scrub(args, root)
        record.update(scrub(outcome, root))
        return record
    finally:
        release(root)


def main() -> None:
    destination = Path(sys.argv[1])
    recorded = [run_case(spec) for spec in cases()]
    document = {"schema": "guard-copilot-vectors.v1", "cases": recorded}
    destination.write_text(json.dumps(document, indent=1, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
    print(f"recorded {len(recorded)} cases")


if __name__ == "__main__":
    main()
