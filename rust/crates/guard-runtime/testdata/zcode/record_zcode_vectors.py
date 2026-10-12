#!/usr/bin/env python3
"""Record ZCode detection vectors from the ORIGINAL Python implementation.

Run against a checkout that still holds `guard/adapters/zcode_config.py`'s
`append_*` discovery functions and `ZCodeHarnessAdapter.detect` (the base of
the commit that introduced the native `zcode_detect` runner-authority kind),
never from Rust output:

    cd <base-worktree>
    HOL_GUARD_NATIVE_BINARY=<release hol-guard-runtime> \\
        PYTHONPATH=$PWD/src python3 <this-file> <output vectors.json>

Each case materializes a fixture tree under a temporary root, runs the
original `detect` over it and records the artifacts and config paths plus the
arguments the native facade sends. `<ROOT>` stands for the fixture root.
"""

from __future__ import annotations

import dataclasses
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

from codex_plugin_scanner.guard.adapters import zcode_config
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.zcode import ZCodeHarnessAdapter
from codex_plugin_scanner.guard.models import GuardArtifact

if not hasattr(zcode_config, "append_cli_config_artifacts"):
    sys.exit("refusing to record: the original Python ZCode discovery is gone")
if not os.environ.get("HOL_GUARD_NATIVE_BINARY"):
    sys.exit("set HOL_GUARD_NATIVE_BINARY to a release hol-guard-runtime")

HOME, WORK = "home", "work"
CLI = f"{HOME}/.zcode/cli"
CACHE = f"{CLI}/plugins/cache"
MARKETS = f"{CLI}/plugins/marketplaces"


def provision_native(guard_home: Path) -> None:
    from codex_plugin_scanner.guard import native_context
    from codex_plugin_scanner.guard.native_policy_snapshot import provision_native_policy_verifier_key
    from codex_plugin_scanner.guard.runtime import approval_context

    (guard_home / "native-runtime").mkdir(mode=0o700, parents=True)
    provision_native_policy_verifier_key(guard_home, b"\x07" * 32)
    os.environ.update(
        {
            "HOL_GUARD_NATIVE": "force",
            "HOL_GUARD_TEST_MODE": "1",
            "HOL_GUARD_NATIVE_DIAGNOSTIC": "1",
            "HOL_GUARD_RESIDENT_TEST_SEAMS": "1",
        }
    )
    native_context.context_digest_guard_home = lambda: guard_home
    approval_context._context_digest_guard_home = lambda _home: guard_home
    probe = native_context.native_context_digest(
        "launch_argv_digest", {"argv": ["guard-context-warmup"]}, guard_home=guard_home
    )
    if not probe:
        sys.exit("native resident did not answer; refusing to record unbound hashes")


def file(path: str, text: str = "{}", mode: int = 0o644) -> dict:
    return {"path": path, "text": text, "mode": mode}


def raw(path: str, data: bytes) -> dict:
    return {"path": path, "hex": data.hex(), "mode": 0o644}


def doc(path: str, value: object) -> dict:
    return file(path, json.dumps(value))


def link(path: str, target: str) -> dict:
    return {"path": path, "target": target}


def config(value: object, name: str = "config.json") -> dict:
    return doc(f"{CLI}/{name}", value)


def case(name: str, files=(), symlinks=(), dirs=(), dir_modes=None, **options) -> dict:
    return {
        "name": name,
        "files": list(files),
        "symlinks": list(symlinks),
        "dirs": list(dirs),
        "dir_modes": dir_modes or {},
        **options,
    }


def plugin(version: str = "1.0.0", market: str = "mk", name: str = "pl", base: str = CACHE) -> str:
    return f"{base}/{market}/{name}/{version}"


def manifest(root: str, value: object) -> dict:
    return doc(f"{root}/.zcode-plugin/plugin.json", value)


MCP_SERVERS = {
    "stdio-server": {
        "command": "npx",
        "args": ["-y", "pkg", 3, 1.5, True, None, [1], {"a": 1}, 1e16, 1e-5, 100.0, -0.0, 1e22, 0.1],
        "env": {"TOKEN": "t", " PADDED ": "p", "": "blank", "NUM": 5},
    },
    "http-server": {"url": "https://example.invalid/mcp", "headers": {"Authorization": "Bearer x", " X ": "y", "N": 1}},
    "sse-server": {"url": "https://example.invalid/sse", "transport": " sse "},
    "typed-stdio": {"command": "run", "type": "stdio"},
    "blank-transport": {"command": "run", "transport": "   "},
    "blank-url": {"url": "   ", "command": "run"},
    "url-only-blank": {"url": "  "},
    "no-endpoint": {"args": ["x"]},
    "bad-command": {"command": 7},
    "empty-command": {"command": ""},
    "not-a-dict": ["x"],
    "environment-fallback": {"command": "c", "env": ["A=1"], "environment": {"E": "1"}},
    "empty-env-wins": {"command": "c", "env": {}, "environment": {"E": "1"}},
    "collide": {"command": "c", "env": {"A": "1", " A": "2", "A ": "3"}},
    "big-numbers": {"command": "c", "args": [12345678901234567890123, -5, 1e400, -1e400, 2.5e-7, 9999999999999998.0]},
}

HOOK_ENTRY = {"matcher": "Bash", "hooks": [{"type": "command", "command": "echo one"}]}
HOOKS_NESTED = {
    "enabled": True,
    "events": {
        "PreToolUse": [
            HOOK_ENTRY,
            {"matcher": "", "command": "direct-one", "hooks": [{"command": "  "}, "x", {"command": "nested-two"}]},
            {"matcher": ["a", 1], "command": "list-matcher"},
            {"matcher": 7, "command": "number-matcher"},
            {"command": "no-matcher"},
            "not-a-dict",
            {"matcher": "Read", "command": "echo HOL_GUARD_MANAGED_ZCODE"},
            {
                "matcher": {"k": [1.5, None, True]},
                "command": "python -c \"'guard', 'hook' codex_plugin_scanner.cli --harness', 'zcode'\"",
            },
        ],
        "UserPromptSubmit": [{"command": "prompt-one"}, {"command": "   "}],
        "İstanbul": [{"command": "turkish"}],
        "Custom": "not-a-list",
    },
    "PreToolUse": [HOOK_ENTRY, {"command": "legacy-only"}],
    "Stop": [{"command": "legacy-stop"}],
    "Unknown": [{"command": "ignored"}],
    "SessionStart": "not-a-list",
}


def cli_config_cases() -> list[dict]:
    out = [
        case("empty_home"),
        case("no_workspace_empty_home", no_workspace=True),
        case("v2_config_only", [doc(f"{HOME}/.zcode/v2/config.json", {"provider": "x"})]),
        case("config_empty_object", [config({})]),
        case("config_non_object", [config([1, 2])]),
        case("config_invalid_json", [file(f"{CLI}/config.json", "{not json")]),
        case("config_empty_file", [file(f"{CLI}/config.json", "")]),
        case("config_bom", [file(f"{CLI}/config.json", '﻿{"mcp":{"servers":{"a":{"command":"x"}}}}')]),
        case("config_trailing_data", [file(f"{CLI}/config.json", '{"a":1} x')]),
        case("config_leading_zero", [file(f"{CLI}/config.json", '{"a":01}')]),
        case("config_invalid_utf8", [raw(f"{CLI}/config.json", b'{"a":"\xff"}')]),
        case("config_deeply_nested", [file(f"{CLI}/config.json", "[" * 100000)]),
        case("config_deeply_nested_closed", [file(f"{CLI}/config.json", "[" * 100000 + "]" * 100000)]),
        case("config_moderately_nested", [file(f"{CLI}/config.json", '{"mcp":{"servers":{}},"x":' + "[" * 400 + "]" * 400 + "}")]),
        case("config_unreadable", [file(f"{CLI}/config.json", '{"mcp":{}}', 0o000)]),
        case("config_is_directory", dirs=[f"{CLI}/config.json"]),
        case("mcp_servers_matrix", [config({"mcp": {"servers": MCP_SERVERS}})]),
        case("mcp_not_dict", [config({"mcp": []})]),
        case("mcp_servers_not_dict", [config({"mcp": {"servers": []}})]),
        case(
            "mcp_duplicate_keys_last_wins",
            [file(f"{CLI}/config.json", '{"mcp":{"servers":{"a":{"command":"x"},"b":{"command":"y"},"a":{"command":"z"}}}}')],
        ),
        case("mcp_unicode_names", [config({"mcp": {"servers": {"ünï-çøde": {"command": "câ", "args": ["ü"], "env": {"É": "ü"}}}}})]),
        case(
            "plugins_enabled_truthiness",
            [
                config(
                    {
                        "plugins": {
                            "enabledPlugins": {
                                "a@m": True, "b@m": False, "c@m": 0, "d@m": 1, "e@m": "", "f@m": None,
                                "g@m": {}, "h@m": [], "i@m": "x", "j@m": 0.0, "k@m": {"a": 1}, "l@m": [0], "m@m": -1.5, "n@m": -0.0, "o@m": -3, "p@m": 1e-320,
                            }
                        }
                    }
                )
            ],
        ),
        case("plugins_not_dict", [config({"plugins": [], "hooks": []})]),
        case("hooks_matrix", [config({"hooks": HOOKS_NESTED})]),
        case("hooks_legacy_only", [config({"hooks": {"PreToolUse": [HOOK_ENTRY], "PostToolUse": [{"command": "x"}]}})]),
        case("hooks_events_not_dict", [config({"hooks": {"events": [1], "Stop": [{"command": "s"}]}})]),
        case(
            "hooks_duplicate_entries_key_order",
            [
                config(
                    {
                        "hooks": {
                            "events": {"Stop": [{"command": "a", "matcher": "m"}, {"matcher": "m", "command": "a"}]},
                            "Stop": [{"command": "a", "matcher": "m"}, {"command": "a", "matcher": 1}],
                        }
                    }
                )
            ],
        ),
        case(
            "hooks_number_kinds_dedupe",
            [config({"hooks": {"events": {"Stop": [{"command": "a", "m": 1}, {"command": "a", "m": 1.0}, {"command": "a", "m": True}]}}})],
        ),
        case("setting_json_also_read", [config({"mcp": {"servers": {"a": {"command": "x"}}}}, "setting.json"), config({"plugins": {"enabledPlugins": {"p@m": True}}})]),
        case(
            "project_config_scope",
            [doc(f"{WORK}/.zcode/cli/config.json", {"mcp": {"servers": {"proj": {"command": "x"}}}}), config({"mcp": {"servers": {"glob": {"command": "y"}}}})],
        ),
        case("project_config_without_workspace", [doc(f"{WORK}/.zcode/cli/config.json", {"mcp": {"servers": {"proj": {"command": "x"}}}})], no_workspace=True),
        case("workspace_is_home", [config({"mcp": {"servers": {"dup": {"command": "x"}}}})], workspace_is_home=True),
        case("zcode_home_override", [doc("zhome/.zcode/cli/config.json", {"mcp": {"servers": {"zh": {"command": "x"}}}}), config({"mcp": {"servers": {"home": {"command": "y"}}}})], zcode_home="zhome"),
    ]
    return out


def plugin_cache_cases() -> list[dict]:
    root = plugin()
    full = [
        manifest(root, {"name": "pl", "version": "1.0.0", "author": {"name": "Ada"}}),
        doc(f"{root}/.zcode-plugin-seed.json", {"marketplace": "mk", "source": "git", "pluginVersion": "1.0.0", "hash": "abc"}),
        doc(f"{root}/.mcp.json", {"mcpServers": {"srv": {"command": "node", "args": ["s.js"], "env": {"K": "v"}}, "web": {"url": "https://example.invalid/x"}, "bad": 1, "none": {}}}),
        doc(f"{root}/hooks/hooks.json", {"hooks": {"PreToolUse": [HOOK_ENTRY, {"command": "plain"}], "Custom": [{"command": "c"}], "Bad": "x"}}),
        doc(f"{root}/hooks/hooks-cursor.json", {"hooks": {"Stop": [{"command": "cursor-stop"}]}}),
        file(f"{root}/skills/a/SKILL.md", "a"),
        file(f"{root}/skills/a/b/SKILL.md", "b"),
        file(f"{root}/skills/SKILL.md", "top"),
        file(f"{root}/skills/.hidden/SKILL.md", "h"),
        file(f"{root}/skills/skill.md", "lowercase"),
        file(f"{root}/commands/alpha.md", "x"),
        file(f"{root}/commands/beta.md", "x"),
        file(f"{root}/commands/c.txt", "x"),
        file(f"{root}/commands/.md", "x"),
        file(f"{root}/commands/x.y.md", "x"),
        file(f"{root}/commands/upper.MD", "x"),
        file(f"{root}/commands/nested/deep.md", "x"),
    ]
    return [
        case("plugin_full", full, dirs=[f"{root}/commands/dir.md", f"{root}/skills/dirskill/SKILL.md"]),
        case("plugin_manifest_only", [manifest(root, {"name": "pl"})]),
        case(
            "plugin_manifest_surrogate_unused_field",
            [manifest(root, {"name": "pl", "description": "\ud800"})],
        ),
        case("plugin_manifest_missing_name_uses_version_dir", [manifest(plugin("2.0.0"), {"version": 3})]),
        case("plugin_manifest_empty_name", [manifest(root, {"name": ""})]),
        case("plugin_author_string", [manifest(root, {"name": "pl", "author": "Grace"})]),
        case("plugin_author_other", [manifest(root, {"name": "pl", "author": 5}), manifest(plugin("2.0.0"), {"name": "q", "author": {"name": 1}})]),
        case("plugin_manifest_empty_object", [manifest(root, {})]),
        case("plugin_manifest_invalid", [file(f"{root}/.zcode-plugin/plugin.json", "nope")]),
        case("plugin_manifest_invalid_utf8", [raw(f"{root}/.zcode-plugin/plugin.json", b"\xff\xfe")]),
        case("plugin_manifest_unreadable", [file(f"{root}/.zcode-plugin/plugin.json", '{"name":"x"}', 0o000)]),
        case("plugin_seed_empty_marketplace", [manifest(root, {"name": "pl"}), doc(f"{root}/.zcode-plugin-seed.json", {"marketplace": "", "source": "s"})]),
        case("plugin_seed_non_strings", [manifest(root, {"name": "pl"}), doc(f"{root}/.zcode-plugin-seed.json", {"marketplace": 1, "source": [], "pluginVersion": 2, "hash": None})]),
        case("plugin_seed_invalid", [manifest(root, {"name": "pl"}), file(f"{root}/.zcode-plugin-seed.json", "x")]),
        case("plugin_seed_empty_object", [manifest(root, {"name": "pl"}), doc(f"{root}/.zcode-plugin-seed.json", {})]),
        case("plugin_mcp_empty_servers", [manifest(root, {"name": "pl"}), doc(f"{root}/.mcp.json", {"mcpServers": {}})]),
        case("plugin_mcp_servers_not_dict", [manifest(root, {"name": "pl"}), doc(f"{root}/.mcp.json", {"mcpServers": []})]),
        case("plugin_mcp_without_manifest_ignored", [doc(f"{root}/.mcp.json", {"mcpServers": {"a": {"command": "x"}}})]),
        case("plugin_hooks_non_dict", [manifest(root, {"name": "pl"}), doc(f"{root}/hooks/hooks.json", {"hooks": []})]),
        case("plugin_hooks_empty", [manifest(root, {"name": "pl"}), doc(f"{root}/hooks/hooks.json", {})]),
        case(
            "plugin_ordering",
            [
                manifest(plugin("2.0", "zeta", "b"), {"name": "zb"}),
                manifest(plugin("1.0", "alpha", "z"), {"name": "az"}),
                manifest(plugin("10.0", "alpha", "a"), {"name": "aa10"}),
                manifest(plugin("9.0", "alpha", "a"), {"name": "aa9"}),
                manifest(plugin("1.0", "Alpha", "a"), {"name": "Aa"}),
                manifest(plugin("1.0", "ünï", "a"), {"name": "uni"}),
                manifest(plugin("1.0", "m", "a"), {"name": "m"}),
                manifest(plugin("1.0", "Zed", "a"), {"name": "zed"}),
                manifest(plugin("1.0", "m", "B"), {"name": "mB"}),
                manifest(plugin("B", "m", "c"), {"name": "mcB"}),
                manifest(plugin("a", "m", "c"), {"name": "mca"}),
            ],
        ),
        case(
            "plugin_symlinked_directories",
            [manifest("real/pl/1.0.0", {"name": "linked"}), file("real/pl/1.0.0/skills/s/SKILL.md", "s")],
            [link(f"{CACHE}/mk", "<ROOT>/real")],
        ),
        case(
            "plugin_skill_symlinks",
            [manifest(root, {"name": "pl"}), file("elsewhere/SKILL.md", "x"), file("elsewhere/inner/SKILL.md", "y")],
            [link(f"{root}/skills/linked-dir", "<ROOT>/elsewhere"), link(f"{root}/skills/file-link/SKILL.md", "<ROOT>/elsewhere/SKILL.md")],
        ),
        case("plugin_loose_files_ignored", [manifest(root, {"name": "pl"}), file(f"{CACHE}/stray.txt"), file(f"{CACHE}/mk/stray.txt")]),
        case(
            "plugin_project_cache",
            [manifest(plugin(base=f"{WORK}/.zcode/cli/plugins/cache"), {"name": "proj"}), manifest(root, {"name": "glob"})],
        ),
        case("plugin_project_cache_without_workspace", [manifest(plugin(base=f"{WORK}/.zcode/cli/plugins/cache"), {"name": "proj"})], no_workspace=True),
        case("plugin_marketplace_dir_unreadable", [manifest(root, {"name": "pl"})], dir_modes={f"{CACHE}/mk": 0o000}),
        case("plugin_cache_root_is_file", [file(f"{CLI}/plugins/cache", "x")]),
    ]


def marketplace_cases() -> list[dict]:
    return [
        case(
            "marketplaces_matrix",
            [
                doc(f"{MARKETS}/alpha/marketplace.json", {"name": "Alpha", "plugins": [1, 2, 3]}),
                doc(f"{MARKETS}/beta/marketplace.json", {"plugins": {"a": 1}}),
                doc(f"{MARKETS}/gamma/marketplace.json", {"name": 5, "plugins": []}),
                file(f"{MARKETS}/delta/marketplace.json", "bad"),
                doc(f"{MARKETS}/epsilon/marketplace.json", {}),
                file(f"{MARKETS}/stray.json"),
            ],
            dirs=[f"{MARKETS}/empty"],
        ),
        case("marketplace_project_scope", [doc(f"{WORK}/.zcode/cli/plugins/marketplaces/pm/marketplace.json", {"name": "P"}), doc(f"{MARKETS}/gm/marketplace.json", {"name": "G"})]),
        case("marketplace_invalid_utf8", [raw(f"{MARKETS}/bad/marketplace.json", b"\xc3\x28")]),
        case("marketplace_root_unreadable", dirs=[MARKETS], dir_modes={MARKETS: 0o000}),
        case("marketplace_symlinked_file", [doc("real/marketplace.json", {"name": "linked"})], [link(f"{MARKETS}/ln/marketplace.json", "<ROOT>/real/marketplace.json")]),
        case(
            "everything_together",
            [
                config({"mcp": {"servers": {"c": {"command": "x"}}}, "plugins": {"enabledPlugins": {"p@m": True}}, "hooks": HOOKS_NESTED}),
                doc(f"{HOME}/.zcode/v2/config.json", {}),
                manifest(plugin(), {"name": "pl", "author": "A"}),
                doc(f"{MARKETS}/m/marketplace.json", {"name": "M", "plugins": [1]}),
            ],
        ),
    ]


def cases() -> list[dict]:
    return cli_config_cases() + plugin_cache_cases() + marketplace_cases()


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
            target.write_text(entry["text"], encoding="utf-8")
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


def run_case(spec: dict) -> dict:
    root = Path(tempfile.mkdtemp(prefix="zcode-vec-")).resolve()
    saved = {key: os.environ.get(key) for key in ("HOME", "ZCODE_HOME")}
    os.environ["HOME"] = str(root / "uhome")
    os.environ.pop("ZCODE_HOME", None)
    if spec.get("zcode_home"):
        os.environ["ZCODE_HOME"] = str(root / spec["zcode_home"])
    try:
        materialize(root, spec)
        home_dir = root / HOME
        workspace = home_dir if spec.get("workspace_is_home") else root / WORK
        context = HarnessContext(
            home_dir=home_dir,
            workspace_dir=None if spec.get("no_workspace") else workspace,
            guard_home=root / "guard-home",
        )
        adapter = ZCodeHarnessAdapter()
        args = {
            "harness": "zcode",
            "configs": [{"path": str(p), "scope": adapter._scope_for(context, p)} for p in adapter._config_candidates(context)],
            "v2_config": str(adapter._zcode_home_dir(context) / ".zcode/v2/config.json"),
            "plugin_roots": [{"path": str(p), "scope": s} for p, s in adapter._plugins_candidates(context)],
            "marketplace_roots": [{"path": str(p), "scope": s} for p, s in adapter._marketplaces_candidates(context)],
        }
        try:
            detection = adapter.detect(context)
            outcome: dict = {
                "artifacts": [artifact_dict(item) for item in detection.artifacts],
                "found_paths": list(detection.config_paths),
            }
        except (ValueError, RecursionError, OSError):
            outcome = {"refused": True}
        record = {key: spec[key] for key in ("name", "files", "symlinks", "dirs", "dir_modes")}
        record["args"] = scrub(args, root)
        record.update(scrub(outcome, root))
        return record
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        release(root)


def main() -> None:
    destination = Path(sys.argv[1])
    guard_home = Path(tempfile.mkdtemp(prefix="zcode-guard-home-")).resolve()
    provision_native(guard_home)
    recorded = [run_case(spec) for spec in cases()]
    from codex_plugin_scanner.guard.native_resident_client import close_native_residents

    close_native_residents(guard_home)
    shutil.rmtree(guard_home, ignore_errors=True)
    document = {"schema": "guard-zcode-vectors.v1", "cases": recorded}
    destination.write_text(json.dumps(document, indent=1, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
    print(f"recorded {len(recorded)} cases")


if __name__ == "__main__":
    main()
