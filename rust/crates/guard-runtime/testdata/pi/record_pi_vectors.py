#!/usr/bin/env python3
"""Record Pi and Oh My Pi detection vectors from the ORIGINAL Python implementation.

Run against a checkout that still holds `_PiFamilyHarnessAdapter._append_settings_artifacts`
(the base of the commit that introduced the native `pi_detect` runner-authority
kind), never from Rust output:

    cd <base-worktree>
    PYTHONPATH=$PWD/src python3 <this-file> <output vectors.json>

Each case materializes a fixture tree under a temporary root, points HOME at
the fixture home, runs the original `detect` over it and records the artifacts
and config paths plus the arguments the native facade sends. Workspace AIBOM
discovery is not part of the port and is switched off. `<ROOT>` stands for the
fixture root, in paths and in file contents.
"""

from __future__ import annotations

import dataclasses
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

from codex_plugin_scanner.guard.adapters import pi as pi_module
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.models import GuardArtifact

if not hasattr(pi_module._PiFamilyHarnessAdapter, "_append_settings_artifacts"):
    sys.exit("refusing to record: the original Python Pi discovery is gone")

pi_module.extend_detection_with_workspace_aibom = lambda detection, **_: detection

AGENT = "home/.pi/agent"
SETTINGS = f"{AGENT}/settings.json"
PROJECT = "work/.pi"
PROJECT_SETTINGS = f"{PROJECT}/settings.json"
OMP_AGENT = "home/.omp/agent"


def file(path: str, text: str = "x", mode: int = 0o644) -> dict:
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
    harness: str = "pi",
    dirs: list[str] | None = None,
    dir_modes: dict[str, int] | None = None,
    home: str = "home",
    no_workspace: bool = False,
    workspace_is_home: bool = False,
    relative: bool = False,
) -> dict:
    return {
        "name": name,
        "harness": harness,
        "files": files or [],
        "symlinks": symlinks or [],
        "dirs": dirs or [],
        "dir_modes": dir_modes or {},
        "home": home,
        "no_workspace": no_workspace,
        "workspace_is_home": workspace_is_home,
        "relative": relative,
    }


def resource_tree(base: str) -> list[dict]:
    return [
        file(f"{base}/extensions/a.ts"),
        file(f"{base}/extensions/nested/b.mjs"),
        file(f"{base}/extensions/nested/deeper/c.cjs"),
        file(f"{base}/extensions/d.mts"),
        file(f"{base}/extensions/e.cts"),
        file(f"{base}/extensions/f.js"),
        file(f"{base}/extensions/notes.txt"),
        file(f"{base}/extensions/.hidden.ts"),
        file(f"{base}/extensions/.ts"),
        file(f"{base}/extensions/trailing."),
        file(f"{base}/extensions/UPPER.TS"),
        file(f"{base}/extensions/types.d.ts"),
        file(f"{base}/extensions/.dot/inner.js"),
        file(f"{base}/skills/SKILL.md"),
        file(f"{base}/skills/alpha/SKILL.md"),
        file(f"{base}/skills/alpha/beta/SKILL.md"),
        file(f"{base}/skills/gamma/skill.md"),
        file(f"{base}/skills/.hidden/SKILL.md"),
        file(f"{base}/prompts/one.md"),
        file(f"{base}/prompts/sub/two.md"),
        file(f"{base}/prompts/.md"),
        file(f"{base}/prompts/three.MD"),
        file(f"{base}/prompts/four.txt"),
        file(f"{base}/themes/dark.json"),
        file(f"{base}/themes/sub/light.yaml"),
        file(f"{base}/themes/x.yml"),
        file(f"{base}/themes/y.js"),
        file(f"{base}/themes/z.ts"),
        file(f"{base}/themes/readme.md"),
    ]


def settings_cases() -> list[dict]:
    return [
        case("nothing"),
        case("settings_empty_object", [doc(SETTINGS, {})]),
        case("settings_invalid_json", [file(SETTINGS, "{not json")]),
        case("settings_empty_file", [file(SETTINGS, "")]),
        case("settings_top_level_list", [doc(SETTINGS, [{"packages": ["a"]}])]),
        case("settings_bom", [raw(SETTINGS, b'\xef\xbb\xbf{"packages": ["bom"]}')]),
        case("settings_invalid_utf8", [raw(SETTINGS, b'{"packages": ["\xff"]}')]),
        case("settings_huge_integer", [file(SETTINGS, '{"packages": ["a"], "n": ' + "9" * 5000 + "}")]),
        case("settings_unreadable", [file(SETTINGS, '{"packages": ["a"]}', mode=0o000)]),
        case("settings_is_directory", dirs=[SETTINGS]),
        case(
            "settings_symlink_to_file",
            [doc("elsewhere/settings.json", {"packages": ["linked"]})],
            [link(SETTINGS, "<ROOT>/elsewhere/settings.json")],
        ),
        case("settings_dangling_symlink", symlinks=[link(SETTINGS, "<ROOT>/missing.json")]),
        case(
            "packages_matrix",
            [doc(SETTINGS, {"packages": ["npm:foo", "", "  ", 5, None, "git:x", "npm:foo", " padded ", ["n"]]})],
        ),
        case("packages_not_list", [doc(SETTINGS, {"packages": {"npm:a": True}, "extensions": "x.ts"})]),
        case("package_lone_surrogate", [file(SETTINGS, '{"packages": ["\\ud800"]}')]),
        case("unused_key_lone_surrogate", [file(SETTINGS, '{"other": "\\ud800", "packages": ["ok"]}')]),
        case("package_escaped_pair", [file(SETTINGS, '{"packages": ["\\ud83d\\ude00", "caf\\u00e9"]}')]),
        case("settings_deep_nesting", [file(SETTINGS, '{"packages": ["a"], "x": ' + "[" * 600 + "]" * 600 + "}")]),
    ]


def configured_cases() -> list[dict]:
    return [
        case(
            "configured_remote_and_missing",
            [
                doc(
                    SETTINGS,
                    {
                        "extensions": ["npm:ext", "git:ext", "http://x/e.ts", "https://x/e.ts", "ssh://x", "./nope.ts"],
                        "skills": ["npm:skill", "missing-skill"],
                        "prompts": ["https://p", "missing.md"],
                        "themes": ["git:t", "missing.json"],
                    },
                )
            ],
        ),
        case(
            "configured_files_inside_and_outside_default",
            [
                doc(
                    SETTINGS,
                    {
                        "extensions": ["extensions/sub/in.ts", "../../../shared/out.ts", "../../../shared/wrong.txt"],
                        "skills": [
                            "../../../shared/skill/SKILL.md",
                            "skills/inner/SKILL.md",
                            "../../../shared/README.md",
                        ],
                        "prompts": ["../../../shared/p.md", "prompts/q.md", "../../../shared/p.txt"],
                        "themes": ["../../../shared/t.yml", "themes/u.json", "../../../shared/t.toml"],
                    },
                ),
                file(f"{AGENT}/extensions/sub/in.ts"),
                file("shared/out.ts"),
                file("shared/wrong.txt"),
                file("shared/skill/SKILL.md"),
                file(f"{AGENT}/skills/inner/SKILL.md"),
                file("shared/README.md"),
                file("shared/p.md"),
                file(f"{AGENT}/prompts/q.md"),
                file("shared/p.txt"),
                file("shared/t.yml"),
                file(f"{AGENT}/themes/u.json"),
                file("shared/t.toml"),
            ],
        ),
        case(
            "configured_directories_outside_default",
            [
                doc(
                    SETTINGS,
                    {
                        "extensions": ["../../../pack/extensions"],
                        "skills": ["../../../pack/skills"],
                        "prompts": ["../../../pack/prompts"],
                        "themes": ["../../../pack/themes/"],
                    },
                ),
                *resource_tree("pack"),
            ],
        ),
        case(
            "configured_directories_inside_default",
            [
                doc(
                    SETTINGS,
                    {
                        "extensions": ["extensions/nested"],
                        "skills": ["skills/alpha"],
                        "prompts": ["prompts/sub"],
                        "themes": ["./themes/sub"],
                    },
                ),
                *resource_tree(AGENT),
            ],
        ),
        case(
            "configured_settings_directory_itself",
            [doc(SETTINGS, {"extensions": ["."], "skills": [""], "prompts": ["."]}), *resource_tree(AGENT)],
        ),
        case(
            "configured_absolute_paths",
            [
                doc(SETTINGS, {"extensions": ["<ROOT>/abs/one.ts", "<ROOT>/abs"], "themes": ["<ROOT>/abs/t.json"]}),
                file("abs/one.ts"),
                file("abs/two.js"),
                file("abs/t.json"),
            ],
        ),
        case(
            "configured_tilde_paths",
            [
                doc(SETTINGS, {"extensions": ["~/ext/home.ts", "~", "~/missing.ts"], "prompts": ["~/p"]}),
                file("home/ext/home.ts"),
                file("home/p/a.md"),
            ],
        ),
        case("configured_unknown_user", [doc(SETTINGS, {"extensions": ["~no-such-user-for-guard-vectors/x.ts"]})]),
        case("configured_lone_surrogate", [file(SETTINGS, '{"extensions": ["\\udc80.ts"]}')]),
        case(
            "configured_entries_not_strings",
            [doc(SETTINGS, {"extensions": [1, None, {"p": "x"}, ["a.ts"], " "], "skills": "skills"})],
        ),
        case(
            "configured_symlinks",
            [
                doc(SETTINGS, {"extensions": ["linked.ts", "linked-dir", "dangling.ts"]}),
                file("real/target.ts"),
                file("real/dir/inner.ts"),
            ],
            [
                link(f"{AGENT}/linked.ts", "<ROOT>/real/target.ts"),
                link(f"{AGENT}/linked-dir", "<ROOT>/real/dir"),
                link(f"{AGENT}/dangling.ts", "<ROOT>/real/missing.ts"),
            ],
        ),
        case(
            "configured_symlink_loop",
            [doc(SETTINGS, {"packages": ["p"], "themes": ["loop.json"]})],
            [link(f"{AGENT}/loop.json", f"<ROOT>/{AGENT}/loop.json")],
        ),
        case(
            "configured_duplicates_default_files",
            [doc(SETTINGS, {"extensions": ["extensions/a.ts", "extensions/a.ts"]}), *resource_tree(AGENT)],
        ),
        case(
            "configured_trailing_slashes_and_dots",
            [
                doc(SETTINGS, {"extensions": ["./x//y/./z.ts", "x/y/", "x/../x/y/z.ts"]}),
                file(f"{AGENT}/x/y/z.ts"),
            ],
        ),
    ]


def glob_cases() -> list[dict]:
    tree = [
        file("g/a.ts"),
        file("g/b.js"),
        file("g/c.txt"),
        file("g/.h.ts"),
        file("g/sub/d.ts"),
        file("g/sub/deep/e.ts"),
        file("g/.hidden/f.ts"),
        file("g/[x]/lit.ts"),
        file("g/x/cls.ts"),
        file("g/q1.ts"),
        file("g/q22.ts"),
        file("g/skills/one/SKILL.md"),
        file("g/skills/.two/SKILL.md"),
        file("g/prompts/p.md"),
        file("g/prompts/sub/r.md"),
    ]
    base = "../../../g"
    return [
        case(
            "glob_patterns",
            [
                doc(
                    SETTINGS,
                    {
                        "extensions": [
                            f"{base}/*.ts",
                            f"{base}/**/*.ts",
                            f"{base}/.*",
                            f"{base}/?1.ts",
                            f"{base}/q[0-9].ts",
                            f"{base}/q[!0-9]*.ts",
                            f"{base}/[x]/*.ts",
                            f"{base}/*/",
                            f"{base}/nomatch-*.ts",
                            f"{base}/[",
                        ],
                    },
                ),
                *tree,
            ],
        ),
        case(
            "glob_recursive_tails",
            [
                doc(
                    SETTINGS,
                    {
                        "extensions": [f"{base}/sub/**"],
                        "skills": [f"{base}/skills/**/SKILL.md", f"{base}/skills/*"],
                        "prompts": [f"{base}/**/prompts", f"{base}/prompts/**/*.md"],
                        "themes": [f"{base}/**/**/*.txt"],
                    },
                ),
                *tree,
            ],
        ),
        case(
            "glob_hidden_patterns",
            [doc(SETTINGS, {"extensions": [f"{base}/.hidden/*", f"{base}/.h*", f"{base}/*/f.ts"]}), *tree],
        ),
        case(
            "glob_through_symlinks",
            [
                doc(SETTINGS, {"extensions": [f"{base}/**/*.ts"], "themes": [f"{base}/*/*.json"]}),
                file("g/one.ts"),
                file("other/two.ts"),
                file("other/t.json"),
            ],
            [
                link("g/via", "<ROOT>/other"),
                link("g/loop", "<ROOT>/g"),
                link("g/dangling.ts", "<ROOT>/nowhere.ts"),
            ],
        ),
        case(
            "glob_unreadable_directory",
            [doc(SETTINGS, {"extensions": [f"{base}/**/*.ts"]}), file("g/ok.ts"), file("g/locked/no.ts")],
            dir_modes={"g/locked": 0o000},
        ),
        case(
            "glob_magic_in_home_directory",
            [
                doc("h[o]me/.pi/agent/settings.json", {"extensions": ["ext.ts", "*.ts"], "packages": ["p"]}),
                file("h[o]me/.pi/agent/ext.ts"),
                file("h[o]me/.pi/agent/extensions/e.ts"),
                file("home/.pi/agent/ext.ts"),
            ],
            home="h[o]me",
        ),
        case(
            "glob_absolute_and_tilde",
            [
                doc(SETTINGS, {"extensions": ["<ROOT>/g/*.ts", "~/hx/*.ts"]}),
                file("g/abs.ts"),
                file("home/hx/t.ts"),
            ],
        ),
    ]


def tree_cases() -> list[dict]:
    return [
        case("default_trees_global", resource_tree(AGENT)),
        case("default_trees_global_and_project", [*resource_tree(AGENT), *resource_tree(PROJECT)]),
        case("default_trees_project_without_workspace", resource_tree(PROJECT), no_workspace=True),
        case("workspace_is_home", [*resource_tree(AGENT), *resource_tree("home/.pi")], workspace_is_home=True),
        case(
            "omp_trees", [*resource_tree(OMP_AGENT), *resource_tree("work/.omp"), *resource_tree(AGENT)], harness="omp"
        ),
        case(
            "omp_settings",
            [
                doc(f"{OMP_AGENT}/settings.json", {"packages": ["npm:o"], "extensions": ["x.ts"]}),
                file(f"{OMP_AGENT}/x.ts"),
            ],
            harness="omp",
        ),
        case(
            "tree_symlinks",
            [file("real/ext.ts"), file("real/dir/inner.ts"), file(f"{AGENT}/extensions/plain.ts")],
            [
                link(f"{AGENT}/extensions/alias.ts", "<ROOT>/real/ext.ts"),
                link(f"{AGENT}/extensions/same.ts", f"<ROOT>/{AGENT}/extensions/plain.ts"),
                link(f"{AGENT}/extensions/linkdir", "<ROOT>/real/dir"),
                link(f"{AGENT}/extensions/dangling.ts", "<ROOT>/real/missing.ts"),
                link(f"{AGENT}/skills/SKILL.md", "<ROOT>/real/missing.md"),
                link(f"{AGENT}/prompts/link.md", "<ROOT>/real/dir"),
            ],
        ),
        case(
            "tree_roots_are_symlinks",
            [*resource_tree("pack")],
            [
                link(f"{AGENT}/extensions", "<ROOT>/pack/extensions"),
                link(f"{AGENT}/skills", "<ROOT>/pack/skills"),
                link(f"{AGENT}/prompts", "<ROOT>/pack/prompts"),
                link(f"{AGENT}/themes", "<ROOT>/pack/themes"),
            ],
        ),
        case(
            "tree_roots_are_files",
            [file(f"{AGENT}/extensions"), file(f"{AGENT}/skills"), file(f"{AGENT}/prompts"), file(f"{AGENT}/themes")],
        ),
        case(
            "tree_directories_named_like_files",
            [file(f"{AGENT}/skills/SKILL.md/inner.txt"), file(f"{AGENT}/prompts/dir.md/inner.txt")],
            dirs=[f"{AGENT}/extensions/folder.ts", f"{AGENT}/themes/folder.json"],
        ),
        case(
            "tree_unreadable_subdirectory",
            [file(f"{AGENT}/extensions/ok.ts"), file(f"{AGENT}/extensions/locked/no.ts")],
            dir_modes={f"{AGENT}/extensions/locked": 0o000},
        ),
        case(
            "tree_sort_order",
            [
                file(f"{AGENT}/extensions/a-b.ts"),
                file(f"{AGENT}/extensions/a/b.ts"),
                file(f"{AGENT}/extensions/a.b.ts"),
                file(f"{AGENT}/extensions/B.ts"),
                file(f"{AGENT}/extensions/é.ts"),
                file(f"{AGENT}/extensions/z.ts"),
            ],
        ),
        case(
            "relative_context",
            [
                *resource_tree(AGENT),
                *resource_tree(PROJECT),
                doc(
                    SETTINGS,
                    {"packages": ["r"], "extensions": ["../../../shared/*.ts", "extensions/a.ts", "missing.ts"]},
                ),
                file("shared/s.ts"),
            ],
            relative=True,
        ),
        case(
            "relative_context_configured_directory",
            [doc(PROJECT_SETTINGS, {"skills": ["skills"], "themes": ["../../pack/themes"]}), *resource_tree("pack")],
            dirs=[f"{PROJECT}/skills/one"],
            relative=True,
        ),
    ]


def cases() -> list[dict]:
    return settings_cases() + configured_cases() + glob_cases() + tree_cases()


def artifact_dict(artifact: GuardArtifact) -> dict:
    payload = dataclasses.asdict(artifact)
    payload.pop("runtime_private_metadata", None)
    payload["args"] = list(artifact.args)
    return payload


def materialize(root: Path, spec: dict) -> None:
    (root / "work").mkdir(parents=True)
    (root / spec["home"]).mkdir(exist_ok=True)
    locked: list[tuple[Path, int]] = []
    for entry in spec["files"]:
        target = root / entry["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        if "hex" in entry:
            target.write_bytes(bytes.fromhex(entry["hex"]))
        else:
            target.write_bytes(entry["text"].replace("<ROOT>", str(root)).encode("utf-8", "surrogatepass"))
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
    for directory, _, _ in os.walk(root):
        os.chmod(directory, 0o755)
    for path in root.rglob("*"):
        if not path.is_symlink():
            path.chmod(0o755)
    shutil.rmtree(root, ignore_errors=True)


def scrub(value: object, root: Path) -> object:
    return json.loads(json.dumps(value, ensure_ascii=False).replace(str(root), "<ROOT>"))


def facade_args(adapter: pi_module._PiFamilyHarnessAdapter, context: HarnessContext) -> dict:
    """The request the native facade sends for this context."""

    roots = [(adapter._global_root(context), "global")]
    project_root = adapter._project_root(context)
    if project_root is not None:
        roots.append((project_root, "project"))
    request: dict[str, object] = {
        "harness": adapter.harness,
        "home": os.path.expanduser("~"),
        "roots": [
            {"path": str(root), "scope": scope, "id_scope": f"{adapter.harness}-{scope}"} for root, scope in roots
        ],
    }
    if not all(root.is_absolute() for root, _ in roots):
        request["cwd"] = os.getcwd()
    return request


def run_case(spec: dict) -> dict:
    root = Path(tempfile.mkdtemp(prefix="pi-vec-")).resolve()
    previous_home, previous_cwd = os.environ.get("HOME"), os.getcwd()
    try:
        materialize(root, spec)
        os.environ["HOME"] = str(root / spec["home"])
        base = Path() if spec["relative"] else root
        if spec["relative"]:
            os.chdir(root)
        home_dir = base / spec["home"]
        workspace = home_dir if spec["workspace_is_home"] else base / "work"
        context = HarnessContext(
            home_dir=home_dir,
            workspace_dir=None if spec["no_workspace"] else workspace,
            guard_home=root / "guard-home",
        )
        adapter = pi_module.OmpHarnessAdapter() if spec["harness"] == "omp" else pi_module.PiHarnessAdapter()
        args = facade_args(adapter, context)
        try:
            detection = adapter.detect(context)
            outcome: dict = {
                "artifacts": [artifact_dict(item) for item in detection.artifacts],
                "found_paths": list(detection.config_paths),
            }
            json.dumps(outcome).encode("utf-8")
        except (ValueError, RecursionError, OSError, RuntimeError):
            outcome = {"refused": True}
        record = {key: spec[key] for key in ("name", "harness", "files", "symlinks", "dirs", "dir_modes", "home")}
        for key in ("no_workspace", "workspace_is_home", "relative"):
            record[key] = spec[key]
        record["args"] = scrub(args, root)
        record.update(scrub(outcome, root))
        return record
    finally:
        os.chdir(previous_cwd)
        if previous_home is None:
            os.environ.pop("HOME", None)
        else:
            os.environ["HOME"] = previous_home
        release(root)


def main() -> None:
    destination = Path(sys.argv[1])
    recorded = [run_case(spec) for spec in cases()]
    document = {"schema": "guard-pi-vectors.v1", "cases": recorded}
    destination.write_text(json.dumps(document, indent=1, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
    print(f"recorded {len(recorded)} cases")


if __name__ == "__main__":
    main()
