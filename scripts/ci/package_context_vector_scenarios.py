"""Scenarios for the package-execution-context parity vectors (repository, executable, dependencies)."""

from __future__ import annotations

from typing import Any

from package_context_vector_support import MANAGERS

R = "{root}"
DEFAULT_ENV = {"PATH": f"{R}/bin", "HOME": f"{R}/home"}
CONFIG = '[core]\n\tbare = false\n[remote "origin"]\n\turl = https://example.test/org/repo.git\n'
SCRIPT = "#!/bin/sh\nexit 0\n"


def w(path: str, text: str = "", *, ex: bool = False) -> dict[str, Any]:
    return {"op": "write", "path": path, "text": text, "exec": ex}


def wh(path: str, hexdata: str) -> dict[str, Any]:
    return {"op": "write", "path": path, "hex": hexdata}


def rep(path: str, text: str, count: int) -> dict[str, Any]:
    return {"op": "write", "path": path, "repeat": text, "count": count}


def sp(path: str, size: int, *, ex: bool = False) -> dict[str, Any]:
    return {"op": "write", "path": path, "size": size, "exec": ex}


def d(path: str) -> dict[str, Any]:
    return {"op": "mkdir", "path": path}


def ln(path: str, target: str) -> dict[str, Any]:
    return {"op": "symlink", "path": path, "target": target}


def tool(name: str, where: str = "bin") -> dict[str, Any]:
    return w(f"{where}/{name}", SCRIPT + f"# {name}\n", ex=True)


def repo(where: str = "ws", config: str = CONFIG) -> list[dict[str, Any]]:
    return [d(f"{where}/.git"), w(f"{where}/.git/config", config)]


def sc(name: str, steps: list[dict[str, Any]] | None = None, **kw: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "name": name,
        "steps": steps or [],
        "workspace": f"{R}/ws",
        "cwd": R,
        "home": f"{R}/home",
        "process_path": f"{R}/procbin",
        "env": dict(DEFAULT_ENV),
        "metadata": {"package_manager": "npm"},
        "executable": None,
        "args": [],
        "launch": "ok",
    }
    base.update(kw)
    return base


def npm_repo(extra: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    return [*repo(), tool("npm"), w("ws/package.json", '{"name":"x"}'), *(extra or [])]


def sink(where: str = "ws") -> list[dict[str, Any]]:
    plain = "# plain\nkey = value\n"
    files = {
        "package.json": '{"name":"x","packageManager":"pnpm@9.0.0","workspaces":["a"],"overrides":{"a":"1"},'
        '"pnpm":{"x":1},"resolutions":{"b":"2"},"scripts":{"test":"t","build":"b"}}',
        ".npmrc": "registry=https://r.test/\n; comment\n# comment\nAuth=${NPM_TOKEN}\n",
        ".yarnrc": plain,
        ".yarnrc.yml": plain,
        "pnpm-workspace.yaml": "packages:\n  - a\n",
        "pnpm-workspace.yml": "packages:\n  - b\n",
        ".pnpmfile.cjs": "module.exports = {}\n",
        "pnpmfile.cjs": "module.exports = {}\n",
        ".pnp.cjs": "module.exports = {}\n",
        "pip.conf": "[global]\nindex-url = https://p.test/\n",
        "pip.ini": "[global]\nindex-url = https://q.test/\n",
        "Pipfile": plain,
        "pyproject.toml": "[project]\nname = 'x'\n",
        "uv.toml": plain,
        ".cargo/config": plain,
        ".cargo/config.toml": plain,
        "Cargo.toml": "[package]\nname = 'x'\n",
        "build.rs": "fn main() {}\n",
        "go.work": "go 1.22\n",
        "go.mod": "module x\n",
        "settings.xml": "<settings/>\n",
        "pom.xml": "<project/>\n",
        ".mvn/maven.config": "-T 2\n",
        "gradle.properties": "a=b\n",
        "settings.gradle": plain,
        "settings.gradle.kts": plain,
        "init.gradle": plain,
        "auth.json": '{"token":"${COMPOSER_TOKEN}"}',
        "composer.json": "{}",
        "composer.patches.json": "{}",
        ".gemrc": "---\n:token: ${GEM_TOKEN}\n",
        ".bundle/config": "BUNDLE_X: y\n",
        "Gemfile": "source 'https://rubygems.org'\n",
        "requirements.txt": "requests==2.0\n",
        "setup.py": "from setuptools import setup\n",
        "setup.cfg": "[metadata]\nname = x\n",
        "bun.lock": "{}",
        "bun.lockb": "bin",
        "package-lock.json": "{}",
        "npm-shrinkwrap.json": "{}",
        "pnpm-lock.yaml": "lock: 1\n",
        "yarn.lock": "# yarn\n",
        "uv.lock": "version = 1\n",
        "poetry.lock": "# poetry\n",
        "Pipfile.lock": "{}",
    }
    steps = [w(f"{where}/{name}", text) for name, text in files.items()]
    steps += [
        w(f"{where}/.yarn/plugins/plugin.cjs", "module.exports = {}\n"),
        w(f"{where}/.yarn/patches/fix.patch", "diff\n"),
        w(f"{where}/patches/a.patch", "diff a\n"),
        w("home/.npmrc", "registry=https://user.test/\n"),
        w("home/.config/pip/pip.conf", "[global]\n"),
        w("home/.config/uv/uv.toml", plain),
        w("home/.cargo/config", plain),
        w("home/.cargo/config.toml", plain),
        w("home/.composer/config.json", "{}"),
        w("home/.composer/auth.json", "{}"),
        w("home/.gemrc", "---\n"),
        w("home/.bundle/config", "BUNDLE_Y: z\n"),
    ]
    return steps


def repository_scenarios() -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    tools = [tool("npm")]
    remotes = (
        '[core]\n\tbare = false\n[remote "origin"]\n\turl = https://b.test/x.git\n\tfetch = +refs/*:refs/*\n'
        '[remote "Upstream"]\n\tURL = https://a.test/x.git\n\turl = https://b.test/x.git\n\turl = \n'
        '[REMOTE "shout"]\n\turl = ssh://h/p?a=b=c\n[branch "main"]\n\turl = https://not-a-remote.test/\n'
        '[remote "x"] \n\turl = https://trailing.test/\n[remotely]\n\turl = https://nope.test/\n\r\n'
        '[remote "crlf"]\r\n\turl = https://crlf.test/\r\n'
    )
    out += [
        sc("git_dir_basic", [*repo(), *tools]),
        sc("git_dir_no_config", [d("ws/.git"), *tools]),
        sc("git_remote_variants", [*repo(config=remotes), *tools]),
        sc(
            "git_remote_split_lines",
            [
                *repo(config='[remote "a"]\n\turl = https://x.test/\u2028[remote "b"]\x0c\turl = https://y.test/\n'),
                *tools,
            ],
        ),
        sc(
            "git_subdir_workspace",
            [*repo(), d("ws/pkg/sub"), *tools, w("ws/pkg/sub/package.json", '{"name":"s"}'), w("ws/.npmrc", "a=b\n")],
            workspace=f"{R}/ws/pkg/sub",
        ),
        sc(
            "git_worktree_absolute_gitfile",
            [
                *repo("main"),
                d("main/.git/worktrees/wt1"),
                w("main/.git/worktrees/wt1/commondir", "../.."),
                w("wt/.git", f"gitdir: {R}/main/.git/worktrees/wt1\n"),
                *tools,
            ],
            workspace=f"{R}/wt",
        ),
        sc(
            "git_worktree_relative_gitfile",
            [
                *repo("main"),
                d("main/.git/worktrees/wt1"),
                w("main/.git/worktrees/wt1/commondir", "../..\n"),
                w("wt/.git", "gitdir: ../main/.git/worktrees/wt1"),
                *tools,
            ],
            workspace=f"{R}/wt",
        ),
        sc(
            "git_worktree_absolute_commondir",
            [
                *repo("main"),
                d("main/.git/worktrees/wt1"),
                w("main/.git/worktrees/wt1/commondir", f"{R}/main/.git"),
                w("wt/.git", f"gitdir:{R}/main/.git/worktrees/wt1"),
                *tools,
            ],
            workspace=f"{R}/wt",
        ),
        sc(
            "git_gitfile_to_plain_dir",
            [d("elsewhere/gd"), w("elsewhere/gd/config", CONFIG), w("ws/.git", f"gitdir: {R}/elsewhere/gd"), *tools],
        ),
        sc("git_gitfile_no_prefix", [w("ws/.git", f"{R}/main\n"), *tools]),
        sc("git_gitfile_empty_path", [w("ws/.git", "gitdir:   \n"), *tools]),
        sc("git_gitfile_non_utf8", [wh("ws/.git", "676974646972ff"), *tools]),
        sc("git_gitfile_missing_target", [w("ws/.git", f"gitdir: {R}/nowhere"), *tools]),
        sc("git_gitfile_target_is_file", [w("other", "x"), w("ws/.git", f"gitdir: {R}/other"), *tools]),
        sc("git_gitfile_oversize_pointer", [rep("ws/.git", "gitdir: x\n", 1700), *tools]),
        sc("git_gitfile_pointer_at_limit", [rep("ws/.git", "g", 16384), *tools]),
        sc(
            "git_commondir_missing_target",
            [d("ws/.git"), w("ws/.git/commondir", "../nope"), *tools],
        ),
        sc(
            "git_commondir_target_is_file",
            [d("ws/.git"), w("ws/.git/commondir", "HEAD"), w("ws/.git/HEAD", "ref: x"), *tools],
        ),
        sc("git_commondir_empty", [*repo(), w("ws/.git/commondir", ""), *tools]),
        sc("git_commondir_non_utf8", [*repo(), wh("ws/.git/commondir", "ff"), *tools]),
        sc(
            "git_commondir_symlink",
            [*repo(), w("real-common", ".."), ln("ws/.git/commondir", f"{R}/real-common"), *tools],
        ),
        sc("git_config_non_utf8", [d("ws/.git"), wh("ws/.git/config", "5b72656d6f74655d0aff"), *tools]),
        sc(
            "git_config_symlink",
            [d("ws/.git"), w("real-config", CONFIG), ln("ws/.git/config", f"{R}/real-config"), *tools],
        ),
        sc("git_config_is_directory", [d("ws/.git/config"), *tools]),
        sc("git_config_oversize", [d("ws/.git"), sp("ws/.git/config", 2 * 1024 * 1024 + 1), *tools]),
        sc("git_marker_symlink_to_dir", [*repo("real"), ln("ws/.git", f"{R}/real/.git"), *tools]),
        sc("git_marker_symlink_to_file", [w("pointer", "gitdir: x"), ln("ws/.git", f"{R}/pointer"), *tools]),
        sc(
            "git_broken_marker_symlink_then_parent_repo",
            [*repo("ws"), ln("ws/sub/.git", f"{R}/gone"), *tools],
            workspace=f"{R}/ws/sub",
        ),
        sc("no_repository", [*tools, w("ws/package.json", '{"name":"x"}')]),
        sc("no_repository_missing_workspace", list(tools)),
        sc("workspace_tilde", [*repo("home/proj"), *tools], workspace="~/proj"),
        sc("workspace_relative", [*repo("proj"), *tools], workspace="proj"),
        sc("workspace_symlink", [*repo("real"), ln("link", f"{R}/real"), *tools], workspace=f"{R}/link"),
        sc("workspace_dotdot", [*repo("ws"), d("ws/a"), *tools], workspace=f"{R}/ws/a/.."),
        sc(
            "workspace_symlink_into_repo_subdir",
            [*repo("repo"), d("repo/p/q"), ln("lnk", f"{R}/repo/p/q"), *tools],
            workspace=f"{R}/lnk",
        ),
    ]
    return out


def manager_scenarios() -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for manager in (*MANAGERS, "brew", "unknown", "NPM", "pyenv"):
        steps = [*repo(), *sink(), tool(manager)]
        out.append(sc(f"manager_{manager}", steps, metadata={"package_manager": manager}, executable=manager))
    out += [
        sc("manager_missing_from_metadata", [*repo(), tool("npm")], metadata={}),
        sc("manager_blank", [*repo(), tool("npm")], metadata={"package_manager": "   "}),
        sc("manager_non_string", [*repo(), tool("npm")], metadata={"package_manager": 7}),
        sc("manager_padded", [*repo(), *sink(), tool("npm")], metadata={"package_manager": "  npm "}),
        sc(
            "manager_uppercase_with_executable",
            [*repo(), *sink(), tool("npm")],
            metadata={"package_manager": "NPM"},
            executable="npm",
        ),
    ]
    for tag, flags in {
        "short": ["-g"],
        "long": ["--global"],
        "location": ["--location=global"],
        "equals": ["--global=true"],
        "padded": [" -g "],
        "other_flags": ["--save", "--globalx", "-G", "--location=user"],
        "empty_flags": [],
        "mixed_types": [3, None, "-g"],
        "after_others": ["--save-dev", "--global"],
    }.items():
        out.append(sc(f"global_{tag}", [*repo(), tool("npm")], metadata={"package_manager": "npm", "flags": flags}))
    out.append(
        sc("global_flags_not_a_list", [*repo(), tool("npm")], metadata={"package_manager": "npm", "flags": "-g"})
    )
    out.append(
        sc("global_and_unsupported", [*repo(), tool("brew")], metadata={"package_manager": "brew", "flags": ["-g"]})
    )
    out.append(sc("global_with_repo_failure", [tool("npm")], metadata={"package_manager": "npm", "flags": ["-g"]}))
    out.append(
        sc(
            "failure_precedence_repo_then_manager",
            [w("ws/.git", "bad"), tool("brew")],
            metadata={"package_manager": "brew", "flags": ["-g"]},
        )
    )
    return out


def executable_scenarios() -> list[dict[str, Any]]:
    base = repo()
    out: list[dict[str, Any]] = [
        sc("exec_path_lookup", [*base, tool("npm")]),
        sc(
            "exec_path_second_entry",
            [*base, tool("npm", "bin2")],
            env={"PATH": f"{R}/bin:{R}/bin2", "HOME": f"{R}/home"},
        ),
        sc(
            "exec_path_first_wins",
            [*base, tool("npm"), tool("npm", "bin2")],
            env={"PATH": f"{R}/bin2:{R}/bin", "HOME": f"{R}/home"},
        ),
        sc("exec_path_empty_string", [*base, tool("npm")], env={"PATH": "", "HOME": f"{R}/home"}),
        sc("exec_path_missing_uses_process_path", [*base, tool("npm", "procbin")], env={"HOME": f"{R}/home"}),
        sc(
            "exec_path_relative_entry",
            [*base, tool("npm", "ws/bin")],
            env={"PATH": "bin", "HOME": f"{R}/home"},
            cwd=f"{R}/ws",
            workspace=f"{R}/ws",
        ),
        sc(
            "exec_path_blank_entry",
            [*base, tool("npm", "ws")],
            env={"PATH": f":{R}/nope", "HOME": f"{R}/home"},
            cwd=f"{R}/ws",
        ),
        sc(
            "exec_path_skips_non_executable",
            [*base, w("bin/npm", SCRIPT), tool("npm", "bin2")],
            env={"PATH": f"{R}/bin:{R}/bin2", "HOME": f"{R}/home"},
        ),
        sc("exec_path_non_executable_only", [*base, w("bin/npm", SCRIPT)]),
        sc(
            "exec_path_skips_directory",
            [*base, d("bin/npm"), tool("npm", "bin2")],
            env={"PATH": f"{R}/bin:{R}/bin2", "HOME": f"{R}/home"},
        ),
        sc("exec_path_symlink", [*base, w("real/npm-cli.js", SCRIPT, ex=True), ln("bin/npm", f"{R}/real/npm-cli.js")]),
        sc(
            "exec_path_symlink_into_workspace",
            [
                *base,
                w("ws/node_modules/.bin/cli.js", SCRIPT, ex=True),
                ln("bin/npm", f"{R}/ws/node_modules/.bin/cli.js"),
            ],
        ),
        sc("exec_path_broken_symlink", [*base, ln("bin/npm", f"{R}/gone")]),
        sc("exec_missing", list(base)),
        sc("exec_missing_explicit_path", list(base), executable="./bin/npm"),
        sc("exec_absolute", [*base, tool("npm", "ext")], executable=f"{R}/ext/npm"),
        sc("exec_relative_workspace", [*base, tool("npm", "ws/bin")], executable="./bin/npm"),
        sc("exec_relative_nested", [*base, tool("npm", "ws/tools/bin")], executable="tools/bin/npm"),
        sc("exec_relative_parent", [*base, tool("npm", "shared")], executable="../shared/npm"),
        sc(
            "exec_relative_in_repo_not_workspace",
            [*repo(), d("ws/pkg"), tool("npm", "ws/bin")],
            workspace=f"{R}/ws/pkg",
            executable="../bin/npm",
        ),
        sc("exec_tilde", [*base, tool("npm", "home/bin")], executable="~/bin/npm"),
        sc("exec_tilde_only_slash", [*base, tool("npm", "home/bin")], executable="~/bin/../bin/npm"),
        sc(
            "exec_symlink_explicit",
            [*base, w("real/cli.js", SCRIPT, ex=True), ln("ws/npm", f"{R}/real/cli.js")],
            executable="./npm",
        ),
        sc("exec_directory", [*base, d("ws/tools")], executable="./tools"),
        sc("exec_not_executable_explicit", [*base, w("ws/npm", SCRIPT)], executable="./npm"),
        sc("exec_empty_file", [*base, w("ws/npm", "", ex=True)], executable="./npm"),
        sc("exec_oversize", [*base, sp("ws/npm", 512 * 1024 * 1024 + 1, ex=True)], executable="./npm"),
        sc("exec_token_semicolon", [*base, tool("npm")], executable="npm;rm"),
        sc("exec_token_and", [*base, tool("npm")], executable="npm && x"),
        sc("exec_token_or", [*base, tool("npm")], executable="a||b"),
        sc("exec_token_pipe", [*base, tool("npm")], executable="a|b"),
        sc("exec_backslash_existing", [*base, w("ws/a\\b", SCRIPT, ex=True)], executable="a\\b"),
        sc("exec_backslash_missing", list(base), executable="x\\y"),
        sc(
            "exec_metadata_override",
            [*base, tool("npm"), tool("pnpm")],
            metadata={"package_manager": "npm", "package_executable": "pnpm"},
        ),
        sc(
            "exec_metadata_padded",
            [*base, tool("npm"), tool("pnpm")],
            metadata={"package_manager": "npm", "package_executable": "  pnpm "},
        ),
        sc(
            "exec_param_beats_metadata",
            [*base, tool("npm"), tool("pnpm")],
            metadata={"package_manager": "npm", "package_executable": "npm"},
            executable="pnpm",
        ),
        sc("exec_param_with_spaces", [*base, tool("npm")], executable=" npm"),
        sc("exec_param_empty", [*base, tool("npm")], executable=""),
        sc(
            "exec_metadata_non_string",
            [*base, tool("npm")],
            metadata={"package_manager": "npm", "package_executable": 5},
        ),
        sc("exec_args", [*base, tool("npm")], args=["install", "left-pad", "--ignore-scripts"]),
        sc("exec_unicode_name", [*base, tool("npmé")], metadata={"package_manager": "npm"}, executable="npmé"),
        sc(
            "exec_in_workspace_location",
            [*base, tool("npm", "ws/node_modules/.bin")],
            executable="./node_modules/.bin/npm",
        ),
        sc(
            "exec_in_repository_location",
            [*repo(), d("ws/pkg"), tool("npm", "tools")],
            workspace=f"{R}/ws/pkg",
            executable=f"{R}/ws/../tools/npm",
        ),
        sc(
            "exec_in_repository_subdir_location",
            [*repo(), d("ws/pkg"), tool("npm", "ws/bin")],
            workspace=f"{R}/ws/pkg",
            executable=f"{R}/ws/bin/npm",
        ),
        sc("exec_no_repository", [tool("npm", "ws/bin")], executable="./bin/npm"),
    ]
    for mode in ("unverified", "mismatch", "no_executable", "nonce"):
        out.append(sc(f"exec_launch_{mode}", [*base, tool("npm")], launch=mode))
        out.append(
            sc(f"exec_launch_{mode}_explicit", [*base, tool("npm", "ws/bin")], launch=mode, executable="./bin/npm")
        )
    return out


def dependency_scenarios() -> list[dict[str, Any]]:
    steps = [*repo(), tool("npm"), w("ws/package.json", '{"name":"x"}'), w("ws/package-lock.json", "{}")]
    meta = {"package_manager": "npm"}
    out: list[dict[str, Any]] = [
        sc("deps_inferred_npm", steps),
        sc("deps_inferred_none_present", [*repo(), tool("npm")]),
        sc("deps_inferred_only_lock", [*repo(), tool("npm"), w("ws/package-lock.json", "{}")]),
        sc(
            "deps_inferred_unknown_manager",
            [*repo(), tool("cargo"), w("ws/Cargo.toml", "x"), w("ws/Cargo.lock", "y")],
            metadata={"package_manager": "cargo"},
        ),
        sc(
            "deps_inferred_symlinked_default",
            [*repo(), tool("npm"), w("real.json", "{}"), ln("ws/package.json", f"{R}/real.json")],
        ),
        sc("deps_inferred_directory_default", [*repo(), tool("npm"), d("ws/package.json")]),
    ]
    configured: dict[str, dict[str, Any]] = {
        "valid": {"manifest_paths": ["package.json"], "lockfile_paths": ["package-lock.json"]},
        "missing": {"manifest_paths": ["nope.json"]},
        "empty_strings": {"manifest_paths": ["", "   "], "lockfile_paths": []},
        "padded": {"manifest_paths": ["  package.json  "]},
        "traversal": {"manifest_paths": ["../outside.json"]},
        "dotdot_inside": {"manifest_paths": ["sub/../package.json"]},
        "absolute": {"manifest_paths": [f"{R}/ws/package.json"]},
        "not_a_list": {"manifest_paths": "package.json"},
        "mixed_types": {"manifest_paths": [1, None, "package.json", ["x"]]},
        "tuple_like_duplicates": {"manifest_paths": ["package.json", "package.json"]},
        "directory": {"manifest_paths": ["sub"]},
        "symlink_inside": {"manifest_paths": ["inlink.json"]},
        "symlink_outside": {"manifest_paths": ["outlink.json"]},
        "symlink_dangling": {"manifest_paths": ["dangling.json"]},
        "symlink_dir_component": {"manifest_paths": ["dirlink/package.json"]},
        "oversize": {"manifest_paths": ["big.bin"]},
        "large_but_allowed": {"lockfile_paths": ["mid.bin"]},
        "empty_file": {"manifest_paths": ["empty.json"]},
        "lock_only_configured": {"lockfile_paths": ["package-lock.json"]},
        "unicode_path": {"manifest_paths": ["dép.json"]},
        "other_metadata_keys_ignored": {"manifest_paths": ["package.json"], "extra": {"a": 1}, "version": "1"},
    }
    extra = [
        w("ws/package.json", '{"name":"x"}'),
        w("ws/package-lock.json", "{}"),
        d("ws/sub"),
        w("outside.json", "{}"),
        ln("ws/inlink.json", f"{R}/ws/package.json"),
        ln("ws/outlink.json", f"{R}/outside.json"),
        ln("ws/dangling.json", f"{R}/gone.json"),
        ln("ws/dirlink", f"{R}/ws/sub"),
        w("ws/sub/package.json", "{}"),
        sp("ws/big.bin", 32 * 1024 * 1024 + 1),
        sp("ws/mid.bin", 1024 * 1024),
        w("ws/empty.json", ""),
        w("ws/dép.json", "{}"),
    ]
    for tag, extra_meta in configured.items():
        out.append(sc(f"deps_{tag}", [*repo(), tool("npm"), *extra], metadata={**meta, **extra_meta}))
    out.append(
        sc(
            "deps_failure_precedence",
            [*repo(), tool("npm"), *extra],
            metadata={**meta, "manifest_paths": ["nope.json", "big.bin"]},
        )
    )
    return out
