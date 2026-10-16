"""Script-free npm registry installs continue without review."""

from __future__ import annotations

import json
import os
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_supply_chain_eval
from codex_plugin_scanner.guard.daemon import hook_native_package_review as package_review
from codex_plugin_scanner.guard.local_supply_chain import evaluate_package_request_artifact
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_tier2_phase13_support import artifact_from_command_fixture

SAFE_FLAGS = "--ignore-scripts --allow-git=none"
ZOD_METADATA = {
    "https://registry.npmjs.org/zod": {
        "name": "zod",
        "dist-tags": {"latest": "3.23.8"},
        "versions": {"3.22.4": {}, "3.23.8": {}},
    }
}


def _install_npm(prefix: Path, version: str) -> None:
    package = prefix / "lib" / "node_modules" / "npm"
    (package / "bin").mkdir(parents=True)
    (package / "bin" / "npm-cli.js").write_text("#!/usr/bin/env node\n", encoding="utf-8")
    (package / "bin" / "npm-cli.js").chmod(0o755)
    (package / "package.json").write_text(json.dumps({"name": "npm", "version": version}), encoding="utf-8")
    (prefix / "bin").mkdir()
    (prefix / "bin" / "npm").symlink_to(Path("..") / "lib" / "node_modules" / "npm" / "bin" / "npm-cli.js")
    (prefix / "bin" / "node").write_text("#!/bin/sh\n", encoding="utf-8")
    (prefix / "bin" / "node").chmod(0o755)


def _environment(prefix: Path, home: Path, *names: str, path: str | None = None) -> dict[str, object]:
    return {
        "path": path if path is not None else f"{prefix / 'bin'}{os.pathsep}/usr/bin",
        "home": str(home),
        "environment_names": sorted({"HOME", "PATH", *names}),
        "library_search_paths": {},
    }


@pytest.fixture
def npm_layout(tmp_path: Path) -> tuple[Path, Path, Path]:
    prefix, home, workspace = tmp_path / "prefix", tmp_path / "home", tmp_path / "workspace"
    home.mkdir()
    workspace.mkdir()
    _install_npm(prefix, "11.9.0")
    return prefix, home, workspace


pytestmark_posix = pytest.mark.skipif(os.name == "nt", reason="npm layout proof is POSIX-only")


@pytestmark_posix
def test_standard_npm_install_reports_its_version(npm_layout: tuple[Path, Path, Path]) -> None:
    prefix, home, workspace = npm_layout
    (home / ".npmrc").write_text("prefix=/tmp/npm-global\n//registry.npmjs.org/:_authToken=x\n", encoding="utf-8")

    assert package_review.verified_npm_version(_environment(prefix, home), workspace=workspace) == "11.9.0"


@pytestmark_posix
def test_an_added_ca_keeps_the_npm_proof(npm_layout: tuple[Path, Path, Path]) -> None:
    prefix, home, workspace = npm_layout

    environment = _environment(prefix, home, "NODE_EXTRA_CA_CERTS")
    assert package_review.verified_npm_version(environment, workspace=workspace) == "11.9.0"


@pytestmark_posix
@pytest.mark.parametrize("name", ["npm_config_cache", "NPM_CONFIG_UPDATE_NOTIFIER", "npm_config_fund"])
def test_cache_and_reporting_settings_keep_the_npm_proof(npm_layout: tuple[Path, Path, Path], name: str) -> None:
    prefix, home, workspace = npm_layout

    assert package_review.verified_npm_version(_environment(prefix, home, name), workspace=workspace) == "11.9.0"


@pytestmark_posix
def test_a_loader_path_outside_the_workspace_keeps_the_npm_proof(npm_layout: tuple[Path, Path, Path]) -> None:
    prefix, home, workspace = npm_layout
    libraries = home / ".local" / "lib"
    libraries.mkdir(parents=True)
    environment = _environment(prefix, home, "LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH")
    environment["library_search_paths"] = {"LD_LIBRARY_PATH": str(libraries), "DYLD_LIBRARY_PATH": str(libraries)}

    assert package_review.verified_npm_version(environment, workspace=workspace) == "11.9.0"


@pytestmark_posix
@pytest.mark.parametrize("entry", ["", "lib", ".", "{workspace}/lib", "{home}/lib:{workspace}", "{home}/link/lib"])
def test_a_loader_path_reaching_the_workspace_fails_closed(npm_layout: tuple[Path, Path, Path], entry: str) -> None:
    prefix, home, workspace = npm_layout
    (home / "link").symlink_to(workspace)
    environment = _environment(prefix, home, "LD_LIBRARY_PATH")
    environment["library_search_paths"] = {"LD_LIBRARY_PATH": entry.format(home=home, workspace=workspace)}

    assert package_review.verified_npm_version(environment, workspace=workspace) is None


@pytestmark_posix
def test_a_loader_path_without_its_stamped_value_fails_closed(npm_layout: tuple[Path, Path, Path]) -> None:
    prefix, home, workspace = npm_layout

    environment = _environment(prefix, home, "LD_LIBRARY_PATH")
    assert package_review.verified_npm_version(environment, workspace=workspace) is None


@pytestmark_posix
@pytest.mark.parametrize(
    "name",
    [
        "npm_config_registry",
        "NPM_CONFIG_ALLOW_GIT",
        "npm_config__cache",
        "npm_config_cafile",
        "NODE_OPTIONS",
        "NODE_PATH",
        "PREFIX",
        "DESTDIR",
        "NODE_TLS_REJECT_UNAUTHORIZED",
    ],
)
def test_settings_that_change_npm_fail_closed(npm_layout: tuple[Path, Path, Path], name: str) -> None:
    prefix, home, workspace = npm_layout

    assert package_review.verified_npm_version(_environment(prefix, home, name), workspace=workspace) is None


@pytestmark_posix
@pytest.mark.parametrize(
    "npmrc",
    ["registry=https://example.test/\n", "@acme:registry=https://example.test/\n", "strict-ssl=false\n"],
)
def test_user_config_that_moves_the_fetch_fails_closed(npm_layout: tuple[Path, Path, Path], npmrc: str) -> None:
    prefix, home, workspace = npm_layout
    (home / ".npmrc").write_text(npmrc, encoding="utf-8")

    assert package_review.verified_npm_version(_environment(prefix, home), workspace=workspace) is None


@pytestmark_posix
@pytest.mark.parametrize("home", [None, "", "relative/home"])
def test_unlocatable_user_config_fails_closed(npm_layout: tuple[Path, Path, Path], home: str | None) -> None:
    prefix, _home, workspace = npm_layout
    environment = _environment(prefix, _home)
    environment["home"] = home

    assert package_review.verified_npm_version(environment, workspace=workspace) is None


@pytestmark_posix
def test_relative_path_entry_before_npm_fails_closed(npm_layout: tuple[Path, Path, Path]) -> None:
    prefix, home, workspace = npm_layout
    environment = _environment(prefix, home, path=f"node_modules/.bin{os.pathsep}{prefix / 'bin'}")

    assert package_review.verified_npm_version(environment, workspace=workspace) is None


@pytestmark_posix
def test_npm_or_node_from_the_workspace_fails_closed(npm_layout: tuple[Path, Path, Path]) -> None:
    prefix, home, workspace = npm_layout
    local = workspace / "tools"
    _install_npm(local, "11.9.0")

    assert package_review.verified_npm_version(_environment(local, home), workspace=workspace) is None
    shadow = workspace / "bin"
    shadow.mkdir()
    (shadow / "node").write_text("#!/bin/sh\n", encoding="utf-8")
    (shadow / "node").chmod(0o755)
    environment = _environment(prefix, home, path=f"{shadow}{os.pathsep}{prefix / 'bin'}")
    assert package_review.verified_npm_version(environment, workspace=workspace) is None


@pytestmark_posix
def test_npm_shim_without_a_readable_version_fails_closed(npm_layout: tuple[Path, Path, Path]) -> None:
    _prefix, home, workspace = npm_layout
    shim = home / "shim"
    shim.mkdir()
    for name in ("npm", "node"):
        (shim / name).write_text("#!/bin/sh\n", encoding="utf-8")
        (shim / name).chmod(0o755)

    environment = _environment(shim.parent, home, path=str(shim))
    assert package_review.verified_npm_version(environment, workspace=workspace) is None


@pytest.mark.parametrize(
    ("command", "reason_code"),
    [
        (f"npm install zod {SAFE_FLAGS}", "native_command_review_required"),
        (f"npm install zod {SAFE_FLAGS} && rm -rf build", "native_package_review"),
        (f"FOO=1 npm install zod {SAFE_FLAGS}", "native_package_review"),
        (f"npm install ~/zod {SAFE_FLAGS}", "native_package_review"),
        (f"npm install $PKG {SAFE_FLAGS}", "native_package_review"),
    ],
)
def test_only_a_plain_npm_package_review_is_settled(tmp_path: Path, command: str, reason_code: str) -> None:
    response = package_review.native_package_review_response(
        object(),
        harness="omp",
        payload={"tool_input": {"command": command}},
        native_result={"reason_code": reason_code, "minimum_action": "review"},
        workspace=tmp_path,
        guard_home=tmp_path / "guard",
    )

    assert response is None


def _settle_piped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, command: str, path: str) -> list[list[str]]:
    """The npm tokens the evaluator saw for ``command``."""

    workspace = tmp_path / "workspace"
    workspace.mkdir(exist_ok=True)
    seen: list[list[str]] = []
    monkeypatch.setattr(package_review.os, "name", "posix")
    monkeypatch.setattr(package_review, "verified_npm_version", lambda *_args, **_kwargs: "11.9.0")
    monkeypatch.setattr(
        package_review,
        "_evaluate",
        lambda *_args, tokens, **_kwargs: seen.append(tokens) or None,
    )
    package_review.native_package_review_response(
        object(),
        harness="omp",
        payload={"tool_input": {"command": command}, package_review.HOOK_EXECUTION_ENVIRONMENT_KEY: {"path": path}},
        native_result={"reason_code": "native_package_review", "minimum_action": "review"},
        workspace=workspace,
        guard_home=tmp_path / "guard",
    )
    return seen


@pytestmark_posix
@pytest.mark.parametrize(
    "suffix",
    ["2>&1", "2>&1 | tail -3", "| tail -n 5", "2>&1|grep -i added", "| head -20 | tail -n3"],
)
def test_output_filters_after_an_install_are_evaluated_without_them(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, suffix: str
) -> None:
    seen = _settle_piped(tmp_path, monkeypatch, f"npm install zod {SAFE_FLAGS} {suffix}", "/usr/bin:/bin")

    assert seen == [["npm", "install", "zod", *SAFE_FLAGS.split()]]


@pytestmark_posix
@pytest.mark.parametrize(
    "suffix",
    [
        "| grep -f/etc/passwd",
        "| grep x /etc/passwd",
        "| tail /etc/passwd",
        "| tail -f log",
        "| tee log",
        "| sh",
        "> out.txt",
        "2>&1 | tail -3 > out.txt",
        "&& tail -3",
    ],
)
def test_other_trailing_commands_keep_review(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, suffix: str) -> None:
    assert _settle_piped(tmp_path, monkeypatch, f"npm install zod {SAFE_FLAGS} {suffix}", "/usr/bin:/bin") == []


@pytestmark_posix
def test_a_filter_from_the_workspace_keeps_review(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    tools = tmp_path / "workspace" / "bin"
    tools.mkdir(parents=True)
    (tools / "tail").write_text("#!/bin/sh\n", encoding="utf-8")
    (tools / "tail").chmod(0o755)
    command = f"npm install zod {SAFE_FLAGS} 2>&1 | tail -3"

    assert _settle_piped(tmp_path, monkeypatch, command, f"{tools}:/usr/bin:/bin") == []
    assert _settle_piped(tmp_path, monkeypatch, command, "") == []


SCRIPT_FREE = {"name": "zod", "scriptFreeRegistryInstall": True}


@pytest.mark.parametrize(
    ("decision", "reasons", "packages", "expected"),
    [
        ("allow", (), (), {"rendered": "allow"}),
        ("monitor", (), (SCRIPT_FREE,), {"rendered": "allow"}),
        ("monitor", (), (SCRIPT_FREE, {"name": "left-pad"}), None),
        ("monitor", (), ({"name": "zod", "scriptFreeRegistryInstall": "true"},), None),
        ("monitor", (), (), None),
        (
            "ask",
            ({"code": "package_lifecycle_scripts_enabled", "message": "Rerun with the flags."},),
            (),
            {"rendered": "deny", "reason": "Rerun with the flags.", "prompted": False},
        ),
        (
            "block",
            ({"code": "package_known_malicious", "message": "zod@9.9.9 is malicious."},),
            (SCRIPT_FREE,),
            {"rendered": "deny", "reason": "zod@9.9.9 is malicious.", "prompted": False},
        ),
        ("ask", ({"code": "unidentified_package", "message": "Unknown package."},), (), None),
    ],
)
def test_evaluator_verdict_settles_the_review(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    decision: str,
    reasons: tuple,
    packages: tuple,
    expected: dict | None,
) -> None:
    monkeypatch.setattr(package_review.os, "name", "posix")
    monkeypatch.setattr(package_review, "verified_npm_version", lambda *_args, **_kwargs: "11.9.0")
    monkeypatch.setattr(
        package_review,
        "_evaluate",
        lambda *_args, **_kwargs: SimpleNamespace(decision=decision, reasons=reasons, packages=packages),
    )
    monkeypatch.setattr(
        package_review,
        "render_pre_tool",
        lambda _harness, verdict, **_kwargs: {
            "rendered": verdict["decision"],
            **({"reason": verdict["reason"]} if "reason" in verdict else {}),
        },
    )

    response = package_review.native_package_review_response(
        object(),
        harness="omp",
        payload={"tool_input": {"command": f"npm install zod {SAFE_FLAGS}"}},
        native_result={"reason_code": "native_package_review", "minimum_action": "review"},
        workspace=tmp_path,
        guard_home=tmp_path / "guard",
    )

    assert response == expected


class TestEvaluatorRule:
    pytestmark = pytest.mark.usefixtures("package_intent_native")

    @staticmethod
    def _evaluate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, command: str, npm_version: str | None):
        monkeypatch.setattr(native_supply_chain_eval, "_test_registry_metadata_override", ZOD_METADATA)
        workspace = tmp_path / "workspace"
        workspace.mkdir(exist_ok=True)
        artifact = artifact_from_command_fixture(command, workspace=workspace)
        if npm_version is not None:
            artifact = replace(artifact, metadata={**artifact.metadata, "verified_npm_version": npm_version})
        return evaluate_package_request_artifact(
            artifact=artifact,
            store=GuardStore(tmp_path / "home"),
            workspace_dir=workspace,
            now="2026-10-12T00:00:00Z",
        )

    @staticmethod
    def _codes(evaluation) -> set[str]:
        return {str(reason.get("code")) for reason in evaluation.reasons}

    @pytest.mark.parametrize("spec", ["zod", "zod@^3", "zod@3.22.4", "zod@latest"])
    def test_script_free_registry_install_is_allowed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, spec: str
    ) -> None:
        evaluation = self._evaluate(tmp_path, monkeypatch, f"npm install -D {spec} {SAFE_FLAGS}", "11.9.0")

        # Watched, not trusted: the request is still recorded as evidence.
        assert evaluation.decision == "monitor", evaluation.reasons
        assert [package.get("scriptFreeRegistryInstall") for package in evaluation.packages] == [True]

    def test_missing_flags_get_rerun_guidance(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        # A git dependency keeps the tree proof out of reach, so only --allow-git=none settles it.
        self._project(tmp_path, {"dependencies": {"left": "github:someone/left"}})
        evaluation = self._evaluate(tmp_path, monkeypatch, "npm install zod --ignore-scripts", "11.9.0")

        assert evaluation.decision == "ask"
        assert "package_lifecycle_scripts_enabled" in self._codes(evaluation)

    @pytest.mark.parametrize("npm_version", [None, "11.6.2", "11.8.9"])
    def test_npm_without_allow_git_keeps_review_without_guidance(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, npm_version: str | None
    ) -> None:
        evaluation = self._evaluate(tmp_path, monkeypatch, f"npm install zod {SAFE_FLAGS}", npm_version)

        assert evaluation.decision == "ask"
        assert "package_lifecycle_scripts_enabled" not in self._codes(evaluation)

    @staticmethod
    def _project(tmp_path: Path, manifest: dict[str, object]) -> None:
        workspace = tmp_path / "workspace"
        workspace.mkdir(exist_ok=True)
        (workspace / "package.json").write_text(json.dumps(manifest), encoding="utf-8")

    @pytest.mark.parametrize("npm_version", ["10.9.9", "11.8.9", "11.9.0", "11.10.1"])
    def test_ignore_scripts_installs_a_git_free_tree_without_review(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, npm_version: str
    ) -> None:
        self._project(tmp_path, {"dependencies": {"zod": "^3.22.0"}})
        evaluation = self._evaluate(tmp_path, monkeypatch, "npm install zod --ignore-scripts", npm_version)

        assert evaluation.decision == "monitor", evaluation.reasons
        assert [package.get("scriptFreeRegistryInstall") for package in evaluation.packages] == [True]

    @pytest.mark.parametrize("npm_version", ["10.9.9", "11.9.0"])
    @pytest.mark.parametrize("dependency", ["github:someone/left", "file:../left", "npm:zod@3"])
    def test_ignore_scripts_keeps_review_when_the_tree_can_hold_a_git_dependency(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, dependency: str, npm_version: str
    ) -> None:
        self._project(tmp_path, {"dependencies": {"left": dependency}})
        evaluation = self._evaluate(tmp_path, monkeypatch, "npm install zod --ignore-scripts", npm_version)

        assert evaluation.decision == "ask"
        assert not any(package.get("scriptFreeRegistryInstall") for package in evaluation.packages)

    def test_older_npm_guidance_asks_only_for_ignore_scripts(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._project(tmp_path, {})
        evaluation = self._evaluate(tmp_path, monkeypatch, "npm install zod", "10.9.9")

        messages = [str(reason.get("message")) for reason in evaluation.reasons]
        guidance = [m for m in messages if "Rerun the same npm command" in m]
        assert evaluation.decision == "ask"
        assert len(guidance) == 1
        assert "with --ignore-scripts and HOL Guard" in guidance[0]

    @pytest.mark.parametrize(
        "command",
        [
            f"npm install zod {SAFE_FLAGS} --allow-g=all",
            f"npm install zod {SAFE_FLAGS} --reg=https://example.test/",
            f"npm install -g zod {SAFE_FLAGS}",
            f"npm install user/zod {SAFE_FLAGS}",
            f"npm install unknown-package-xyz {SAFE_FLAGS}",
        ],
    )
    def test_unproven_installs_keep_review(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, command: str) -> None:
        evaluation = self._evaluate(tmp_path, monkeypatch, command, "11.9.0")

        assert evaluation.decision != "allow"
        assert not any(package.get("scriptFreeRegistryInstall") for package in evaluation.packages)

    def test_project_npmrc_registry_keeps_review(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        workspace = tmp_path / "workspace"
        workspace.mkdir()
        (workspace / ".npmrc").write_text("registry=https://example.test/\n", encoding="utf-8")

        evaluation = self._evaluate(tmp_path, monkeypatch, f"npm install zod {SAFE_FLAGS}", "11.9.0")

        assert evaluation.decision != "allow"
        assert not any(package.get("scriptFreeRegistryInstall") for package in evaluation.packages)


def test_the_safety_guide_install_reaches_the_evaluator_and_settles(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The managed safety guide names this install as the one that continues.

    Codex ran a bare `npm install` for a Vite game, which runs package install
    scripts and is rightly reviewed. The script-free form the guide gives must
    reach the evaluator intact and be settled by a script-free verdict.
    """

    guide = (Path(package_review.__file__).parents[1] / "agent-safety-guidance.md").read_text(encoding="utf-8")
    command = "npm install --ignore-scripts"
    # The npm ci form is proven by the Rust lockfile install tests.
    for named in (command, "npm ci --ignore-scripts"):
        assert f"`{named}`" in " ".join(guide.split())
    seen: list[list[str]] = []
    monkeypatch.setattr(package_review.os, "name", "posix")
    monkeypatch.setattr(package_review, "verified_npm_version", lambda *_args, **_kwargs: "11.6.2")
    monkeypatch.setattr(
        package_review,
        "_evaluate",
        lambda *_args, tokens, **_kwargs: (
            seen.append(tokens) or SimpleNamespace(decision="allow", reasons=(), packages=(SCRIPT_FREE,))
        ),
    )
    monkeypatch.setattr(
        package_review, "render_pre_tool", lambda _harness, verdict, **_kwargs: {"rendered": verdict["decision"]}
    )

    response = package_review.native_package_review_response(
        object(),
        harness="codex",
        payload={"tool_input": {"command": command}},
        native_result={"reason_code": "native_package_review", "minimum_action": "review"},
        workspace=tmp_path,
        guard_home=tmp_path / "guard",
    )

    assert seen == [command.split()]
    assert response == {"rendered": "allow"}
