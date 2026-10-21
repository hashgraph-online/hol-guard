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
from tests.package_review_settings import review_package_signals

SAFE_FLAGS = "--ignore-scripts --allow-git=none"
ZOD_METADATA = {
    "https://registry.npmjs.org/zod": {
        "name": "zod",
        "dist-tags": {"latest": "3.23.8"},
        "versions": {"3.22.4": {}, "3.23.8": {}},
    }
}


pytestmark_posix = pytest.mark.skipif(os.name == "nt", reason="npm layout proof is POSIX-only")


def _proof(version: str | None = "11.9.0", *, filters_outside: bool = True):
    """A stand-in for the resident's npm proof, which the Rust tests cover."""

    return lambda *_args, **_kwargs: (version, filters_outside)


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


def _settle_piped(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    command: str,
    path: str,
    *,
    filters_outside: bool = True,
) -> list[list[str]]:
    """The npm tokens the evaluator saw for ``command``."""

    workspace = tmp_path / "workspace"
    workspace.mkdir(exist_ok=True)
    seen: list[list[str]] = []
    monkeypatch.setattr(package_review.os, "name", "posix")
    monkeypatch.setattr(package_review, "npm_install_proof", _proof(filters_outside=filters_outside))
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
def test_a_filter_the_resident_cannot_place_outside_keeps_review(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    command = f"npm install zod {SAFE_FLAGS} 2>&1 | tail -3"

    assert _settle_piped(tmp_path, monkeypatch, command, "/usr/bin:/bin", filters_outside=False) == []


@pytest.mark.parametrize(
    ("filters", "programs"),
    [
        ("", []),
        ("| tail -3", ["tail"]),
        (" | tail -3", ["tail"]),
        ("| head -20 | tail -n3", ["head", "tail"]),
        ("| tail -3 | tail -1", ["tail"]),
    ],
)
def test_the_filter_programs_are_named_once_in_order(filters: str, programs: list[str]) -> None:
    assert package_review._filter_programs(filters) == programs


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
    monkeypatch.setattr(package_review, "npm_install_proof", _proof())
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
        review_package_signals(tmp_path / "home")
        # A git dependency keeps the tree proof out of reach, so only --allow-git=none settles it.
        self._project(tmp_path, {"dependencies": {"left": "github:someone/left"}})
        evaluation = self._evaluate(tmp_path, monkeypatch, "npm install zod --ignore-scripts", "11.9.0")

        assert evaluation.decision == "ask"
        assert "package_lifecycle_scripts_enabled" in self._codes(evaluation)

    @pytest.mark.parametrize("npm_version", [None, "11.6.2", "11.8.9"])
    def test_npm_without_allow_git_keeps_review_without_guidance(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, npm_version: str | None
    ) -> None:
        review_package_signals(tmp_path / "home")
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
        review_package_signals(tmp_path / "home")
        self._project(tmp_path, {"dependencies": {"left": dependency}})
        evaluation = self._evaluate(tmp_path, monkeypatch, "npm install zod --ignore-scripts", npm_version)

        assert evaluation.decision == "ask"
        assert not any(package.get("scriptFreeRegistryInstall") for package in evaluation.packages)

    def test_older_npm_guidance_asks_only_for_ignore_scripts(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        review_package_signals(tmp_path / "home")
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
    monkeypatch.setattr(package_review, "npm_install_proof", _proof("11.6.2"))
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
