"""Package reviews settle from the package evaluator's verdict."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_supply_chain_eval
from codex_plugin_scanner.guard.daemon import hook_native_package_review as package_review
from codex_plugin_scanner.guard.local_supply_chain import evaluate_package_request_artifact
from codex_plugin_scanner.guard.native_package_review_plan import NativePackageReviewPlanError
from codex_plugin_scanner.guard.native_supply_chain_registry_cache import RegistryDeadlineError
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
REVIEW = {"reason_code": "native_package_review", "minimum_action": "review"}
ARTIFACT = object()


def _plan(answer: object):
    """A stand-in for the resident's plan, which the Rust tests cover."""

    def plan(*_args: object, **_kwargs: object) -> object:
        if isinstance(answer, Exception):
            raise answer
        return answer

    return plan


def _respond(tmp_path: Path, native_result: dict[str, object] = REVIEW, *, workspace: Path | None = None):
    return package_review.native_package_review_response(
        object(),
        harness="omp",
        payload={"tool_input": {"command": f"npm install zod {SAFE_FLAGS}"}},
        native_result=native_result,
        workspace=tmp_path if workspace is None else workspace,
        guard_home=tmp_path / "guard",
    )


@pytest.mark.parametrize(
    "native_result",
    [
        {"reason_code": "native_file_read_review", "minimum_action": "review"},
        {"reason_code": "native_package_review", "minimum_action": "block"},
        {"reason_code": "native_command_review_required", "minimum_action": "block"},
    ],
)
def test_only_a_package_or_command_review_is_planned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, native_result: dict[str, object]
) -> None:
    monkeypatch.setattr(package_review, "package_review_plan", _plan(AssertionError("planned")))

    assert _respond(tmp_path, native_result) is None


@pytest.mark.parametrize("reason_code", ["native_package_review", "native_command_review_required"])
def test_the_plan_is_told_which_review_it_settles(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reason_code: str
) -> None:
    """The resident plans a command review only for `npx`/`bunx`, block-only."""

    reasons: list[object] = []

    def plan(*_args: object, **kwargs: object) -> tuple[None, bool]:
        reasons.append(kwargs["review_reason"])
        return None, False

    monkeypatch.setattr(package_review, "package_review_plan", plan)

    assert _respond(tmp_path, {"reason_code": reason_code, "minimum_action": "review"}) is None
    assert reasons == [reason_code]


@pytest.mark.parametrize(
    "answer",
    [(None, False), NativePackageReviewPlanError("unavailable")],
)
def test_a_review_with_no_plan_stays_queued(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, answer: object) -> None:
    monkeypatch.setattr(package_review, "package_review_plan", _plan(answer))
    monkeypatch.setattr(package_review, "_evaluate", _plan(AssertionError("evaluated")))

    assert _respond(tmp_path) is None


def test_a_block_only_review_still_downloading_stays_queued(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Asking for a retry would only ever lead to a block or the same review."""

    monkeypatch.setattr(package_review, "package_review_plan", _plan((ARTIFACT, False)))
    monkeypatch.setattr(package_review, "_evaluate", _plan(RegistryDeadlineError()))

    assert _respond(tmp_path) is None


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
@pytest.mark.parametrize("may_allow", [True, False])
def test_evaluator_verdict_settles_the_review(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    decision: str,
    reasons: tuple,
    packages: tuple,
    expected: dict | None,
    may_allow: bool,
) -> None:
    evaluated: list[object] = []
    monkeypatch.setattr(package_review, "package_review_plan", _plan((ARTIFACT, may_allow)))
    monkeypatch.setattr(
        package_review,
        "_evaluate",
        lambda _store, *, artifact, workspace: (
            evaluated.append((artifact, workspace))
            or SimpleNamespace(decision=decision, reasons=reasons, packages=packages)
        ),
    )
    monkeypatch.setattr(
        package_review,
        "render_pre_tool",
        lambda _harness, verdict, **_kwargs: {
            "rendered": verdict["decision"],
            **({"reason": verdict["reason"]} if "reason" in verdict else {}),
        },
    )

    response = _respond(tmp_path)

    assert evaluated == [(ARTIFACT, tmp_path)]
    # Without the resident's npm proof only a block applies; stopping a
    # command runs nothing.
    assert response == (expected if may_allow or decision == "block" else None)


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
