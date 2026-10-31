from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.models import GuardArtifact
from codex_plugin_scanner.guard.runtime.secret_file_request_services.developer_inspection import (
    DeveloperShellEffect,
    _compound_developer_effect_graph,
)
from tests.runtime_artifact_policy_support import (
    _runtime_artifact_command_action_floor,
)


def test_compound_effect_graph_composes_directory_reads_and_filters(tmp_path: Path) -> None:
    home = tmp_path / "home"
    workspace = home / "projects" / "workspace"
    source = workspace / "src"
    source.mkdir(parents=True)
    (source / "example.ts").write_text("export const value = 1;\n", encoding="utf-8")

    graph = _compound_developer_effect_graph(
        f"cd {workspace} && rg -n value src | sed -n '1,20p' | head -5",
        home_dir=home,
    )

    assert graph is not None
    assert tuple(segment.effect for segment in graph.segments) == (
        DeveloperShellEffect.DIRECTORY,
        DeveloperShellEffect.LOCAL_READ,
        DeveloperShellEffect.STREAM_FILTER,
        DeveloperShellEffect.STREAM_FILTER,
    )


@pytest.mark.parametrize(
    "suffix",
    (
        "rg -n value src > report.txt",
        "rg -n value src | xargs sh -c 'echo changed'",
        "rg --pre 'cat .env' value src",
        "cat .env",
        "git push origin main",
        "echo $(cat src/example.ts)",
        "source src/example.ts",
    ),
)
def test_compound_effect_graph_rejects_unproven_or_mutating_segment(tmp_path: Path, suffix: str) -> None:
    home = tmp_path / "home"
    workspace = home / "projects" / "workspace"
    source = workspace / "src"
    source.mkdir(parents=True)
    (source / "example.ts").write_text("export const value = 1;\n", encoding="utf-8")
    (workspace / ".env").write_text("placeholder\n", encoding="utf-8")

    assert _compound_developer_effect_graph(f"cd {workspace} && {suffix}", home_dir=home) is None


def test_compound_effect_graph_rejects_incomplete_directory_proof(tmp_path: Path) -> None:
    home = tmp_path / "home"
    workspace = home / "projects" / "workspace"
    workspace.mkdir(parents=True)

    assert _compound_developer_effect_graph(f"cd {workspace} && cd missing && pwd", home_dir=home) is None


def test_compound_effect_graph_allows_remote_read_but_rejects_remote_mutation(tmp_path: Path) -> None:
    home = tmp_path / "home"
    workspace = home / "projects" / "workspace"
    workspace.mkdir(parents=True)

    read_graph = _compound_developer_effect_graph(
        "gh pr view 42 --repo example/project --json number | head -1",
        cwd=workspace,
        home_dir=home,
    )

    assert read_graph is not None
    assert DeveloperShellEffect.REMOTE_READ in {segment.effect for segment in read_graph.segments}
    assert (
        _compound_developer_effect_graph(
            "gh repo delete example/project --yes",
            cwd=workspace,
            home_dir=home,
        )
        is None
    )


def test_compound_action_floor_applies_to_non_tool_action_primary() -> None:
    artifact = GuardArtifact(
        artifact_id="test:package",
        name="package request",
        harness="codex",
        artifact_type="package_request",
        source_scope="project",
        config_path="guard-config",
        metadata={"command_action_floor": "require-reapproval"},
    )

    assert _runtime_artifact_command_action_floor(artifact) == "require-reapproval"
