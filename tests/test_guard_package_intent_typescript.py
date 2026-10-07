from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.package_intent import (
    parse_package_intent,
)
from tests.package_intent_fixtures import (
    _native_package_intent,  # noqa: F401 -- registers the module autouse fixture
    _write_text,
    _write_typescript_workspace,
)


def test_parse_package_intent_records_complete_typescript_launch_without_silent_verification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    _write_typescript_workspace(workspace)
    manager = tmp_path / "bin" / "npx"
    _write_text(manager, "#!/bin/sh\n")
    manager.chmod(0o755)
    monkeypatch.setenv("PATH", str(manager.parent))
    command = "npx --no-install tsc --noEmit --pretty src/example.ts"

    intent = parse_package_intent(command, workspace=workspace)

    assert intent is not None
    assert "local-execution-requires-review" in intent.notes
    evidence = intent.local_executions[0].typescript_launch
    assert evidence is not None
    assert evidence.status == "complete"
    assert evidence.reasons == ()
    assert evidence.config_mode == "explicit_sources"
    assert evidence.source_files == ("src/example.ts",)
    assert evidence.evidence_scope == "launch_identity"
    assert evidence.review_disposition == "review_required"
    assert evidence.direct_silent_verification is False
    assert evidence.binding_digest.startswith("sha256:")


@pytest.mark.parametrize(
    ("case", "command", "expected_reason"),
    (
        (
            "explicit-package",
            "npx --no-install --package typescript tsc --noEmit src/example.ts",
            "explicit_package_source",
        ),
        ("source-drift", "npx --no-install tsc --noEmit src/example.ts", "manifest_source_drift"),
        ("wrong-executable", "npx --no-install tsc --noEmit src/example.ts", "wrong_typescript_executable"),
        ("config", "npx --no-install tsc --noEmit --project tsconfig.json", "compiler_arguments_not_read_only"),
        ("launch-mismatch", "npx tsc --noEmit src/example.ts", "remote_install_not_disabled"),
        ("lock-drift", "npx --no-install tsc --noEmit src/example.ts", "manifest_lock_version_drift"),
    ),
)
def test_typescript_launch_evidence_rejects_minimal_exploit_deltas(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: str,
    command: str,
    expected_reason: str,
) -> None:
    baseline_workspace = tmp_path / "baseline"
    baseline_workspace.mkdir()
    _write_typescript_workspace(baseline_workspace)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    _write_typescript_workspace(
        workspace,
        dependency="file:./substituted" if case == "source-drift" else "^5.9.0",
        locked_version="5.8.4" if case == "lock-drift" else "5.9.0",
        wrong_executable=case == "wrong-executable",
    )
    manager = tmp_path / "bin" / "npx"
    _write_text(manager, "#!/bin/sh\n")
    manager.chmod(0o755)
    monkeypatch.setenv("PATH", str(manager.parent))

    baseline_intent = parse_package_intent(
        "npx --no-install tsc --noEmit src/example.ts",
        workspace=baseline_workspace,
    )
    assert baseline_intent is not None
    assert "local-execution-requires-review" in baseline_intent.notes
    baseline_evidence = baseline_intent.local_executions[0].typescript_launch
    assert baseline_evidence is not None
    assert baseline_evidence.status == "complete"
    assert baseline_evidence.review_disposition == "review_required"
    assert baseline_evidence.direct_silent_verification is False

    intent = parse_package_intent(command, workspace=workspace)

    assert intent is not None
    assert "local-execution-requires-review" in intent.notes
    evidence = intent.local_executions[0].typescript_launch
    assert evidence is not None
    assert evidence.status == "incomplete"
    assert expected_reason in evidence.reasons
    assert evidence.binding_digest != baseline_evidence.binding_digest
    assert evidence.review_disposition == "review_required"
    assert evidence.direct_silent_verification is False


@pytest.mark.parametrize(
    "command",
    (
        "npx --package typescript tsc --noEmit",
        "npx --package tsc@file:./evil tsc --noEmit",
        "npx --package=tsc@file:./evil tsc --noEmit",
    ),
)
def test_parse_package_intent_keeps_explicit_typescript_package_guarded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    command: str,
) -> None:
    _write_text(tmp_path / "package.json", '{"devDependencies":{"typescript":"^5.9.0"}}\n')
    _write_text(tmp_path / "package-lock.json", '{"packages":{"node_modules/typescript":{"version":"5.9.0"}}}\n')
    runner = tmp_path / "node_modules" / ".bin" / "tsc"
    _write_text(runner, "#!/bin/sh\n")
    runner.chmod(0o755)
    manager = tmp_path / "bin" / "npx"
    _write_text(manager, "#!/bin/sh\n")
    manager.chmod(0o755)
    monkeypatch.setenv("PATH", str(manager.parent))

    intent = parse_package_intent(command, workspace=tmp_path)
    assert intent is not None
    assert "local-execution-requires-review" in intent.notes
    assert len(intent.local_executions) == 1
    evidence = intent.local_executions[0].typescript_launch
    if evidence is not None:
        assert evidence.status == "incomplete"
        assert evidence.review_disposition == "review_required"
        assert evidence.direct_silent_verification is False


@pytest.mark.parametrize(
    "command_suffix",
    (
        "--pretty",
        "--noEmit=false --pretty",
        "--noEmit --generateTrace trace-output",
        "--noEmit --outDir generated",
        "--noEmit --pretty 2> diagnostics.ts",
        "--noEmit 2>diagnostics.ts",
    ),
)
def test_parse_package_intent_keeps_non_read_only_typescript_execution_guarded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    command_suffix: str,
) -> None:
    _write_text(tmp_path / "package.json", '{"devDependencies":{"typescript":"^5.9.0"}}\n')
    _write_text(tmp_path / "package-lock.json", '{"packages":{"node_modules/typescript":{"version":"5.9.0"}}}\n')
    runner = tmp_path / "node_modules" / ".bin" / "tsc"
    _write_text(runner, "#!/bin/sh\n")
    runner.chmod(0o755)
    manager = tmp_path / "bin" / "npx"
    _write_text(manager, "#!/bin/sh\n")
    manager.chmod(0o755)
    monkeypatch.setenv("PATH", str(manager.parent))

    intent = parse_package_intent(f"npx tsc {command_suffix}", workspace=tmp_path)
    assert intent is not None
    assert "local-execution-requires-review" in intent.notes
    assert len(intent.local_executions) == 1
    evidence = intent.local_executions[0].typescript_launch
    if evidence is not None:
        assert evidence.status == "incomplete"
        assert evidence.review_disposition == "review_required"
        assert evidence.direct_silent_verification is False


def test_parse_package_intent_keeps_uninstalled_typescript_execution_guarded(tmp_path: Path) -> None:
    _write_text(tmp_path / "package.json", '{"devDependencies":{"typescript":"^5.9.0"}}\n')
    _write_text(tmp_path / "package-lock.json", '{"packages":{"node_modules/typescript":{"version":"5.9.0"}}}\n')

    intent = parse_package_intent("npx tsc --noEmit --pretty", workspace=tmp_path)
    assert intent is not None
    assert "local-execution-requires-review" in intent.notes
    assert len(intent.local_executions) == 1
    evidence = intent.local_executions[0].typescript_launch
    if evidence is not None:
        assert evidence.status == "incomplete"
        assert evidence.review_disposition == "review_required"
        assert evidence.direct_silent_verification is False


def test_parse_package_intent_keeps_unlocked_typescript_execution_guarded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _write_text(tmp_path / "package.json", '{"devDependencies":{"typescript":"^5.9.0"}}\n')
    _write_text(tmp_path / "package-lock.json", '{"packages":{"node_modules/other":{"version":"1.0.0"}}}\n')
    runner = tmp_path / "node_modules" / ".bin" / "tsc"
    _write_text(runner, "#!/bin/sh\n")
    runner.chmod(0o755)
    manager = tmp_path / "bin" / "npx"
    _write_text(manager, "#!/bin/sh\n")
    manager.chmod(0o755)
    monkeypatch.setenv("PATH", str(manager.parent))

    intent = parse_package_intent("npx tsc --noEmit --pretty", workspace=tmp_path)
    assert intent is not None
    assert "local-execution-requires-review" in intent.notes
    assert len(intent.local_executions) == 1
    evidence = intent.local_executions[0].typescript_launch
    if evidence is not None:
        assert evidence.status == "incomplete"
        assert evidence.review_disposition == "review_required"
        assert evidence.direct_silent_verification is False


def test_parse_package_intent_keeps_transitive_only_typescript_lock_guarded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _write_text(tmp_path / "package.json", '{"devDependencies":{"typescript":"^5.9.0"}}\n')
    _write_text(
        tmp_path / "package-lock.json",
        '{"packages":{"node_modules/tool/node_modules/typescript":{"version":"5.9.0"}}}\n',
    )
    runner = tmp_path / "node_modules" / ".bin" / "tsc"
    _write_text(runner, "#!/bin/sh\n")
    runner.chmod(0o755)
    manager = tmp_path / "bin" / "npx"
    _write_text(manager, "#!/bin/sh\n")
    manager.chmod(0o755)
    monkeypatch.setenv("PATH", str(manager.parent))

    intent = parse_package_intent("npx tsc --noEmit --pretty", workspace=tmp_path)
    assert intent is not None
    assert "local-execution-requires-review" in intent.notes
    assert len(intent.local_executions) == 1
    evidence = intent.local_executions[0].typescript_launch
    if evidence is not None:
        assert evidence.status == "incomplete"
        assert evidence.review_disposition == "review_required"
        assert evidence.direct_silent_verification is False


def test_parse_package_intent_keeps_ambiguous_pnpm_typescript_lock_guarded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _write_text(tmp_path / "package.json", '{"devDependencies":{"typescript":"^5.9.0"}}\n')
    _write_text(tmp_path / "pnpm-lock.yaml", "packages:\n  typescript@5.9.0:\n    resolution: {}\n")
    runner = tmp_path / "node_modules" / ".bin" / "tsc"
    _write_text(runner, "#!/bin/sh\n")
    runner.chmod(0o755)
    manager = tmp_path / "bin" / "npx"
    _write_text(manager, "#!/bin/sh\n")
    manager.chmod(0o755)
    monkeypatch.setenv("PATH", str(manager.parent))

    intent = parse_package_intent("npx tsc --noEmit --pretty", workspace=tmp_path)
    assert intent is not None
    assert "local-execution-requires-review" in intent.notes
    assert len(intent.local_executions) == 1
    evidence = intent.local_executions[0].typescript_launch
    if evidence is not None:
        assert evidence.status == "incomplete"
        assert evidence.review_disposition == "review_required"
        assert evidence.direct_silent_verification is False


def test_parse_package_intent_keeps_legacy_transitive_typescript_lock_guarded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _write_text(tmp_path / "package.json", '{"devDependencies":{"typescript":"^5.9.0"}}\n')
    _write_text(
        tmp_path / "package-lock.json",
        '{"dependencies":{"tool":{"dependencies":{"typescript":{"version":"5.9.0"}}}}}\n',
    )
    runner = tmp_path / "node_modules" / ".bin" / "tsc"
    _write_text(runner, "#!/bin/sh\n")
    runner.chmod(0o755)
    manager = tmp_path / "bin" / "npx"
    _write_text(manager, "#!/bin/sh\n")
    manager.chmod(0o755)
    monkeypatch.setenv("PATH", str(manager.parent))

    intent = parse_package_intent("npx tsc --noEmit --pretty", workspace=tmp_path)
    assert intent is not None
    assert "local-execution-requires-review" in intent.notes
    assert len(intent.local_executions) == 1
    evidence = intent.local_executions[0].typescript_launch
    if evidence is not None:
        assert evidence.status == "incomplete"
        assert evidence.review_disposition == "review_required"
        assert evidence.direct_silent_verification is False
