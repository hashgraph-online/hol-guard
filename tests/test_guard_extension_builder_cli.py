"""The installed-style authoring CLI runs before Guard state or lifecycle setup."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner import cli
from codex_plugin_scanner.guard.cli import commands_router
from codex_plugin_scanner.guard.extension_builder.io import canonical_json
from codex_plugin_scanner.guard.extension_builder.kit import write_kit
from tests.extension_builder_support import cli_document, make_kit, repository_fixture


def invoke(arguments: list[str], capsys: pytest.CaptureFixture[str]) -> tuple[int, dict[str, object]]:
    result = cli.main(arguments)
    return result, json.loads(capsys.readouterr().out)


def write_external_trust_map(repository: Path, extension_id: str = "command.demo") -> None:
    binding = repository / f"contracts/extensions/trust/{extension_id}.v1.json"
    binding.parent.mkdir(parents=True, exist_ok=True)
    binding.write_text(
        canonical_json(
            {
                "schemaVersion": "guard.extension-trust-binding.v1",
                "extension": extension_id,
                "trustClass": "external",
            }
        ),
        encoding="utf-8",
    )


@pytest.mark.parametrize("program,prefix", [("hol-guard", []), ("plugin-scanner", ["guard"])])
def test_both_entrypoint_families_support_authoring_without_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    program: str,
    prefix: list[str],
) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("Authoring must not initialize policy, workspace, or GuardStore")

    monkeypatch.setattr(sys, "argv", [program])
    monkeypatch.setattr(commands_router, "resolve_guard_home", forbidden)
    monkeypatch.setattr(commands_router, "_resolve_guard_workspace", forbidden)
    monkeypatch.setattr(commands_router, "GuardStore", forbidden)
    monkeypatch.setattr(commands_router, "enforce_lifecycle_gate", forbidden)
    source = tmp_path / "surface.json"
    source.write_text(canonical_json(cli_document()), encoding="utf-8")
    output = tmp_path / "kit"
    arguments = [
        *prefix,
        "extensions",
        "generate",
        "--from",
        "cli",
        "--input",
        str(source),
        "--output",
        str(output),
        "--slug",
        "builder-demo",
        "--publisher",
        "community.example",
        "--homepage",
        "https://example.test/demo",
        "--executable",
        "builder-demo",
        "--json",
    ]
    status, generated = invoke(arguments, capsys)
    assert status == 0 and generated["generated"] is True
    assert generated["reviewedOperations"] == 0
    status, validated = invoke([*prefix, "extensions", "validate", str(output), "--json"], capsys)
    assert status == 0 and validated["validated"] is True
    assert not (tmp_path / ".hol-guard").exists()


def test_existing_inspection_parser_is_unchanged() -> None:
    parser = cli._build_parser("hol-guard", program_mode="hol-guard")
    arguments = parser.parse_args(["command", "extensions", "--json"])
    assert arguments.guard_command == "command"


def test_cli_domain_errors_are_json_and_nonzero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "argv", ["hol-guard"])
    source = tmp_path / "source.json"
    source.write_text("{}", encoding="utf-8")
    status, error = invoke(
        [
            "extensions",
            "generate",
            "--from",
            "cli",
            "--input",
            str(source),
            "--output",
            str(tmp_path / "kit"),
            "--json",
        ],
        capsys,
    )
    assert status == 2
    assert error["error"]["code"] == "missing_metadata"
    assert not (tmp_path / "kit").exists()
    status, error = invoke(["extensions", "validate", str(tmp_path / "absent"), "--json"], capsys)
    assert status == 2 and error["ok"] is False


def test_cli_replay_and_diff_exit_statuses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "argv", ["hol-guard"])
    original = make_kit(tmp_path)
    reviewed = make_kit(tmp_path, reviewed=True)
    old = tmp_path / "original"
    changed = tmp_path / "reviewed"
    write_kit(original, old)
    write_kit(reviewed, changed)
    replay = tmp_path / "replay"
    status, _ = invoke(
        [
            "extensions",
            "generate",
            "--from",
            "snapshot",
            "--input",
            str(old / "discovery.json"),
            "--output",
            str(replay),
            "--json",
        ],
        capsys,
    )
    assert status == 0
    status, equal = invoke(["extensions", "diff", str(old), str(replay), "--json"], capsys)
    assert status == 0 and equal["changed"] is False
    status, different = invoke(["extensions", "diff", str(old), str(changed), "--json"], capsys)
    assert status == 1 and different["changed"] is True
    status, error = invoke(
        [
            "extensions",
            "generate",
            "--from",
            "snapshot",
            "--input",
            str(old / "discovery.json"),
            "--output",
            str(tmp_path / "invalid"),
            "--slug",
            "override",
            "--json",
        ],
        capsys,
    )
    assert status == 2 and error["error"]["code"] == "snapshot_override"


def test_cli_apply_is_plan_only_until_explicit_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "argv", ["hol-guard"])
    kit = make_kit(tmp_path)
    location = tmp_path / "kit"
    write_kit(kit, location)
    repository = repository_fixture(tmp_path)
    arguments = ["extensions", "apply", str(location), "--repo", str(repository), "--json"]
    status, plan = invoke(arguments, capsys)
    assert status == 0 and plan["written"] is False
    status, result = invoke([*arguments, "--write", "--expected-plan", plan["planDigest"]], capsys)
    assert status == 0 and result["written"] is True
    status, conflict = invoke([*arguments, "--write", "--expected-plan", plan["planDigest"]], capsys)
    assert status == 3 and conflict["error"]["code"] == "repository_conflict"


def handoff_source(extension_id: str = "command.demo") -> dict[str, object]:
    return {
        "schema": "guard.command-extension-source.v1",
        "extension": {"extension_id": extension_id},
    }


def write_handoff_inputs(
    repository: Path,
    *,
    source: dict[str, object] | None = None,
    include_script: bool = True,
) -> tuple[Path, Path]:
    source_path = repository / "contributions/command-sources/command.demo.json"
    fixture_path = repository / "tests/fixtures/command-source-demo.v1.json"
    source_path.parent.mkdir(parents=True)
    fixture_path.parent.mkdir(parents=True)
    source_path.write_text(canonical_json(handoff_source() if source is None else source), encoding="utf-8")
    fixture_path.write_text("{}", encoding="utf-8")
    if include_script:
        script = repository / "scripts/prepare_extension_contribution.py"
        script.parent.mkdir()
        script.write_text("# invoked by the subprocess stub\n", encoding="utf-8")
    return source_path, fixture_path


def handoff_arguments(
    repository: Path,
    source_path: Path,
    fixture_path: Path,
    *,
    json_output: bool = True,
    compiler: Path | None = None,
) -> list[str]:
    arguments = [
        "extensions",
        "handoff",
        "--repo",
        str(repository),
        "--source",
        str(source_path),
        "--fixture",
        str(fixture_path),
    ]
    if compiler is not None:
        arguments.extend(("--compiler", str(compiler)))
    if json_output:
        arguments.append("--json")
    return arguments


def test_cli_handoff_delegates_complete_repository_preparation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "argv", ["hol-guard"])
    source_path, fixture_path = write_handoff_inputs(tmp_path)
    write_external_trust_map(tmp_path)
    compiler = tmp_path / "guard-command-source"
    compiler.write_text("# already-built compiler\n", encoding="utf-8")
    script = tmp_path / "scripts/prepare_extension_contribution.py"
    calls: list[tuple[list[str], Path]] = []

    def run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        cwd = kwargs["cwd"]
        assert isinstance(cwd, Path)
        calls.append((command, cwd))
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=json.dumps({"ok": True, "checked": True, "targetCommandsExecuted": 0}),
            stderr="",
        )

    monkeypatch.setattr("codex_plugin_scanner.guard.cli.extension_builder_commands.subprocess.run", run)
    status, result = invoke(
        handoff_arguments(tmp_path, source_path, fixture_path, compiler=compiler),
        capsys,
    )

    assert status == 0
    assert result == {"contributionId": "command.demo", "readyForPullRequest": True, "targetCommandsExecuted": 0}
    assert calls == [
        (
            [
                sys.executable,
                str(script),
                "--check",
                "--source",
                str(source_path),
                "--fixture",
                str(fixture_path),
                "--compiler",
                str(compiler),
            ],
            tmp_path,
        )
    ]


@pytest.mark.parametrize(
    ("source", "code"),
    [
        ({"schema": "other", "extension": {"extension_id": "command.demo"}}, "source_schema"),
        ({"schema": "guard.command-extension-source.v1", "extension": {"extension_id": "demo"}}, "source_identity"),
    ],
)
def test_cli_handoff_rejects_invalid_source_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    source: dict[str, object],
    code: str,
) -> None:
    monkeypatch.setattr(sys, "argv", ["hol-guard"])
    source_path, fixture_path = write_handoff_inputs(tmp_path, source=source, include_script=False)

    status, error = invoke(handoff_arguments(tmp_path, source_path, fixture_path), capsys)

    assert status == 2 and error["error"]["code"] == code


def test_cli_handoff_rejects_noncanonical_paths_before_running_preparation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "argv", ["hol-guard"])
    source_path = tmp_path / "drafts/command.demo.json"
    fixture_path = tmp_path / "tests/fixtures/command-source-demo.v1.json"
    source_path.parent.mkdir(parents=True)
    fixture_path.parent.mkdir(parents=True)
    source_path.write_text(canonical_json(handoff_source()), encoding="utf-8")
    fixture_path.write_text("{}", encoding="utf-8")

    status, error = invoke(handoff_arguments(tmp_path, source_path, fixture_path), capsys)

    assert status == 2 and error["error"]["code"] == "canonical_paths"


@pytest.mark.parametrize(
    ("schema", "extension", "trust_class", "code"),
    [
        ("other", "command.demo", "external", "trust_shape"),
        ("guard.extension-trust-binding.v1", 123, "external", "trust_shape"),
        ("guard.extension-trust-binding.v1", "command.other", "external", "missing_external_trust"),
        ("guard.extension-trust-binding.v1", "command.demo", "first-party", "trust_class"),
        ("guard.extension-trust-binding.v1", "command.demo", "unknown", "trust_shape"),
    ],
)
def test_cli_handoff_rejects_invalid_trust_bindings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    schema: str,
    extension: object,
    trust_class: str,
    code: str,
) -> None:
    monkeypatch.setattr(sys, "argv", ["hol-guard"])
    source_path, fixture_path = write_handoff_inputs(tmp_path, include_script=False)
    identity = extension if isinstance(extension, str) else "command.demo"
    map_path = tmp_path / f"contracts/extensions/trust/{identity}.v1.json"
    map_path.parent.mkdir(parents=True)
    map_path.write_text(
        canonical_json({"schemaVersion": schema, "extension": extension, "trustClass": trust_class}),
        encoding="utf-8",
    )

    status, error = invoke(handoff_arguments(tmp_path, source_path, fixture_path), capsys)

    assert status == 2 and error["error"]["code"] == code


def test_cli_handoff_requires_authored_binding_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "argv", ["hol-guard"])
    source_path, fixture_path = write_handoff_inputs(tmp_path)
    aggregate = tmp_path / "contracts/extensions/trust-class-map.v1.json"
    aggregate.parent.mkdir(parents=True)
    aggregate.write_text(
        canonical_json(
            {
                "schemaVersion": "guard.extension-trust-class-map.v1",
                "classes": {"external": ["command.demo"]},
            }
        )
    )
    status, error = invoke(handoff_arguments(tmp_path, source_path, fixture_path), capsys)
    assert status == 2 and error["error"]["code"] == "trust_shape"


def test_cli_handoff_requires_repository_preparation_tooling(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "argv", ["hol-guard"])
    source_path, fixture_path = write_handoff_inputs(tmp_path, include_script=False)
    write_external_trust_map(tmp_path)

    status, error = invoke(handoff_arguments(tmp_path, source_path, fixture_path), capsys)

    assert status == 2 and error["error"]["code"] == "repository_layout"


@pytest.mark.parametrize("outcome", ["nonzero", "invalid_json", "incomplete", "launch_error"])
def test_cli_handoff_rejects_failed_preparation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    outcome: str,
) -> None:
    monkeypatch.setattr(sys, "argv", ["hol-guard"])
    source_path, fixture_path = write_handoff_inputs(tmp_path)
    write_external_trust_map(tmp_path)

    def run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        if outcome == "launch_error":
            raise OSError("unavailable")
        if outcome == "nonzero":
            return subprocess.CompletedProcess(command, 2, stdout="", stderr="invalid fixture")
        if outcome == "invalid_json":
            return subprocess.CompletedProcess(command, 0, stdout="not JSON", stderr="")
        return subprocess.CompletedProcess(command, 0, stdout=json.dumps({"ok": True, "checked": True}), stderr="")

    monkeypatch.setattr("codex_plugin_scanner.guard.cli.extension_builder_commands.subprocess.run", run)
    status, error = invoke(handoff_arguments(tmp_path, source_path, fixture_path), capsys)

    assert status == 2 and error["error"]["code"] == "handoff_validation"


def test_cli_handoff_human_output_confirms_the_safety_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "argv", ["hol-guard"])
    source_path, fixture_path = write_handoff_inputs(tmp_path)
    binding = tmp_path / "contracts/extensions/trust/command.demo.v1.json"
    binding.parent.mkdir(parents=True)
    binding.write_text(
        canonical_json(
            {
                "schemaVersion": "guard.extension-trust-binding.v1",
                "extension": "command.demo",
                "trustClass": "external",
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.extension_builder_commands.subprocess.run",
        lambda command, **_kwargs: subprocess.CompletedProcess(
            command,
            0,
            stdout=json.dumps({"ok": True, "checked": True, "targetCommandsExecuted": 0}),
            stderr="",
        ),
    )

    status = cli.main(handoff_arguments(tmp_path, source_path, fixture_path, json_output=False))
    output = capsys.readouterr().out

    assert status == 0
    assert "Contribution handoff is ready for command.demo." in output
    assert "Source, fixture, external trust mapping, and generated projections agree." in output
    assert "No target was executed and active protection was not changed." in output


def test_cli_output_conflicts_have_dedicated_status(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "argv", ["hol-guard"])
    kit = make_kit(tmp_path)
    location = tmp_path / "kit"
    write_kit(kit, location)
    status, error = invoke(
        [
            "extensions",
            "generate",
            "--from",
            "snapshot",
            "--input",
            str(location / "discovery.json"),
            "--output",
            str(location),
            "--json",
        ],
        capsys,
    )
    assert status == 3 and error["error"]["code"] == "output_exists"
