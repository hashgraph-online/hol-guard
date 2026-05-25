"""Package intent parser tests."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.runtime.package_intent import (
    parse_manifest_dependency_changes,
    parse_package_intent,
)


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


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


def test_parse_package_intent_pip_install_supports_requirements_constraints_vcs_editable_and_redaction(
    tmp_path: Path,
) -> None:
    _write_text(tmp_path / "requirements.txt", "flask==3.0.0\n")
    _write_text(tmp_path / "constraints.txt", "werkzeug==3.0.0\n")

    intent = parse_package_intent(
        "pip install -r requirements.txt -c constraints.txt demo[cli]==2.0 "
        "git+https://user:pass@example.com/org/private.git#egg=private-demo "
        "-e ../editable --index-url https://token@example.com/simple --hash sha256:deadbeef",
        workspace=tmp_path,
    )

    assert intent is not None
    assert intent.package_manager == "pip"
    assert intent.intent_kind == "install"
    assert intent.manifest_paths == ("requirements.txt", "constraints.txt")
    assert [target.package_name for target in intent.targets] == ["demo", "private-demo", "editable"]
    assert intent.targets[0].extras == ("cli",)
    assert intent.targets[2].editable is True
    assert "user:pass" not in intent.redacted_command
    assert "token@" not in intent.redacted_command
    assert "deadbeef" not in intent.redacted_command


def test_parse_package_intent_pip_install_supports_inline_requirement_flag_forms(tmp_path: Path) -> None:
    _write_text(tmp_path / "requirements.txt", "flask==3.0.0\n")
    _write_text(tmp_path / "constraints.txt", "werkzeug==3.0.0\n")

    intent = parse_package_intent(
        "pip install --requirement=requirements.txt -cconstraints.txt demo==1.0.0",
        workspace=tmp_path,
    )

    assert intent is not None
    assert intent.manifest_paths == ("requirements.txt", "constraints.txt")
    assert intent.targets[0].package_name == "demo"


def test_parse_package_intent_pipx_install_and_run_are_supported() -> None:
    install_intent = parse_package_intent("pipx install black --python 3.12")
    run_intent = parse_package_intent("pipx run --python 3.11 httpie==3.2.2")

    assert install_intent is not None
    assert install_intent.package_manager == "pipx"
    assert install_intent.intent_kind == "install"
    assert install_intent.targets[0].package_name == "black"
    assert run_intent is not None
    assert run_intent.package_manager == "pipx"
    assert run_intent.intent_kind == "execute"
    assert run_intent.targets[0].package_name == "httpie"
    assert run_intent.targets[0].requested_specifier == "3.2.2"


def test_parse_package_intent_uv_add_sync_and_execute_are_supported(tmp_path: Path) -> None:
    _write_text(tmp_path / "pyproject.toml", "[project]\nname = 'demo'\n")
    _write_text(tmp_path / "uv.lock", "version = 1\n")

    add_intent = parse_package_intent("uv add fastapi==0.115.0", workspace=tmp_path)
    pip_intent = parse_package_intent("uv pip install httpx==0.27.0", workspace=tmp_path)
    run_intent = parse_package_intent("uvx ruff==0.6.9")
    sync_intent = parse_package_intent("uv sync --locked", workspace=tmp_path)

    assert add_intent is not None
    assert add_intent.package_manager == "uv"
    assert add_intent.intent_kind == "install"
    assert add_intent.targets[0].package_name == "fastapi"
    assert pip_intent is not None
    assert pip_intent.intent_kind == "install"
    assert pip_intent.targets[0].package_name == "httpx"
    assert run_intent is not None
    assert run_intent.package_manager == "uvx"
    assert run_intent.intent_kind == "execute"
    assert run_intent.targets[0].package_name == "ruff"
    assert sync_intent is not None
    assert sync_intent.intent_kind == "sync"
    assert sync_intent.manifest_paths == ("pyproject.toml",)
    assert sync_intent.lockfile_paths == ("uv.lock",)


def test_parse_package_intent_skips_wrapper_flags_before_manager_detection() -> None:
    npm_intent = parse_package_intent("sudo -E npm install react")
    pip_intent = parse_package_intent("env -i pip install flask==3.0.0")

    assert npm_intent is not None
    assert npm_intent.package_manager == "npm"
    assert npm_intent.targets[0].package_name == "react"
    assert pip_intent is not None
    assert pip_intent.package_manager == "pip"
    assert pip_intent.targets[0].package_name == "flask"


def test_parse_package_intent_poetry_and_pipenv_use_project_lockfile_context(tmp_path: Path) -> None:
    _write_text(tmp_path / "pyproject.toml", "[tool.poetry]\nname = 'demo'\n")
    _write_text(tmp_path / "poetry.lock", "[[package]]\nname='requests'\nversion='2.32.0'\n")
    _write_text(tmp_path / "Pipfile", "[packages]\nrequests = '*'\n")
    _write_text(tmp_path / "Pipfile.lock", '{"default":{"requests":{"version":"==2.32.0"}}}\n')

    poetry_intent = parse_package_intent("poetry add requests@^2.32 --group dev --extras socks", workspace=tmp_path)
    poetry_install = parse_package_intent("poetry install --sync", workspace=tmp_path)
    pipenv_intent = parse_package_intent("pipenv install flask~=3.0", workspace=tmp_path)
    pipenv_sync = parse_package_intent("pipenv sync", workspace=tmp_path)

    assert poetry_intent is not None
    assert poetry_intent.package_manager == "poetry"
    assert poetry_intent.targets[0].package_name == "requests"
    assert poetry_intent.targets[0].requested_specifier == "^2.32"
    assert poetry_intent.targets[0].extras == ("socks",)
    assert poetry_intent.targets[0].dependency_group == "dev"
    assert poetry_install is not None
    assert poetry_install.intent_kind == "sync"
    assert poetry_install.lockfile_paths == ("poetry.lock",)
    assert pipenv_intent is not None
    assert pipenv_intent.package_manager == "pipenv"
    assert pipenv_intent.targets[0].package_name == "flask"
    assert pipenv_sync is not None
    assert pipenv_sync.intent_kind == "sync"
    assert pipenv_sync.lockfile_paths == ("Pipfile.lock",)


def test_parse_package_intent_cargo_go_maven_gradle_composer_and_ruby_are_supported() -> None:
    cargo_add = parse_package_intent("cargo add clap@4.5.7 --features derive")
    cargo_install = parse_package_intent("cargo install cargo-audit --git https://github.com/RustSec/rustsec.git")
    go_get = parse_package_intent("go get github.com/gin-gonic/gin@v1.10.0")
    go_install = parse_package_intent("go install example.com/cmd/tool@latest")
    maven = parse_package_intent("mvn dependency:get -Dartifact=org.example:demo:1.2.3")
    gradle = parse_package_intent("./gradlew addDependency --dependency org.example:demo:1.2.3")
    composer = parse_package_intent("composer require laravel/framework:^11.0")
    bundler = parse_package_intent("bundle add rspec --version 3.13.0")
    gem = parse_package_intent("gem install rails -v 7.1.3")

    assert cargo_add is not None
    assert cargo_add.package_manager == "cargo"
    assert cargo_add.targets[0].package_name == "clap"
    assert cargo_add.targets[0].requested_specifier == "4.5.7"
    assert cargo_install is not None
    assert cargo_install.targets[0].source_url == "https://github.com/RustSec/rustsec.git"
    assert go_get is not None
    assert go_get.targets[0].package_name == "github.com/gin-gonic/gin"
    assert go_install is not None
    assert go_install.targets[0].requested_specifier == "latest"
    assert maven is not None
    assert maven.targets[0].package_name == "org.example:demo"
    assert gradle is not None
    assert gradle.targets[0].package_name == "org.example:demo"
    assert composer is not None
    assert composer.targets[0].package_name == "laravel/framework"
    assert bundler is not None
    assert bundler.targets[0].package_name == "rspec"
    assert gem is not None
    assert gem.targets[0].package_name == "rails"


def test_parse_manifest_dependency_changes_supports_primary_manifests_lockfiles_and_tier2_formats() -> None:
    cases = [
        (
            "package.json",
            '{"dependencies":{"react":"18.2.0"}}',
            '{"dependencies":{"react":"18.3.0","lodash":"4.17.21"}}',
            {"react": ("18.2.0", "18.3.0"), "lodash": (None, "4.17.21")},
        ),
        (
            "pyproject.toml",
            '[project]\ndependencies = ["fastapi==0.110.0"]\n',
            '[project]\ndependencies = ["fastapi==0.115.0", "httpx>=0.27"]\n',
            {"fastapi": ("0.110.0", "0.115.0"), "httpx": (None, ">=0.27")},
        ),
        (
            "requirements.txt",
            "flask==3.0.0\n",
            "flask==3.1.0\nrequests==2.32.0\n",
            {"flask": ("3.0.0", "3.1.0"), "requests": (None, "2.32.0")},
        ),
        (
            "package-lock.json",
            '{"packages":{"node_modules/react":{"version":"18.2.0"}}}',
            '{"packages":{"node_modules/react":{"version":"18.3.0"},"node_modules/lodash":{"version":"4.17.21"}}}',
            {"react": ("18.2.0", "18.3.0"), "lodash": (None, "4.17.21")},
        ),
        (
            "Cargo.toml",
            '[dependencies]\nclap = "4.4"\n',
            '[dependencies]\nclap = "4.5"\nserde = "1.0"\n',
            {"clap": ("4.4", "4.5"), "serde": (None, "1.0")},
        ),
        (
            "go.mod",
            "require github.com/gin-gonic/gin v1.9.0\n",
            "require (\n github.com/gin-gonic/gin v1.10.0\n github.com/spf13/cobra v1.8.0\n)\n",
            {"github.com/gin-gonic/gin": ("v1.9.0", "v1.10.0"), "github.com/spf13/cobra": (None, "v1.8.0")},
        ),
        (
            "pom.xml",
            "<project><dependencies><dependency><groupId>org.example</groupId><artifactId>demo</artifactId><version>1.0.0</version></dependency></dependencies></project>",
            "<project><dependencies><dependency><groupId>org.example</groupId><artifactId>demo</artifactId><version>1.2.0</version></dependency><dependency><groupId>org.example</groupId><artifactId>extra</artifactId><version>2.0.0</version></dependency></dependencies></project>",
            {"org.example:demo": ("1.0.0", "1.2.0"), "org.example:extra": (None, "2.0.0")},
        ),
        (
            "pom.xml",
            '<project xmlns="http://maven.apache.org/POM/4.0.0"><dependencies><dependency><groupId>org.example</groupId><artifactId>demo</artifactId><version>1.0.0</version></dependency></dependencies></project>',
            '<project xmlns="http://maven.apache.org/POM/4.0.0"><dependencies><dependency><groupId>org.example</groupId><artifactId>demo</artifactId><version>1.1.0</version></dependency></dependencies></project>',
            {"org.example:demo": ("1.0.0", "1.1.0")},
        ),
        (
            "build.gradle.kts",
            'dependencies { implementation("org.example:demo:1.0.0") }\n',
            'dependencies { implementation("org.example:demo:1.2.0") implementation("org.example:extra:2.0.0") }\n',
            {"org.example:demo": ("1.0.0", "1.2.0"), "org.example:extra": (None, "2.0.0")},
        ),
        (
            "composer.json",
            '{"require":{"laravel/framework":"^10.0"}}',
            '{"require":{"laravel/framework":"^11.0","guzzlehttp/guzzle":"^7.0"}}',
            {"laravel/framework": ("^10.0", "^11.0"), "guzzlehttp/guzzle": (None, "^7.0")},
        ),
        (
            "Gemfile",
            'gem "rails", "7.1.2"\n',
            'gem "rails", "7.1.3"\ngem "rspec", "3.13.0"\n',
            {"rails": ("7.1.2", "7.1.3"), "rspec": (None, "3.13.0")},
        ),
    ]

    for path, before_text, after_text, expected in cases:
        result = parse_manifest_dependency_changes(path=path, before_text=before_text, after_text=after_text)

        assert result.truncated is False
        assert result.parse_errors == ()
        actual = {change.package_name: (change.before, change.after) for change in result.changes}
        assert actual == expected


def test_parse_manifest_dependency_changes_truncates_large_lockfiles_safely() -> None:
    before_text = '{"packages":{}}'
    package_entries = ",".join(f'"node_modules/pkg-{index}":{{"version":"1.0.{index}"}}' for index in range(500))
    after_text = f'{{"packages":{{{package_entries}}}}}'

    result = parse_manifest_dependency_changes(
        path="package-lock.json",
        before_text=before_text,
        after_text=after_text,
        byte_limit=256,
    )

    assert result.changes == ()
    assert result.truncated is True
    assert result.parse_errors == ("byte_limit_exceeded",)


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
