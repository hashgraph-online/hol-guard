from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.package_intent import (
    parse_manifest_dependency_changes,
    parse_package_intent,
)
from tests.package_intent_fixtures import (
    _native_package_intent,  # noqa: F401 -- registers the module autouse fixture
    _write_text,
)


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


@pytest.mark.parametrize(
    "options",
    [
        "--with-requirements requirements.txt",
        "--with-requirements=requirements.txt",
        "--with-editable ./local-tool",
        "--with-editable=./local-tool",
    ],
)
def test_uvx_dependency_options_do_not_replace_execution_target(options: str) -> None:
    intent = parse_package_intent(f"uvx {options} ruff==0.6.9")

    assert intent is not None
    assert intent.targets[0].package_name == "ruff"
    assert intent.targets[0].requested_specifier == "0.6.9"


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
