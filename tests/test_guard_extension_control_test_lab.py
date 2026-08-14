from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon.extension_control_errors import ExtensionControlApiError
from codex_plugin_scanner.guard.daemon.extension_control_test_api import (
    evaluate_extension_control_test,
)
from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
)
from codex_plugin_scanner.guard.runtime.extension_control_authority import (
    AuthorityHealth,
    ExtensionControlAuthorityView,
)
from codex_plugin_scanner.guard.runtime.extension_control_runtime import ExtensionControlRuntime


def _runtime() -> ExtensionControlRuntime:
    return ExtensionControlRuntime(
        ExtensionControlAuthorityView(
            AuthorityHealth.PROTECTED,
            7,
            BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
            (),
        )
    )


def test_test_lab_evaluates_without_returning_command_or_path(tmp_path: Path) -> None:
    secret = "guard-test-secret-4c7f"
    raw_command = f"git reset --hard {secret}"

    result = evaluate_extension_control_test(
        registry=BUILT_IN_COMMAND_EXTENSION_REGISTRY,
        runtime=_runtime(),
        payload={"command": raw_command, "extension_id": "command.git"},
    )

    encoded = json.dumps(result, sort_keys=True)
    assert result["schema_version"] == "guard.daemon.extension-control-test.v1"
    assert result["decision"] in {"allowed", "ask-first", "blocked"}
    assert result["revision"] == 7
    assert secret not in encoded
    assert raw_command not in encoded
    assert str(tmp_path) not in encoded
    assert "command" not in result
    assert isinstance(result["matches"], list)


def test_test_lab_canonicalizes_extension_alias_and_filters_matches() -> None:
    result = evaluate_extension_control_test(
        registry=BUILT_IN_COMMAND_EXTENSION_REGISTRY,
        runtime=_runtime(),
        payload={"command": "git reset --hard HEAD~1", "extension_id": "command.git"},
    )

    for match in result["matches"]:
        assert match["extension_id"] == "command.git"
        assert match["permission_id"] == "command.git.permission.hard-reset"


def test_test_lab_rejects_unknown_or_oversized_inputs() -> None:
    runtime = _runtime()
    with pytest.raises(ExtensionControlApiError) as unknown:
        evaluate_extension_control_test(
            registry=BUILT_IN_COMMAND_EXTENSION_REGISTRY,
            runtime=runtime,
            payload={"command": "git status", "extension_id": "command.not-real"},
        )
    assert unknown.value.status == 404
    assert unknown.value.code == "unknown_extension"

    with pytest.raises(ExtensionControlApiError) as oversized:
        evaluate_extension_control_test(
            registry=BUILT_IN_COMMAND_EXTENSION_REGISTRY,
            runtime=runtime,
            payload={"command": "x" * 4097},
        )
    assert oversized.value.status == 400
    assert oversized.value.code == "invalid_test_command"


def test_test_lab_does_not_require_store_or_mutation_proof() -> None:
    # The evaluator accepts only registry/runtime state. There is intentionally no
    # GuardStore, receipt writer, approval proof, filesystem mutation, or executor
    # dependency in this path.
    result = evaluate_extension_control_test(
        registry=BUILT_IN_COMMAND_EXTENSION_REGISTRY,
        runtime=_runtime(),
        payload={"command": "git status", "extension_id": "command.git"},
    )
    assert result["authority_health"] == "protected"
