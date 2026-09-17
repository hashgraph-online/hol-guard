"""Cross-platform integration preserves checkout line endings."""

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.extension_builder.repository_edits import (
    CATALOG_PATH,
    PYPROJECT_PATH,
    STAGING_PATH,
    TRUST_PATH,
)
from codex_plugin_scanner.guard.extension_builder.repository_write import apply_kit
from tests.extension_builder_support import make_kit, repository_fixture


@pytest.mark.parametrize("kind", ["cli", "mcp"])
def test_crlf_checkout_preserves_shared_newlines_and_replays(tmp_path: Path, kind: str) -> None:
    kit = make_kit(tmp_path, kind, reviewed=True)
    repository = repository_fixture(tmp_path)
    shared = (PYPROJECT_PATH, TRUST_PATH, STAGING_PATH, CATALOG_PATH)
    for name in shared:
        path = repository / name
        path.write_bytes(path.read_bytes().replace(b"\r\n", b"\n").replace(b"\n", b"\r\n"))
    plan = apply_kit(kit, repository)
    apply_kit(kit, repository, write=True, expected_plan=plan["planDigest"])
    for name in shared:
        content = (repository / name).read_bytes()
        assert b"\r\n" in content
        assert b"\n" not in content.replace(b"\r\n", b"")
    repeated = apply_kit(kit, repository)
    assert all(item["action"] == "unchanged" for item in repeated["files"])
