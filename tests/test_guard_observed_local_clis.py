from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.observed_local_clis import (
    commands_from_requests,
    discover_observed_local_clis,
)


@pytest.fixture(autouse=True)
def _native_package_intent(package_intent_native):
    """Parse runner intents through the resident authority."""

    return package_intent_native


def _wrangler_workspace(workspace: Path) -> Path:
    (workspace / "package.json").parent.mkdir(parents=True, exist_ok=True)
    (workspace / "package.json").write_text(
        '{"name":"demo","devDependencies":{"wrangler":"^4.12.0"}}\n',
        encoding="utf-8",
    )
    package_dir = workspace / "node_modules" / "wrangler"
    (package_dir / "bin").mkdir(parents=True)
    (package_dir / "package.json").write_text(
        '{"name":"wrangler","version":"4.12.0","bin":{"wrangler":"bin/wrangler.js"}}\n',
        encoding="utf-8",
    )
    target = package_dir / "bin" / "wrangler.js"
    target.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    target.chmod(0o755)
    link = workspace / "node_modules" / ".bin" / "wrangler"
    link.parent.mkdir(parents=True)
    link.symlink_to(Path("..") / "wrangler" / "bin" / "wrangler.js")
    return workspace


class _Store:
    def __init__(self, requests: list[dict[str, object]], items: list[dict[str, object]] | None = None) -> None:
        self.requests = requests
        self.items = list(items or [])
        self.recorded: list[tuple[str, str | None, str]] = []

    def list_local_cli_items(self) -> list[dict[str, object]]:
        return self.items

    def list_approval_requests(self, *, status: str | None, limit: int) -> list[dict[str, object]]:
        assert status is None
        return self.requests[:limit]

    def record_local_cli_observation(
        self,
        identity,
        *,
        seen_at: str,
        source_path: str | None,
        surface: str,
        only_if_missing: bool = False,
        replayed_at: str | None = None,
    ) -> None:
        assert only_if_missing
        assert replayed_at is not None
        self.recorded.append((identity.cli_id, source_path, surface))


def test_commands_from_requests_dedupes_and_skips_tool_labels() -> None:
    records = [
        {"raw_command_text": "npx wrangler whoami", "workspace": "/w"},
        {"raw_command_text": " npx wrangler whoami ", "workspace": "/w"},
        {"raw_command_text": "tool:mcp__github__search", "workspace": "/w"},
        {"raw_command_text": "npx wrangler whoami", "workspace": None},
        {"raw_command_text": None, "workspace": "/w"},
    ]

    assert commands_from_requests(records) == (("npx wrangler whoami", Path("/w")),)


def test_backfill_records_paused_wrangler_once(tmp_path: Path) -> None:
    workspace = _wrangler_workspace(tmp_path / "workspace")
    store = _Store(
        [
            {"raw_command_text": "npx wrangler --version", "workspace": str(workspace)},
            {"raw_command_text": "npx wrangler deploy", "workspace": str(workspace)},
            {"raw_command_text": "npx wrangler deploy", "workspace": str(tmp_path / "gone")},
        ]
    )

    added = discover_observed_local_clis(store, seen_at="2026-10-08T00:00:00Z", home_dir=tmp_path / "home")

    assert added == 1
    [(cli_id, source_path, surface)] = store.recorded
    assert cli_id.startswith("local-cli.wrangler-")
    assert source_path == "project-tool"
    assert surface == "cli"


def test_backfill_leaves_listed_clis_untouched(tmp_path: Path) -> None:
    workspace = _wrangler_workspace(tmp_path / "workspace")
    request = {"raw_command_text": "npx wrangler whoami", "workspace": str(workspace)}
    first = _Store([request])
    discover_observed_local_clis(first, seen_at="2026-10-08T00:00:00Z", home_dir=tmp_path / "home")
    listed = _Store([request], items=[{"cli_id": first.recorded[0][0]}])

    assert discover_observed_local_clis(listed, seen_at="2026-10-08T00:00:00Z", home_dir=tmp_path / "home") == 0
    assert listed.recorded == []
