"""AIBOM exports redact local paths and keep untrusted fields inside table cells."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import aibom_cli
from codex_plugin_scanner.guard.adapters.base import HarnessContext


@pytest.mark.security_critical
@pytest.mark.parametrize("export_format", ["json", "markdown"])
@pytest.mark.parametrize("outside_home", [False, True])
@pytest.mark.parametrize("present", [False, True])
def test_export_redacts_paths_without_changing_skill_presence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    export_format: str,
    outside_home: bool,
    present: bool,
) -> None:
    """Both export formats use real paths for presence, but never include their absolute forms."""
    home = tmp_path / "private-home"
    home.mkdir()
    skill_root = tmp_path / "private-workspace" if outside_home else home / ".pi/skills/example"
    skill_root.mkdir(parents=True)
    skill_file = skill_root / "SKILL.md"
    if present:
        skill_file.write_text("---\nname: example\n---\n# Example\n", encoding="utf-8")
    original = {
        "artifact_id": "example-skill",
        "artifact_name": "Example",
        "artifact_type": "skill_file",
        "harness": "pi",
        "source_scope": "global",
        "config_path": str(skill_file),
        "last_policy_action": "allow",
        "present": True,
        "custom_field": "preserve-me",
        "launch_command": f"python {home}/server.py --token fake-secret",
    }
    store = SimpleNamespace(list_inventory=lambda: [original], get_sync_payload=lambda _key: None)
    context = HarnessContext(home, skill_root, tmp_path / "guard")
    monkeypatch.setattr(aibom_cli, "collect_aibom_snapshots", lambda *_args, **_kwargs: ())
    monkeypatch.setattr(aibom_cli, "_resolve_trust_attestation_context", lambda *_args, **_kwargs: {})

    payload = aibom_cli.build_aibom_export_payload(
        store, context, generated_at="2026-09-11T00:00:00Z", export_format=export_format
    )

    row = payload["artifacts"][0]
    expected = "SKILL.md" if outside_home else "{home}/.pi/skills/example/SKILL.md"
    assert row["config_path"] == expected
    assert row["present"] is present
    assert row["trust_verdict"] == "allow"
    assert row["custom_field"] == "preserve-me"
    assert row["launch_command"] == "python {home}/server.py --token redacted"
    assert "fake-secret" not in json.dumps(payload)
    assert original["launch_command"].endswith("--token fake-secret")
    assert str(skill_file) not in json.dumps(payload)
    assert str(home) not in json.dumps(payload)
    assert original["config_path"] == str(skill_file)
    assert original["present"] is True


@pytest.mark.parametrize("present", [False, True])
def test_markdown_export_escapes_every_artifact_cell(present: bool) -> None:
    """Pipes, multiline text, HTML and formatting cannot create extra table cells or rows."""
    untrusted = "first\\|second\r\nthird\nfourth <img> `code` [link](url) *bold* _italic_"
    row = dict.fromkeys(("artifact_name", "harness", "artifact_type", "source_scope", "trust_verdict"), untrusted)
    row["present"] = present
    payload = {
        "artifacts": [row, {"artifact_name": "Plain", "present": True}],
        "layer_summary": {},
        "trust_summary": {},
    }

    markdown = aibom_cli._render_aibom_markdown(payload)

    table_rows = [line for line in markdown.splitlines() if line.startswith("| ")]
    assert len(table_rows) == 4  # Heading, separator, and exactly two artifact rows.
    cells = table_rows[2].removeprefix("| ").removesuffix(" |").split(" | ")
    assert len(cells) == 6
    assert cells[-1] == ("yes" if present else "no")
    assert all(cell == cells[0] for cell in cells[:5])
    assert "\\|" in cells[0]
    assert "first\\\\" in cells[0]
    assert "second third fourth" in cells[0]
    assert "&lt;img&gt;" in cells[0]
    assert "\\`code\\`" in cells[0]
    assert "\\[link\\]\\(url\\)" in cells[0]
    assert "\\*bold\\*" in cells[0]
    assert "\\_italic\\_" in cells[0]
    assert row["artifact_name"] == untrusted
