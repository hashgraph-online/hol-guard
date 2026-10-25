"""Regression coverage for nested sensitive metadata in the serializer."""

from __future__ import annotations

import copy
import json

import pytest

from codex_plugin_scanner.guard.inventory_contract_redaction import _safe_json


@pytest.mark.security_critical
@pytest.mark.parametrize("sensitive_parent", [False, True])
def test_nested_sensitive_metadata_keeps_all_sibling_keys(sensitive_parent: bool) -> None:
    """Keep every nested field while redacting its sensitive values without modifying the input."""
    source = {
        "tokenInfo": {
            "primary": {"value": "first-private-value", "note": "first-private-note"},
            "secondary": {"value": "second-private-value", "note": "second-private-note"},
            "history": [{"left": "third-private-value", "right": "fourth-private-value"}],
        }
    }
    original = copy.deepcopy(source)
    result = _safe_json(source, parent_sensitive=sensitive_parent)
    assert result == {
        "tokenInfo": {
            "primary": {"value": "[REDACTED]", "note": "[REDACTED]"},
            "secondary": {"value": "[REDACTED]", "note": "[REDACTED]"},
            "history": [{"left": "[REDACTED]", "right": "[REDACTED]"}],
        }
    }
    assert source == original
    assert "private-value" not in json.dumps(result)
    assert "private-note" not in json.dumps(result)


def test_sensitive_ancestor_does_not_disable_unsafe_key_redaction() -> None:
    """Preserve structural names, not literal secrets embedded in a key itself."""
    result = _safe_json({"safeField": "private-value", "sk-secret-key": "another-private-value"}, parent_sensitive=True)
    assert result == {"safeField": "[REDACTED]", "[REDACTED]": "[REDACTED]"}


def test_an_export_asks_for_every_metadata_value_in_the_prefetched_batch(monkeypatch, tmp_path) -> None:
    """Pin that the batch covers the walk: one request, then no further asks."""
    from dataclasses import dataclass, field
    from pathlib import Path

    from codex_plugin_scanner.guard import native_inventory_url_redaction as native_url
    from codex_plugin_scanner.guard.inventory_contract_redaction import (
        _is_supported_scanner_run,
        _prefetch_export_redactions,
        _redact_known_path,
        _safe_artifact_metadata,
        _safe_finding_text,
        _scanner_finding_title,
    )

    requests: list[list[dict[str, object]]] = []

    def answers(tasks, *, guard_home=None, timeout_seconds=10.0):
        requests.append(list(tasks))
        return ["redacted" for _ in tasks]

    monkeypatch.setattr(native_url, "_answers", answers)

    @dataclass
    class Artifact:
        artifact_type: str = "mcp_server"
        config_path: str | None = None
        command: str | None = None
        url: str | None = None
        transport: str | None = None
        metadata: dict[str, object] = field(default_factory=dict)

    home = tmp_path / "home"
    artifacts = (
        Artifact(
            config_path=f"{home}/.config/one.json",
            command="npx server --root /private/root",
            url="https://one.example.test/path?token=abc",
            metadata={
                "entry": f"{home}/.config/entry.py",
                "nested": {"path": Path(f"{home}/.config/nested.py"), "endpoint": "https://two.example.test"},
                "items": [f"{home}/.config/list.py", "https://three.example.test"],
                "apiToken": "private-value",
            },
        ),
        Artifact(artifact_type="skill", config_path=f"{home}/.config/two.json"),
    )

    @dataclass
    class Finding:
        title: str
        description: str
        file_path: str | None = None

    @dataclass
    class Run:
        source: str
        message: str
        findings: tuple[Finding, ...]

    runs = (
        Run(
            source="cisco-mcp-scanner",
            message=f"scanned {home}/.config",
            findings=(
                Finding("npx tool --token abc", "found in /private/root", f"{home}/.config/hit.py"),
                Finding("another finding", ""),
                # A finding with no title of its own: the export gives it a
                # stand-in, so the batch has to carry the stand-in too.
                Finding("", "an untitled finding"),
            ),
        ),
        # A run from a scanner the export drops. Nothing of it is ever redacted,
        # so nothing of it belongs in the batch either.
        Run(
            source="some-other-scanner",
            message=f"scanned {home}/.config/unsupported",
            findings=(Finding("unsupported finding", f"seen at {home}/.config/unsupported.py"),),
        ),
    )
    with native_url.redaction_pass():
        _prefetch_export_redactions(artifacts, runs, home_dir=home, workspace_dir=None)
        prefetched = len(requests)
        prefetched_tasks = len(requests[0])
        for artifact in artifacts:
            _safe_artifact_metadata(artifact, home_dir=home, workspace_dir=None)
        for run in runs:
            if not _is_supported_scanner_run(run):
                continue
            _safe_finding_text(run.message, home_dir=home, workspace_dir=None)
            for finding in run.findings:
                _safe_finding_text(_scanner_finding_title(finding), home_dir=home, workspace_dir=None)
                _safe_finding_text(finding.description, home_dir=home, workspace_dir=None)
                if finding.file_path:
                    _redact_known_path(finding.file_path, home, None)
    assert prefetched == 1
    assert len(requests) == prefetched
    # The dropped run's three strings would have been asked about had the batch
    # not applied the same filter the export does.
    assert not any("unsupported" in str(task.get("value", "")) for task in requests[0]), (
        "the batch asked about a run the export never redacts"
    )
    assert prefetched_tasks == len(requests[0])
