"""Every Python site that produces a Guard verdict stays audited.

See `docs/guard/audits/maj-ac-01-per-root-authority-audit.md`. A new site has to
be read and recorded in the baseline before it can land.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from tests.delivery_scripts import script

audit = script("audit_python_verdict_sites")


def _baseline() -> dict[str, object]:
    return json.loads(audit.BASELINE.read_text(encoding="utf-8"))


def test_discovered_verdict_sites_match_the_audit() -> None:
    found = {(str(site["file"]), str(site["func"])) for site in audit.discover()}
    recorded = {(str(site["file"]), str(site["func"])) for site in _baseline()["sites"]}
    assert found == recorded


def test_check_mode_passes_on_the_committed_baseline() -> None:
    assert audit.main(["--check"]) == 0


def test_every_audited_site_carries_a_reading() -> None:
    document = _baseline()
    readings = set(document["readings"])
    for site in document["sites"]:
        assert site["reading"] in readings, site["func"]
        assert str(site["note"]).strip(), site["func"]


def test_only_the_recorded_findings_compose_a_verdict_in_python() -> None:
    """The audit's open findings. Fixing one removes its row.

    `_run_guard_protect_command` was the second finding and is gone: PR #6320
    deleted the rewrite once a probe showed the resident reads the approval-gate
    row for itself. `_script_free_watch` was the first; the resident now settles
    the script-free watch and `native_package_review_response` renders its answer.
    """

    composed = sorted(str(site["func"]) for site in _baseline()["sites"] if site["reading"] == "composes-in-python")
    assert composed == []


def test_every_recorded_template_still_resists_parsing() -> None:
    """The templates the scan cannot read, so the audit stays honest about them."""

    recorded = {(str(entry["file"]), str(entry["label"])) for entry in _baseline()["unparsed_templates"]}
    found = {(str(entry["file"]), str(entry["label"])) for entry in audit.unparsed_templates()}
    assert found == recorded


def _check_against(baseline: object, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> int:
    doctored = tmp_path / "python-verdict-sites.json"
    doctored.write_text(json.dumps(baseline), encoding="utf-8")
    monkeypatch.setattr(audit, "BASELINE", doctored)
    return audit.main(["--check"])


def test_check_fails_when_a_site_gains_an_action(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """A cleared fail-closed site that grows an allow is the drift this gate exists to catch.

    Its name does not change, so only the recorded action set can notice.
    """

    baseline = _baseline()
    for site in baseline["sites"]:
        if site["reading"] == "fails-closed":
            site["actions"] = sorted({*site["actions"], "allow"})
            break
    else:  # pragma: no cover - the baseline always has fail-closed rows
        pytest.fail("no fail-closed site to doctor")
    assert _check_against(baseline, monkeypatch, tmp_path) == 1


def test_check_fails_when_the_unparsed_templates_drift(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    template = {"file": "src/codex_plugin_scanner/guard/example.py", "label": "literal#0", "line": 1, "reason": "x"}
    stale = _baseline()
    stale["unparsed_templates"] = [*stale["unparsed_templates"], template]
    assert _check_against(stale, monkeypatch, tmp_path) == 1

    monkeypatch.setattr(audit, "unparsed_templates", lambda: [template])
    assert _check_against(_baseline(), monkeypatch, tmp_path) == 1


def test_a_verdict_behind_a_conditional_or_a_constant_is_found() -> None:
    """The shapes a literal-only scan misses: both branches, and a named constant."""

    module = ast.parse(
        """
_ALLOW = {"policy_action": "allow"}


def conditional(flag):
    return "allow" if flag else "block"


def from_constant():
    return dict(_ALLOW)
"""
    )
    constants = audit._verdict_constants(module)
    functions = {node.name: node for node in module.body if isinstance(node, ast.FunctionDef)}
    conditional = {hit["value"] for hit in audit._hits(functions["conditional"], constants)}
    from_constant = {hit["value"] for hit in audit._hits(functions["from_constant"], constants)}
    assert conditional == {"allow", "block"}
    assert from_constant == {"allow"}


def test_python_carried_as_a_script_template_is_scanned() -> None:
    """The generated hook clients run on the hook path; their verdicts count."""

    found = {str(site["func"]) for site in audit.discover()}
    assert "BOUNDED_HOOK_NATIVE_TEMPLATE:_to_native" in found
    assert "BOUNDED_HOOK_SCRIPT_TEMPLATE:_rewrite_grok_decision" in found


def test_an_unnamed_template_keeps_its_label_when_lines_move() -> None:
    """The label of a literal with no name of its own cannot be its line number.

    Line numbers move whenever anything above them is edited, and before
    Python 3.12 the constant parts of an f-string report the enclosing
    JoinedStr's position instead of their own. Either would make `--check`
    report the same unchanged template as newly unreadable.
    """

    template = '"def guard():\\n    return \\"allow\\"\\n"\n'
    first = ast.parse(f"TOP = 1\nf({template})")
    shifted = ast.parse(f"TOP = 1\n# a comment nobody reads\nSECOND = 2\nf({template})")

    assert [label for label, _line, _source in audit._embedded_sources(first)] == ["literal#0"]
    assert [label for label, _line, _source in audit._embedded_sources(shifted)] == ["literal#0"]
