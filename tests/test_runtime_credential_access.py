"""Credential capabilities remain visible independently of embedded secrets."""

import json
import shutil
from pathlib import Path

import pytest

from codex_plugin_scanner.checks import security
from codex_plugin_scanner.checks.security import check_credential_access, check_no_hardcoded_secrets
from codex_plugin_scanner.models import ScanOptions, Severity
from codex_plugin_scanner.policy import POLICY_PROFILES, build_rule_inventory, evaluate_policy
from codex_plugin_scanner.reporting import format_json, format_markdown, format_sarif, should_fail_for_severity
from codex_plugin_scanner.rules import get_rule_spec
from codex_plugin_scanner.scanner import scan_plugin
from codex_plugin_scanner.suppressions import apply_suppressions, compute_effective_score

RUNTIME_RULE = "RUNTIME_CREDENTIAL_ACCESS"
IMPERSONATION_RULE = "GCLOUD_SERVICE_ACCOUNT_IMPERSONATION"


def _check(tmp_path: Path, content: str, path: str = "scripts/read.sh"):
    target = tmp_path / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    return check_credential_access(tmp_path)


@pytest.mark.parametrize(
    "assignment",
    [
        'VALUE="$(printenv GRAFANA_TOKEN)"',
        'VALUE="$(printenv "API_KEY")"',
        'VALUE="$(printenv "$TOKEN_VAR")"',
        'VALUE="$(printenv "${PASSWORD_ENV}")"',
        'TOKEN="$(printenv "$LOOKUP_VAR")"',
        'api_key="$(printenv HOME)"',
        'VALUE="$(printenv SERVICE_ACCESS_KEY_ID)"',
        'VALUE="$(printenv PRIVATE_KEY)"',
        'VALUE="$(printenv CREDENTIALS)"',
        'VALUE="$(printenv SERVICE_PASSWD)"',
        'VALUE="$(printenv SERVICE_APIKEY)"',
        'VALUE="$(printenv service_secret)"',
        'VALUE="$(gcloud auth print-access-token)"',
        'VALUE="$(gcloud auth application-default print-access-token)"',
        'VALUE="$(gcloud --configuration="$CONFIG" auth print-access-token --project="$PROJECT")"',
        'TOKEN="$(printenv TOKEN 2>/dev/null || true)"',
        'TOKEN="$(gcloud auth print-access-token 2>/dev/null || true)"',
        'authToken="$(printenv CONFIG_PATH)"',
        'clientSecret="$(printenv "$LOOKUP_VAR")"',
        'dbPassword="$(printenv HOME)"',
    ],
)
def test_runtime_reads_pass_literal_check_but_require_review(tmp_path, assignment):
    literal, runtime = _check(tmp_path, f"# Read the configured value.\n{assignment}\n")

    assert literal.passed is True
    assert literal.points == literal.max_points == 7
    assert literal.findings == ()
    assert runtime.name == "Runtime credential access"
    assert runtime.passed is True
    assert runtime.points == runtime.max_points == 0
    assert "requires review" in runtime.message
    assert len(runtime.findings) == 1
    finding = runtime.findings[0]
    assert finding.rule_id == RUNTIME_RULE
    assert finding.severity is Severity.LOW
    assert finding.category == "security"
    assert finding.source == "native"
    assert (finding.file_path, finding.line_number) == ("scripts/read.sh", 2)
    assert "have not been verified" in finding.description
    assert "does not prove limited access" in finding.remediation


@pytest.mark.parametrize(
    "name",
    [
        "PATH",
        "HOME",
        "LANG",
        "CONFIG_PATH",
        "TOKENIZER",
        "SECRETARY",
        "PUBLIC_KEY",
        "API_KEYBOARD",
        "MYTOKEN",
        "TOKEN_NAME",
        "TOKEN_VAR",
        "TOKEN_ENV",
        "PASSWORD_FILE",
        "SECRET_PATH",
    ],
)
def test_noncredential_and_direct_metadata_names_do_not_signal_access(tmp_path, name):
    literal, runtime = _check(tmp_path, f'VALUE="$(printenv {name})"\n')

    assert literal.passed is True
    assert literal.points == 7
    assert runtime.findings == ()
    assert "requires review" not in literal.message
    assert "other access is not ruled out" in runtime.message


@pytest.mark.parametrize("destination", ["TOKEN_NAME", "TOKEN_VAR", "TOKEN_ENV", "PASSWORD_FILE", "SECRET_PATH"])
def test_metadata_destinations_do_not_imply_credential_access(tmp_path, destination):
    literal, runtime = _check(tmp_path, f'{destination}="$(printenv CONFIG_PATH)"\n')
    assert literal.passed is True
    assert runtime.findings == ()


@pytest.mark.parametrize("name", ["TOKEN_VAR", "TOKEN_NAME", "PASSWORD_ENV", "SECRET_PATH"])
def test_indirect_credential_metadata_names_still_signal_access(tmp_path, name):
    literal, runtime = _check(tmp_path, f'VALUE="$(printenv "${{{name}}}")"\n')
    assert literal.passed is True
    assert [finding.rule_id for finding in runtime.findings] == [RUNTIME_RULE]


@pytest.mark.parametrize(
    "command",
    [
        "gcloud auth print-access-token --impersonate-service-account=reader@example.invalid",
        "gcloud --impersonate-service-account reader@example.invalid auth print-access-token",
        'gcloud auth print-access-token --impersonate-service-account "$SERVICE_ACCOUNT"',
        'gcloud --impersonate-service-account="${SERVICE_ACCOUNT}" auth application-default print-access-token',
        'gcloud --project="$PROJECT" auth print-access-token --impersonate-service-account=$SA',
        "gcloud auth print-access-token --impersonate-service-account=${SA} 2>/dev/null || true",
    ],
)
def test_impersonation_has_one_specific_medium_finding(tmp_path, command):
    literal, runtime = _check(tmp_path, f'VALUE="$({command})"\n')

    assert literal.passed is True
    assert literal.points == 7
    assert len(runtime.findings) == 1
    finding = runtime.findings[0]
    assert finding.rule_id == IMPERSONATION_RULE
    assert finding.severity is Severity.MEDIUM
    assert "another service account" in finding.description
    assert "impersonation permissions" in finding.description
    assert "successful execution have not been verified" in finding.description
    assert command not in finding.description
    assert "reader@example.invalid" not in finding.description


@pytest.mark.parametrize(
    "assignment",
    [
        'VALUE="$(gcloud auth print-access-token --account=reader@example.invalid)"',
        'VALUE="$(gcloud auth print-access-token --project=impersonate-service-account)"',
        'VALUE="$(gcloud auth print-access-token)" # --impersonate-service-account=reader@example.invalid',
        'TOKEN="$(printenv IMPERSONATE_SERVICE_ACCOUNT)"',
    ],
)
def test_option_values_and_comments_do_not_forge_impersonation(tmp_path, assignment):
    literal, runtime = _check(tmp_path, assignment + "\n")
    assert literal.passed is True
    assert [finding.rule_id for finding in runtime.findings] == [RUNTIME_RULE]
    assert runtime.findings[0].severity is Severity.LOW


@pytest.mark.parametrize(
    ("path", "language"),
    [
        ("scripts/read.sh", None),
        ("scripts/read.bash", None),
        ("README.md", "bash"),
        ("README.mdx", "sh"),
        ("README.markdown", "shell"),
    ],
)
def test_supported_shell_contexts_preserve_finding_location(tmp_path, path, language):
    content = 'TOKEN="$(printenv TOKEN)"\n'
    if language:
        content = f"# Usage\n```{language}\n{content}```\n"
    literal, runtime = _check(tmp_path, content, path)
    assert literal.passed is True
    assert [(finding.rule_id, finding.file_path, finding.line_number) for finding in runtime.findings] == [
        (RUNTIME_RULE, path, 3 if language else 1)
    ]


@pytest.mark.parametrize(
    ("path", "content"),
    [
        ("README.rst", '```bash\nTOKEN="$(printenv TOKEN)"\n```\n'),
        ("README.adoc", '```bash\nTOKEN="$(printenv TOKEN)"\n```\n'),
        ("README.md", 'TOKEN="$(printenv TOKEN)"\n'),
        ("README.md", '```python\nTOKEN="$(printenv TOKEN)"\n```\n'),
        ("README.md", '```bash\nTOKEN="$(printenv TOKEN)"\n'),
        ("source.py", 'TOKEN="$(printenv TOKEN)"\n'),
        ("source.ts", 'TOKEN="$(printenv TOKEN)"\n'),
    ],
)
def test_nonshell_contexts_do_not_turn_literals_into_capabilities(tmp_path, path, content):
    literal, runtime = _check(tmp_path, content, path)
    assert literal.passed is False
    assert [finding.rule_id for finding in literal.findings] == ["HARDCODED_SECRET"]
    assert runtime.findings == ()


@pytest.mark.parametrize(
    "content",
    [
        'TOKEN="literal-937$(printenv TOKEN)"',
        'TOKEN="$(printenv TOKEN)literal-937"',
        'TOKEN="$(printenv TOKEN)"#literal-937',
        "TOKEN='$(printenv TOKEN)'",
        'TOKEN="\\$(printenv TOKEN)"',
        'TOKEN="$(printenv TOKEN; printf literal-937)"',
        'TOKEN="$(printenv TOKEN OTHER_TOKEN)"',
        'TOKEN="$(printenv TOKEN 2>/tmp/capture)"',
        'TOKEN="$(gcloud auth print-access-token --flags-file=/tmp/flags)"',
        'TOKEN="$(gcloud auth print-access-token --impersonate-service-account="$(printenv ACCOUNT)")"',
        'TOKEN="$(gcloud auth print-identity-token)"',
        'TOKEN="$(printf actual-pass-937)"',
        'true && TOKEN="$(printenv TOKEN)"',
        "cat <<'EOF'\nTOKEN=\"$(printenv TOKEN)\"\nEOF\n",
        "VALUE='prefix\nTOKEN=\"$(printenv TOKEN)\"\nsuffix'\n",
    ],
)
def test_unsupported_or_literal_payloads_keep_existing_secret_findings(tmp_path, content):
    literal, runtime = _check(tmp_path, content + "\n")
    assert literal.passed is False
    assert literal.points == 0
    assert [finding.rule_id for finding in literal.findings] == ["HARDCODED_SECRET"]
    assert runtime.findings == ()
    assert literal.findings[0].severity is Severity.HIGH


def test_identical_location_findings_are_deduplicated_but_later_impersonation_remains(tmp_path):
    content = (
        'TOKEN="$(printenv TOKEN)"; PASSWORD="$(printenv PASSWORD)"\n'
        "# Both ordinary reads precede a different identity request.\n"
        'VALUE="$(gcloud auth print-access-token --impersonate-service-account=$SA)"\n'
    )
    literal, runtime = _check(tmp_path, content)
    assert literal.passed is True
    assert [(finding.rule_id, finding.line_number) for finding in runtime.findings] == [
        (RUNTIME_RULE, 1),
        (IMPERSONATION_RULE, 3),
    ]


def test_different_capability_rules_on_one_line_are_both_retained(tmp_path):
    literal, runtime = _check(
        tmp_path,
        'TOKEN="$(printenv TOKEN)"; VALUE="$(gcloud auth print-access-token --impersonate-service-account=$SA)"\n',
    )
    assert literal.passed is True
    assert {(finding.rule_id, finding.severity, finding.line_number) for finding in runtime.findings} == {
        (RUNTIME_RULE, Severity.LOW, 1),
        (IMPERSONATION_RULE, Severity.MEDIUM, 1),
    }


def test_repeated_reads_on_different_lines_keep_both_locations(tmp_path):
    literal, runtime = _check(tmp_path, 'TOKEN="$(printenv TOKEN)"\nTOKEN="$(printenv TOKEN)"\n')
    assert literal.passed is True
    assert [(finding.rule_id, finding.line_number) for finding in runtime.findings] == [
        (RUNTIME_RULE, 1),
        (RUNTIME_RULE, 2),
    ]


@pytest.mark.parametrize("provider_literal", [False, True])
def test_real_literal_and_runtime_findings_coexist(tmp_path, provider_literal):
    # Synthetic regression material assembled here so it is never a repository credential.
    value = "".join(("sk-proj-", "A1b2C3d4", "E5f6G7h8", "I9j0K1l2")) if provider_literal else "actual-pass-937"
    literal, runtime = _check(tmp_path, f'TOKEN="$(printenv TOKEN)"\npassword="{value}"\n')
    assert literal.passed is False
    assert literal.points == 0
    assert {
        (finding.rule_id, finding.severity, finding.line_number) for finding in literal.findings + runtime.findings
    } == {
        ("HARDCODED_SECRET", Severity.HIGH, 2),
        (RUNTIME_RULE, Severity.LOW, 1),
    }
    assert [finding.rule_id for finding in literal.findings] == ["HARDCODED_SECRET"]
    assert [finding.rule_id for finding in runtime.findings] == [RUNTIME_RULE]
    assert all(value not in finding.description for finding in literal.findings + runtime.findings)


def test_credential_read_scope_does_not_hide_a_provider_secret_literal(tmp_path):
    token = "".join(("sk-proj-", "A1b2C3d4", "E5f6G7h8", "I9j0K1l2"))
    literal, runtime = _check(tmp_path, f'TOKEN="$(gcloud auth print-access-token --account={token})"\n')
    assert literal.passed is False
    assert {(finding.rule_id, finding.severity) for finding in literal.findings + runtime.findings} == {
        ("HARDCODED_SECRET", Severity.HIGH),
        (RUNTIME_RULE, Severity.LOW),
    }


def test_legacy_literal_check_keeps_its_original_contract(tmp_path):
    literal, runtime = _check(tmp_path, 'TOKEN="$(printenv TOKEN)"\n')
    assert runtime.findings
    assert literal.findings == ()
    assert check_no_hardcoded_secrets(tmp_path) == literal


def test_runtime_read_budget_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setattr(security, "MAX_SECRET_MATCHES_PER_FILE", 1)
    literal, runtime = _check(tmp_path, 'TOKEN="$(printenv TOKEN)"\nPASSWORD="$(printenv PASSWORD)"\n')
    assert literal.passed is False
    assert literal.points == 0
    assert literal.max_points == 7
    assert [finding.rule_id for finding in literal.findings] == ["SCAN_RESOURCE_BUDGET_EXCEEDED"]
    assert runtime.passed is False
    assert runtime.points == runtime.max_points == 0
    assert "incomplete" in literal.message.lower()
    assert "incomplete" in runtime.message.lower()


@pytest.fixture
def capability_scan(tmp_path):
    shutil.copytree(Path(__file__).parent / "fixtures" / "good-plugin", tmp_path, dirs_exist_ok=True)
    target = tmp_path / "scripts" / "read.sh"
    target.parent.mkdir()
    target.write_text(
        'TOKEN="$(printenv CUSTOMER_PRIVATE_TOKEN)"\n'
        'VALUE="$(gcloud auth print-access-token --impersonate-service-account=private-reader@example.invalid)"\n',
        encoding="utf-8",
    )
    return scan_plugin(tmp_path, options=ScanOptions(cisco_skill_scan="off", cisco_mcp_scan="off"))


def test_full_scan_retains_capabilities_without_deducting_literal_check_points(capability_scan):
    result = capability_scan
    checks = {check.name: check for category in result.categories for check in category.checks}
    literal, runtime = checks["No hardcoded secrets"], checks["Runtime credential access"]
    assert literal.passed is True
    assert literal.points == literal.max_points == 7
    assert literal.findings == ()
    assert runtime.points == runtime.max_points == 0
    assert {finding.rule_id for finding in runtime.findings} == {RUNTIME_RULE, IMPERSONATION_RULE}
    assert result.score == 100
    assert {finding.rule_id for finding in result.findings} == {RUNTIME_RULE, IMPERSONATION_RULE}
    assert result.severity_counts == {"critical": 0, "high": 0, "medium": 1, "low": 1, "info": 0}
    assert should_fail_for_severity(result, "high") is False
    assert should_fail_for_severity(result, "medium") is True
    assert should_fail_for_severity(result, "low") is True


def test_json_markdown_and_sarif_retain_runtime_review_evidence(capability_scan):
    result = capability_scan
    json_text = format_json(result)
    payload = json.loads(json_text)
    assert payload["summary"]["findings"] == result.severity_counts
    findings = {finding["ruleId"]: finding for finding in payload["findings"]}
    assert findings[RUNTIME_RULE]["severity"] == "low"
    assert findings[IMPERSONATION_RULE]["severity"] == "medium"
    assert findings[RUNTIME_RULE]["lineNumber"] == 1
    assert findings[IMPERSONATION_RULE]["lineNumber"] == 2
    assert all(finding["filePath"] == "scripts/read.sh" for finding in findings.values())
    checks = {check["name"]: check for category in payload["categories"] for check in category["checks"]}
    literal, runtime = checks["No hardcoded secrets"], checks["Runtime credential access"]
    assert literal["passed"] is True
    assert literal["findings"] == []
    assert runtime["points"] == runtime["maxPoints"] == 0
    assert "requires review" in runtime["message"]
    assert {finding["ruleId"] for finding in runtime["findings"]} == {RUNTIME_RULE, IMPERSONATION_RULE}

    markdown = format_markdown(result)
    assert "**LOW** Runtime credential access" in markdown
    assert "**MEDIUM** Service-account impersonation requested" in markdown
    assert "No findings detected" not in markdown

    sarif_text = format_sarif(result)
    run = json.loads(sarif_text)["runs"][0]
    sarif_findings = {finding["ruleId"]: finding for finding in run["results"]}
    assert sarif_findings[RUNTIME_RULE]["level"] == "note"
    assert sarif_findings[IMPERSONATION_RULE]["level"] == "warning"
    assert {rule["id"] for rule in run["tool"]["driver"]["rules"]} == {RUNTIME_RULE, IMPERSONATION_RULE}
    for rule_id, line in [(RUNTIME_RULE, 1), (IMPERSONATION_RULE, 2)]:
        location = sarif_findings[rule_id]["locations"][0]["physicalLocation"]
        assert location == {"artifactLocation": {"uri": "scripts/read.sh"}, "region": {"startLine": line}}
    for report in (json_text, markdown, sarif_text):
        assert "CUSTOMER_PRIVATE_TOKEN" not in report
        assert "private-reader@example.invalid" not in report
        assert "print-access-token" not in report


@pytest.mark.parametrize("with_impersonation", [False, True])
def test_strict_policy_uses_capability_severity_even_when_literal_check_passes(capability_scan, with_impersonation):
    findings = tuple(
        finding for finding in capability_scan.findings if with_impersonation or finding.rule_id == RUNTIME_RULE
    )
    profile = POLICY_PROFILES["strict-security"]
    inventory = build_rule_inventory(
        findings, set(profile.required_executed_rules) | {finding.rule_id for finding in findings}
    )
    evaluation = evaluate_policy(findings, profile.name, rule_inventory=inventory)
    assert inventory["HARDCODED_SECRET"].passed is True
    assert evaluation.missing_required_rules == ()
    assert evaluation.failed_required_pass_rules == ()
    assert evaluation.policy_pass is (not with_impersonation)
    assert evaluation.severity_failures == ((IMPERSONATION_RULE,) if with_impersonation else ())


@pytest.mark.parametrize("mode", ["disable", "baseline", "enabled-rules"])
def test_suppressing_literal_restores_points_while_capabilities_remain(tmp_path, capability_scan, mode):
    target = tmp_path / "scripts" / "read.sh"
    target.write_text(target.read_text() + 'password="actual-pass-937"\n', encoding="utf-8")
    result = scan_plugin(tmp_path, options=ScanOptions(cisco_skill_scan="off", cisco_mcp_scan="off"))
    checks = {check.name: check for category in result.categories for check in category.checks}
    assert checks["No hardcoded secrets"].points == 0
    assert checks["No hardcoded secrets"].passed is False
    runtime = checks["Runtime credential access"]
    assert {finding.rule_id for finding in runtime.findings} == {RUNTIME_RULE, IMPERSONATION_RULE}

    restored = apply_suppressions(
        result,
        enabled_rules=frozenset({RUNTIME_RULE, IMPERSONATION_RULE}) if mode == "enabled-rules" else frozenset(),
        disabled_rules=frozenset({"HARDCODED_SECRET"}) if mode == "disable" else frozenset(),
        baseline_ids=frozenset({"HARDCODED_SECRET"}) if mode == "baseline" else frozenset(),
        ignore_paths=(),
    )
    checks = {check.name: check for category in restored.categories for check in category.checks}
    literal = checks["No hardcoded secrets"]
    assert literal.passed is True
    assert literal.points == literal.max_points == 7
    assert literal.findings == ()
    assert checks["Runtime credential access"] == runtime
    assert {finding.rule_id for finding in restored.findings} == {RUNTIME_RULE, IMPERSONATION_RULE}
    assert compute_effective_score(restored) == capability_scan.score == 100
    assert compute_effective_score(result) < compute_effective_score(restored)
    assert should_fail_for_severity(restored, "medium") is True


@pytest.mark.parametrize(("rule_id", "severity"), [(RUNTIME_RULE, Severity.LOW), (IMPERSONATION_RULE, Severity.MEDIUM)])
def test_capability_rule_metadata_matches_emitted_severity(rule_id, severity):
    spec = get_rule_spec(rule_id)
    assert spec is not None
    assert spec.category == "security"
    assert spec.default_severity is severity
    assert spec.weight == 0


def test_kimi_scan_reports_declared_skill_capability_and_excludes_unlisted_file(tmp_path):
    shutil.copytree(Path(__file__).parent / "fixtures" / "kimi-plugin-good", tmp_path, dirs_exist_ok=True)
    skill = tmp_path / "skills" / "using-demo" / "SKILL.md"
    skill.write_text(skill.read_text() + '\n```bash\nTOKEN="$(printenv DEMO_TOKEN)"\n```\n', encoding="utf-8")
    (tmp_path / "unlisted.sh").write_text(
        'TOKEN="$(gcloud auth print-access-token --impersonate-service-account=$SA)"\n', encoding="utf-8"
    )
    result = scan_plugin(tmp_path, ScanOptions(ecosystem="kimi", cisco_skill_scan="off", cisco_mcp_scan="off"))
    assert result.ecosystems == ("kimi",)
    capabilities = [finding for finding in result.findings if finding.rule_id in {RUNTIME_RULE, IMPERSONATION_RULE}]
    assert [(finding.rule_id, finding.severity, finding.file_path) for finding in capabilities] == [
        (RUNTIME_RULE, Severity.LOW, "skills/using-demo/SKILL.md")
    ]
    assert all(finding.file_path != "unlisted.sh" for finding in result.findings)
    checks = {check.name: check for category in result.categories for check in category.checks}
    assert checks["No hardcoded secrets"].passed is True
    assert checks["No hardcoded secrets"].findings == ()
    assert checks["Runtime credential access"].findings == tuple(capabilities)
