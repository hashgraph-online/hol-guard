"""``policy init``, ``validate``, ``test`` and ``check`` run from one file, with no Guard home."""

from __future__ import annotations

import io
import json
import os
import shutil
import stat
from pathlib import Path

import pytest

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.cli.commands_dispatch_policy_dx import run_policy_file_command
from codex_plugin_scanner.guard.policy_starters import POLICY_MODELINE, POLICY_STARTERS

SPEC = Path(__file__).resolve().parents[1] / "spec" / "guard-policy" / "v1alpha1"
FIXTURES = SPEC / "fixtures"
MANIFEST = json.loads((FIXTURES / "manifest.json").read_text(encoding="utf-8"))
STARTER_IDS = [starter.id for starter in POLICY_STARTERS]


def _run(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, str]:
    code = main(["guard", "policy", *argv])
    return code, capsys.readouterr().out


def _json(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, dict[str, object]]:
    code, output = _run(capsys, *argv, "--format", "json")
    return code, json.loads(output)


def _private_copy(source: Path, tmp_path: Path) -> Path:
    target = tmp_path / source.name
    shutil.copyfile(source, target)
    target.chmod(0o600)
    return target


def test_init_writes_the_default_starter_with_the_modeline_and_two_tests(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    target = tmp_path / "guard-policy.yaml"

    code, payload = _json(capsys, "init", "--output", str(target))

    assert code == 0
    assert payload["starter"] == "safe-defaults"
    assert payload["tests"] == 2
    text = target.read_text(encoding="utf-8")
    assert text.startswith(POLICY_MODELINE + "\n")
    assert text.count("expect:") == 2
    assert stat.S_IMODE(target.stat().st_mode) == 0o600


@pytest.mark.parametrize("starter", STARTER_IDS)
def test_every_starter_validates_and_passes_its_own_tests(
    starter: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    target = tmp_path / f"{starter}.yaml"
    assert _run(capsys, "init", "--starter", starter, "--output", str(target))[0] == 0

    validate_code, validated = _json(capsys, "validate", str(target))
    test_code, tested = _json(capsys, "test", str(target))

    assert validate_code == 0
    assert validated["status"] == "valid"
    assert test_code == 0
    assert tested["total"] == 2
    assert tested["failed"] == 0


def test_init_lists_starters_and_refuses_unknown_ones(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code, listing = _json(capsys, "init", "--list")
    unknown_code, unknown = _json(capsys, "init", "--starter", "nonsense", "--output", str(tmp_path / "x.yaml"))

    assert code == 0
    assert [item["id"] for item in listing["starters"]] == STARTER_IDS
    assert unknown_code == 4
    assert unknown["error"] == "unknown_starter"
    assert not (tmp_path / "x.yaml").exists()


def test_init_does_not_overwrite_without_force(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    target = tmp_path / "guard-policy.yaml"
    target.write_text("keep me\n", encoding="utf-8")

    code, payload = _json(capsys, "init", "--output", str(target))
    forced_code, _ = _json(capsys, "init", "--output", str(target), "--force")

    assert code == 4
    assert payload["error"] == "policy_file_exists"
    assert forced_code == 0
    assert target.read_text(encoding="utf-8").startswith(POLICY_MODELINE)


@pytest.mark.parametrize(("relative", "expected_code"), sorted(MANIFEST["invalid"].items()))
def test_validate_reports_the_manifest_code_for_every_invalid_fixture(
    relative: str, expected_code: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    target = _private_copy(FIXTURES / relative, tmp_path)

    code, payload = _json(capsys, "validate", str(target))

    assert code == 4
    assert payload["status"] == "schema_invalid"
    codes = [item["code"] for item in payload["diagnostics"]]
    assert expected_code in codes
    for item in payload["diagnostics"]:
        assert {"code", "path", "line", "col", "message"} <= set(item)
        assert item["category"] == "schema_invalid"


def test_validate_points_at_the_line_and_column_of_the_problem(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    target = _private_copy(FIXTURES / "invalid" / "invalid-timestamp.yaml", tmp_path)

    _, payload = _json(capsys, "validate", str(target))

    (item,) = payload["diagnostics"]
    assert item["path"] == "spec.rules[0].lifetime.expiresAt"
    assert (item["line"], item["col"]) == (17, 20)


def test_validate_suggests_the_correct_field_name_and_expected_values(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    source = (FIXTURES / "valid" / "basic.yaml").read_text(encoding="utf-8")
    target = tmp_path / "typo.yaml"
    target.write_text(source.replace("defaultAction:", "defaultActon:", 1), encoding="utf-8")
    target.chmod(0o600)

    code, payload = _json(capsys, "validate", str(target))

    assert code == 4
    extra = next(item for item in payload["diagnostics"] if item["code"] == "schema_additionalProperties")
    assert "defaultAction" in extra["suggestion"]


def test_json_validation_is_not_capped_but_text_is(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    rules = "".join(
        f"""    - id: rule-{index}
      enabled: true
      effect: block
      surprise: true
      match:
        tools:
          - shell
      lifetime:
        mode: permanent
      provenance:
        source: builder
        createdAt: 2026-10-14T00:00:00Z
"""
        for index in range(30)
    )
    target = tmp_path / "many.yaml"
    target.write_text(
        "apiVersion: guard.hashgraphonline.com/v1alpha1\nkind: GuardPolicy\n"
        "metadata:\n  id: policy.many\n  name: Many\n  revision: 1\n"
        f"spec:\n  rules:\n{rules}",
        encoding="utf-8",
    )
    target.chmod(0o600)

    code, payload = _json(capsys, "validate", str(target))
    text_code, text = _run(capsys, "validate", str(target))

    assert code == 4
    assert len(payload["diagnostics"]) >= 30
    assert text_code == 4
    assert "more; run with --format json" in text


@pytest.mark.parametrize(
    ("fixture", "code"),
    [("basic.yaml", "unsupported_policy_match"), ("extensions-and-scalars.yaml", "unsupported_policy_lifetime")],
)
def test_validate_separates_not_enforceable_from_schema_invalid(
    fixture: str, code: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # These documents satisfy the schema, so only the compiler can say Guard would not enforce them.
    target = _private_copy(FIXTURES / "valid" / fixture, tmp_path)

    result, payload = _json(capsys, "validate", str(target))

    assert result == 4
    assert payload["status"] == "not_enforceable"
    assert [item["code"] for item in payload["diagnostics"]] == [code]
    assert payload["diagnostics"][0]["category"] == "not_enforceable"
    assert payload["diagnostics"][0]["suggestion"]
    assert payload["diagnostics"][0]["line"] is not None


def test_validate_file_mode_error_suggests_chmod(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    target = tmp_path / "open.yaml"
    shutil.copyfile(FIXTURES / "valid" / "basic.yaml", target)
    target.chmod(0o666)

    code, payload = _json(capsys, "validate", str(target))

    assert code == 4
    assert payload["status"] == "file_untrusted"
    (item,) = payload["diagnostics"]
    assert item["code"] == "policy_file_insecure_mode"
    assert item["suggestion"] == f"chmod 600 {target}"


def test_validate_accepts_every_enforceable_fixture(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    for relative in ("valid/business-selector.yaml", "valid/with-tests.yaml", "valid/enforceable-scopes.yaml"):
        code, payload = _json(capsys, "validate", str(_private_copy(FIXTURES / relative, tmp_path)))
        assert code == 0, relative
        assert payload["valid"] is True


def test_policy_test_passes_the_fixture_suite_and_prints_a_summary(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    target = _private_copy(FIXTURES / "valid" / "enforceable-scopes.yaml", tmp_path)

    code, payload = _json(capsys, "test", str(target))
    text_code, text = _run(capsys, "test", str(target))

    assert code == 0
    assert payload["ok"] is True
    assert payload["total"] == payload["passed"] == 12
    assert text_code == 0
    assert "12 passed, 0 failed, 12 total" in text


def test_policy_test_exits_one_when_a_case_fails(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    source = (FIXTURES / "valid" / "enforceable-scopes.yaml").read_text(encoding="utf-8")
    target = tmp_path / "failing.yaml"
    target.write_text(
        source.replace(
            "effect: block\n        ruleId: block-shell-in-ci", "effect: allow\n        ruleId: allow-mcp", 1
        ),
        encoding="utf-8",
    )
    target.chmod(0o600)

    code, payload = _json(capsys, "test", str(target))
    text_code, text = _run(capsys, "test", str(target))

    assert code == 1
    assert text_code == 1
    assert payload["ok"] is False
    failed = [item for item in payload["results"] if item["status"] == "fail"]
    assert [item["id"] for item in failed] == ["shell-blocked-in-ci"]
    assert failed[0]["actual"] == {"effect": "block", "ruleId": "block-shell-in-ci"}
    assert "FAIL" in text


def test_policy_test_rejects_an_unknown_rule_reference_with_exit_four(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    source = (FIXTURES / "valid" / "enforceable-scopes.yaml").read_text(encoding="utf-8")
    target = tmp_path / "unknown-rule.yaml"
    target.write_text(source.replace("ruleId: block-shell-in-ci", "ruleId: no-such-rule", 1), encoding="utf-8")
    target.chmod(0o600)

    code, payload = _json(capsys, "test", str(target))

    assert code == 4
    assert payload["error"] == "x_hol_tests_invalid"


def test_policy_test_on_an_invalid_file_exits_four(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code, payload = _json(capsys, "test", str(_private_copy(FIXTURES / "invalid" / "duplicate-key.yaml", tmp_path)))

    assert code == 4
    assert payload["status"] == "schema_invalid"


def test_policy_test_watch_reruns_when_the_file_changes(tmp_path: Path) -> None:
    source = (FIXTURES / "valid" / "enforceable-scopes.yaml").read_text(encoding="utf-8")
    target = tmp_path / "watched.yaml"
    target.write_text(source, encoding="utf-8")
    target.chmod(0o600)
    stream = io.StringIO()
    args = type("Args", (), {"policy_command": "test", "file": str(target), "watch": True, "watch_max_runs": 2})()
    ticks = iter(range(10))

    def sleep(_seconds: float) -> None:
        if next(ticks) == 0:
            target.write_text(
                source.replace(
                    "effect: block\n        ruleId: block-shell-in-ci", "effect: allow\n        ruleId: allow-mcp", 1
                )
            )
            os.utime(target, ns=(1, 2_000_000_000))

    from codex_plugin_scanner.guard.cli import commands_dispatch_policy_dx as dx

    code = dx._run_test(args, stream, sleep=sleep)

    output = stream.getvalue()
    assert output.count("12 passed, 0 failed, 12 total") == 1
    assert output.count("11 passed, 1 failed, 12 total") == 1
    assert code == 1


def test_policy_check_decides_an_event_and_names_the_rule(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    target = _private_copy(FIXTURES / "valid" / "enforceable-scopes.yaml", tmp_path)
    event = json.dumps({"harness": "codex", "tool": "shell", "workspace": "ci-workspace"})

    code, payload = _json(capsys, "check", str(target), "--event", event)
    text_code, text = _run(capsys, "check", str(target), "--event", event)

    assert code == 0
    assert payload["effect"] == "block"
    assert payload["ruleId"] == "block-shell-in-ci"
    selected = [item for item in payload["candidates"] if item["state"] == "selected"]
    assert [item["ruleId"] for item in selected] == ["block-shell-in-ci"]
    assert text_code == 0
    assert "Decision: block by rule block-shell-in-ci" in text


def test_policy_check_reads_the_event_from_stdin(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    target = _private_copy(FIXTURES / "valid" / "enforceable-scopes.yaml", tmp_path)
    monkeypatch.setattr("sys.stdin", io.StringIO('{"harness":"codex","tool":"mcp"}'))

    code, payload = _json(capsys, "check", str(target), "--event", "-")

    assert code == 0
    assert payload["ruleId"] == "allow-mcp-in-codex"


def test_policy_check_decides_a_command(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    target = _private_copy(FIXTURES / "parity" / "command-rules.yaml", tmp_path)

    code, blocked = _json(capsys, "check", str(target), "--command", "docker compose up")
    _, other = _json(capsys, "check", str(target), "--command", "git status")

    assert code == 0
    assert (blocked["effect"], blocked["ruleId"], blocked["action"]) == ("block", "block-docker", "block")
    assert (other["effect"], other["ruleId"]) == ("default", None)


@pytest.mark.parametrize(
    ("event", "code"),
    [
        ("not json", "event_invalid_json"),
        ('{"tool":"shell"}', "event_invalid"),
        ('{"harness":"codex","tool":"browser"}', "event_invalid"),
    ],
)
def test_policy_check_rejects_a_bad_event_with_exit_four(
    event: str, code: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    target = _private_copy(FIXTURES / "valid" / "enforceable-scopes.yaml", tmp_path)

    result, payload = _json(capsys, "check", str(target), "--event", event)

    assert result == 4
    assert payload["error"].startswith("event_")
    assert payload["error"] == code or code == "event_invalid"


def test_policy_check_requires_an_event_or_a_command(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    target = _private_copy(FIXTURES / "valid" / "enforceable-scopes.yaml", tmp_path)

    with pytest.raises(SystemExit):
        main(["guard", "policy", "check", str(target)])
    capsys.readouterr()


def test_file_commands_need_no_guard_home(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "never-created"
    monkeypatch.setenv("HOME", str(home))
    target = _private_copy(FIXTURES / "valid" / "with-tests.yaml", tmp_path)

    code, _ = _json(capsys, "test", str(target))

    assert code == 0
    assert not home.exists()


def test_unknown_file_command_is_refused() -> None:
    with pytest.raises(ValueError, match="unknown_policy_file_command"):
        run_policy_file_command(type("Args", (), {"policy_command": "nope"})())


_TOOL_RULE_AND_TESTS = """\
    - id: block-env
      enabled: true
      effect: block
      description: No environment reads.
      match:
        tools:
          - prompt-env-read
      lifetime:
        mode: permanent
      provenance:
        source: builder
        createdAt: 2026-10-14T00:00:00Z
  x-hol.tests:
    - id: env-blocked
      event:
        harness: codex
        tool: prompt-env-read
      expect:
        effect: block
        ruleId: block-env
    - id: package-falls-through
      event:
        harness: codex
        artifact: pkg:npm/left-pad
      expect:
        effect: default
"""


def _command_and_tool_policy(tmp_path: Path) -> Path:
    source = (FIXTURES / "parity" / "command-rules.yaml").read_text(encoding="utf-8")
    target = tmp_path / "mixed.yaml"
    target.write_text(source + _TOOL_RULE_AND_TESTS, encoding="utf-8")
    target.chmod(0o600)
    return target


def test_policy_test_and_check_event_decide_with_the_other_rules_when_a_command_rule_exists(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    target = _command_and_tool_policy(tmp_path)

    test_code, tested = _json(capsys, "test", str(target))
    check_code, checked = _json(capsys, "check", str(target), "--event", '{"harness":"codex","tool":"prompt-env-read"}')

    assert (test_code, tested["passed"], tested["total"]) == (0, 2, 2)
    assert (check_code, checked["ruleId"]) == (0, "block-env")


def test_policy_check_rejects_a_blank_command_with_exit_four(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    target = _private_copy(FIXTURES / "parity" / "command-rules.yaml", tmp_path)

    code, payload = _json(capsys, "check", str(target), "--command", "   ")

    assert code == 4
    assert payload["error"] == "command_value_required"


def test_policy_tests_do_not_pass_examples_for_a_business_policy_that_has_no_local_rows() -> None:
    from codex_plugin_scanner.guard.policy_document_yaml import parse_policy_document_yaml
    from codex_plugin_scanner.guard.policy_tests_runner import run_policy_tests

    source = (FIXTURES / "valid" / "business-selector.yaml").read_text(encoding="utf-8")
    tests = "  x-hol.tests:\n    - id: anything\n      event:\n        harness: codex\n        tool: shell\n"
    document = parse_policy_document_yaml(
        source.rstrip("\n") + "\n" + tests + "      expect:\n        effect: default\n"
    )

    run = run_policy_tests(document, now="2026-10-14T12:00:00Z")

    assert (run.passed, run.failed) == (0, 1)
    assert run.results[0].message.startswith("business_rules_not_evaluated_locally")


def test_policy_check_refuses_a_business_policy_it_cannot_evaluate(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    target = _private_copy(FIXTURES / "valid" / "business-selector.yaml", tmp_path)

    code, payload = _json(capsys, "check", str(target), "--event", '{"harness":"codex","tool":"shell"}')

    assert code == 4
    assert payload["error"] == "business_rules_not_evaluated_locally"


def test_validate_does_not_tell_users_to_rename_valid_extension_keys(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    source = (FIXTURES / "valid" / "basic.yaml").read_text(encoding="utf-8")
    target = tmp_path / "extension.yaml"
    target.write_text(source.replace("defaultAction:", "x-note: kept\n    defaultActon:", 1), encoding="utf-8")
    target.chmod(0o600)

    code, payload = _json(capsys, "validate", str(target))

    assert code == 4
    extra = next(item for item in payload["diagnostics"] if item["code"] == "schema_additionalProperties")
    assert "x-note" not in extra["suggestion"]
    assert "defaultAction" in extra["suggestion"]


@pytest.mark.parametrize("starter", [item for item in POLICY_STARTERS if item.rules])
def test_starter_summaries_do_not_promise_approval_prompts_their_block_rules_do_not_give(starter) -> None:
    assert all(rule.effect == "block" for rule in starter.rules)
    assert "ask" not in starter.summary.lower()
    assert not any("approving" in rule.description for rule in starter.rules)
