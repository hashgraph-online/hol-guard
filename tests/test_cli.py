"""Tests for CLI output formatting and argument parsing."""

import json
import shutil
import sys
import tempfile
import zipfile
from pathlib import Path

from codex_plugin_scanner import cli as cli_module
from codex_plugin_scanner.cli import format_json, format_text, main
from codex_plugin_scanner.rules import get_rule_spec as original_get_rule_spec
from codex_plugin_scanner.scanner import scan_plugin

FIXTURES = Path(__file__).parent / "fixtures"
NONEXISTENT_PLUGIN_DIR = Path("/nonexistent/plugin-dir").resolve()


class TestFormatJson:
    def test_valid_json_output(self):
        result = scan_plugin(FIXTURES / "good-plugin")
        output = format_json(result)
        parsed = json.loads(output)
        assert parsed["schema_version"] == "scan-result.v1"
        assert parsed["tool_version"]
        assert parsed["profile"] == "default"
        assert parsed["score"] == 100
        assert parsed["grade"] == "A"
        assert len(parsed["categories"]) == 7
        assert "timestamp" in parsed
        assert "pluginDir" in parsed
        assert "summary" in parsed
        assert "findings" in parsed

    def test_categories_have_correct_structure(self):
        result = scan_plugin(FIXTURES / "good-plugin")
        output = format_json(result)
        parsed = json.loads(output)
        cat = parsed["categories"][0]
        assert "name" in cat
        assert "score" in cat
        assert "max" in cat
        assert "checks" in cat
        check = cat["checks"][0]
        assert "name" in check
        assert "passed" in check
        assert "points" in check
        assert "maxPoints" in check
        assert "message" in check
        assert "findings" in check

    def test_bad_plugin_json(self):
        result = scan_plugin(FIXTURES / "bad-plugin")
        output = format_json(result)
        parsed = json.loads(output)
        assert parsed["score"] < 60
        assert parsed["summary"]["findings"]["high"] >= 1


class TestFormatText:
    def test_contains_header(self):
        result = scan_plugin(FIXTURES / "good-plugin")
        output = format_text(result)
        assert "Codex Plugin Scanner" in output
        assert "100/100" in output
        assert "Excellent" in output

    def test_contains_category_names(self):
        result = scan_plugin(FIXTURES / "good-plugin")
        output = format_text(result)
        assert "Manifest Validation" in output
        assert "Security" in output

    def test_contains_final_score_line(self):
        result = scan_plugin(FIXTURES / "good-plugin")
        output = format_text(result)
        assert "Final Score" in output

    def test_bad_plugin_output(self):
        result = scan_plugin(FIXTURES / "bad-plugin")
        output = format_text(result)
        assert "38/100" in output
        assert "Failing" in output


class TestMain:
    def test_returns_0_for_good_plugin(self):
        rc = main([str(FIXTURES / "good-plugin")])
        assert rc == 0

    def test_returns_0_by_default(self):
        rc = main([str(FIXTURES / "bad-plugin")])
        assert rc == 0

    def test_returns_1_for_score_below_min(self):
        rc = main([str(FIXTURES / "bad-plugin"), "--min-score", "50"])
        assert rc == 1

    def test_returns_0_when_score_meets_min(self):
        rc = main([str(FIXTURES / "good-plugin"), "--min-score", "50"])
        assert rc == 0

    def test_returns_1_for_nonexistent_dir(self):
        rc = main(["/nonexistent/path/that/does/not/exist"])
        assert rc == 1

    def test_returns_0_for_file_not_dir(self):
        rc = main([str(FIXTURES / "good-plugin" / "README.md")])
        assert rc == 1

    def test_json_flag(self, capsys):
        main([str(FIXTURES / "good-plugin"), "--json"])
        output = capsys.readouterr().out
        parsed = json.loads(output)
        assert parsed["score"] == 100

    def test_output_flag(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = Path(tmpdir) / "report.json"
            main([str(FIXTURES / "good-plugin"), "--output", str(out_file)])
            content = out_file.read_text(encoding="utf-8")
            parsed = json.loads(content)
            assert parsed["score"] == 100

    def test_min_score_boundary(self):
        rc = main([str(FIXTURES / "bad-plugin"), "--min-score", "38"])
        assert rc == 0

    def test_min_score_just_above(self):
        rc = main([str(FIXTURES / "bad-plugin"), "--min-score", "39"])
        assert rc == 1

    def test_version_flag(self, capsys):
        import contextlib

        with contextlib.suppress(SystemExit):
            main(["--version"])

    def test_text_mode_with_min_score_failure(self, capsys):
        main([str(FIXTURES / "bad-plugin"), "--min-score", "50"])
        captured = capsys.readouterr()
        # Should still produce text output
        assert "38/100" in captured.out

    def test_min_score_exact_boundary(self):
        # At exact boundary should pass (>=)
        rc = main([str(FIXTURES / "good-plugin"), "--min-score", "100"])
        assert rc == 0

    def test_lint_list_rules(self, capsys):
        rc = main(["lint", "--list-rules"])
        output = capsys.readouterr().out
        assert rc == 0
        assert "HARDCODED_SECRET" in output

    def test_lint_explain(self, capsys):
        rc = main(["lint", "--explain", "CODEXIGNORE_MISSING"])
        output = capsys.readouterr().out
        assert rc == 0
        assert '"rule_id": "CODEXIGNORE_MISSING"' in output

    def test_lint_fails_for_strict_profile(self):
        rc = main(["lint", str(FIXTURES / "bad-plugin"), "--profile", "strict-security"])
        assert rc == 1

    def test_lint_fix_generates_templates(self, tmp_path):
        (tmp_path / "plugin.json").write_text('{"name":"demo","path":"./skills"}', encoding="utf-8")
        rc = main(["lint", str(tmp_path), "--fix"])
        assert rc == 0
        assert (tmp_path / ".codexignore").exists()
        assert (tmp_path / "README.md").exists()

    def test_scan_with_strict_fails_when_findings_present(self):
        rc = main(["scan", str(FIXTURES / "bad-plugin"), "--strict"])
        assert rc == 1

    def test_lint_with_baseline_suppresses_rule(self, tmp_path, capsys):
        baseline = tmp_path / "baseline.txt"
        baseline.write_text("README_MISSING\n", encoding="utf-8")
        rc = main(["lint", str(FIXTURES / "minimal-plugin"), "--baseline", str(baseline), "--format", "json"])
        output = capsys.readouterr().out
        assert rc in (0, 1)
        assert "README_MISSING" not in output

    def test_lint_json_only_looks_up_rule_spec_once_per_finding(self, monkeypatch, capsys):
        lookup_count = 0

        def counting_get_rule_spec(rule_id: str):
            nonlocal lookup_count
            lookup_count += 1
            return original_get_rule_spec(rule_id)

        monkeypatch.setattr(cli_module, "get_rule_spec", counting_get_rule_spec)

        rc = main(["lint", str(FIXTURES / "bad-plugin"), "--format", "json"])
        output = json.loads(capsys.readouterr().out)

        assert rc in (0, 1)
        assert lookup_count == len(output["findings"])

    def test_verify_json(self, capsys):
        rc = main(["verify", str(FIXTURES / "good-plugin"), "--format", "json"])
        output = capsys.readouterr().out
        assert rc == 0
        parsed = json.loads(output)
        assert parsed["verify_pass"] is True

    def test_verify_rejects_nonexistent_directory(self, capsys):
        rc = main(["verify", str(NONEXISTENT_PLUGIN_DIR), "--format", "json"])
        captured = capsys.readouterr()
        assert rc == 1
        assert f'Error: "{NONEXISTENT_PLUGIN_DIR}" is not a directory.' in captured.err

    def test_verify_text_outputs_human_readable_summary(self, capsys):
        rc = main(["verify", str(FIXTURES / "good-plugin"), "--format", "text"])
        output = capsys.readouterr().out
        assert rc == 0
        assert "Verification: PASS" in output
        assert "manifest:" in output
        assert '"verify_pass"' not in output

    def test_scan_reports_severity_gate_failures(self, capsys):
        rc = main(["scan", str(FIXTURES / "bad-plugin"), "--fail-on-severity", "high"])
        captured = capsys.readouterr()
        assert rc == 1
        assert 'Findings met or exceeded the "high" severity threshold.' in captured.err

    def test_scan_reports_strict_failures(self, capsys):
        rc = main(["scan", str(FIXTURES / "bad-plugin"), "--strict"])
        captured = capsys.readouterr()
        assert rc == 1
        assert "Strict mode failed because findings were present." in captured.err

    def test_scan_reports_policy_failures(self, capsys):
        rc = main(["scan", str(FIXTURES / "bad-plugin"), "--profile", "strict-security"])
        captured = capsys.readouterr()
        assert rc == 1
        assert 'Policy profile "strict-security" failed.' in captured.err

    def test_doctor_bundle(self, tmp_path):
        bundle = tmp_path / "doctor.json"
        rc = main(["doctor", str(FIXTURES / "good-plugin"), "--bundle", str(bundle)])
        assert rc == 0
        assert bundle.exists()

    def test_doctor_rejects_nonexistent_directory(self, capsys):
        rc = main(["doctor", str(NONEXISTENT_PLUGIN_DIR)])
        captured = capsys.readouterr()
        assert rc == 1
        assert f'Error: "{NONEXISTENT_PLUGIN_DIR}" is not a directory.' in captured.err

    def test_doctor_bundle_captures_stdio_artifacts(self, tmp_path):
        plugin_dir = tmp_path / "plugin"
        shutil.copytree(FIXTURES / "good-plugin", plugin_dir)
        (plugin_dir / ".mcp.json").write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "echo": {
                            "command": sys.executable,
                            "args": [
                                "-u",
                                "-c",
                                "import sys; print('doctor-out'); print('doctor-err', file=sys.stderr)",
                            ],
                        }
                    }
                }
            ),
            encoding="utf-8",
        )
        bundle = tmp_path / "doctor-bundle.zip"

        rc = main(["doctor", str(plugin_dir), "--bundle", str(bundle)])

        assert rc == 0
        with zipfile.ZipFile(bundle) as archive:
            stderr_log = archive.read("stderr.log").decode("utf-8")
            stdout_log = archive.read("stdout.log").decode("utf-8")
            timeout_markers = archive.read("timeout-markers.txt").decode("utf-8")
        assert "doctor-err" in stderr_log
        assert "doctor-out" in stdout_log
        assert "none" in timeout_markers

    def test_submit_writes_artifact(self, tmp_path):
        artifact = tmp_path / "plugin-quality.json"
        rc = main(["submit", str(FIXTURES / "good-plugin"), "--attest", str(artifact)])
        assert rc == 0
        parsed = json.loads(artifact.read_text(encoding="utf-8"))
        assert parsed["schema_version"] == "plugin-quality.v1"

    def test_scan_json_reports_repository_scope_for_marketplace_repo(self, capsys):
        rc = main(["scan", str(FIXTURES / "multi-plugin-repo"), "--format", "json"])
        assert rc == 0
        parsed = json.loads(capsys.readouterr().out)
        assert parsed["scope"] == "repository"
        assert parsed["repository"]["localPluginCount"] == 2
        assert len(parsed["plugins"]) == 2
        assert parsed["skippedTargets"][0]["name"] == "remote-plugin"

    def test_submit_blocks_on_verify_fail(self, tmp_path):
        artifact = tmp_path / "plugin-quality.json"
        rc = main(["submit", str(FIXTURES / "bad-plugin"), "--attest", str(artifact)])
        assert rc == 1

    def test_submit_rejects_nonexistent_directory(self, tmp_path, capsys):
        artifact = tmp_path / "plugin-quality.json"
        rc = main(["submit", str(NONEXISTENT_PLUGIN_DIR), "--attest", str(artifact)])
        captured = capsys.readouterr()
        assert rc == 1
        assert f'Error: "{NONEXISTENT_PLUGIN_DIR}" is not a directory.' in captured.err

    def test_scan_json_uses_effective_score_as_primary_score(self, tmp_path, capsys):
        plugin_dir = tmp_path / "plugin"
        shutil.copytree(FIXTURES / "good-plugin", plugin_dir)
        (plugin_dir / "README.md").unlink()
        baseline = tmp_path / "baseline.txt"
        baseline.write_text("README_MISSING\n", encoding="utf-8")

        rc = main(
            [
                "scan",
                str(plugin_dir),
                "--format",
                "json",
                "--baseline",
                str(baseline),
            ]
        )
        payload = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert payload["score"] == payload["effective_score"]
        assert payload["raw_score"] < payload["effective_score"]

    def test_submit_artifact_uses_effective_score_as_primary_score(self, tmp_path):
        plugin_dir = tmp_path / "plugin"
        shutil.copytree(FIXTURES / "good-plugin", plugin_dir)
        (plugin_dir / "README.md").unlink()
        baseline = tmp_path / "baseline.txt"
        baseline.write_text("README_MISSING\n", encoding="utf-8")
        artifact = tmp_path / "plugin-quality.json"

        rc = main(
            [
                "submit",
                str(plugin_dir),
                "--baseline",
                str(baseline),
                "--min-score",
                "0",
                "--attest",
                str(artifact),
            ]
        )
        payload = json.loads(artifact.read_text(encoding="utf-8"))

        assert rc == 0
        assert payload["scan"]["score"] == payload["scan"]["effective_score"]
        assert payload["scan"]["raw_score"] < payload["scan"]["effective_score"]
