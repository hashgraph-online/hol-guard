"""Tests for code quality checks."""

import ast
import tempfile
from pathlib import Path

import pytest

from codex_plugin_scanner.checks.code_quality import (
    _find_code_files,
    check_no_eval,
    check_no_shell_injection,
    run_code_quality_checks,
)
from codex_plugin_scanner.models import Severity

FIXTURES = Path(__file__).parent / "fixtures"


def _symlink_or_skip(link_path: Path, target: Path) -> None:
    try:
        link_path.symlink_to(target)
    except (NotImplementedError, OSError):
        pytest.skip("symlinks are not supported in this environment")


class TestCheckNoEval:
    def test_passes_clean_dir(self):
        r = check_no_eval(FIXTURES / "good-plugin")
        assert r.passed and r.points == 5

    def test_fails_with_eval(self):
        r = check_no_eval(FIXTURES / "code-quality-bad")
        assert not r.passed and r.points == 0
        assert "eval()" in r.message or "Function()" in r.message

    def test_handles_empty_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            r = check_no_eval(Path(tmpdir))
            assert r.passed and r.points == 5

    def test_ignores_symlinked_code_files_outside_root(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            outside = root.parent / "outside-evil.js"
            outside.write_text("eval('owned')", encoding="utf-8")
            _symlink_or_skip(root / "linked-evil.js", outside)
            r = check_no_eval(root)
            assert r.passed is True

    @pytest.mark.parametrize(
        "source",
        (
            "model.eval()",
            "self.model.eval()",
            "self.cross_model.eval()\nself.fusion.eval()",
            "proposal.eval()\nranker.eval()",
            "gen.model.eval()\npolicy.model.eval()",
            "model.eval(\n    # switch to inference mode\n)",
            "(model.eval)()",
            "model.eval().to(device)",
            "models[index].eval()",
            "load_model().eval()",
            "模型.eval()",
            "\ufeffmodel.eval()",
            "# eval(source) is intentionally unused\nmodel.eval()",
            'description = "eval(source)"\nmodel.eval()',
            'def infer():\n    """Avoid eval(source)."""\n    model.eval()',
            "class Model:\n    def eval(self):\n        return self\nModel().eval()",
        ),
    )
    def test_python_inference_methods_are_not_dynamic_execution(self, tmp_path: Path, source: str):
        (tmp_path / "inference.py").write_text(source, encoding="utf-8")

        result = check_no_eval(tmp_path)

        assert result.passed is True
        assert result.points == result.max_points == 5
        assert result.findings == ()

    @pytest.mark.parametrize(
        "source",
        (
            "eval(source)",
            "eval()",
            "(eval)(source)",
            "evaluate = eval\nevaluate(source)",
            "builtins.eval(source)",
            "builtins.eval()",
            "__builtins__.eval(source)",
            "import builtins as b\nb.eval(source)",
            "import builtins as b\nb.eval()",
            "import builtins as b\nevaluate = b.eval\nevaluate(source)",
            "from builtins import eval as evaluate\nevaluate(source)",
            "model.eval(source)",
            "model.eval(source=source)",
            "model.eval(*args)",
            "model.eval(**kwargs)",
            "model.eval()\neval(source)",
            "model.eval(\n    source\n)",
            'message = f"result: {eval(source)}"',
            "class Model:\n    def eval(self):\n        return eval(source)\nModel().eval()",
            "import functools\nmodel.eval = functools.partial(eval, source)\nmodel.eval()",
        ),
    )
    def test_python_dynamic_eval_still_fails(self, tmp_path: Path, source: str):
        (tmp_path / "runner.py").write_text(source, encoding="utf-8")

        result = check_no_eval(tmp_path)

        assert result.passed is False
        assert result.points == 0
        assert len(result.findings) == 1
        finding = result.findings[0]
        assert finding.rule_id == "DANGEROUS_DYNAMIC_EXECUTION"
        assert finding.severity is Severity.HIGH
        assert finding.file_path == "runner.py"

    @pytest.mark.parametrize("source", ("if :\n    eval(source)", "model.eval(\n", "\x00eval(source)"))
    def test_unparseable_python_keeps_conservative_text_detection(self, tmp_path: Path, source: str):
        (tmp_path / "invalid.py").write_text(source, encoding="utf-8")

        assert check_no_eval(tmp_path).passed is False

    @pytest.mark.parametrize("error", (SyntaxError, ValueError, RecursionError))
    def test_python_parser_failure_retains_text_detection(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, error: type[Exception]
    ):
        def cannot_parse(_source: str):
            raise error("parser unavailable for this source")

        (tmp_path / "runner.py").write_text("eval(source)", encoding="utf-8")
        monkeypatch.setattr(ast, "parse", cannot_parse)

        result = check_no_eval(tmp_path)

        assert result.passed is False
        assert result.findings[0].severity is Severity.HIGH

    @pytest.mark.parametrize("extension", (".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"))
    @pytest.mark.parametrize("source", ("eval(source)", "window.eval(source)", "model.eval()", "new Function(source)"))
    def test_javascript_and_typescript_dynamic_execution_detection_is_unchanged(
        self, tmp_path: Path, extension: str, source: str
    ):
        (tmp_path / f"runner{extension}").write_text(source, encoding="utf-8")

        result = check_no_eval(tmp_path)

        assert result.passed is False
        assert result.findings[0].severity is Severity.HIGH

    def test_preselected_python_files_use_the_same_detection(self, tmp_path: Path):
        safe = tmp_path / "inference.py"
        unsafe = tmp_path / "runner.py"
        safe.write_text("model.eval()", encoding="utf-8")
        unsafe.write_text("eval(source)", encoding="utf-8")

        assert check_no_eval(tmp_path, files=(safe,)).passed is True
        result = check_no_eval(tmp_path, files=(safe, unsafe))
        assert [finding.file_path for finding in result.findings] == ["runner.py"]


class TestCheckNoShellInjection:
    def test_passes_clean_dir(self):
        r = check_no_shell_injection(FIXTURES / "good-plugin")
        assert r.passed and r.points == 5

    def test_fails_with_shell_injection(self):
        r = check_no_shell_injection(FIXTURES / "code-quality-bad")
        assert not r.passed and r.points == 0

    def test_handles_empty_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            r = check_no_shell_injection(Path(tmpdir))
            assert r.passed and r.points == 5

    def test_ignores_template_literal_near_spawn_switch_label(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "dispatcher.ts").write_text(
                "const message = `failed ${reason}`;\nswitch (kind) {\n  case 'spawn':\n    return message;\n}\n",
                encoding="utf-8",
            )

            result = check_no_shell_injection(root)

            assert result.passed is True
            assert result.points == 5

    def test_ignores_regexp_exec_with_interpolated_template(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "matcher.ts").write_text(
                "const match = new RegExp(pattern).exec(`value ${candidate}`);\n",
                encoding="utf-8",
            )

            result = check_no_shell_injection(root)

            assert result.passed is True
            assert result.points == 5

    @pytest.mark.parametrize("receiver", ("mycp", "scp", "foochild_process"))
    def test_ignores_shell_receiver_identifier_suffixes(self, receiver: str):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "runner.js").write_text(
                f"{receiver}.exec(`echo ${{userInput}}`);\n",
                encoding="utf-8",
            )

            result = check_no_shell_injection(root)

            assert result.passed is True
            assert result.points == 5

    def test_detects_interpolated_template_passed_directly_to_exec(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "runner.js").write_text(
                "exec(`echo ${userInput}`);\n",
                encoding="utf-8",
            )

            result = check_no_shell_injection(root)

            assert result.passed is False
            assert result.points == 0
            assert result.findings[0].file_path == "runner.js"

    def test_detects_interpolated_template_passed_to_required_child_process(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "runner.js").write_text(
                "require('child_process').exec(`echo ${userInput}`);\n",
                encoding="utf-8",
            )

            result = check_no_shell_injection(root)

            assert result.passed is False
            assert result.points == 0
            assert result.findings[0].file_path == "runner.js"

    def test_detects_one_hop_variable_passed_to_required_node_child_process(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "runner.js").write_text(
                'const cmd = `echo ${userInput}`;\nrequire("node:child_process").exec(cmd);\n',
                encoding="utf-8",
            )

            result = check_no_shell_injection(root)

            assert result.passed is False
            assert result.points == 0
            assert result.findings[0].file_path == "runner.js"

    def test_detects_typed_interpolated_template_variable_in_typescript(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "runner.ts").write_text(
                "export const command: string = `echo ${userInput}`;\nchild_process.exec(command);\n",
                encoding="utf-8",
            )

            result = check_no_shell_injection(root)

            assert result.passed is False
            assert result.points == 0
            assert result.findings[0].file_path == "runner.ts"

    @pytest.mark.parametrize("suffix", ("as const", "satisfies string"))
    def test_detects_typescript_template_assertion_suffixes(self, suffix: str):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "runner.ts").write_text(
                f"const cmd = `echo ${{userInput}}` {suffix};\nchild_process.exec(cmd);\n",
                encoding="utf-8",
            )

            result = check_no_shell_injection(root)

            assert result.passed is False
            assert result.points == 0
            assert result.findings[0].file_path == "runner.ts"

    def test_detects_interpolated_template_dollar_variable_passed_to_child_process_exec(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "runner.js").write_text(
                "const cmd$ = `echo ${userInput}`;\nchild_process.exec(cmd$);\n",
                encoding="utf-8",
            )

            result = check_no_shell_injection(root)

            assert result.passed is False
            assert result.points == 0
            assert result.findings[0].file_path == "runner.js"


class TestFindCodeFiles:
    def test_finds_js_files(self):
        files = _find_code_files(FIXTURES / "code-quality-bad")
        names = [f.name for f in files]
        assert "evil.js" in names

    def test_skips_non_code_files(self):
        files = _find_code_files(FIXTURES / "code-quality-bad")
        for f in files:
            assert f.suffix in {".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"}

    def test_skips_excluded_dirs(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            node_dir = Path(tmpdir) / "node_modules" / "pkg"
            node_dir.mkdir(parents=True)
            (node_dir / "index.js").write_text("eval()")
            files = _find_code_files(Path(tmpdir))
            assert len(files) == 0

    def test_skips_symlinked_code_files_outside_root(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            outside = root.parent / "outside-evil.ts"
            outside.write_text("eval('owned')", encoding="utf-8")
            _symlink_or_skip(root / "linked-evil.ts", outside)
            files = _find_code_files(root)
            assert files == []


class TestRunCodeQualityChecks:
    def test_good_plugin_gets_10(self):
        results = run_code_quality_checks(FIXTURES / "good-plugin")
        assert sum(c.points for c in results) == 10

    def test_bad_code_gets_0(self):
        results = run_code_quality_checks(FIXTURES / "code-quality-bad")
        assert sum(c.points for c in results) == 0

    def test_returns_tuple_of_correct_length(self):
        results = run_code_quality_checks(FIXTURES / "good-plugin")
        assert isinstance(results, tuple)
        assert len(results) == 2
