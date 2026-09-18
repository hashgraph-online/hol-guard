"""Independent expectations and failure receipts for installed Secrets probes."""

from __future__ import annotations

import ast
import base64
import copy
import errno
import hashlib
import io
import json
import sys
import zipfile
from pathlib import PureWindowsPath
from types import SimpleNamespace

import pytest

from ci.native_runtime import probe_installed_offline_secrets as probe


def public_result():
    return {
        "schema": "guard-repository-secret-scan.v1",
        "detector_version": "example",
        "files_scanned": 1,
        "bytes_scanned": 40,
        "commits_scanned": 0,
        "history_enabled": False,
        "truncated": False,
        "truncation_reasons": [],
        "errors": [],
        "finding_count": 1,
        "findings": [
            {
                "rule_id": "github-token",
                "family": "GitHub token",
                "severity": "critical",
                "confidence": "high",
                "confidence_score": 1.0,
                "line": 1,
                "path": "config.ts",
                "source": "working_tree",
                "commit": None,
                "validation": "github",
                "entropy": 4.2,
                "context_reasons": ["provider-format"],
            }
        ],
    }


@pytest.mark.parametrize(
    "field,value",
    [("rule_id", "other-rule"), ("path", "other.ts"), ("line", 2), ("source", "staged"), ("commit", "unexpected")],
)
def test_independent_occurrences_reject_plausible_but_wrong_results(field, value):
    payload = public_result()
    payload["findings"][0][field] = value
    with pytest.raises(probe.ProbeError):
        probe._validate_public(payload, expected=[("github-token", "config.ts", 1)])


@pytest.mark.parametrize("change", ["candidate", "missing_context", "partial", "wrong_bytes", "wrong_count"])
def test_public_contract_rejects_loss_or_disclosure(change):
    payload = public_result()
    if change == "candidate":
        payload["findings"][0]["candidate"] = "must-never-be-public"
    elif change == "missing_context":
        del payload["findings"][0]["context_reasons"]
    elif change == "partial":
        payload["truncated"] = True
    elif change == "wrong_bytes":
        payload["bytes_scanned"] = 39
    else:
        payload["finding_count"] = 0
    with pytest.raises(probe.ProbeError):
        probe._validate_public(payload, expected=[("github-token", "config.ts", 1)], files=1, size=40)


def test_full_public_parity_covers_fields_beyond_occurrence_identity():
    expected = public_result()
    changed = copy.deepcopy(expected)
    changed["findings"][0]["context_reasons"] = []
    assert probe._public_digest(expected) != probe._public_digest(changed)
    assert probe._validate_public(expected, expected=[("github-token", "config.ts", 1)]) == expected


def test_fixture_has_seventeen_provider_formats_and_independent_context_suppression():
    files, expected = probe._rich_fixture()
    assert len(probe._PROVIDERS) == 17
    assert len({rule for rule, _, _ in expected}) == 18
    assert ("github-token", "tests/.env", 2) in expected
    assert ("github-token", "src/unicode.ts", 3) in expected
    assert "tests/fixture.py" in files and not any(path == "tests/fixture.py" for _, path, _ in expected)
    assert "android/google-services.json" in files
    assert not any(path == "android/google-services.json" for _, path, _ in expected)


@pytest.mark.parametrize(
    "output",
    [probe._BODY.encode(), probe._PROVIDERS[2][2].encode(), probe._PROVIDERS[11][2].encode(), b"/private/fixture/path"],
)
def test_command_receipt_never_retains_leaked_output(monkeypatch, tmp_path, output):
    instance = probe.Probe({}, tmp_path, lambda: None)
    if output.startswith(b"/"):
        output = str(tmp_path).encode()

    def run(*args, **kwargs):
        kwargs["stdout"].write(output)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(probe.subprocess, "run", run)
    with pytest.raises(probe.ProbeError, match="disclosure"):
        instance.command(["unused"], expected_exit=0, label="privacy")
    rendered = json.dumps(instance.cases).encode()
    assert output not in rendered
    assert instance.cases[0]["stdout_sha256"] == probe._digest(output)


def test_failed_exit_keeps_bounded_diagnostics_and_checkpoint(monkeypatch, tmp_path):
    checkpoints = []
    instance = probe.Probe({}, tmp_path, lambda: checkpoints.append(True))

    def run(*args, **kwargs):
        kwargs["stderr"].write(b"bounded diagnostic")
        return SimpleNamespace(returncode=9)

    monkeypatch.setattr(probe.subprocess, "run", run)
    with pytest.raises(probe.ProbeError, match="unexpected_exit"):
        instance.command(["unused"], expected_exit=0, label="failure")
    assert checkpoints
    assert instance.cases[0]["exit_code"] == 9
    assert "bounded diagnostic" not in json.dumps(instance.cases)
    assert instance.cases[0]["status"] == "failed"


@pytest.mark.parametrize("payload", [b"not json", json.dumps(public_result()).encode()])
def test_semantic_failure_never_leaves_successful_command_marked_passed(monkeypatch, tmp_path, payload):
    checkpoints = []
    instance = probe.Probe(
        {"hol-guard": tmp_path / "hol-guard"}, tmp_path, lambda: checkpoints.append(copy.deepcopy(instance.cases))
    )

    def run(*args, **kwargs):
        kwargs["stdout"].write(payload)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(probe.subprocess, "run", run)
    with pytest.raises(probe.ProbeError):
        instance.scan("semantics", tmp_path, expected=[("gitlab-token", "other.ts", 9)])
    assert instance.cases[-1]["exit_code"] == 0
    assert instance.cases[-1]["status"] == "failed"
    assert any(rows[-1]["status"] == "command_completed" for rows in checkpoints)
    assert all(rows[-1]["status"] != "passed" for rows in checkpoints)
    assert checkpoints[-1][-1]["reason"] in {"invalid_public_payload", "independent_occurrences"}


def test_successful_command_still_requires_a_public_contract(monkeypatch, tmp_path):
    instance = probe.Probe({}, tmp_path, lambda: None)
    monkeypatch.setattr(probe.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(returncode=0))
    assert instance.command(["unused"], expected_exit=0, label="command") == b""
    assert instance.cases[-1]["status"] == "command_completed"


def test_enospc_is_not_silently_classified_as_unsupported_symlink():
    assert probe._unsupported_link(OSError(errno.EPERM, "permission"))
    assert probe._unsupported_link(NotImplementedError())
    assert not probe._unsupported_link(OSError(errno.ENOSPC, "storage full"))


def test_link_fixture_keeps_invalid_bytes_without_windows_device_names():
    assert PureWindowsPath("nul.ts").is_reserved()
    fixture = probe._links_fixture(b"a realistic credential line\n")
    assert len(fixture) == 3
    assert all(not PureWindowsPath(name).is_reserved() for name in fixture)
    assert sorted(fixture.values()) == sorted([b"a realistic credential line\n", b"\xff\xfe", b"\0TOKEN=ordinary"])


def test_git_setup_failure_has_its_own_stage_and_private_diagnostics(monkeypatch, tmp_path):
    checkpoints = []
    instance = probe.Probe({}, tmp_path, lambda: checkpoints.append(copy.deepcopy(instance.cases)))
    completed = {
        "case": "explicit_history_commit_bound",
        "status": "passed",
        "validation": "independent_history_bounds",
    }
    instance.cases.append(completed.copy())
    private_output = str(tmp_path).encode() + b" " + probe._BODY.encode()
    monkeypatch.setattr(
        probe.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=128, stdout=b"", stderr=private_output),
    )
    with pytest.raises(probe.ProbeError, match="fixture_git_setup"):
        instance.git(tmp_path / "links", "add", ".")
    assert instance.cases[0] == completed
    assert instance.cases[1]["case"] == "fixture_git_setup"
    assert instance.cases[1]["fixture"] == "links"
    assert instance.cases[1]["operation"] == "add"
    assert instance.cases[1]["exit_code"] == 128
    assert instance.cases[1]["stderr_sha256"] == probe._digest(private_output)
    assert private_output not in json.dumps(instance.cases).encode()
    assert checkpoints[-1][-1]["status"] == "failed"


@pytest.mark.parametrize("failure_stage", ["exercise", "final_attestation"])
def test_later_probe_failure_does_not_relabel_completed_history(monkeypatch, tmp_path, failure_stage):
    destination = tmp_path / "receipt.json"
    completed = {
        "case": "explicit_history_commit_bound",
        "status": "passed",
        "validation": "independent_history_bounds",
    }
    attest_calls = []

    def attest(*args):
        attest_calls.append(True)
        if len(attest_calls) == 2:
            raise probe.ProbeError("installed_artifact_changed_during_probe")
        return {"source_sha": "fixture"}, {}

    def exercise(instance, *args):
        instance.cases.append(completed.copy())
        if failure_stage == "exercise":
            raise probe.ProbeError("fixture_git_setup")

    monkeypatch.setattr(probe, "_attest", attest)
    monkeypatch.setattr(probe, "_exercise", exercise)
    monkeypatch.setattr(
        sys,
        "argv",
        ["probe", "--wheel", str(tmp_path / "fixture.whl"), "--source-sha", "fixture", "--json", str(destination)],
    )
    assert probe.main() == 1
    receipt = json.loads(destination.read_bytes())
    assert receipt["status"] == "failed" and receipt["run_complete"] is False
    assert receipt["cases"][0] == completed
    assert receipt["cases"][1]["status"] == "failed"
    assert receipt["cases"][1]["stage"] == failure_stage
    assert receipt["failure_stage"] == failure_stage


def test_source_interpreter_cannot_claim_installed_qualification(monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "flags", SimpleNamespace(isolated=0))
    with pytest.raises(probe.ProbeError, match="isolated_interpreter_required"):
        probe._attest(tmp_path / "unused.whl", "1" * 40)


def test_child_environment_removes_oracle_and_python_import_overrides(monkeypatch):
    for key in ("PYTHONPATH", "PYTHONHOME", "GUARD_PYTHON_ORACLE", "HOL_GUARD_NATIVE_MODE", "PYTEST_CURRENT_TEST"):
        monkeypatch.setenv(key, "must-not-propagate")
    environment = probe._environment()
    assert "must-not-propagate" not in environment.values()
    assert environment["PYTHONNOUSERSITE"] == environment["PYTHONSAFEPATH"] == "1"


@pytest.mark.parametrize("corruption", ["changed_installed_bytes", "source_shadow"])
def test_supplied_wheel_attestation_rejects_substitution(monkeypatch, tmp_path, corruption):
    site = tmp_path / "site-packages"
    launchers = tmp_path / "bin"
    launchers.mkdir()
    modules = {}
    wheel = tmp_path / "hol_guard.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        for name in probe._MODULES:
            relative = name.replace(".", "/") + ".py"
            path = site / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"# installed wheel module\n")
            archive.writestr(relative, path.read_bytes())
            modules[name] = SimpleNamespace(__file__=str(path))
    entries = []
    records = []
    interpreter = launchers / ("python.exe" if probe.os.name == "nt" else "python")
    for name, value in (
        ("hol-guard", "codex_plugin_scanner.cli:main"),
        ("hol-guard-secrets", "codex_plugin_scanner.guard.secrets.cli:main"),
    ):
        entries.append(SimpleNamespace(group="console_scripts", name=name, value=value))
        path = launchers / (name + (".exe" if probe.os.name == "nt" else ""))
        content = b"#!" + str(interpreter).encode() + b"\n" + probe._wrapper_templates(value.split(":")[0])[0].encode()
        if probe.os.name == "nt":
            content = _windows_wrapper(str(interpreter), value.split(":")[0])
        path.write_bytes(content)
        digest = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=").decode()
        records.append(f"../bin/{path.name},sha256={digest},{len(content)}")
    distribution = SimpleNamespace(
        locate_file=lambda name: site / name,
        read_text=lambda name: "\n".join(records) if name == "RECORD" else None,
        entry_points=entries,
        version="3.0.1",
    )
    flags = {name: getattr(sys.flags, name) for name in dir(sys.flags) if not name.startswith("_")}
    flags["isolated"] = 1
    monkeypatch.setattr(sys, "flags", SimpleNamespace(**flags))
    monkeypatch.setattr(sys, "executable", str(interpreter))
    monkeypatch.setattr(sys, "prefix", str(tmp_path))
    if probe.os.name == "nt":
        monkeypatch.setattr(probe, "_windows_launcher_resources", lambda path: None)
    monkeypatch.setattr(probe.importlib.metadata, "distribution", lambda name: distribution)
    monkeypatch.setattr(probe.importlib, "import_module", lambda name: modules[name])
    monkeypatch.setattr(probe.sysconfig, "get_path", lambda name: str(launchers))
    identity, _ = probe._attest(wheel, "1" * 40)
    assert len(identity["module_sha256"]) == len(probe._MODULES)
    module = modules[probe._MODULES[0]]
    if corruption == "changed_installed_bytes":
        (site / (probe._MODULES[0].replace(".", "/") + ".py")).write_bytes(b"changed")
    else:
        module.__file__ = str(tmp_path / "source" / "cli.py")
    with pytest.raises(probe.ProbeError, match="wheel"):
        probe._attest(wheel, "1" * 40)


def _windows_wrapper(interpreter, module, *, source=None):
    payload = io.BytesIO()
    with zipfile.ZipFile(payload, "w") as archive:
        archive.writestr("__main__.py", source or probe._wrapper_templates(module)[0])
    # Parser fixture only, never executed as a Windows executable.
    return b"MZ-parser-fixture" + f'#!"{interpreter}"\n'.encode() + payload.getvalue()


@pytest.mark.parametrize("windows", [False, True])
@pytest.mark.parametrize("corruption", [None, "other_interpreter", "other_entrypoint", "extra_code"])
def test_launcher_wrapper_binds_lexical_interpreter_and_only_expected_entrypoint(windows, corruption):
    interpreter = r"C:\owned\Scripts\python.exe" if windows else "/owned/bin/python"
    actual = interpreter.replace("owned", "other") if corruption == "other_interpreter" else interpreter
    module = "codex_plugin_scanner.cli"
    source = probe._wrapper_templates("another.cli" if corruption == "other_entrypoint" else module)[0]
    if corruption == "extra_code":
        source += "raise SystemExit(0)\n"
    content = _windows_wrapper(actual, module, source=source) if windows else f"#!{actual}\n{source}".encode()
    if corruption:
        with pytest.raises(probe.ProbeError):
            probe._launcher_wrapper(content, module=module, interpreter=interpreter, windows=windows)
    else:
        assert probe._launcher_wrapper(content, module=module, interpreter=interpreter, windows=windows)[
            "interpreter_matches_current_installation"
        ]


@pytest.mark.parametrize("transport", ["posix", "distlib", "uv"])
@pytest.mark.parametrize("hidden_statement", [False, True])
def test_wrapper_byte_parser_honors_the_actual_python_encoding_cookie(transport, hidden_statement):
    windows = transport != "posix"
    interpreter = r"C:\owned\Scripts\python.exe" if windows else "/owned/bin/python"
    module = "codex_plugin_scanner.cli"
    prefix = (
        b"# coding: unicode_escape\n# \\x0araise SystemExit(0)\\x0a#\n"
        if hidden_statement
        else "# coding: utf-8\n# café\n".encode()
    )
    source = prefix + probe._wrapper_templates(module)[0].encode()
    resources = None
    if transport == "posix":
        content = f"#!{interpreter}\n".encode() + source
        loaded_source = content
    else:
        loaded_source = source
        if transport == "distlib":
            content = _windows_wrapper(interpreter, module, source=source)
        else:
            payload = io.BytesIO()
            with zipfile.ZipFile(payload, "w") as archive:
                archive.writestr("__main__.py", source)
            content = b"MZ-resource-fixture"
            resources = {
                "UV_TRAMPOLINE_KIND": b"\x01",
                "UV_PYTHON_PATH": interpreter.encode(),
                "UV_SCRIPT_DATA": payload.getvalue(),
            }
    # Parse only: never execute the witness. The real bytes parser sees an
    # extra statement which decoding as UTF-8 before parsing conceals.
    actual = ast.parse(loaded_source)
    assert any(isinstance(node, ast.Raise) for node in actual.body) is hidden_statement
    if hidden_statement:
        assert not any(isinstance(node, ast.Raise) for node in ast.parse(loaded_source.decode("utf-8")).body)
        with pytest.raises(probe.ProbeError, match="launcher_entrypoint_wrapper_mismatch"):
            probe._launcher_wrapper(
                content, module=module, interpreter=interpreter, windows=windows, resources=resources
            )
    else:
        assert probe._launcher_wrapper(
            content, module=module, interpreter=interpreter, windows=windows, resources=resources
        )["interpreter_matches_current_installation"]


def test_posix_cookie_line_positions_include_the_original_shebang():
    interpreter = "/owned/bin/python"
    module = "codex_plugin_scanner.cli"
    content = (
        f"#!{interpreter}\n# ordinary comment\n".encode()
        + b"# coding: unicode_escape\n# \\x0araise SystemExit(0)\\x0a#\n"
        + probe._wrapper_templates(module)[0].encode()
    )
    # A third-line cookie is an ordinary comment to Python's source loader.
    assert not any(isinstance(node, ast.Raise) for node in ast.parse(content).body)
    assert probe._launcher_wrapper(content, module=module, interpreter=interpreter, windows=False)[
        "interpreter_matches_current_installation"
    ]


@pytest.mark.parametrize("corruption", [None, "other_interpreter", "wrong_kind", "oversize_zip"])
def test_uv_windows_resource_wrapper_binds_python_path_and_script_kind(corruption):
    interpreter = r"C:\owned\Scripts\python.exe"
    module = "codex_plugin_scanner.cli"
    zipped = io.BytesIO()
    with zipfile.ZipFile(zipped, "w") as archive:
        archive.writestr("__main__.py", probe._wrapper_templates(module)[0])
    resources = {
        "UV_TRAMPOLINE_KIND": b"\x01",
        "UV_PYTHON_PATH": interpreter.encode(),
        "UV_SCRIPT_DATA": zipped.getvalue(),
    }
    if corruption == "other_interpreter":
        resources["UV_PYTHON_PATH"] = interpreter.replace("owned", "other").encode()
    elif corruption == "wrong_kind":
        resources["UV_TRAMPOLINE_KIND"] = b"\x02"
    elif corruption == "oversize_zip":
        resources["UV_SCRIPT_DATA"] = b"X" * (probe._MAX_WRAPPER + 1025)
    if corruption:
        with pytest.raises(probe.ProbeError):
            probe._launcher_wrapper(
                b"MZ-resource-fixture", module=module, interpreter=interpreter, windows=True, resources=resources
            )
    else:
        assert probe._launcher_wrapper(
            b"MZ-resource-fixture", module=module, interpreter=interpreter, windows=True, resources=resources
        )["uv_pe_resources"]


def test_replaced_launcher_fails_distribution_record_binding(monkeypatch, tmp_path):
    script = tmp_path / "hol-guard"
    script.write_bytes(b"changed launcher")
    distribution = SimpleNamespace(
        locate_file=lambda name: tmp_path / name, read_text=lambda name: "hol-guard,sha256=stale,12\n"
    )
    with pytest.raises(probe.ProbeError, match="launcher_record_mismatch"):
        probe._launcher_binding(distribution, script, "codex_plugin_scanner.cli")


@pytest.mark.parametrize("oversized", [False, True])
def test_windows_resources_load_only_as_data_and_always_release_handle(monkeypatch, tmp_path, oversized):
    import ctypes

    names = {"UV_TRAMPOLINE_KIND": 1, "UV_PYTHON_PATH": 2, "UV_SCRIPT_DATA": 3}
    buffers = {
        1: ctypes.create_string_buffer(b"\x01"),
        2: ctypes.create_string_buffer(b"C:\\owned\\python.exe"),
        3: ctypes.create_string_buffer(b"zipped-script"),
    }
    loaded, freed = [], []

    def load(path, unused, flags):
        loaded.append(flags)
        return 100

    api = SimpleNamespace(
        LoadLibraryExW=load,
        FindResourceW=lambda handle, name, resource_type: names[name],
        SizeofResource=lambda handle, resource: 100000 if oversized else len(buffers[resource].raw) - 1,
        LoadResource=lambda handle, resource: resource,
        LockResource=lambda resource: ctypes.addressof(buffers[resource]),
        FreeLibrary=lambda handle: freed.append(handle),
    )
    monkeypatch.setattr(ctypes, "WinDLL", lambda *args, **kwargs: api, raising=False)
    if oversized:
        with pytest.raises(probe.ProbeError, match="launcher_resource_size"):
            probe._windows_launcher_resources(tmp_path / "unexecuted.exe")
    else:
        assert probe._windows_launcher_resources(tmp_path / "unexecuted.exe")["UV_TRAMPOLINE_KIND"] == b"\x01"
    assert loaded == [2]
    assert freed == [100]


def test_oversized_output_is_bounded_and_its_digest_scope_is_explicit(monkeypatch, tmp_path):
    monkeypatch.setattr(probe, "_MAX_OUTPUT", 16)
    instance = probe.Probe({}, tmp_path, lambda: None)

    def run(*args, **kwargs):
        kwargs["stdout"].write(b"x" * 100)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(probe.subprocess, "run", run)
    with pytest.raises(probe.ProbeError, match="command_output_limit"):
        instance.command(["unused"], expected_exit=0, label="output_limit")
    assert instance.cases[0]["stdout_bytes"] == 100
    assert instance.cases[0]["digest_scope"] == "bounded_prefix"


def test_installed_probe_remains_attempted_after_other_qualification_failure(monkeypatch, tmp_path):
    from scripts import build_native_qualification_artifacts as builder

    attempted = []

    def run(argv, **kwargs):
        attempted.append(argv[0])
        if argv[0] == "paired":
            raise probe.subprocess.CalledProcessError(1, argv)

    monkeypatch.setattr(builder, "_run", run)
    with pytest.raises(RuntimeError, match="paired_sampling"):
        builder._run_required_checks(
            (("paired_sampling", ["paired"]), ("installed_offline_secrets", ["secrets"])), cwd=tmp_path
        )
    assert attempted == ["paired", "secrets"]


def test_builder_supplies_actual_candidate_wheel_to_isolated_independent_probe(monkeypatch, tmp_path):
    from scripts import build_native_qualification_artifacts as builder

    candidate = tmp_path / "candidate"
    candidate.mkdir()
    (candidate / "uv.lock").write_text('[[package]]\nname = "psutil"\nversion = "7.2.2"\n')
    captured = []
    monkeypatch.setattr(
        builder,
        "_build",
        lambda source, **kwargs: (source / "python", source / "candidate.whl", {"source_sha": "1" * 40}),
    )
    monkeypatch.setattr(builder, "_run", lambda *args, **kwargs: "")
    monkeypatch.setattr(builder, "_run_required_checks", lambda checks, **kwargs: captured.extend(checks))
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "builder",
            "--baseline",
            str(tmp_path / "baseline"),
            "--candidate",
            str(candidate),
            "--target",
            "test-target",
            "--platform-tag",
            "test-platform",
            "--output-dir",
            str(tmp_path / "output"),
        ],
    )
    assert builder.main() == 0
    checks = dict(captured)
    assert set(checks) == {
        "paired_sampling",
        "installed_ollama",
        "installed_artifact_transitions",
        "installed_offline_secrets",
    }
    command = checks["installed_offline_secrets"]
    assert command[:2] == [str(candidate / "python"), "-I"]
    assert command[command.index("--wheel") + 1] == str(candidate / "candidate.whl")
    assert command[command.index("--source-sha") + 1] == "1" * 40
