"""Code observations and delivery refusals using isolated real CPython."""

from __future__ import annotations

import importlib.util
import marshal
import os
import shlex
import shutil
import subprocess
import sys
import sysconfig
import tempfile
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon.hook_native_exact_action import native_launch_evidence
from tests.native_launch_evidence_helpers import _inventory, _permission
from tests.test_native_review_exact_action_always import _verdict

pytestmark = pytest.mark.skipif(sys.platform != "darwin", reason="isolated macOS CPython layout fixture")


def _copy_runtime(project: Path) -> tuple[Path, Path]:
    executable = Path(sys.executable).resolve()
    library = Path(sysconfig.get_path("stdlib"))
    version = f"python{sys.version_info.major}.{sys.version_info.minor}"
    dylib = library.parent / f"lib{version}.dylib"
    assert executable.is_file() and dylib.is_file(), "select the test CPython distribution"
    installed = project / "runtime" / "lib" / version
    installed.mkdir(parents=True)
    interpreter = project / "runtime" / "bin" / version
    interpreter.parent.mkdir()
    shutil.copy2(executable, interpreter)
    shutil.copy2(dylib, installed.parent / dylib.name)
    # CPython's path landmark and the actual UTF-8 startup implementation.
    shutil.copy2(library / "os.py", installed / "os.py")
    (installed / "encodings").mkdir()
    for name in ("__init__.py", "aliases.py", "utf_8.py"):
        shutil.copy2(library / "encodings" / name, installed / "encodings" / name)
    return interpreter, installed


def _environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    parent = Path(__file__).resolve().parents[1] / "rust" / "target" / "python-wire-tests"
    parent.mkdir(parents=True, exist_ok=True)
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    for name in tuple(os.environ):
        if name.startswith("PYTHON"):
            monkeypatch.delenv(name)
    return parent, home


def _execute(argv: list[str], project: Path, home: Path) -> str:
    completed = subprocess.run(
        argv,
        cwd=project,
        env={"HOME": str(home), "PATH": "/usr/bin:/bin"},
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert completed.returncode == 0, completed.stderr
    return completed.stdout


def _unchecked_bytecode(source: str, filename: Path) -> bytes:
    header = importlib.util.MAGIC_NUMBER + (1).to_bytes(4, "little") + bytes(8)
    return header + marshal.dumps(compile(source, str(filename), "exec"))


@pytest.mark.parametrize("changed", ["source", "transitive", "bytecode"])
def test_installed_python_standard_module_mutation_changes_observed_inventory(
    native_context_digest: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, changed: str
) -> None:
    del native_context_digest
    parent, home = _environment(tmp_path, monkeypatch)
    with tempfile.TemporaryDirectory(prefix="stdlib-", dir=parent) as directory:
        project = Path(directory).resolve()
        interpreter, installed = _copy_runtime(project)
        module = installed / "colorsys.py"
        library = Path(sysconfig.get_path("stdlib"))
        module.write_bytes((library / "colorsys.py").read_bytes() + b"\nfixture_marker = 'safe'\n")
        selected = module
        if changed == "transitive":
            selected = installed / "calendar.py"
            selected.write_text("fixture_marker = 'safe'\n")
            module.write_text(module.read_text() + "\nfrom calendar import fixture_marker\n")
        elif changed == "bytecode":
            selected = Path(importlib.util.cache_from_source(str(module)))
            selected.parent.mkdir()
            selected.write_bytes(_unchecked_bytecode(module.read_text(), module))
        script = project / "report.py"
        script.write_text("import colorsys\nprint(colorsys.fixture_marker)\n")
        argv = [str(interpreter), "-I", "-S", "-B", str(script)]

        assert _execute(argv, project, home) == "safe\n"
        command = shlex.join(argv)
        before = _inventory(command, project)
        assert before is not None, "the resolved standard implementation must retain an identity"
        module.touch()
        (project / "unrelated.txt").write_text("ordinary data")
        assert _inventory(command, project) == before
        metadata = selected.stat()
        body = selected.read_bytes()
        replacement = body.replace(b"fixture_marker = 'safe'", b"fixture_marker = 'evil'")
        if changed == "bytecode":
            replacement = _unchecked_bytecode(module.read_text().replace("'safe'", "'evil'"), module)
        assert len(replacement) == len(body)
        selected.write_bytes(replacement)
        os.utime(selected, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
        assert _execute(argv, project, home) == "evil\n", "the interpreter must load the changed installed body"
        after = _inventory(command, project)
        assert after is not None and after != before, "Python consent ignored changed installed standard code"
        # A compiled alternative is not silently treated as this source file.
        (installed / "colorsys.so").write_bytes(b"unproven native implementation")
        result, receipt = _verdict()
        assert native_launch_evidence(
            harness="claude-code",
            tool_name="Bash",
            payload={"tool_name": "Bash", "tool_input": {"command": command}, "cwd": str(project)},
            native_result=result,
            native_receipt=receipt,
            workspace=project,
            home_dir=project.parent / "home",
        ) == (None, "python_runtime_module_unproven")


@pytest.mark.parametrize("changed", ["source", "bytecode"])
def test_real_python_local_module_and_active_bytecode_change_observed_inventory(
    native_context_digest: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, changed: str
) -> None:
    del native_context_digest
    parent, home = _environment(tmp_path, monkeypatch)
    with tempfile.TemporaryDirectory(prefix="local-", dir=parent) as directory:
        project = Path(directory).resolve()
        interpreter, _ = _copy_runtime(project)
        script = project / "report.py"
        script.write_text("import helper\nprint(helper.value)\n")
        helper = project / "helper.py"
        helper.write_text("value = 'safe'\n")
        selected = helper
        if changed == "bytecode":
            selected = Path(importlib.util.cache_from_source(str(helper)))
            selected.parent.mkdir()

        def bytecode(value: str) -> bytes:
            # CPython's unchecked hash cache really executes instead of the
            # unchanged source. This is test-owned code, not analyzer probing.
            return _unchecked_bytecode(f"value = '{value}'\n", helper)

        if changed == "bytecode":
            selected.write_bytes(bytecode("safe"))
        argv = [str(interpreter), "-S", "-B", str(script)]
        assert _execute(argv, project, home) == "safe\n"
        command = shlex.join(argv)
        before = _inventory(command, project)
        assert before is not None, "a local module proof must remain eligible"
        metadata = selected.stat()
        selected.write_bytes(b"value = 'evil'\n" if changed == "source" else bytecode("evil"))
        os.utime(selected, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
        assert _execute(argv, project, home) == "evil\n"
        assert _inventory(command, project) not in {None, before}


@pytest.mark.parametrize("changed", ["source", "bytecode", "symlink-bytecode"])
def test_python_implicit_encoding_startup_changes_observed_inventory(
    native_context_digest: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, changed: str
) -> None:
    del native_context_digest
    parent, home = _environment(tmp_path, monkeypatch)
    with tempfile.TemporaryDirectory(prefix="bootstrap-", dir=parent) as directory:
        project = Path(directory).resolve()
        interpreter, installed = _copy_runtime(project)
        script = project / "report.py"
        script.write_text("print('report')\n")
        marker = project / "startup-marker"
        codec = installed / "encodings" / "utf_8.py"
        # Test-owned startup code writes only the isolated marker. Physical
        # execution proves that an implicit interpreter import runs it.
        payload = (
            "\nimport posix as _fixture_posix\n"
            f"_fixture_fd = _fixture_posix.open({str(marker)!r}, 0x601, 0o600)\n"
            "_fixture_posix.write(_fixture_fd, b'safe')\n"
            "_fixture_posix.close(_fixture_fd)\n"
        )
        codec.write_text(codec.read_text() + payload)
        if changed == "symlink-bytecode":
            bodies = installed / "codec-bodies"
            bodies.mkdir()
            codec.rename(bodies / "utf_8.py")
            codec.symlink_to(Path("..") / "codec-bodies" / "utf_8.py")
        selected = codec
        if changed != "source":
            selected = Path(importlib.util.cache_from_source(str(codec)))
            selected.parent.mkdir()
            selected.write_bytes(_unchecked_bytecode(codec.read_text(), codec))
        argv = [str(interpreter), "-I", "-S", "-B", str(script)]
        command = shlex.join(argv)
        before = _inventory(command, project)
        assert before is not None, "a captured runtime must retain a reusable identity"
        assert not marker.exists(), "identity analysis must not run implicit startup code"
        assert _execute(argv, project, home) == "report\n"
        assert marker.read_text() == "safe"
        metadata = selected.stat()
        evil_source = codec.read_text().replace("b'safe'", "b'evil'")
        replacement = evil_source.encode() if changed == "source" else _unchecked_bytecode(evil_source, codec)
        assert len(replacement) == metadata.st_size
        selected.write_bytes(replacement)
        os.utime(selected, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
        after = _inventory(command, project)
        assert marker.read_text() == "safe", "analysis must not execute the changed codec"
        assert _execute(argv, project, home) == "report\n"
        assert marker.read_text() == "evil"
        assert after is not None and after != before, "implicit encoding code escaped the Python identity"


def test_python_native_runtime_library_is_bound_without_changing_the_launcher(
    native_context_digest: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    del native_context_digest
    parent, home = _environment(tmp_path, monkeypatch)
    with tempfile.TemporaryDirectory(prefix="native-runtime-", dir=parent) as directory:
        project = Path(directory).resolve()
        interpreter, installed = _copy_runtime(project)
        script = project / "report.py"
        script.write_text("import sys\nprint(sys.version)\n")
        argv = [str(interpreter), "-I", "-S", "-B", str(script)]
        command = shlex.join(argv)
        version = sys.version.split()[0]
        changed_version = version[:-1] + ("3" if version[-1] != "3" else "4")
        assert version in _execute(argv, project, home)
        before = _inventory(command, project)
        assert before is not None
        launcher_bytes = interpreter.read_bytes()
        library = installed.parent / f"libpython{sys.version_info.major}.{sys.version_info.minor}.dylib"
        original = library.read_bytes()
        replacement = original.replace(version.encode(), changed_version.encode())
        assert replacement != original and len(replacement) == len(original)
        metadata = library.stat()
        library.write_bytes(replacement)
        # Only this isolated fixture copy is signed. No installed runtime or
        # hook is replaced. The new process must actually load the new bytes.
        signed = subprocess.run(
            ["/usr/bin/codesign", "--force", "--sign", "-", str(library)],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert signed.returncode == 0, signed.stderr
        os.utime(library, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
        assert interpreter.read_bytes() == launcher_bytes
        assert changed_version in _execute(argv, project, home)
        assert _inventory(command, project) not in {None, before}, "unchanged launcher hid changed libpython bytes"


def test_conflicting_python_home_configuration_cannot_certify_a_different_bootstrap(
    native_context_digest: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    del native_context_digest
    parent, home = _environment(tmp_path, monkeypatch)
    with tempfile.TemporaryDirectory(prefix="configuration-", dir=parent) as directory:
        project = Path(directory).resolve()
        marker = project / "selected-startup"
        installations = []
        for name in ("first", "other"):
            root = project / name
            root.mkdir()
            image, installed = _copy_runtime(root)
            codec = installed / "encodings" / "utf_8.py"
            payload = (
                "\nimport posix as _fixture_posix\n"
                f"_fixture_fd = _fixture_posix.open({str(marker)!r}, 0x601, 0o600)\n"
                f"_fixture_posix.write(_fixture_fd, {name.encode()!r})\n"
                "_fixture_posix.close(_fixture_fd)\n"
            )
            codec.write_text(codec.read_text() + payload)
            installations.append(image)
        interpreter, alternate = installations
        config = interpreter.parent.parent / "pyvenv.cfg"
        config.write_text(f"home = {interpreter.parent}\ninclude-system-site-packages = false\n")
        script = project / "report.py"
        script.write_text("print('report')\n")
        argv = [str(interpreter), "-I", "-S", "-B", str(script)]
        command = shlex.join(argv)
        assert _execute(argv, project, home) == "report\n"
        assert marker.read_text() == "first"
        before = _inventory(command, project)
        assert before is not None
        metadata = config.stat()
        config.write_text(f"home = {alternate.parent}\ninclude-system-site-packages = false\n")
        assert config.stat().st_size == metadata.st_size
        os.utime(config, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
        after = _inventory(command, project)
        assert marker.read_text() == "first", "configuration discovery must not execute the new startup"
        assert _execute(argv, project, home) == "report\n"
        assert marker.read_text() == "first", "the loaded libpython still chooses its own bootstrap"
        assert after is None, "conflicting metadata must not certify the unexecuted installation"


@pytest.mark.parametrize("selector", ["zip", "path-override", "bin-config"])
def test_unbound_python_path_selectors_are_specific_uncertainty(
    native_context_digest: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, selector: str
) -> None:
    del native_context_digest
    parent, home = _environment(tmp_path, monkeypatch)
    with tempfile.TemporaryDirectory(prefix="selectors-", dir=parent) as directory:
        project = Path(directory).resolve()
        interpreter, installed = _copy_runtime(project)
        script = project / "report.py"
        script.write_text("print('report')\n")
        argv = [str(interpreter), "-I", "-S", "-B", str(script)]
        command = shlex.join(argv)
        assert _execute(argv, project, home) == "report\n"
        assert _inventory(command, project) is not None
        paths = {
            "zip": installed.parent / f"python{sys.version_info.major}{sys.version_info.minor}.zip",
            "path-override": interpreter.with_name(interpreter.name + "._pth"),
            "bin-config": interpreter.parent / "pyvenv.cfg",
        }
        paths[selector].write_bytes(b"unbound path selection")
        result, receipt = _verdict()
        assert native_launch_evidence(
            harness="claude-code",
            tool_name="Bash",
            payload={"tool_name": "Bash", "tool_input": {"command": command}, "cwd": str(project)},
            native_result=result,
            native_receipt=receipt,
            workspace=project,
            home_dir=project.parent / "home",
        ) == (None, "python_runtime_bootstrap_unproven")


def test_system_site_configuration_changes_real_startup_and_observed_inventory(
    native_context_digest: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    del native_context_digest
    parent, home = _environment(tmp_path, monkeypatch)
    with tempfile.TemporaryDirectory(prefix="system-site-", dir=parent) as directory:
        project = Path(directory).resolve()
        base_image, installed = _copy_runtime(project)
        shutil.copy2(Path(sysconfig.get_path("stdlib")) / "_sitebuiltins.py", installed / "_sitebuiltins.py")
        shutil.copy2(
            Path(sysconfig.get_path("stdlib")) / "encodings" / "utf_8_sig.py",
            installed / "encodings" / "utf_8_sig.py",
        )
        site = installed / "site-packages"
        site.mkdir()
        (site / "hook.pth").write_text("import fixture_startup\n")
        (site / "fixture_startup.py").write_text("print('activated')\n")
        venv = project / "venv"
        (venv / "bin").mkdir(parents=True)
        (venv / "lib" / installed.name / "site-packages").mkdir(parents=True)
        interpreter = venv / "bin" / base_image.name
        interpreter.symlink_to(base_image)
        config = venv / "pyvenv.cfg"
        body = f"home = {base_image.parent}\ninclude-system-site-packages = false\n"
        config.write_text(body)
        script = project / "report.py"
        script.write_text("print('report')\n")
        argv = [str(interpreter), "-I", "-B", str(script)]
        command = shlex.join(argv)
        assert _execute(argv, project, home) == "report\n"
        before = _inventory(command, project)
        assert before is not None
        metadata = config.stat()
        config.write_text(body.replace("false", "true "))
        assert config.stat().st_size == metadata.st_size
        os.utime(config, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
        after = _inventory(command, project)
        assert _execute(argv, project, home) == "activated\nreport\n"
        assert after is not None and after != before


def test_dynamic_bootstrap_cannot_reuse_identity_when_outside_code_changes(
    native_context_digest: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    del native_context_digest
    parent, home = _environment(tmp_path, monkeypatch)
    with tempfile.TemporaryDirectory(prefix="dynamic-bootstrap-", dir=parent) as directory:
        project = Path(directory).resolve()
        interpreter, installed = _copy_runtime(project)
        marker = project / "outside-code-marker"
        payload = project / "outside-code.py"
        body = (
            f"import posix\nfd = posix.open({str(marker)!r}, 0x601, 0o600)\nposix.write(fd, b'safe')\nposix.close(fd)\n"
        )
        payload.write_text(body)
        codec = installed / "encodings" / "utf_8.py"
        codec.write_text(codec.read_text() + f"\nimport _io\nexec(_io.open({str(payload)!r}, 'rb').read(), {{}})\n")
        script = project / "report.py"
        script.write_text("print('report')\n")
        argv = [str(interpreter), "-I", "-S", "-B", str(script)]
        command = shlex.join(argv)
        before = _permission(command, project)
        inventory_before = _inventory(command, project)
        assert not marker.exists(), "identity discovery cannot execute the bootstrap"
        assert _execute(argv, project, home) == "report\n"
        assert marker.read_text() == "safe"
        metadata = payload.stat()
        payload.write_text(body.replace("b'safe'", "b'evil'"))
        os.utime(payload, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
        after = _permission(command, project)
        inventory_after = _inventory(command, project)
        assert marker.read_text() == "safe", "identity discovery cannot execute outside code"
        assert _execute(argv, project, home) == "report\n"
        assert marker.read_text() == "evil"
        assert inventory_before == inventory_after, "observations alone do not prove a closed code identity"
        # Off the execution-owner route the review keeps both approval choices
        # (``docs/guard/approval-invariant.md``). The token is the command
        # hash, so it is unchanged by code the observation never closed over:
        # the approval claims the command, never the bytes behind it.
        assert before == after
        assert before[0] is not None and before[1] is None
