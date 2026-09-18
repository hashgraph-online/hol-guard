"""Qualify retained Python Secrets through a supplied wheel's real launchers.

Run using that installation's Python with -I. All scan inputs are generated
locally. Receipts contain identities, dimensions and result digests, never
input credentials, full CLI payloads, private paths or raw exception text.
The optional mutation worker loads the installed distribution's entrypoint
under a deterministic filesystem race; ordinary cases execute its launcher.
"""

from __future__ import annotations

import argparse
import ast
import base64
import csv
import errno
import hashlib
import hmac
import importlib
import importlib.metadata
import io
import json
import math
import ntpath
import os
import platform
import re
import subprocess
import sys
import sysconfig
import tempfile
import time
import zipfile
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_BODY = "7tH3mZ5qP9vC2xL4nR6sB8wF1jK0dE5uA7iY"
_PROVIDERS = (
    ("github-token", "GITHUB_TOKEN", "ghp_" + _BODY),
    ("gitlab-token", "GITLAB_TOKEN", "glpat-" + _BODY),
    ("aws-access-key", "AWS_ACCESS_KEY_ID", "AKIA" + "7H3MZ5QP9VC2XL4N"),
    ("slack-token", "SLACK_TOKEN", "xoxb-" + _BODY),
    ("slack-webhook", "SLACK_WEBHOOK", "https://hooks.slack.com/services/" + _BODY),
    ("stripe-secret-key", "STRIPE_SECRET_KEY", "sk_live_" + _BODY),
    ("openai-api-key", "OPENAI_API_KEY", "sk-proj-" + _BODY),
    ("anthropic-api-key", "ANTHROPIC_API_KEY", "sk-ant-" + _BODY),
    ("huggingface-token", "HF_TOKEN", "hf_" + _BODY),
    ("npm-token", "NPM_TOKEN", "npm_" + _BODY),
    ("pypi-token", "PYPI_TOKEN", "pypi-" + _BODY),
    ("google-api-key", "GOOGLE_API_KEY", "AIza" + _BODY[:35]),
    ("sendgrid-api-key", "SENDGRID_API_KEY", "SG." + _BODY + "." + _BODY[::-1]),
    ("pem-private-key", "PRIVATE_KEY", "-----BEGIN " + "PRIVATE KEY-----"),
    ("database-url-password", "DATABASE_PASSWORD_URL", "postgres://service:" + _BODY + "@localhost/app"),
    ("basic-auth-url-password", "AUTH_PASSWORD_URL", "https://service:" + _BODY + "@localhost/api"),
    ("jwt-token", "AUTH_TOKEN", "eyJ" + _BODY + "." + _BODY[::-1] + "." + _BODY),
)
_PUBLIC_KEYS = {
    "schema",
    "detector_version",
    "files_scanned",
    "commits_scanned",
    "bytes_scanned",
    "history_enabled",
    "truncated",
    "truncation_reasons",
    "finding_count",
    "findings",
    "errors",
}
_FINDING_KEYS = {
    "rule_id",
    "family",
    "severity",
    "confidence",
    "confidence_score",
    "line",
    "path",
    "source",
    "commit",
    "validation",
    "entropy",
    "context_reasons",
}
_MODULES = (
    "codex_plugin_scanner.cli",
    "codex_plugin_scanner.path_support",
    "codex_plugin_scanner.guard.secrets.cli",
    "codex_plugin_scanner.guard.secrets.secret_detection",
    "codex_plugin_scanner.guard.secrets.secret_repository_scanner",
    "codex_plugin_scanner.guard.secrets.secret_staged_scanner",
    "codex_plugin_scanner.guard.secrets.git_blob_scan_cache",
    "codex_plugin_scanner.guard.secrets.git_object_reader",
)
_MAX_OUTPUT = 2 * 1024 * 1024
_MAX_LAUNCHER = 4 * 1024 * 1024
_MAX_WRAPPER = 8192


class ProbeError(RuntimeError):
    """Only fixed, non-sensitive codes may be included in a receipt."""


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise ProbeError(code)


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _public_digest(value: object) -> str:
    return _digest(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


def _unsupported_link(error: OSError | NotImplementedError) -> bool:
    return (
        isinstance(error, NotImplementedError)
        or error.errno
        in {
            errno.EACCES,
            errno.EPERM,
            errno.ENOSYS,
            errno.EOPNOTSUPP,
        }
        or getattr(error, "winerror", None) == 1314
    )


def _environment() -> dict[str, str]:
    prefixes = ("HOL_GUARD_", "GUARD_", "PYTEST_", "PYTHON", "GIT_")
    environment = {key: value for key, value in os.environ.items() if not key.startswith(prefixes)}
    environment.update(
        {
            "PYTHONSAFEPATH": "1",
            "PYTHONNOUSERSITE": "1",
            "PYTHONUTF8": "1",
            "NO_COLOR": "1",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
        }
    )
    return environment


def _wrapper_templates(module: str) -> tuple[str, str]:
    uv = (
        "import sys\n"
        f"from {module} import main\n"
        'if __name__ == "__main__":\n'
        '    if sys.argv[0].endswith("-script.pyw"):\n'
        "        sys.argv[0] = sys.argv[0][:-11]\n"
        '    elif sys.argv[0].endswith(".exe"):\n'
        "        sys.argv[0] = sys.argv[0][:-4]\n"
        "    sys.exit(main())\n"
    )
    distlib = (
        "import re\nimport sys\n"
        f"from {module} import main\n"
        'if __name__ == "__main__":\n'
        "    sys.argv[0] = re.sub(r'(-script\\.pyw|\\.exe)?$', '', sys.argv[0])\n"
        "    sys.exit(main())\n"
    )
    return uv, distlib


def _windows_launcher_resources(path: Path) -> dict[str, bytes] | None:
    """Read uv 0.9.26 resources as data; LoadLibrary does not execute its code."""
    import ctypes
    from ctypes import wintypes

    library = ctypes.WinDLL("kernel32", use_last_error=True)
    library.LoadLibraryExW.argtypes = (wintypes.LPCWSTR, wintypes.HANDLE, wintypes.DWORD)
    library.LoadLibraryExW.restype = wintypes.HMODULE
    library.FindResourceW.argtypes = (wintypes.HMODULE, wintypes.LPCWSTR, ctypes.c_void_p)
    library.FindResourceW.restype = wintypes.HANDLE
    library.SizeofResource.argtypes = (wintypes.HMODULE, wintypes.HANDLE)
    library.SizeofResource.restype = wintypes.DWORD
    library.LoadResource.argtypes = (wintypes.HMODULE, wintypes.HANDLE)
    library.LoadResource.restype = wintypes.HANDLE
    library.LockResource.argtypes = (wintypes.HANDLE,)
    library.LockResource.restype = ctypes.c_void_p
    library.FreeLibrary.argtypes = (wintypes.HMODULE,)
    library.FreeLibrary.restype = wintypes.BOOL
    handle = library.LoadLibraryExW(str(path), None, 2)  # LOAD_LIBRARY_AS_DATAFILE
    _require(bool(handle), "launcher_resource_load")
    try:
        output = {}
        for name, limit in (
            ("UV_TRAMPOLINE_KIND", 1),
            ("UV_PYTHON_PATH", 4096),
            ("UV_SCRIPT_DATA", _MAX_WRAPPER + 1024),
        ):
            resource = library.FindResourceW(handle, name, ctypes.c_void_p(10))  # RT_RCDATA
            if not resource and name == "UV_TRAMPOLINE_KIND":
                return None
            _require(bool(resource), "launcher_resource_missing")
            size = library.SizeofResource(handle, resource)
            _require(0 < size <= limit, "launcher_resource_size")
            loaded = library.LoadResource(handle, resource)
            _require(bool(loaded), "launcher_resource_load")
            pointer = library.LockResource(loaded)
            _require(bool(pointer), "launcher_resource_pointer")
            output[name] = ctypes.string_at(pointer, size)
        return output
    finally:
        library.FreeLibrary(handle)


def _launcher_wrapper(
    content: bytes, *, module: str, interpreter: str, windows: bool, resources: dict[str, bytes] | None = None
) -> dict[str, object]:
    """Validate supported generated wrappers without executing their source."""
    _require(0 < len(content) <= _MAX_LAUNCHER, "launcher_size")
    try:
        if windows:
            _require(content.startswith(b"MZ"), "launcher_executable_format")
            if resources is not None:
                _require(resources["UV_TRAMPOLINE_KIND"] == b"\x01", "launcher_trampoline_kind")
                executable = resources["UV_PYTHON_PATH"].decode("utf-8")
                payload = resources["UV_SCRIPT_DATA"]
                _require(len(payload) <= _MAX_WRAPPER + 1024, "launcher_wrapper_size")
            else:
                payload = content
            with zipfile.ZipFile(io.BytesIO(payload)) as archive:
                _require(archive.namelist() == ["__main__.py"], "launcher_embedded_wrapper")
                info = archive.getinfo("__main__.py")
                _require(info.file_size <= _MAX_WRAPPER, "launcher_wrapper_size")
                source = archive.read(info)
                prefix = payload[: info.header_offset]
            if resources is None:
                marker = prefix.rfind(b"#!")
                _require(marker >= 2, "launcher_interpreter_directive")
                directive = prefix[marker:]
        else:
            directive, _ = content.split(b"\n", 1)
            directive += b"\n"
            # Keep the shebang: Python recognizes encoding cookies only on
            # the original first two lines when it loads source bytes.
            source = content
        if resources is None:
            _require(directive.startswith(b"#!") and directive.endswith(b"\n"), "launcher_interpreter_directive")
            executable = directive[2:].rstrip(b"\r\n").decode("utf-8")
            if windows and executable.startswith('"') and executable.endswith('"'):
                executable = executable[1:-1]
        paths = ntpath if windows else os.path
        _require(
            paths.isabs(executable)
            and paths.normcase(paths.normpath(executable)) == paths.normcase(paths.normpath(interpreter)),
            "launcher_interpreter_mismatch",
        )
        _require(len(source) <= _MAX_WRAPPER, "launcher_wrapper_size")
        observed = ast.dump(ast.parse(source), include_attributes=False)
        templates = _wrapper_templates(module)
        matches = [
            index
            for index, template in enumerate(templates)
            if observed == ast.dump(ast.parse(template), include_attributes=False)
        ]
        _require(len(matches) == 1, "launcher_entrypoint_wrapper_mismatch")
    except ProbeError:
        raise
    except (ValueError, UnicodeError, SyntaxError, zipfile.BadZipFile, KeyError):
        raise ProbeError("launcher_wrapper_invalid") from None
    return {
        "interpreter_matches_current_installation": True,
        "wrapper": ("uv", "distlib")[matches[0]],
        "windows_embedded_wrapper": windows,
        "uv_pe_resources": resources is not None,
    }


def _launcher_binding(distribution: Any, launcher: Path, module: str) -> tuple[str, dict[str, object]]:
    _require(not launcher.is_symlink(), "launcher_symlink")
    _require(launcher.stat().st_size <= _MAX_LAUNCHER, "launcher_size")
    with launcher.open("rb") as stream:
        content = stream.read(_MAX_LAUNCHER + 1)
    _require(len(content) <= _MAX_LAUNCHER, "launcher_size")
    record = distribution.read_text("RECORD")
    _require(isinstance(record, str) and len(record) <= 4 * 1024 * 1024, "installed_record_missing_or_large")
    launcher_path = os.path.normcase(os.path.abspath(launcher))
    entries = [
        row
        for row in csv.reader(io.StringIO(record))
        if len(row) == 3 and os.path.normcase(os.path.abspath(distribution.locate_file(row[0]))) == launcher_path
    ]
    expected_hash = "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=").decode()
    _require(len(entries) == 1 and entries[0][1:] == [expected_hash, str(len(content))], "launcher_record_mismatch")
    executable = os.path.abspath(sys.executable)
    prefix = os.path.abspath(sys.prefix)
    _require(os.path.commonpath((prefix, executable)) == prefix, "launcher_interpreter_outside_prefix")
    # Do not resolve Python symlinks: different venvs can share the base inode.
    resources = _windows_launcher_resources(launcher) if os.name == "nt" else None
    binding = _launcher_wrapper(
        content, module=module, interpreter=executable, windows=os.name == "nt", resources=resources
    )
    with launcher.open("rb") as stream:
        _require(stream.read(_MAX_LAUNCHER + 1) == content, "launcher_changed_during_attestation")
    binding["record_verified"] = True
    return _digest(content), binding


def _attest(wheel: Path, source_sha: str) -> tuple[dict[str, object], dict[str, Path]]:
    _require(bool(sys.flags.isolated), "isolated_interpreter_required")
    _require(re.fullmatch(r"[0-9a-f]{40}", source_sha) is not None, "source_identity")
    distribution = importlib.metadata.distribution("hol-guard")
    origin = json.loads(distribution.read_text("direct_url.json") or "{}")
    _require(not origin.get("dir_info", {}).get("editable", False), "editable_install")
    module_digests: dict[str, str] = {}
    with zipfile.ZipFile(wheel) as archive:
        for name in _MODULES:
            relative = name.replace(".", "/") + ".py"
            expected = Path(str(distribution.locate_file(relative))).resolve(strict=True)
            module = importlib.import_module(name)
            _require(Path(module.__file__).resolve() == expected, "wheel_import_required")
            _require("site-packages" in expected.parts, "wheel_location_required")
            content = expected.read_bytes()
            _require(content == archive.read(relative), "installed_module_differs_from_wheel")
            module_digests[name] = _digest(content)
        manifest_names = [name for name in archive.namelist() if name.endswith("/runtime-manifest.json")]
        native_identity: dict[str, object] = {"bundled": False}
        if manifest_names:
            _require(len(manifest_names) == 1, "wheel_manifest_count")
            manifest = json.loads(archive.read(manifest_names[0]))
            _require(manifest.get("source_sha") == source_sha, "wheel_build_identity")
            native_identity = {"bundled": True, "manifest_sha256": _digest(archive.read(manifest_names[0]))}
    entrypoints = {entry.name: entry for entry in distribution.entry_points if entry.group == "console_scripts"}
    launchers: dict[str, Path] = {}
    launcher_digests, launcher_bindings = {}, {}
    for name, target in (
        ("hol-guard", "codex_plugin_scanner.cli:main"),
        ("hol-guard-secrets", "codex_plugin_scanner.guard.secrets.cli:main"),
    ):
        _require(name in entrypoints and entrypoints[name].value == target, "wheel_entrypoint")
        launcher = Path(sysconfig.get_path("scripts")) / (name + (".exe" if os.name == "nt" else ""))
        _require(launcher.is_file(), "installed_launcher_missing")
        _require(launcher.resolve().parent == Path(sysconfig.get_path("scripts")).resolve(), "launcher_location")
        launcher_digests[name], launcher_bindings[name] = _launcher_binding(
            distribution, launcher, target.split(":")[0]
        )
        launchers[name] = launcher.resolve()
    return {
        "package_version": distribution.version,
        "source_sha": source_sha,
        "wheel_sha256": _digest(wheel.read_bytes()),
        "module_sha256": module_digests,
        "launcher_sha256": launcher_digests,
        "launcher_binding": launcher_bindings,
        "native_artifact": native_identity,
    }, launchers


def _rich_fixture() -> tuple[dict[str, bytes], list[tuple[str, str, int]]]:
    files, expected = {}, []
    for index, (rule, name, value) in enumerate(_PROVIDERS):
        path = f"src/provider-{index:02d}.ts"
        files[path] = f'{name}="{value}"\n'.encode()
        expected.append((rule, path, 1))
    token = _PROVIDERS[0][2]
    generic = f'PAYMENTS_API_SECRET="{_BODY}"\n'
    contexts = (
        ("src/generic.ts", generic, "credential-assignment", 1),
        (".env.production", generic, "credential-assignment", 1),
        ("docs/generic.md", generic, None, 0),
        ("tests/fixture.py", "# fixture\n" + f'TOKEN="{token}"\n', None, 0),
        ("tests/.env", "# fixture\n" + f'TOKEN="{token}"\n', "github-token", 2),
        ("docs/provider.md", f'TOKEN="{token}"\n', "github-token", 1),
        ("src/unicode.ts", "# café\r\n# 雪\n" + f'TOKEN="{token}"\n', "github-token", 3),
        ("src/reference.ts", "API_SECRET=process.env.PAYMENTS_API_SECRET\n", None, 0),
        ("src/low.ts", 'API_SECRET="' + "A" * 36 + '"\n', None, 0),
        ("src/unrelated.ts", f'BUILD_CACHE_KEY="{_BODY}"\n', None, 0),
        ("android/google-services.json", f'current_key="{_PROVIDERS[11][2]}"\n', None, 0),
    )
    for path, text, rule, line in contexts:
        files[path] = text.encode()
        if rule:
            expected.append((rule, path, line))
    return files, expected


def _write_files(root: Path, files: dict[str, bytes]) -> None:
    root.mkdir(parents=True, exist_ok=True)
    for relative, content in files.items():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)


def _links_fixture(line: bytes) -> dict[str, bytes]:
    # NUL remains a Windows device name even with a filename extension.
    return {"original.ts": line, "invalid.ts": b"\xff\xfe", "binary_nul.ts": b"\0TOKEN=ordinary"}


def _validate_public(
    public: object,
    *,
    expected: list[tuple[str, str, int]] | None,
    source: str = "working_tree",
    files: int | None = None,
    size: int | None = None,
    truncated: bool = False,
    errors: list[str] | None = None,
) -> dict[str, Any]:
    _require(isinstance(public, dict) and set(public) == _PUBLIC_KEYS, "public_schema_fields")
    assert isinstance(public, dict)
    _require(public["schema"] == "guard-repository-secret-scan.v1", "public_schema")
    _require(public["truncated"] is truncated and public["errors"] == (errors or []), "completeness")
    findings = public["findings"]
    _require(isinstance(findings, list) and public["finding_count"] == len(findings), "finding_count")
    if files is not None:
        _require(public["files_scanned"] == files, "file_coverage")
    if size is not None:
        _require(public["bytes_scanned"] == size, "byte_coverage")
    actual = []
    for finding in findings:
        _require(set(finding) == _FINDING_KEYS, "finding_public_fields")
        _require(finding["source"] == source, "finding_source")
        _require(finding["commit"] is None or source == "git_history", "finding_commit")
        _require(isinstance(finding["family"], str) and bool(finding["family"]), "finding_family")
        _require(finding["severity"] in {"medium", "high", "critical"}, "finding_severity")
        _require(finding["confidence"] in {"low", "medium", "high"}, "finding_confidence")
        _require(0 <= finding["confidence_score"] <= 1 and math.isfinite(finding["entropy"]), "finding_scores")
        _require(isinstance(finding["context_reasons"], list), "finding_context")
        actual.append((finding["rule_id"], finding["path"], finding["line"]))
    if expected is not None:
        _require(actual == sorted(expected, key=lambda item: (item[1], item[2], item[0])), "independent_occurrences")
    return public


class Probe:
    def __init__(self, launchers: dict[str, Path], root: Path, checkpoint: Callable[[], None]):
        self.launchers, self.root, self.checkpoint = launchers, root, checkpoint
        self.cases: list[dict[str, object]] = []
        self.deadline = time.monotonic() + 180

    def command(self, argv: list[str], *, expected_exit: int, label: str) -> bytes:
        remaining = self.deadline - time.monotonic()
        _require(remaining > 0, "probe_deadline")
        row: dict[str, object] = {"case": label, "status": "running"}
        self.cases.append(row)
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            try:
                result = subprocess.run(
                    argv,
                    cwd=self.root,
                    env=_environment(),
                    stdout=stdout,
                    stderr=stderr,
                    timeout=min(25, remaining),
                    check=False,
                )
            except subprocess.TimeoutExpired:
                row.update(status="failed", reason="command_timeout")
                raise ProbeError("command_timeout") from None
            finally:
                stdout_size, stderr_size = stdout.seek(0, 2), stderr.seek(0, 2)
                stdout.seek(0)
                stderr.seek(0)
                output, error = stdout.read(_MAX_OUTPUT + 1), stderr.read(_MAX_OUTPUT + 1)
                row.update(
                    stdout_bytes=stdout_size,
                    stderr_bytes=stderr_size,
                    stdout_sha256=_digest(output),
                    stderr_sha256=_digest(error),
                    digest_scope="complete" if max(stdout_size, stderr_size) <= _MAX_OUTPUT else "bounded_prefix",
                )
                self.checkpoint()
        row["exit_code"] = result.returncode
        try:
            _require(len(output) <= _MAX_OUTPUT and len(error) <= _MAX_OUTPUT, "command_output_limit")
            _require(
                all(value.encode() not in output + error for value in (_BODY, *(item[2] for item in _PROVIDERS))),
                "candidate_disclosure",
            )
            _require(str(self.root).encode() not in output + error, "private_path_disclosure")
            _require(result.returncode == expected_exit, "unexpected_exit")
        except ProbeError as failure:
            row.update(status="failed", reason=str(failure))
            self.checkpoint()
            raise
        row["status"] = "command_completed"
        self.checkpoint()
        return output

    def public_result(self, raw: bytes, **expectations: Any) -> dict[str, Any]:
        try:
            public = json.loads(raw)
            result = _validate_public(public, **expectations)
        except Exception as failure:
            reason = str(failure) if isinstance(failure, ProbeError) else "invalid_public_payload"
            self.cases[-1].update(status="failed", reason=reason)
            self.checkpoint()
            raise ProbeError(reason) from None
        self.cases[-1].update(
            status="passed",
            validation="full_public_contract",
            public_sha256=_public_digest(result),
            findings=result["finding_count"],
            files=result["files_scanned"],
            bytes=result["bytes_scanned"],
        )
        self.checkpoint()
        return result

    def git(self, root: Path, *arguments: str) -> str:
        # Repository metadata is local test input; do not retain its output.
        operation = arguments[0] if arguments and arguments[0] in {"init", "config", "add", "commit"} else "other"
        row: dict[str, object] = {
            "case": "fixture_git_setup",
            "stage": "fixture_setup",
            "operation": operation,
            "fixture": root.name if root.name in {"rich", "bounds", "many", "history", "links"} else "other",
            "status": "failed",
        }
        try:
            result = subprocess.run(
                ["git", "-C", str(root), *arguments],
                cwd=self.root,
                env=_environment(),
                capture_output=True,
                check=False,
                timeout=20,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            row.update(error_type=type(error).__name__, reason="fixture_git_setup")
            self.cases.append(row)
            self.checkpoint()
            raise ProbeError("fixture_git_setup") from None
        if result.returncode != 0:
            row.update(
                exit_code=result.returncode,
                reason="fixture_git_setup",
                stdout_bytes=len(result.stdout),
                stderr_bytes=len(result.stderr),
                stdout_sha256=_digest(result.stdout[:_MAX_OUTPUT]),
                stderr_sha256=_digest(result.stderr[:_MAX_OUTPUT]),
                digest_scope="complete"
                if max(len(result.stdout), len(result.stderr)) <= _MAX_OUTPUT
                else "bounded_prefix",
            )
            self.cases.append(row)
            self.checkpoint()
            raise ProbeError("fixture_git_setup")
        return result.stdout.decode().strip()

    def repository(self, root: Path, files: dict[str, bytes]) -> None:
        _write_files(root, files)
        self.git(root, "init")
        self.git(root, "config", "core.autocrlf", "false")
        self.git(root, "config", "user.name", "Guard Qualification")
        self.git(root, "config", "user.email", "guard-qualification@example.invalid")
        self.git(root, "add", ".")

    def scan(
        self,
        label: str,
        target: Path,
        *,
        arguments: tuple[str, ...] = (),
        exit_code: int = 0,
        alias: bool = False,
        **expectations: Any,
    ) -> dict[str, Any]:
        name = "hol-guard-secrets" if alias else "hol-guard"
        argv = [str(self.launchers[name]), *([] if alias else ["secrets"]), "scan", str(target), "--json", *arguments]
        raw = self.command(argv, expected_exit=exit_code, label=label)
        return self.public_result(raw, **expectations)


def _mutation_worker(arguments: argparse.Namespace) -> int:
    _, launchers = _attest(arguments.wheel, arguments.source_sha)
    root = arguments.mutation_worker.resolve()
    victim = root / "a-changed.ts"
    original_path_open, original_os_open = Path.open, os.open
    triggered = False

    def mutate(path: object, readable: bool) -> None:
        nonlocal triggered
        if readable and isinstance(path, (str, Path)) and Path(path) == victim and not triggered:
            triggered = True
            if arguments.mutation_kind == "growth":
                victim.write_bytes(b"X" * 2048)
            else:
                victim.unlink()
                if arguments.mutation_kind == "symlink":
                    victim.symlink_to(root.parent / "outside.ts")
                else:
                    victim.write_bytes(b"replacement")

    def path_open(path: Path, *args: Any, **kwargs: Any) -> Any:
        mutate(path, kwargs.get("mode", args[0] if args else "r") == "rb")
        return original_path_open(path, *args, **kwargs)

    def os_open(path: object, flags: int, *args: Any, **kwargs: Any) -> int:
        access_mask = getattr(os, "O_ACCMODE", os.O_WRONLY | os.O_RDWR)
        mutate(path, flags & access_mask == os.O_RDONLY)
        return original_os_open(path, flags, *args, **kwargs)

    entry = next(
        entry
        for entry in importlib.metadata.distribution("hol-guard").entry_points
        if entry.group == "console_scripts" and entry.name == "hol-guard"
    )
    sys.argv = [
        str(launchers["hol-guard"]),
        "secrets",
        "scan",
        str(root),
        "--json",
        "--max-file-bytes",
        "1024",
        "--fail-on-findings",
    ]
    Path.open, os.open = path_open, os_open
    try:
        code = entry.load()()
    finally:
        Path.open, os.open = original_path_open, original_os_open
    _require(triggered, "mutation_not_triggered")
    return code


def _exercise(probe: Probe, wheel: Path, source_sha: str) -> None:
    rich, expected = _rich_fixture()
    target = probe.root / "rich"
    probe.repository(target, rich)
    rich_result = probe.scan(
        "rich_launcher", target, expected=expected, files=len(rich), size=sum(map(len, rich.values()))
    )
    alias = probe.scan("rich_dedicated_launcher", target, alias=True, expected=expected)
    repeated = probe.scan(
        "rich_fail_and_repeat", target, arguments=("--fail-on-findings",), exit_code=3, expected=expected
    )
    _require(rich_result == alias == repeated, "full_public_entrypoint_parity")
    for relative in rich:
        (target / relative).write_bytes(b"VALUE=ordinary\n")
    probe.scan("safe_unstaged_working_tree", target, expected=[], files=len(rich))
    staged = probe.scan(
        "rich_staged_original_bytes",
        target,
        arguments=("--staged", "--fail-on-findings"),
        exit_code=3,
        expected=expected,
        source="staged",
        files=len(rich),
        size=sum(map(len, rich.values())),
    )
    staged_alias = probe.scan(
        "rich_staged_dedicated_launcher",
        target,
        alias=True,
        arguments=("--staged",),
        expected=expected,
        source="staged",
    )
    _require(staged == staged_alias, "full_public_staged_parity")
    normalized = json.loads(json.dumps(staged))
    for finding in normalized["findings"]:
        finding["source"] = "working_tree"
    _require(normalized == rich_result, "full_public_working_staged_parity")

    from codex_plugin_scanner.guard.secrets.cli import build_parser
    from codex_plugin_scanner.guard.secrets.secret_detection import scan_secret_text

    defaults = vars(build_parser().parse_args(["scan"]))
    expected_defaults = {
        "max_files": 5000,
        "max_file_bytes": 2097152,
        "max_total_bytes": 134217728,
        "max_findings": 500,
        "max_commits": 500,
    }
    _require({key: defaults[key] for key in expected_defaults} == expected_defaults, "installed_default_bounds")
    token = _PROVIDERS[0][2]
    line = f'TOKEN="{token}"\n'.encode()
    finding = scan_secret_text(line.decode(), path="src/settings.ts").findings[0]
    key = b"guard-offline-qualification-caller"
    public = finding.to_public_dict(fingerprint_key=key)
    independent_hmac = hmac.new(key, ("github-token\0" + token).encode(), hashlib.sha256).hexdigest()
    _require(public["fingerprint"] == independent_hmac, "caller_hmac")
    _require(finding.fingerprint(b"different-caller") != independent_hmac, "caller_hmac_separation")
    probe.cases.append(
        {"case": "installed_defaults_and_caller_hmac", "status": "passed", "defaults": expected_defaults}
    )

    bounded = probe.root / "bounds"
    probe.repository(bounded, {"a.ts": line, "b.ts": line})
    for staged_mode in (False, True):
        prefix = ("--staged",) if staged_mode else ()
        label = "staged" if staged_mode else "working"
        source = "staged" if staged_mode else "working_tree"
        for option in ("--max-files", "--max-findings"):
            probe.scan(
                label + option,
                bounded,
                arguments=(*prefix, option, "1", "--fail-on-findings"),
                exit_code=2,
                expected=[("github-token", "a.ts", 1)],
                source=source,
                truncated=True,
            )
        probe.scan(
            label + "_total_byte_bound",
            bounded,
            arguments=(*prefix, "--max-total-bytes", "1"),
            exit_code=2,
            expected=[],
            files=0,
            size=0,
            truncated=True,
        )
        probe.scan(
            label + "_file_byte_bound",
            bounded,
            arguments=(*prefix, "--max-file-bytes", "1"),
            exit_code=2 if staged_mode else 0,
            expected=[],
            files=0,
            size=0,
            truncated=staged_mode,
            errors=["git_staged_blob_unavailable_or_oversized"] if staged_mode else [],
        )
    many = probe.root / "many"
    probe.repository(many, {"a.ts": line * 501, "z.ts": b"VALUE=ordinary\n"})
    for staged_mode in (False, True):
        prefix = ("--staged",) if staged_mode else ()
        label = "staged" if staged_mode else "working"
        source = "staged" if staged_mode else "working_tree"
        probe.scan(
            label + "_default_findings",
            many,
            arguments=(*prefix, "--fail-on-findings"),
            exit_code=2,
            expected=[("github-token", "a.ts", number) for number in range(1, 501)],
            source=source,
            truncated=True,
        )
        probe.scan(
            label + "_explicit_findings",
            many,
            arguments=(*prefix, "--max-findings", "502", "--fail-on-findings"),
            exit_code=3,
            expected=[("github-token", "a.ts", number) for number in range(1, 502)],
            source=source,
        )
    large = probe.root / "large.ts"
    large.write_bytes(line + b" " * (2097153 - len(line)))
    probe.scan("default_file_size", large, expected=[], files=0, size=0)
    probe.scan(
        "explicit_file_size",
        large,
        arguments=("--max-file-bytes", "2097153"),
        expected=[("github-token", "large.ts", 1)],
        files=1,
        size=2097153,
    )
    probe.scan(
        "non_git_staged_error",
        probe.root,
        arguments=("--staged",),
        exit_code=2,
        expected=[],
        files=0,
        size=0,
        truncated=True,
        errors=["git_staged_enumeration_failed"],
    )
    probe.command(
        [str(probe.launchers["hol-guard"]), "secrets", "scan", str(probe.root / "missing"), "--json"],
        expected_exit=2,
        label="missing_target",
    )
    probe.cases[-1].update(status="passed", validation="expected_exit_and_privacy")
    probe.checkpoint()

    history = probe.root / "history"
    probe.repository(history, {"config.ts": line})
    probe.git(history, "commit", "-m", "first")
    (history / "config.ts").write_bytes(line + b"# revision two\n")
    probe.git(history, "add", ".")
    probe.git(history, "commit", "-m", "second")
    history_raw = probe.command(
        [
            str(probe.launchers["hol-guard"]),
            "secrets",
            "scan",
            str(history),
            "--json",
            "--history",
            "--max-commits",
            "1",
            "--fail-on-findings",
        ],
        expected_exit=2,
        label="explicit_history_commit_bound",
    )
    history_result = json.loads(history_raw)
    _require(
        set(history_result) == _PUBLIC_KEYS
        and history_result["history_enabled"]
        and history_result["truncated"]
        and history_result["commits_scanned"] == 1
        and history_result["finding_count"] == 2
        and history_result["errors"] == []
        and history_result["truncation_reasons"] == ["max_commits"],
        "history_commit_bound",
    )
    _require(
        {finding["source"] for finding in history_result["findings"]} == {"working_tree", "git_history"},
        "history_occurrence_sources",
    )
    probe.cases[-1].update(
        status="passed", validation="independent_history_bounds", public_sha256=_public_digest(history_result)
    )
    probe.checkpoint()

    links = probe.root / "links"
    probe.repository(links, _links_fixture(line))
    link_expected = [("github-token", "original.ts", 1)]
    files = 3
    for name, operation in (
        ("hardlink", lambda path: os.link(links / "original.ts", path)),
        ("internal_symlink", lambda path: path.symlink_to(links / "original.ts")),
    ):
        try:
            operation(links / (name + ".ts"))
        except (OSError, NotImplementedError) as error:
            _require(_unsupported_link(error), "link_setup_failed")
            probe.cases.append({"case": name, "status": "unsupported_by_host", "error_type": type(error).__name__})
        else:
            link_expected.append(("github-token", name + ".ts", 1))
            files += 1
    outside = probe.root / "outside.ts"
    outside.write_bytes(line)
    symlinks_supported = True
    try:
        (links / "external.ts").symlink_to(outside)
        (links / "dangling.ts").symlink_to(probe.root / "absent")
    except (OSError, NotImplementedError) as error:
        _require(_unsupported_link(error), "link_setup_failed")
        symlinks_supported = False
        probe.cases.append(
            {
                "case": "external_and_dangling_symlink",
                "status": "unsupported_by_host",
                "error_type": type(error).__name__,
            }
        )
    probe.scan(
        "links_invalid_encoding_binary", links, expected=link_expected, files=files, size=len(line) * len(link_expected)
    )
    for kind in ("growth", "replacement", "symlink"):
        if kind == "symlink" and not symlinks_supported:
            probe.cases.append({"case": "mutation_symlink", "status": "unsupported_by_host"})
            continue
        mutation_root = probe.root / ("mutation-" + kind)
        _write_files(mutation_root, {"a-changed.ts": b"initial", "b-observed.ts": line})
        command = [
            sys.executable,
            "-I",
            str(Path(__file__).resolve()),
            "--wheel",
            str(wheel),
            "--source-sha",
            source_sha,
            "--mutation-worker",
            str(mutation_root),
            "--mutation-kind",
            kind,
        ]
        raw = probe.command(command, expected_exit=2, label="installed_entrypoint_mutation_" + kind)
        probe.public_result(
            raw,
            expected=[("github-token", "b-observed.ts", 1)],
            files=1,
            size=len(line),
            truncated=True,
            errors=["working_tree_file_changed"],
        )
    probe.checkpoint()
    _require(all(row["status"] in {"passed", "unsupported_by_host"} for row in probe.cases), "unfinished_case")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel", required=True, type=Path)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--json", type=Path)
    parser.add_argument("--mutation-worker", type=Path)
    parser.add_argument("--mutation-kind", choices=("growth", "replacement", "symlink"))
    arguments = parser.parse_args()
    if arguments.mutation_worker is not None:
        try:
            return _mutation_worker(arguments)
        except Exception:
            print("installed_secrets_mutation_failed", file=sys.stderr)
            return 1
    _require(arguments.json is not None, "receipt_path_required")
    destination = arguments.json.resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    receipt: dict[str, object] = {
        "schema": "hol-guard.installed-offline-secrets.v1",
        "run_complete": False,
        "platform": sys.platform,
        "machine": platform.machine(),
        "python": platform.python_version(),
        "scope": "installed retained Python; no native detector activation",
        "output_capture": "temporary files; post-exit 2MiB parser/buffer limit; no active child-output disk limit",
        "cases": [],
        "probe_sha256": _digest(Path(__file__).read_bytes()),
        "started_utc": datetime.now(UTC).isoformat(),
    }

    def checkpoint() -> None:
        temporary = destination.with_suffix(destination.suffix + ".partial")
        temporary.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.replace(temporary, destination)

    checkpoint()
    failure_stage = "initial_attestation"
    try:
        identity, launchers = _attest(arguments.wheel.resolve(), arguments.source_sha)
        receipt["identity"] = identity
        failure_stage = "fixture_setup"
        with tempfile.TemporaryDirectory(prefix="guard-installed-secrets-") as temporary:
            probe = Probe(launchers, Path(temporary).resolve(), checkpoint)
            receipt["cases"] = probe.cases
            failure_stage = "exercise"
            _exercise(probe, arguments.wheel.resolve(), arguments.source_sha)
            failure_stage = "final_attestation"
            final_identity, _ = _attest(arguments.wheel.resolve(), arguments.source_sha)
            _require(final_identity == identity, "installed_artifact_changed_during_probe")
            failure_stage = "fixture_cleanup"
        receipt.update(run_complete=True, status="passed", finished_utc=datetime.now(UTC).isoformat())
    except Exception as error:
        reason = str(error) if isinstance(error, ProbeError) else "unexpected_probe_error"
        cases = receipt["cases"]
        if cases and cases[-1]["status"] in {"running", "command_completed"}:
            cases[-1].update(status="failed", reason=reason)
        elif not cases or cases[-1]["status"] != "failed":
            cases.append(
                {"case": "probe_" + failure_stage, "stage": failure_stage, "status": "failed", "reason": reason}
            )
        receipt.update(
            status="failed",
            reason=reason,
            error_type=type(error).__name__,
            failure_stage=failure_stage,
        )
        checkpoint()
        print("installed_offline_secrets_failed", file=sys.stderr)
        return 1
    checkpoint()
    print(json.dumps({"schema": receipt["schema"], "status": "passed", "case_count": len(receipt["cases"])}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
