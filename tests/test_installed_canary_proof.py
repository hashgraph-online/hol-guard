from __future__ import annotations

import base64
import hashlib
import importlib.metadata
import importlib.util
import json
import marshal
import os
import struct
import subprocess
import sys
import zipfile
from pathlib import Path
from typing import cast

import pytest
from typing_extensions import override

from scripts.installed_canary_proof import (
    InstalledCanaryError,
    _generated_console_scripts,  # pyright: ignore[reportPrivateUsage]
    _pep610_wheel_origin,  # pyright: ignore[reportPrivateUsage]
    load_subject,
    main,
    verify_download,
    verify_installed_record,
    verify_wheel_payloads,
    write_subject,
)
from scripts.run_installed_canary import (
    _codex_install_smoke,  # pyright: ignore[reportPrivateUsage]
    _no_post_execution_proof_smoke,  # pyright: ignore[reportPrivateUsage]
    _runtime_dependency_smoke,  # pyright: ignore[reportPrivateUsage]
    _validate_corpus_bindings,  # pyright: ignore[reportPrivateUsage]
)

VERSION = "2.0.1117.dev123"
SOURCE_SHA = "a" * 40
WHEEL_NAME = f"hol_guard-{VERSION}-py3-none-any.whl"


def test_current_corpus_manifest_is_verified_by_its_canonical_bindings() -> None:
    root = Path(__file__).resolve().parents[1]

    bindings = _validate_corpus_bindings(root)

    assert (
        bindings["manifest_sha256"]
        == hashlib.sha256((root / "tests/fixtures/guard-command-corpus/seed-manifest.json").read_bytes()).hexdigest()
    )
    assert bindings["source_files_verified"] == 1 + len(tuple((root / "tests").glob("guard_command_corpus_oracle*.py")))


def test_harness_without_post_execution_proof_remains_unconfirmed() -> None:
    assert _no_post_execution_proof_smoke() == {
        "harness": "opencode",
        "post_execution_surface": False,
        "execution_status": "allowed_unconfirmed",
        "proof_level": "pre_hook",
        "policy_action": "warn",
        "decision_reason_code": "no_match",
    }


def test_installed_codex_setup_uses_an_isolated_home() -> None:
    assert _codex_install_smoke() == {
        "harness": "codex",
        "active": True,
        "managed_config": True,
    }


def test_installed_wheel_declares_pyyaml_as_a_runtime_dependency() -> None:
    assert _runtime_dependency_smoke() == {
        "name": "pyyaml",
        "specifier": ">=6.0.3",
    }


def test_runtime_dependency_check_normalizes_missing_installed_wheel(monkeypatch: pytest.MonkeyPatch) -> None:
    def missing_distribution(_name: str) -> list[str] | None:
        raise importlib.metadata.PackageNotFoundError("hol-guard")

    monkeypatch.setattr(importlib.metadata, "requires", missing_distribution)

    with pytest.raises(InstalledCanaryError, match="not available"):
        _ = _runtime_dependency_smoke()


def test_installed_codex_setup_normalizes_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    def timed_out(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(["hol-guard", "install", "codex"], timeout=60)

    monkeypatch.setattr(subprocess, "run", timed_out)

    with pytest.raises(InstalledCanaryError, match="timed out"):
        _ = _codex_install_smoke()


def test_installed_codex_setup_reports_bounded_child_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    child_error = "codex_hook_inventory_unsupported_event_shape"

    def failed(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess([], 1, stdout="", stderr=f"prefix-{child_error}" * 300)

    monkeypatch.setattr(subprocess, "run", failed)

    with pytest.raises(InstalledCanaryError, match=child_error) as failure:
        _ = _codex_install_smoke()
    assert len(str(failure.value)) < 2200


class _ConsoleScriptDistribution(importlib.metadata.Distribution):
    @override
    def read_text(self, filename: str) -> str | None:
        return None

    @override
    def locate_file(self, path: str | os.PathLike[str]) -> Path:
        return Path(path)

    @property
    @override
    def entry_points(self) -> importlib.metadata.EntryPoints:
        return importlib.metadata.EntryPoints(
            [importlib.metadata.EntryPoint(name="hol-guard", value="package:main", group="console_scripts")]
        )


def test_generated_console_scripts_follow_the_interpreter_layout(tmp_path: Path) -> None:
    distribution = _ConsoleScriptDistribution()
    posix_root = tmp_path / "posix/lib/python3.12/site-packages"
    windows_root = tmp_path / "windows/Lib/site-packages"

    assert _generated_console_scripts(
        distribution,
        posix_root,
        scripts_root=tmp_path / "posix/bin",
        suffix="",
    ) == {"../../../bin/hol-guard"}
    assert _generated_console_scripts(
        distribution,
        windows_root,
        scripts_root=tmp_path / "windows/Scripts",
        suffix=".exe",
    ) == {"../../Scripts/hol-guard.exe"}


def test_pep610_origin_requires_exact_archive_hash_metadata() -> None:
    digest = "b" * 64
    wheel = {"filename": WHEEL_NAME, "sha256": digest}
    url = f"file:///fixture/{WHEEL_NAME}"
    expected = {"hash": f"sha256={digest}", "hashes": {"sha256": digest}}

    assert _pep610_wheel_origin({"url": url, "archive_info": expected}, wheel).path.endswith(WHEEL_NAME)
    for archive_info in (
        {},
        {"hash": f"sha256={'c' * 64}"},
        {"hashes": {"sha256": digest, "sha512": "d" * 128}},
        {**expected, "unexpected": True},
    ):
        with pytest.raises(InstalledCanaryError, match="PEP 610"):
            _ = _pep610_wheel_origin({"url": url, "archive_info": archive_info}, wheel)
    with pytest.raises(InstalledCanaryError, match="origin"):
        _ = _pep610_wheel_origin({"url": f"{url}#sha256={digest}", "archive_info": expected}, wheel)


def _subject(tmp_path: Path) -> tuple[Path, dict[str, object]]:
    dist = tmp_path / "dist"
    dist.mkdir()
    _ = (dist / WHEEL_NAME).write_bytes(b"immutable-wheel")
    output = tmp_path / "subject.json"
    return output, write_subject(dist, VERSION, SOURCE_SHA, output)


def test_subject_binds_exact_version_source_and_wheel_bytes(tmp_path: Path) -> None:
    output, subject = _subject(tmp_path)

    assert subject == {
        "schema_version": "hol-guard.installed-canary-subject.v1",
        "project": "hol-guard",
        "version": VERSION,
        "source_sha": SOURCE_SHA,
        "wheel": {
            "filename": WHEEL_NAME,
            "sha256": hashlib.sha256(b"immutable-wheel").hexdigest(),
        },
    }
    assert load_subject(output, version=VERSION, source_sha=SOURCE_SHA) == subject


def test_missing_or_mismatched_proof_fails_closed(tmp_path: Path) -> None:
    with pytest.raises(InstalledCanaryError, match="required"):
        _ = load_subject(tmp_path / "missing.json", version=VERSION, source_sha=SOURCE_SHA)

    output, _subject_value = _subject(tmp_path)
    with pytest.raises(InstalledCanaryError, match="source SHA"):
        _ = load_subject(output, version=VERSION, source_sha="b" * 40)


def test_download_must_byte_match_the_build_subject(tmp_path: Path) -> None:
    _output, subject = _subject(tmp_path)
    downloaded = tmp_path / "downloaded"
    downloaded.mkdir()
    wheel = downloaded / WHEEL_NAME
    _ = wheel.write_bytes(b"immutable-wheel")

    assert verify_download(subject, downloaded) == wheel
    _ = wheel.write_bytes(b"different-wheel")
    with pytest.raises(InstalledCanaryError, match="bytes differ"):
        _ = verify_download(subject, downloaded)


def test_verify_download_cli_emits_hash_bound_install_requirement(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    output, _subject_value = _subject(tmp_path)
    downloaded = tmp_path / "downloaded"
    downloaded.mkdir()
    _ = (downloaded / WHEEL_NAME).write_bytes(b"immutable-wheel")

    assert (
        main(
            [
                "verify-download",
                "--subject",
                str(output),
                "--version",
                VERSION,
                "--source-sha",
                SOURCE_SHA,
                "--download-dir",
                str(downloaded),
            ]
        )
        == 0
    )
    result_value = cast(object, json.loads(capsys.readouterr().out))
    assert isinstance(result_value, dict)
    result = cast(dict[str, object], result_value)
    assert result["status"] == "exact"
    requirement = result["requirement"]
    assert isinstance(requirement, str)
    assert requirement.startswith("hol-guard @ file:")
    assert requirement.endswith(f"#sha256={result['sha256']}")


def test_subject_rejects_extra_untrusted_fields(tmp_path: Path) -> None:
    output, subject = _subject(tmp_path)
    subject["untrusted"] = True
    _ = output.write_text(json.dumps(subject), encoding="utf-8")

    with pytest.raises(InstalledCanaryError, match="unexpected shape"):
        _ = load_subject(output, version=VERSION, source_sha=SOURCE_SHA)


def test_verified_wheel_detects_payload_tamper_even_when_installed_record_is_rewritten(tmp_path: Path) -> None:
    root = tmp_path / "site-packages"
    package = root / "codex_plugin_scanner"
    dist_info = root / f"hol_guard-{VERSION}.dist-info"
    package.mkdir(parents=True)
    dist_info.mkdir()
    module = package / "__init__.py"
    metadata = dist_info / "METADATA"
    record = dist_info / "RECORD"
    _ = module.write_bytes(b"trusted-module")
    _ = metadata.write_bytes(b"Name: hol-guard\n")
    _ = record.write_text("codex_plugin_scanner/__init__.py,,\n", encoding="utf-8")
    wheel = tmp_path / WHEEL_NAME
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.write(module, "codex_plugin_scanner/__init__.py")
        archive.write(metadata, f"hol_guard-{VERSION}.dist-info/METADATA")
        archive.write(record, f"hol_guard-{VERSION}.dist-info/RECORD")

    class FakeDistribution(importlib.metadata.Distribution):
        @override
        def read_text(self, filename: str) -> str | None:
            if filename == "METADATA":
                return f"Name: hol-guard\nVersion: {VERSION}\n"
            return None

        @override
        def locate_file(self, path: str | os.PathLike[str]) -> Path:
            return root / str(path)

    distribution = FakeDistribution()
    assert verify_wheel_payloads(distribution, wheel) == 2
    cache_dir = package / "__pycache__"
    cache_dir.mkdir()
    malicious_cache = cache_dir / f"__init__.{sys.implementation.cache_tag}.pyc"
    source_stat = module.stat()
    malicious_code = compile("INJECTED = True\n", str(module), "exec")
    header = importlib.util.MAGIC_NUMBER + struct.pack("<III", 0, int(source_stat.st_mtime), source_stat.st_size)
    _ = malicious_cache.write_bytes(header + marshal.dumps(malicious_code))

    with pytest.raises(InstalledCanaryError, match="files not present"):
        _ = verify_wheel_payloads(distribution, wheel)
    malicious_cache.unlink()
    _ = module.write_bytes(b"rewritten-module")
    digest_bytes = hashlib.sha256(module.read_bytes()).digest()
    rewritten_digest = base64.urlsafe_b64encode(digest_bytes).decode().rstrip("=")
    _ = record.write_text(
        "".join(
            (
                f"codex_plugin_scanner/__init__.py,sha256={rewritten_digest},{module.stat().st_size}\n",
                f"hol_guard-{VERSION}.dist-info/RECORD,,\n",
            )
        ),
        encoding="utf-8",
    )

    assert verify_installed_record(distribution)[1] == 1

    with pytest.raises(InstalledCanaryError, match="differs from the verified wheel"):
        _ = verify_wheel_payloads(distribution, wheel)

    _ = module.write_bytes(b"trusted-module")
    injected = package / "injected.py"
    _ = injected.write_bytes(b"importable-injection")
    rows: list[str] = []
    for path in (module, injected):
        digest = base64.urlsafe_b64encode(hashlib.sha256(path.read_bytes()).digest()).decode().rstrip("=")
        rows.append(f"{path.relative_to(root).as_posix()},sha256={digest},{path.stat().st_size}")
    rows.append(f"hol_guard-{VERSION}.dist-info/RECORD,,")
    _ = record.write_text("\n".join(rows) + "\n", encoding="utf-8")

    assert verify_installed_record(distribution)[1] == 2
    with pytest.raises(InstalledCanaryError, match="files not present"):
        _ = verify_wheel_payloads(distribution, wheel)

    injected.unlink()
    _ = record.write_text(
        "".join(
            (
                f"codex_plugin_scanner/__init__.py,sha256={rows[0].split('sha256=', 1)[1]}\n",
                f"hol_guard-{VERSION}.dist-info/RECORD,,\n",
            )
        ),
        encoding="utf-8",
    )
    external_package = tmp_path / "external-package"
    external_package.mkdir()
    _ = (external_package / "__init__.py").write_bytes(b"SYMLINK_INJECTION_EXECUTED = True")
    linked_package = package / "injectedpkg"
    try:
        linked_package.symlink_to(external_package, target_is_directory=True)
    except OSError:
        pytest.skip("Directory symlinks are unavailable on this platform")

    with pytest.raises(InstalledCanaryError, match="symbolic link"):
        _ = verify_wheel_payloads(distribution, wheel)
