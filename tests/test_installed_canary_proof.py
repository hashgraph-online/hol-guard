from __future__ import annotations

import base64
import hashlib
import importlib.metadata
import importlib.util
import json
import marshal
import os
import struct
import sys
import zipfile
from pathlib import Path
from typing import cast

import pytest
from typing_extensions import override

from scripts.installed_canary_proof import (
    InstalledCanaryError,
    load_subject,
    main,
    verify_download,
    verify_installed_record,
    verify_wheel_payloads,
    write_subject,
)

VERSION = "2.0.1117.dev123"
SOURCE_SHA = "a" * 40
WHEEL_NAME = f"hol_guard-{VERSION}-py3-none-any.whl"


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
