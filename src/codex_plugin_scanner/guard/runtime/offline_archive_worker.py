"""Digest-bound, resource-bounded archive parser used only by the child."""

from __future__ import annotations

import os
import posixpath
import stat
import tarfile
import time
from pathlib import Path
from typing import BinaryIO

from .offline_archive_contract import (
    _NESTED_ARCHIVE_SUFFIXES,
    ArchiveInspectionResult,
    _ArchivePolicyError,
    _result,
)
from .offline_archive_policy import (
    _hash_file,
    _hash_stream,
    _install_script_risk,
    _member_kind,
    _member_path_conflicts,
    _normalized_link_target,
    _preflight_expanded_tar_stream,
    _python_build_script_risk,
    _unsafe_member_reason,
)


def _inspect_archive(
    path: Path,
    *,
    expected_sha256: str,
    timeout_seconds: float,
    max_archive_bytes: int,
    max_files: int,
    max_expanded_bytes: int,
    max_member_bytes: int,
    max_package_json_bytes: int,
    max_decompression_ratio: float,
    max_nested_archives: int,
    max_path_depth: int,
) -> ArchiveInspectionResult:
    deadline = time.monotonic() + timeout_seconds
    try:
        file_stat = path.lstat()
    except OSError:
        return _result(
            "incomplete",
            "external_archive_inspection_incomplete",
            "External archive could not be opened for offline inspection.",
            severity="high",
        )
    if (
        not stat.S_ISREG(file_stat.st_mode)
        or file_stat.st_nlink != 1
        or stat.S_IMODE(file_stat.st_mode) & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH)
    ):
        return _result(
            "blocked",
            "external_archive_blob_rejected",
            "External archive blob is not a regular immutable file.",
            severity="high",
        )
    if file_stat.st_size > max_archive_bytes:
        return _result(
            "blocked",
            "external_archive_download_size_limit",
            "External archive exceeded Guard's inspection size limit.",
            severity="high",
        )
    try:
        actual_sha256, actual_size = _hash_file(path, max_bytes=max_archive_bytes, deadline=deadline)
    except TimeoutError:
        return _result(
            "incomplete",
            "external_archive_inspection_timeout",
            "External archive inspection exceeded Guard's time limit.",
            severity="high",
        )
    except (OSError, ValueError):
        return _result(
            "incomplete",
            "external_archive_inspection_incomplete",
            "External archive could not be read completely for offline inspection.",
            severity="high",
        )
    if actual_size != file_stat.st_size or actual_sha256 != expected_sha256:
        return _result(
            "blocked",
            "external_archive_digest_mismatch",
            "External archive changed between download and offline inspection.",
            severity="high",
            sha256=actual_sha256,
        )
    archive_source: BinaryIO | None = None
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        live_stat = os.fstat(descriptor)
        if (
            not stat.S_ISREG(live_stat.st_mode)
            or live_stat.st_dev != file_stat.st_dev
            or live_stat.st_ino != file_stat.st_ino
            or live_stat.st_nlink != 1
            or live_stat.st_size != actual_size
            or stat.S_IMODE(live_stat.st_mode) & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH)
        ):
            return _result(
                "blocked",
                "external_archive_digest_mismatch",
                "External archive changed before offline inspection.",
                severity="high",
                sha256=actual_sha256,
            )
        archive_source = os.fdopen(descriptor, "rb", closefd=True)
        descriptor = -1
        live_sha256, live_size = _hash_stream(
            archive_source,
            max_bytes=max_archive_bytes,
            deadline=deadline,
        )
        if live_size != actual_size or live_sha256 != expected_sha256:
            return _result(
                "blocked",
                "external_archive_digest_mismatch",
                "External archive changed before offline inspection.",
                severity="high",
                sha256=live_sha256,
            )
        try:
            _preflight_expanded_tar_stream(
                archive_source,
                compressed_size=actual_size,
                max_expanded_bytes=max_expanded_bytes,
                max_decompression_ratio=max_decompression_ratio,
                deadline=deadline,
            )
        except _ArchivePolicyError as error:
            return _result(
                "blocked",
                error.code,
                error.message,
                severity="high",
                sha256=actual_sha256,
            )
        with tarfile.open(fileobj=archive_source, mode="r:*") as archive:
            member_count = 0
            expanded_bytes = 0
            nested_archives = 0
            seen_paths: dict[str, str] = {}
            hardlink_targets: list[str] = []
            for member in archive:
                if time.monotonic() > deadline:
                    return _result(
                        "incomplete",
                        "external_archive_inspection_timeout",
                        "External archive inspection exceeded Guard's time limit.",
                        severity="high",
                        sha256=actual_sha256,
                    )
                member_count += 1
                if member_count > max_files:
                    return _result(
                        "blocked",
                        "tarball_file_count_limit",
                        "External archive exceeded Guard's file-count limit.",
                        severity="high",
                        sha256=actual_sha256,
                    )
                unsafe_reason = _unsafe_member_reason(member)
                if unsafe_reason is not None:
                    return _result(
                        "blocked",
                        "tarball_zip_slip",
                        "External archive contains unsafe paths, links, or special files.",
                        severity="high",
                        sha256=actual_sha256,
                    )
                normalized_name = posixpath.normpath(member.name.replace("\\", "/"))
                if len(normalized_name.split("/")) > max_path_depth:
                    return _result(
                        "blocked",
                        "external_archive_path_depth_limit",
                        "External archive exceeded Guard's path-depth limit.",
                        severity="high",
                        sha256=actual_sha256,
                    )
                kind = _member_kind(member)
                if kind is None:
                    return _result(
                        "blocked",
                        "external_archive_unsupported_member",
                        "External archive contains an unsupported member type.",
                        severity="high",
                        sha256=actual_sha256,
                    )
                portable_path = normalized_name.casefold()
                if _member_path_conflicts(portable_path, kind, seen_paths):
                    return _result(
                        "blocked",
                        "external_archive_path_conflict",
                        "External archive contains duplicate or conflicting member paths.",
                        severity="high",
                        sha256=actual_sha256,
                    )
                seen_paths[portable_path] = kind
                if kind in {"symlink", "hardlink"}:
                    link_target = _normalized_link_target(member, normalized_name)
                    if link_target is None:
                        return _result(
                            "blocked",
                            "tarball_zip_slip",
                            "External archive contains unsafe paths, links, or special files.",
                            severity="high",
                            sha256=actual_sha256,
                        )
                    if kind == "hardlink":
                        hardlink_targets.append(link_target.casefold())
                if member.size < 0 or member.size > max_member_bytes:
                    return _result(
                        "blocked",
                        "external_archive_member_size_limit",
                        "External archive contains an oversized member.",
                        severity="high",
                        sha256=actual_sha256,
                    )
                expanded_bytes += member.size
                if expanded_bytes > max_expanded_bytes:
                    return _result(
                        "blocked",
                        "external_archive_expanded_size_limit",
                        "External archive exceeded Guard's expanded-size limit.",
                        severity="high",
                        sha256=actual_sha256,
                    )
                if expanded_bytes > max(1, actual_size) * max_decompression_ratio:
                    return _result(
                        "blocked",
                        "external_archive_decompression_ratio_limit",
                        "External archive exceeded Guard's decompression-ratio limit.",
                        severity="high",
                        sha256=actual_sha256,
                    )
                if normalized_name.lower().endswith(_NESTED_ARCHIVE_SUFFIXES):
                    nested_archives += 1
                    if nested_archives > max_nested_archives:
                        return _result(
                            "blocked",
                            "external_archive_nesting_limit",
                            "External archive exceeded Guard's nested-archive limit.",
                            severity="high",
                            sha256=actual_sha256,
                        )
                manifest_name = posixpath.basename(normalized_name).lower()
                is_package_manifest = manifest_name == "package.json"
                is_python_build_manifest = manifest_name in {"setup.py", "pyproject.toml"}
                is_node_gyp_manifest = manifest_name == "binding.gyp"
                if (is_package_manifest or is_python_build_manifest or is_node_gyp_manifest) and kind != "file":
                    return _result(
                        "blocked",
                        "external_archive_manifest_link",
                        "External archive build manifest must be an independent regular file.",
                        severity="high",
                        sha256=actual_sha256,
                    )
                if is_node_gyp_manifest:
                    return _result(
                        "blocked",
                        "node_gyp_implicit_install_script",
                        "External archive contains a native build manifest that npm may execute implicitly.",
                        severity="high",
                        sha256=actual_sha256,
                    )
                if not is_package_manifest and not is_python_build_manifest:
                    continue
                if member.size > max_package_json_bytes:
                    return _result(
                        "blocked",
                        "tarball_package_json_limit",
                        "External archive package manifest exceeded Guard's scan limit.",
                        severity="high",
                        sha256=actual_sha256,
                    )
                extracted = archive.extractfile(member)
                if extracted is None:
                    return _result(
                        "incomplete",
                        "external_archive_inspection_incomplete",
                        "External archive package manifest could not be inspected.",
                        severity="high",
                        sha256=actual_sha256,
                    )
                # The member was proven to be a regular file above. The extra
                # byte is a bounded overflow probe; equality with the declared
                # member size also detects a truncated tar stream.
                manifest_payload = extracted.read(min(member.size + 1, max_package_json_bytes + 1))
                if len(manifest_payload) != member.size or len(manifest_payload) > max_package_json_bytes:
                    return _result(
                        "incomplete",
                        "external_archive_inspection_incomplete",
                        "External archive package manifest could not be read completely.",
                        severity="high",
                        sha256=actual_sha256,
                    )
                install_script_risk = (
                    _install_script_risk(manifest_payload)
                    if is_package_manifest
                    else _python_build_script_risk(manifest_name, manifest_payload)
                )
                if install_script_risk is not None:
                    return _result(
                        "blocked",
                        install_script_risk[0],
                        install_script_risk[1],
                        severity="high",
                        sha256=actual_sha256,
                    )
            if any(seen_paths.get(target) != "file" for target in hardlink_targets):
                return _result(
                    "blocked",
                    "external_archive_unsafe_hardlink",
                    "External archive contains a hard link without a regular in-archive target.",
                    severity="high",
                    sha256=actual_sha256,
                )
        archive_source.seek(0)
        final_sha256, final_size = _hash_stream(
            archive_source,
            max_bytes=max_archive_bytes,
            deadline=deadline,
        )
        if final_size != actual_size or final_sha256 != expected_sha256:
            return _result(
                "blocked",
                "external_archive_digest_mismatch",
                "External archive changed during offline inspection.",
                severity="high",
                sha256=final_sha256,
            )
    except TimeoutError:
        return _result(
            "incomplete",
            "external_archive_inspection_timeout",
            "External archive inspection exceeded Guard's time limit.",
            severity="high",
            sha256=actual_sha256,
        )
    except (OSError, tarfile.TarError, UnicodeDecodeError, ValueError):
        return _result(
            "incomplete",
            "external_archive_inspection_incomplete",
            "External archive could not be parsed completely in offline inspection.",
            severity="high",
            sha256=actual_sha256,
        )
    finally:
        if archive_source is not None:
            archive_source.close()
        if descriptor >= 0:
            os.close(descriptor)
    return _result(
        "clean",
        "external_archive_inspection_clean",
        "External archive completed bounded offline inspection.",
        severity="low",
        sha256=actual_sha256,
    )
