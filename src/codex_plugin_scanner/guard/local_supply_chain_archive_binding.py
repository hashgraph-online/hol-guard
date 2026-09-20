"""Archive binding helpers using the original live supply-chain namespace."""

from __future__ import annotations


def _external_archive_downloads(evaluation: object) -> tuple[_api.RestrictedArchiveDownload, ...]:
    value = getattr(evaluation, "external_archive_downloads", ())
    if not isinstance(value, tuple):
        return ()
    return tuple(item for item in value if isinstance(item, _api.RestrictedArchiveDownload))


def _cleanup_external_archive_downloads(evaluation: object) -> None:
    for download in _api._external_archive_downloads(evaluation):
        download.cleanup()


def _package_evaluation_requires_external_archive_binding(evaluation: object) -> bool:
    source_hashes = getattr(evaluation, "external_archive_source_hashes", ())
    if isinstance(source_hashes, (list, tuple)) and any(
        isinstance(item, str) and len(item) == 64 for item in source_hashes
    ):
        return True
    reasons = getattr(evaluation, "reasons", ())
    if isinstance(reasons, (list, tuple)) and any(
        isinstance(reason, _api.Mapping) and reason.get("code") == "external_tarball_source" for reason in reasons
    ):
        return True
    packages = getattr(evaluation, "packages", ())
    if not isinstance(packages, (list, tuple)):
        return False
    return any(
        isinstance(package, _api.Mapping)
        and isinstance(package_reasons := package.get("reasons"), (list, tuple))
        and any(
            isinstance(reason, _api.Mapping) and reason.get("code") == "external_tarball_source"
            for reason in package_reasons
        )
        for package in packages
    )


def _verified_external_archive_replacements(evaluation: object) -> dict[str, str] | None:
    replacements: dict[str, str] = {}
    for download in _api._external_archive_downloads(evaluation):
        descriptor = -1
        try:
            path_stat = download.path.lstat()
            descriptor = _api.os.open(
                download.path,
                _api.os.O_RDONLY | getattr(_api.os, "O_BINARY", 0) | getattr(_api.os, "O_NOFOLLOW", 0),
            )
            file_stat = _api.os.fstat(descriptor)
            if (
                not _api.stat.S_ISREG(path_stat.st_mode)
                or not _api.stat.S_ISREG(file_stat.st_mode)
                or path_stat.st_dev != file_stat.st_dev
                or path_stat.st_ino != file_stat.st_ino
                or file_stat.st_nlink != 1
                or file_stat.st_size != download.size
                or _api.stat.S_IMODE(file_stat.st_mode) & (_api.stat.S_IWUSR | _api.stat.S_IWGRP | _api.stat.S_IWOTH)
            ):
                return None
            digest = _api.hashlib.sha256()
            size = 0
            with _api.os.fdopen(descriptor, "rb", closefd=True) as archive_file:
                descriptor = -1
                while True:
                    chunk = archive_file.read(min(64 * 1024, download.size - size + 1))
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > download.size:
                        return None
                    digest.update(chunk)
        except OSError:
            return None
        finally:
            if descriptor >= 0:
                _api.os.close(descriptor)
        if size != download.size or digest.hexdigest() != download.sha256:
            return None
        replacements[download.source_url] = str(download.path)
    return replacements


def _bound_external_archive_launch_command(
    launch_command: _api.Sequence[str],
    *,
    evaluation: object,
) -> list[str] | None:
    replacements = _api._verified_external_archive_replacements(evaluation)
    if replacements is None:
        return None
    if not replacements:
        return None if _api._package_evaluation_requires_external_archive_binding(evaluation) else list(launch_command)
    bound_command = [str(item) for item in launch_command]
    for source_url, replacement in replacements.items():
        replacement_count = 0
        for index, argument in enumerate(bound_command):
            if source_url not in argument:
                continue
            bound_command[index] = argument.replace(source_url, replacement)
            replacement_count += 1
        if replacement_count == 0:
            return None
    return bound_command


def _package_manager_launch_environment(
    environment: _api.Mapping[str, str],
    *,
    guard_home: _api.Path,
    launch_cwd: _api.Path,
) -> dict[str, str]:
    """Exclude Guard's interception shim from the reviewed and executed package-manager path."""

    launch_environment = dict(environment)
    try:
        shim_dir = (guard_home / "package-shims" / "bin").expanduser().resolve()
    except (OSError, RuntimeError, ValueError):
        raise ValueError("Guard's package shim path could not be verified") from None
    path_entries = environment.get("PATH", "").split(_api.os.pathsep)
    filtered_entries: list[str] = []
    for entry in path_entries:
        if not entry:
            continue
        try:
            path_entry = _api.Path(entry).expanduser()
            if not path_entry.is_absolute():
                path_entry = launch_cwd / path_entry
            resolved_entry = path_entry.resolve()
        except (OSError, RuntimeError, ValueError):
            raise ValueError("package manager PATH could not be verified") from None
        if resolved_entry != shim_dir:
            filtered_entries.append(entry)
    launch_environment["PATH"] = _api.os.pathsep.join(filtered_entries)
    return launch_environment


# Bind after declarations so importing this owner directly preserves the facade cycle.
from . import local_supply_chain as _api  # noqa: E402
