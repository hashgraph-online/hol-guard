"""Direct-URL provenance and explicit local-wheel selection."""

from __future__ import annotations

from pathlib import Path
from urllib.parse import ParseResult

from packaging.version import Version


def _vcs_install_payload(direct_url: dict[str, object] | None) -> dict[str, object] | None:
    if not isinstance(direct_url, dict):
        return None
    vcs_info = direct_url.get("vcs_info")
    if not isinstance(vcs_info, dict):
        return None
    vcs = vcs_info.get("vcs")
    if not isinstance(vcs, str) or not vcs.strip():
        return None
    payload: dict[str, object] = {"kind": "vcs", "vcs": vcs.strip()}
    raw_url = direct_url.get("url")
    if isinstance(raw_url, str) and raw_url.strip():
        payload["url"] = _update._credential_safe_url(raw_url.strip())
    requested_revision = vcs_info.get("requested_revision")
    if isinstance(requested_revision, str) and requested_revision.strip():
        payload["requested_revision"] = requested_revision.strip()
    commit_id = vcs_info.get("commit_id")
    if isinstance(commit_id, str) and commit_id.strip():
        payload["commit_id"] = commit_id.strip()
    return payload


def _local_archive_install_payload(direct_url: dict[str, object] | None) -> dict[str, object] | None:
    if not isinstance(direct_url, dict):
        return None
    if isinstance(direct_url.get("vcs_info"), dict):
        return None
    if not isinstance(direct_url.get("archive_info"), dict):
        return None
    raw_url = direct_url.get("url")
    if not isinstance(raw_url, str) or not raw_url.strip():
        return None
    parsed = _update.urlparse(raw_url)
    if parsed.scheme != "file":
        return None
    raw_path = _update._file_url_to_path(parsed)
    if not raw_path:
        return None
    archive_path = _update.Path(raw_path)
    if not archive_path.is_absolute():
        return {
            "kind": "local_archive",
            "archive_type": "wheel" if archive_path.suffix.lower() == ".whl" else "archive",
            "url": _update._credential_safe_url(raw_url),
            "path": str(archive_path),
            "path_exists": False,
            "path_resolution_error": "relative_file_url",
        }
    resolved_archive_path, path_resolution_error = _update._safe_resolve_path(archive_path)
    archive_path_value = resolved_archive_path or archive_path
    archive_type = "wheel" if archive_path.suffix.lower() == ".whl" else "archive"
    payload: dict[str, object] = {
        "kind": "local_archive",
        "archive_type": archive_type,
        "url": _update._credential_safe_url(raw_url),
        "path": str(archive_path_value),
        "path_exists": _update._safe_path_exists(archive_path_value),
    }
    if path_resolution_error is not None:
        payload["path_resolution_error"] = path_resolution_error
    return payload


def _recover_local_archive_install(
    local_archive_install: dict[str, object] | None,
    *,
    direct_url: dict[str, object] | None,
    guard_home: Path,
    installed_version: str,
) -> dict[str, object] | None:
    if (
        local_archive_install is None
        or local_archive_install.get("archive_type") != "wheel"
        or local_archive_install.get("path_exists") is True
    ):
        return local_archive_install
    staged_path_value = local_archive_install.get("path")
    archive_sha256 = _update._direct_url_archive_sha256(direct_url)
    if not isinstance(staged_path_value, str) or not archive_sha256:
        return local_archive_install
    staged_path = _update.Path(staged_path_value)
    if not staged_path.is_absolute():
        return local_archive_install
    original_path = _update.recover_local_wheel_original(
        guard_home=guard_home,
        staged_path=staged_path,
        installed_version=installed_version,
        wheel_sha256=archive_sha256,
    )
    if original_path is None:
        return local_archive_install
    return {
        **local_archive_install,
        "path": str(original_path),
        "path_exists": True,
        "original_source_receipt": "verified",
    }


def _direct_url_archive_sha256(direct_url: dict[str, object] | None) -> str | None:
    if not isinstance(direct_url, dict):
        return None
    archive_info = direct_url.get("archive_info")
    if not isinstance(archive_info, dict):
        return None
    hashes = archive_info.get("hashes")
    candidate = hashes.get("sha256") if isinstance(hashes, dict) else None
    if not isinstance(candidate, str):
        hash_value = archive_info.get("hash")
        if not isinstance(hash_value, str):
            return None
        lowered = hash_value.lower()
        for prefix in ("sha256=", "sha256:"):
            if lowered.startswith(prefix):
                candidate = hash_value[len(prefix) :]
                break
    if not isinstance(candidate, str):
        return None
    normalized = candidate.strip().lower()
    if len(normalized) != 64 or any(character not in "0123456789abcdef" for character in normalized):
        return None
    return normalized


def _local_source_install_payload(direct_url: dict[str, object] | None) -> dict[str, object] | None:
    if not isinstance(direct_url, dict):
        return None
    if isinstance(direct_url.get("vcs_info"), dict):
        return None
    if isinstance(direct_url.get("archive_info"), dict):
        return None
    raw_url = direct_url.get("url")
    if not isinstance(raw_url, str) or not raw_url.strip():
        return None
    parsed = _update.urlparse(raw_url)
    if parsed.scheme != "file":
        return None
    raw_path = _update._file_url_to_path(parsed)
    if not raw_path:
        return None
    source_path = _update.Path(raw_path)
    if not source_path.is_absolute():
        return {
            "kind": "local_path",
            "url": _update._credential_safe_url(raw_url),
            "path": str(source_path),
            "path_exists": False,
            "path_resolution_error": "relative_file_url",
        }
    resolved_source_path, path_resolution_error = _update._safe_resolve_path(source_path)
    source_path_value = resolved_source_path or source_path
    payload: dict[str, object] = {
        "kind": "local_path",
        "url": _update._credential_safe_url(raw_url),
        "path": str(source_path_value),
        "path_exists": _update._safe_path_exists(source_path_value),
    }
    if path_resolution_error is not None:
        payload["path_resolution_error"] = path_resolution_error
    return payload


def _resolve_requested_wheel_path(wheel: str | None) -> tuple[Path | None, str | None]:
    if not isinstance(wheel, str) or not wheel.strip():
        return None, None
    candidate = _update.Path(wheel).expanduser()
    if not candidate.is_absolute():
        candidate = _update.Path.cwd() / candidate
    try:
        if candidate.is_symlink():
            return None, "HOL Guard wheel path must not be a symbolic link."
    except OSError:
        return None, "Could not inspect HOL Guard wheel path."
    resolved_candidate, path_resolution_error = _update._safe_resolve_path(candidate)
    if path_resolution_error is not None or resolved_candidate is None:
        return None, f"Could not resolve HOL Guard wheel path {candidate}: {path_resolution_error or 'unknown error'}"
    candidate = resolved_candidate
    if not candidate.exists():
        if candidate.suffix.lower() == ".whl":
            return None, f"HOL Guard wheel not found: {candidate}"
        return None, f"Directory of wheels not found: {candidate}"
    if candidate.is_dir():

        def _safe_mtime(path: _update.Path) -> int:
            try:
                return path.stat().st_mtime_ns
            except OSError:
                return 0

        try:
            directory_entries = list(candidate.iterdir())
        except OSError as error:
            return None, (
                f"Could not read HOL Guard wheel directory {candidate}: {_update.redact_sensitive_text(str(error))}"
            )

        wheels: list[_update.Path] = []
        for path in directory_entries:
            if not path.is_file():
                continue
            if _update._parsed_hol_guard_wheel_version(path) is None:
                continue
            wheels.append(path)
        wheels.sort(
            key=lambda path: (
                _update._parsed_hol_guard_wheel_version(path) or _update.Version("0"),
                _safe_mtime(path),
                path.name.lower(),
            ),
            reverse=True,
        )
        if not wheels:
            return None, f"No HOL Guard wheels found in {candidate}."
        return wheels[0], None
    if candidate.suffix.lower() != ".whl":
        return None, f"Expected a HOL Guard wheel file or a directory of wheels, got {candidate}."
    if not candidate.is_file():
        return None, f"Expected a HOL Guard wheel file, got {candidate}."
    if _update._parsed_hol_guard_wheel_version(candidate) is None:
        return None, f"Expected a HOL Guard wheel file, got {candidate}."
    return candidate, None


def _local_archive_update_hint(local_archive_install: dict[str, object]) -> str:
    archive_path = local_archive_install.get("path")
    if isinstance(archive_path, str) and archive_path.strip():
        return _update._shell_command(["hol-guard", "update", "--wheel", archive_path.strip()])
    return "hol-guard update --wheel <wheel-or-directory>"


def _file_url_to_path(parsed: ParseResult) -> str:
    path = _update.urllib.request.url2pathname(parsed.path)
    netloc = parsed.netloc.strip()
    if netloc and netloc.lower() != "localhost":
        if _update.os.name == "nt":
            return _update.urllib.request.url2pathname(f"//{netloc}{path}")
        return f"//{netloc}{path}"
    return path


def _safe_resolve_path(path: Path) -> tuple[Path | None, str | None]:
    try:
        return path.resolve(strict=False), None
    except (OSError, RuntimeError) as error:
        return None, _update.redact_sensitive_text(str(error))


def _safe_path_exists(path: Path) -> bool:
    try:
        return path.exists()
    except (OSError, RuntimeError):
        return False


def _parsed_hol_guard_wheel_version(path: Path) -> Version | None:
    filename = path.name
    suffix = path.suffix
    if suffix.lower() != ".whl":
        return None
    parts = filename[: -len(suffix)].split("-")
    if len(parts) < 5 or parts[0].lower() != "hol_guard":
        return None
    try:
        return _update.Version(parts[1])
    except _update.InvalidVersion:
        return None


def _direct_url_payload() -> dict[str, object] | None:
    try:
        distribution = _update.importlib.metadata.distribution("hol-guard")
    except _update.importlib.metadata.PackageNotFoundError:
        return None
    raw_payload = distribution.read_text("direct_url.json")
    if raw_payload is None:
        return None
    try:
        payload = _update.json.loads(raw_payload)
    except _update.json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def _public_direct_url_payload(payload: dict[str, object]) -> dict[str, object]:
    public: dict[str, object] = {}
    for key, value in payload.items():
        if key == "url" and isinstance(value, str):
            public[key] = _update._credential_safe_url(value)
        elif isinstance(value, dict):
            public[key] = _update._public_direct_url_payload(value)
        elif isinstance(value, list):
            public[key] = [
                _update._public_direct_url_payload(item) if isinstance(item, dict) else item for item in value
            ]
        else:
            public[key] = value
    return public


def _credential_safe_url(value: str) -> str:
    try:
        parsed = _update.urlparse(value)
        port = parsed.port
    except ValueError:
        return "[redacted-url]"
    # Older CPython releases rewrite file:relative into the absolute-looking file:///relative form.
    if parsed.scheme == "file" and not parsed.netloc and parsed.path and not parsed.path.startswith("/"):
        relative_path = parsed.path
        if parsed.params:
            relative_path = f"{relative_path};{parsed.params}"
        return f"file:{relative_path}"
    netloc = parsed.netloc
    if parsed.username is not None or parsed.password is not None:
        hostname = parsed.hostname
        if hostname is None:
            return "[redacted-url]"
        rendered_host = f"[{hostname}]" if ":" in hostname else hostname
        netloc = f"{rendered_host}:{port}" if port is not None else rendered_host
    return parsed._replace(netloc=netloc, query="", fragment="").geturl()


# Bind the facade after definitions so either module can be imported first.
from . import update_commands as _update  # noqa: E402
