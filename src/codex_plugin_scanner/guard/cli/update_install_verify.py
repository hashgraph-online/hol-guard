"""Trusted post-install verification for the HOL Guard distribution."""

from __future__ import annotations

import re
from pathlib import Path

from packaging.version import InvalidVersion, Version

from .update_subprocess import (
    InstalledDistribution,
    TrustedUpdateContext,
    UpdateSubprocessError,
    _path_is_within,
)

DISTRIBUTION_QUERY_SCRIPT = """
from __future__ import annotations

import importlib.metadata
import json
import stat
from pathlib import Path

distribution = importlib.metadata.distribution("hol-guard")
root = Path(distribution.locate_file("")).resolve()
direct_url = None
direct_url_entries = [
    entry
    for entry in (distribution.files or ())
    if entry.as_posix().endswith(".dist-info/direct_url.json")
]
if len(direct_url_entries) > 1:
    raise RuntimeError("multiple direct_url metadata files")
if direct_url_entries:
    direct_url_path = Path(distribution.locate_file(direct_url_entries[0])).resolve(strict=True)
    direct_url_path.relative_to(root)
    direct_url_stat = direct_url_path.stat()
    if not stat.S_ISREG(direct_url_stat.st_mode) or not 0 < direct_url_stat.st_size <= 65536:
        raise RuntimeError("invalid direct_url metadata file")
    direct_url = json.loads(direct_url_path.read_text(encoding="utf-8"))
    if not isinstance(direct_url, dict):
        raise RuntimeError("invalid direct_url metadata payload")
code_source = ""
version_file_entries = [
    entry
    for entry in (distribution.files or ())
    if entry.as_posix() == "codex_plugin_scanner/version.py"
]
if len(version_file_entries) == 1:
    version_file = Path(distribution.locate_file(version_file_entries[0]))
    try:
        code_source = version_file.read_text(encoding="utf-8")[:4096]
    except OSError:
        code_source = ""
print(json.dumps({
    "code_source": code_source,
    "direct_url": direct_url,
    "name": distribution.metadata.get("Name"),
    "root": str(root),
    "version": distribution.version,
}, sort_keys=True))
""".strip()

_VERSION_ASSIGNMENT_PATTERN = re.compile(r"^__version__\s*=\s*['\"]([^'\"]+)['\"]", re.MULTILINE)


def _code_version_from_source(version_text: str) -> str:
    match = _VERSION_ASSIGNMENT_PATTERN.search(version_text)
    return match.group(1) if match is not None else ""


def parse_distribution_probe_payload(
    payload: dict[str, object],
    *,
    install_prefix: Path,
) -> InstalledDistribution:
    """Validate one trusted distribution-probe record."""

    required_keys = {"direct_url", "name", "root", "version"}
    if not required_keys <= set(payload) or set(payload) - required_keys - {"code_source"}:
        raise UpdateSubprocessError("update_version_output_invalid")
    name = payload.get("name")
    version = payload.get("version")
    root_value = payload.get("root")
    direct_url_value = payload.get("direct_url")
    code_source_value = payload.get("code_source")
    if code_source_value is not None and not isinstance(code_source_value, str):
        raise UpdateSubprocessError("update_version_output_invalid")
    code_version = None if code_source_value is None else _code_version_from_source(code_source_value)
    if not isinstance(name, str) or name.lower().replace("_", "-") != "hol-guard":
        raise UpdateSubprocessError("update_version_output_invalid")
    if not isinstance(version, str):
        raise UpdateSubprocessError("update_version_output_invalid")
    try:
        normalized_version = str(Version(version))
    except InvalidVersion as error:
        raise UpdateSubprocessError("update_version_output_invalid") from error
    if code_version:
        try:
            code_version = str(Version(code_version))
        except InvalidVersion as error:
            raise UpdateSubprocessError("update_version_output_invalid") from error
    if not isinstance(root_value, str):
        raise UpdateSubprocessError("update_version_output_invalid")
    try:
        root = Path(root_value).resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise UpdateSubprocessError("update_version_output_invalid") from error
    if not _path_is_within(root, install_prefix):
        raise UpdateSubprocessError("update_package_origin_mismatch")
    if direct_url_value is not None and not isinstance(direct_url_value, dict):
        raise UpdateSubprocessError("update_version_output_invalid")
    direct_url = None
    if isinstance(direct_url_value, dict):
        direct_url = {str(key): value for key, value in direct_url_value.items() if isinstance(key, str)}
        if len(direct_url) != len(direct_url_value):
            raise UpdateSubprocessError("update_version_output_invalid")
    return InstalledDistribution(
        name="hol-guard",
        version=normalized_version,
        root=root,
        direct_url=direct_url,
        code_version=code_version,
    )


def verify_installed_distribution(update_context: TrustedUpdateContext) -> str:
    """Return the installed version after checking code/metadata agreement.

    One trusted probe serves both needs: the dist-info version becomes the
    update's resulting version, and the version stamped into the installed
    ``version.py`` must agree with it. An interrupted installer can leave
    fresh metadata beside stale code files; that state previously reported a
    successful update and later surfaced as store schema failures. A probe
    without a code version (older builds) skips the agreement check.
    """

    distribution = update_context.query_distribution()
    code_version = getattr(distribution, "code_version", None)
    if code_version is None:
        return str(distribution.version)
    if not code_version or Version(code_version) != Version(str(distribution.version)):
        raise UpdateSubprocessError(
            "update_install_inconsistent",
            detail=(
                f"installed code files report {code_version or 'no version'} "
                f"while installed metadata reports {distribution.version}"
            ),
        )
    return str(distribution.version)
