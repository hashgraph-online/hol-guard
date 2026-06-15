"""Dashboard asset sync helpers with trusted-source verification."""

from __future__ import annotations

import importlib.util
import re
import subprocess
from pathlib import Path
from urllib.parse import urlparse

from ..redaction import redact_sensitive_text

_TRUSTED_REPO_SLUG = "hashgraph-online/hol-guard"
_GIT_HOOKS_DISABLED = ("/dev/null",)
_GIT_TIMEOUT_SECONDS = 10.0
_RUN_PROCESS = subprocess.run


def sync_dashboard_assets() -> dict[str, object] | None:
    """Copy committed dashboard assets from a verified hol-guard checkout."""
    spec = importlib.util.find_spec("codex_plugin_scanner.guard.daemon.server")
    if spec is None or spec.origin is None:
        return None
    installed_static = Path(spec.origin).with_name("static")
    try:
        if not installed_static.is_dir():
            return None
    except OSError:
        return None

    try:
        source_checkout = find_source_checkout()
    except OSError:
        return {"source_checkout_found": False, "installed_static": str(installed_static)}
    if source_checkout is None:
        return {"source_checkout_found": False, "installed_static": str(installed_static)}

    source_static = _resolve_source_static(source_checkout)
    if source_static is None:
        return {
            "source_checkout_found": True,
            "source_checkout": str(source_checkout),
            "dashboard_dir_found": False,
            "notes": [
                "Source checkout found but no built dashboard assets. Run `npm run build` in the dashboard directory.",
            ],
        }

    static_prefix = source_static.relative_to(source_checkout).as_posix()
    installed_index = installed_static / "index.html"
    needs_copy = True
    try:
        if installed_index.is_file():
            committed_index = _read_committed_file(source_checkout, f"{static_prefix}/index.html")
            if committed_index is not None:
                needs_copy = committed_index != installed_index.read_bytes()
    except OSError:
        needs_copy = True

    if not needs_copy:
        return {
            "source_checkout_found": True,
            "source_checkout": str(source_checkout),
            "copied": False,
            "reason": "installed assets are already up to date",
        }

    try:
        copied_count = _export_committed_static_files(
            source_checkout=source_checkout,
            static_prefix=static_prefix,
            installed_static=installed_static,
        )
    except (OSError, ValueError) as error:
        return {
            "source_checkout_found": True,
            "source_checkout": str(source_checkout),
            "copied": False,
            "error": redact_sensitive_text(str(error)),
            "notes": ["Dashboard asset sync failed. The daemon may serve stale UI."],
        }
    if copied_count == 0:
        return {
            "source_checkout_found": True,
            "source_checkout": str(source_checkout),
            "dashboard_dir_found": False,
            "notes": [
                "Trusted checkout found but no committed dashboard assets at HEAD. "
                "Commit a dashboard build before syncing.",
            ],
        }

    return {
        "source_checkout_found": True,
        "source_checkout": str(source_checkout),
        "installed_static": str(installed_static),
        "copied": True,
        "copied_files": copied_count,
        "notes": [f"Synced {copied_count} committed dashboard asset files to the installed package."],
    }


def find_source_checkout() -> Path | None:
    """Return a verified local hol-guard checkout near the current working directory."""
    try:
        cwd = Path.cwd().resolve()
    except OSError:
        return None
    candidates = [cwd, *cwd.parents]
    for candidate in candidates:
        checkout = verify_source_checkout(candidate)
        if checkout is not None:
            return checkout
    for candidate in candidates:
        try:
            for sub in candidate.iterdir():
                try:
                    checkout = verify_source_checkout(sub)
                    if checkout is not None:
                        return checkout
                except OSError:
                    continue
        except OSError:
            continue
    return None


def verify_source_checkout(path: Path) -> Path | None:
    """Accept only the canonical hol-guard GitHub origin and source tree markers."""
    try:
        if not (path / "dashboard" / "package.json").is_file():
            return None
        if not (path / "src" / "codex_plugin_scanner").is_dir():
            return None
        if not (path / ".git").exists():
            return None
    except OSError:
        return None

    try:
        config_path = path / ".git" / "config"
        if not config_path.is_file():
            return None
        remote_text = config_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None

    origin_urls = _origin_urls_from_git_config(remote_text)
    if not any(_is_trusted_hol_guard_origin(url) for url in origin_urls):
        return None
    if not _git_head_exists(path):
        return None
    return path


def _resolve_source_static(checkout: Path) -> Path | None:
    dashboard_dir = checkout / "dashboard"
    source_static = dashboard_dir / "src" / "codex_plugin_scanner" / "guard" / "daemon" / "static"
    if source_static.is_dir():
        return source_static
    fallback = checkout / "src" / "codex_plugin_scanner" / "guard" / "daemon" / "static"
    if fallback.is_dir():
        return fallback
    return None


def _origin_urls_from_git_config(config_text: str) -> list[str]:
    urls: list[str] = []
    in_origin = False
    for line in config_text.splitlines():
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            section_match = re.fullmatch(r'\[remote "(.+)"\]', stripped)
            in_origin = section_match is not None and section_match.group(1) == "origin"
            continue
        if in_origin and stripped.startswith("url ="):
            urls.append(stripped.split("=", 1)[1].strip())
    return urls


def _normalize_github_repo_slug(url: str) -> str | None:
    candidate = url.strip()
    if candidate == "":
        return None
    if candidate.startswith("git@"):
        host_and_path = candidate[4:]
        if ":" not in host_and_path:
            return None
        host, repo_path = host_and_path.split(":", 1)
        if host != "github.com":
            return None
        return repo_path.strip("/").removesuffix(".git")
    parsed = urlparse(candidate)
    if parsed.scheme not in {"http", "https", "ssh"}:
        return None
    host = parsed.hostname
    if host is None:
        return None
    if host != "github.com":
        return None
    return parsed.path.strip("/").removesuffix(".git")


def _is_trusted_hol_guard_origin(url: str) -> bool:
    slug = _normalize_github_repo_slug(url)
    return slug == _TRUSTED_REPO_SLUG


def _git_head_exists(checkout: Path) -> bool:
    result = _git_run(checkout, "rev-parse", "--verify", "HEAD")
    return result is not None and result.returncode == 0


def _git_run(
    checkout: Path,
    *args: str,
    text: bool = True,
) -> subprocess.CompletedProcess[str] | subprocess.CompletedProcess[bytes] | None:
    try:
        return _RUN_PROCESS(
            [
                "git",
                "-c",
                f"core.hooksPath={_GIT_HOOKS_DISABLED[0]}",
                "-C",
                str(checkout),
                *args,
            ],
            capture_output=True,
            check=False,
            text=text,
            timeout=_GIT_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None


def _is_safe_committed_tree_path(path: str) -> bool:
    if path == "" or path.startswith(("/", "\\")) or "\\" in path or "\0" in path:
        return False
    return all(part not in {"", ".", ".."} for part in path.split("/"))


def _list_committed_static_files(checkout: Path, static_prefix: str) -> list[str]:
    result = _git_run(checkout, "ls-tree", "-r", "--name-only", "HEAD", "--", static_prefix)
    if result is None or result.returncode != 0:
        return []
    files: list[str] = []
    prefix = f"{static_prefix.rstrip('/')}/"
    stdout = result.stdout
    if not isinstance(stdout, str):
        return []
    for line in stdout.splitlines():
        relative = line.strip()
        if (
            relative == ""
            or relative.endswith("/")
            or not relative.startswith(prefix)
            or not _is_safe_committed_tree_path(relative)
        ):
            continue
        files.append(relative)
    return files


def _read_committed_file(checkout: Path, relative_path: str) -> bytes | None:
    if not _is_safe_committed_tree_path(relative_path):
        return None
    result = _git_run(checkout, "show", f"HEAD:{relative_path}", text=False)
    if result is None or result.returncode != 0:
        return None
    stdout = result.stdout
    if not isinstance(stdout, bytes):
        return None
    return stdout


def _relative_static_path(relative_path: str, static_prefix: str) -> Path | None:
    normalized_prefix = static_prefix.rstrip("/")
    if not relative_path.startswith(f"{normalized_prefix}/"):
        return None
    suffix = relative_path.removeprefix(f"{normalized_prefix}/")
    if not _is_safe_committed_tree_path(suffix):
        return None
    return Path(suffix)


def _resolve_static_export_path(installed_static: Path, relative_to_static: Path) -> Path | None:
    base = installed_static.resolve()
    destination = (base / relative_to_static).resolve()
    try:
        destination.relative_to(base)
    except ValueError:
        return None
    return destination


def _export_committed_static_files(
    *,
    source_checkout: Path,
    static_prefix: str,
    installed_static: Path,
) -> int:
    copied_count = 0
    for relative_path in _list_committed_static_files(source_checkout, static_prefix):
        payload = _read_committed_file(source_checkout, relative_path)
        if payload is None:
            continue
        relative_to_static = _relative_static_path(relative_path, static_prefix)
        if relative_to_static is None:
            continue
        dest = _resolve_static_export_path(installed_static, relative_to_static)
        if dest is None:
            continue
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(payload)
        copied_count += 1
    return copied_count


__all__ = [
    "find_source_checkout",
    "sync_dashboard_assets",
    "verify_source_checkout",
]
