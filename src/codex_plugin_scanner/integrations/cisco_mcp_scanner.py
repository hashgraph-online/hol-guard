"""Cisco MCP scanner integration."""

from __future__ import annotations

import asyncio
import importlib.util
import os
import sys
from collections.abc import Awaitable
from dataclasses import dataclass
from importlib import metadata as importlib_metadata
from importlib.machinery import ModuleSpec
from importlib.metadata import Distribution
from pathlib import Path
from threading import Thread
from types import ModuleType
from typing import Protocol, TypeGuard, TypeVar

from ..models import Finding, Severity, severity_from_value
from .cisco_skill_scanner import CiscoIntegrationStatus, cisco_runtime_unavailable_message

_EXCLUDED_DIRS = {
    ".codex-plugin",
    ".git",
    ".next",
    ".turbo",
    ".venv",
    "__pycache__",
    "coverage",
    "node_modules",
    "venv",
}
_SOURCE_SUFFIXES = {".cjs", ".js", ".json", ".jsx", ".mjs", ".py", ".ts", ".tsx"}
_MAX_TARGET_SIZE_BYTES = 1_000_000
T = TypeVar("T")


class _CiscoAnalyzer(Protocol):
    async def analyze(self, content: str, metadata: dict[str, str]) -> list[object] | tuple[object, ...]: ...


class _CiscoAnalyzerFactory(Protocol):
    def __call__(self) -> _CiscoAnalyzer: ...


def _is_analyzer_factory(value: object) -> TypeGuard[_CiscoAnalyzerFactory]:
    return callable(value)


async def _await_result(awaitable: Awaitable[T]) -> T:
    return await awaitable


@dataclass(frozen=True, slots=True)
class CiscoMcpScanSummary:
    """Normalized summary from a Cisco MCP scan run."""

    status: CiscoIntegrationStatus
    message: str
    findings: tuple[Finding, ...]
    targets_scanned: int
    analyzers_used: tuple[str, ...]
    total_findings: int
    findings_by_severity: dict[str, int]
    scan_mode: str = "static"


@dataclass(frozen=True, slots=True)
class _StaticScanTarget:
    read_path: Path
    tool_name: str
    content_type: str


def _empty_counts() -> dict[str, int]:
    return {severity.value: 0 for severity in Severity}


def _build_summary(
    *,
    status: CiscoIntegrationStatus,
    message: str,
    findings: tuple[Finding, ...] = (),
    targets_scanned: int = 0,
    analyzers_used: tuple[str, ...] = (),
) -> CiscoMcpScanSummary:
    counts = _empty_counts()
    for finding in findings:
        counts[finding.severity.value] += 1
    return CiscoMcpScanSummary(
        status=status,
        message=message,
        findings=findings,
        targets_scanned=targets_scanned,
        analyzers_used=analyzers_used,
        total_findings=len(findings),
        findings_by_severity=counts,
    )


def _load_mcp_scanner_components(*, blocked_root: Path | None = None) -> dict[str, _CiscoAnalyzerFactory]:
    module = _load_distribution_module("cisco-ai-mcp-scanner", "mcpscanner", blocked_root=blocked_root)
    components: dict[str, _CiscoAnalyzerFactory] = {}

    yara_analyzer = getattr(module, "YaraAnalyzer", None)
    if _is_analyzer_factory(yara_analyzer):
        components["YaraAnalyzer"] = yara_analyzer

    # LLM analyzer: available when MCP_SCANNER_LLM_API_KEY is set
    if os.environ.get("MCP_SCANNER_LLM_API_KEY"):
        llm_analyzer = getattr(module, "LLMAnalyzer", None)
        if _is_analyzer_factory(llm_analyzer):
            components["LLMAnalyzer"] = llm_analyzer

    # Cisco AI Defense API analyzer: available when MCP_SCANNER_API_KEY is set
    if os.environ.get("MCP_SCANNER_API_KEY"):
        api_analyzer = getattr(module, "APIAnalyzer", None)
        if _is_analyzer_factory(api_analyzer):
            components["APIAnalyzer"] = api_analyzer

    if not components:
        raise ImportError("cisco-ai-mcp-scanner does not expose any analyzer factories")
    return components


def _load_distribution_module(
    distribution_name: str,
    module_name: str,
    *,
    blocked_root: Path | None = None,
) -> ModuleType:
    try:
        distribution = importlib_metadata.distribution(distribution_name)
    except importlib_metadata.PackageNotFoundError as exc:
        raise ImportError(f"{distribution_name} is not installed") from exc
    spec = _distribution_module_spec(distribution, module_name)
    if spec is not None and blocked_root is not None and not _spec_outside_blocked_root(spec, blocked_root):
        spec = None
    if spec is None:
        spec = _editable_distribution_spec(module_name, blocked_root=blocked_root)
    if spec is None or spec.loader is None:
        raise ImportError(f"Unable to resolve {module_name} from {distribution_name}")
    module = importlib.util.module_from_spec(spec)
    previous_module = sys.modules.get(module_name)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        if previous_module is None:
            sys.modules.pop(module_name, None)
        else:
            sys.modules[module_name] = previous_module
        raise
    return module


def _coerce_path(value: object) -> Path | None:
    if isinstance(value, str):
        return Path(value)
    if isinstance(value, os.PathLike):
        path_value = os.fspath(value)
        if isinstance(path_value, str):
            return Path(path_value)
    return None


def _distribution_module_spec(distribution: Distribution, module_name: str) -> ModuleSpec | None:
    files = distribution.files or ()
    package_init_relative = f"{module_name}/__init__.py"
    module_relative = f"{module_name}.py"
    for package_file in files:
        if str(package_file).replace("\\", "/") != package_init_relative:
            continue
        package_init = Path(package_file.locate())
        if package_init.is_file():
            return importlib.util.spec_from_file_location(
                module_name,
                package_init,
                submodule_search_locations=[str(package_init.parent)],
            )
    for package_file in files:
        if str(package_file).replace("\\", "/") != module_relative:
            continue
        module_file = Path(package_file.locate())
        if module_file.is_file():
            return importlib.util.spec_from_file_location(module_name, module_file)
    locate_file = getattr(distribution, "locate_file", None)
    if not callable(locate_file):
        return None
    package_dir = _coerce_path(locate_file(module_name))
    if package_dir is not None and package_dir.is_dir():
        package_init = package_dir / "__init__.py"
        if package_init.is_file():
            return importlib.util.spec_from_file_location(
                module_name,
                package_init,
                submodule_search_locations=[str(package_dir)],
            )
    module_file = _coerce_path(locate_file(module_relative))
    if module_file is not None and module_file.is_file():
        return importlib.util.spec_from_file_location(module_name, module_file)
    return None


def _editable_distribution_spec(module_name: str, *, blocked_root: Path | None) -> ModuleSpec | None:
    spec = importlib.util.find_spec(module_name)
    if spec is None or spec.loader is None:
        return None
    if blocked_root is not None and not _spec_outside_blocked_root(spec, blocked_root):
        return None
    return spec


def _spec_outside_blocked_root(spec: ModuleSpec, blocked_root: Path) -> bool:
    blocked_root_resolved = blocked_root.resolve()
    candidate_paths: list[Path] = []
    spec_origin = getattr(spec, "origin", None)
    if isinstance(spec_origin, str) and spec_origin not in {"built-in", "frozen"}:
        candidate_paths.append(Path(spec_origin).resolve())
    search_locations = getattr(spec, "submodule_search_locations", None)
    if search_locations is not None:
        candidate_paths.extend(Path(location).resolve() for location in search_locations)
    return all(not _path_within_root(candidate_path, blocked_root_resolved) for candidate_path in candidate_paths)


def _path_within_root(candidate_path: Path, root: Path) -> bool:
    try:
        candidate_path.relative_to(root)
    except ValueError:
        return False
    return True


def _relative_path(plugin_dir: Path, file_path: Path) -> str:
    try:
        return file_path.resolve().relative_to(plugin_dir.resolve()).as_posix()
    except ValueError:
        return file_path.as_posix()


def _normalize_rule_fragment(value: str) -> str:
    normalized = []
    for character in value.upper():
        normalized.append(character if character.isalnum() else "-")
    return "".join(normalized).strip("-") or "FINDING"


def _extract_rule_id(details: object, threat_category: str) -> str:
    if isinstance(details, dict):
        raw_response = details.get("raw_response")
        if isinstance(raw_response, dict):
            candidate = raw_response.get("rule")
            if isinstance(candidate, str) and candidate.strip():
                return f"CISCO-MCP-{_normalize_rule_fragment(candidate)}"
        candidate = details.get("threat_type")
        if isinstance(candidate, str) and candidate.strip():
            return f"CISCO-MCP-{_normalize_rule_fragment(candidate)}"
    return f"CISCO-MCP-{_normalize_rule_fragment(threat_category)}"


def _extract_description(summary: str, details: object) -> str:
    if isinstance(details, dict):
        evidence = details.get("evidence")
        if isinstance(evidence, str) and evidence.strip():
            return evidence.strip()
    return summary or "Cisco MCP scanner reported a potential issue."


def _extract_title(summary: str, threat_category: str) -> str:
    if summary:
        return summary
    return threat_category.replace("_", " ").title() or "Cisco MCP scanner finding"


def _normalize_finding(plugin_dir: Path, file_path: Path, finding: object) -> Finding:
    summary = str(getattr(finding, "summary", "") or "")
    details = getattr(finding, "details", {})
    threat_category = str(getattr(finding, "threat_category", "") or "mcp-security")
    return Finding(
        rule_id=_extract_rule_id(details, threat_category),
        severity=severity_from_value(str(getattr(finding, "severity", "info") or "info")),
        category="security",
        title=_extract_title(summary, threat_category),
        description=_extract_description(summary, details),
        file_path=_relative_path(plugin_dir, file_path),
        source="cisco-mcp-scanner",
    )


def _collect_static_targets(plugin_dir: Path) -> tuple[_StaticScanTarget, ...]:
    config_path = plugin_dir / ".mcp.json"
    resolved_config_path = _safe_resolved_static_target(plugin_dir, config_path)
    if resolved_config_path is None:
        return ()

    targets: list[_StaticScanTarget] = []
    seen_targets: set[Path] = set()
    try:
        if resolved_config_path.stat().st_size <= _MAX_TARGET_SIZE_BYTES:
            targets.append(
                _StaticScanTarget(
                    read_path=resolved_config_path,
                    tool_name=config_path.name,
                    content_type="mcp-config",
                )
            )
            seen_targets.add(resolved_config_path)
    except OSError:
        pass
    for root, dirs, files in os.walk(plugin_dir, topdown=True):
        dirs[:] = sorted(dir_name for dir_name in dirs if dir_name not in _EXCLUDED_DIRS)
        current_dir = Path(root)
        for file_name in sorted(files):
            file_path = current_dir / file_name
            if file_path == config_path or file_path.suffix.lower() not in _SOURCE_SUFFIXES:
                continue
            resolved_file_path = _safe_resolved_static_target(plugin_dir, file_path)
            if resolved_file_path is None or resolved_file_path in seen_targets:
                continue
            try:
                if resolved_file_path.stat().st_size > _MAX_TARGET_SIZE_BYTES:
                    continue
            except OSError:
                continue
            targets.append(
                _StaticScanTarget(
                    read_path=resolved_file_path,
                    tool_name=resolved_file_path.name,
                    content_type="mcp-source",
                )
            )
            seen_targets.add(resolved_file_path)
    return tuple(targets)


def _safe_resolved_static_target(plugin_dir: Path, target: Path) -> Path | None:
    try:
        resolved_root = plugin_dir.resolve(strict=True)
        resolved_target = target.resolve(strict=True)
        if not resolved_target.is_file():
            return None
    except (OSError, RuntimeError):
        return None
    try:
        resolved_target.relative_to(resolved_root)
    except ValueError:
        return None
    return resolved_target


def _run_awaitable(awaitable: Awaitable[T]) -> T:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(_await_result(awaitable))

    result: list[T] = []
    errors: list[BaseException] = []

    def _runner() -> None:
        try:
            result.append(asyncio.run(_await_result(awaitable)))
        except BaseException as exc:
            errors.append(exc)

    thread = Thread(target=_runner)
    thread.start()
    thread.join()
    if errors:
        raise errors[0]
    if result:
        return result[0]
    raise RuntimeError("Cisco MCP scanner completed without a result.")


async def _scan_targets(
    plugin_dir: Path, targets: tuple[_StaticScanTarget, ...], analyzer: _CiscoAnalyzer
) -> tuple[tuple[Finding, ...], int]:
    findings: list[Finding] = []
    targets_scanned = 0
    for target in targets:
        try:
            content = target.read_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        external_findings = await analyzer.analyze(
            content,
            {
                "tool_name": target.tool_name,
                "content_type": target.content_type,
                "file_path": str(target.read_path),
            },
        )
        targets_scanned += 1
        for finding in external_findings:
            findings.append(_normalize_finding(plugin_dir, target.read_path, finding))
    return tuple(findings), targets_scanned


async def _scan_targets_multi(
    plugin_dir: Path,
    targets: tuple[_StaticScanTarget, ...],
    analyzers: tuple[tuple[str, _CiscoAnalyzer], ...],
) -> tuple[tuple[Finding, ...], int, tuple[str, ...], dict[str, str]]:
    findings: list[Finding] = []
    targets_scanned = 0
    successful_analyzers: set[str] = set()
    analyzer_errors: dict[str, str] = {}
    for target in targets:
        try:
            content = target.read_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        targets_scanned += 1
        for analyzer_name, analyzer in analyzers:
            try:
                external_findings = await analyzer.analyze(
                    content,
                    {
                        "tool_name": target.tool_name,
                        "content_type": target.content_type,
                        "file_path": str(target.read_path),
                    },
                )
            except Exception as exc:
                if analyzer_name not in analyzer_errors:
                    analyzer_errors[analyzer_name] = str(exc)
                continue
            successful_analyzers.add(analyzer_name)
            for finding in external_findings:
                normalized = _normalize_finding(plugin_dir, target.read_path, finding)
                findings.append(normalized)
    # Preserve configured order for deterministic output
    ordered_successful = tuple(name for name, _ in analyzers if name in successful_analyzers)
    # Only report errors for analyzers that never succeeded
    failed_only = {n: e for n, e in analyzer_errors.items() if n not in successful_analyzers}
    return tuple(findings), targets_scanned, ordered_successful, failed_only


def run_cisco_mcp_scan(
    plugin_dir: Path,
    mode: str = "auto",
    timeout_seconds: float | None = None,
) -> CiscoMcpScanSummary:
    """Run Cisco MCP scanner static analysis when available."""

    config_path = plugin_dir / ".mcp.json"

    if mode == "off":
        return _build_summary(
            status=CiscoIntegrationStatus.SKIPPED,
            message="Cisco MCP scanning disabled by configuration.",
        )

    if _safe_resolved_static_target(plugin_dir, config_path) is None:
        return _build_summary(
            status=CiscoIntegrationStatus.SKIPPED,
            message="No .mcp.json found; Cisco MCP scan skipped.",
        )
    runtime_message = cisco_runtime_unavailable_message()
    if runtime_message is not None:
        return _build_summary(
            status=CiscoIntegrationStatus.UNAVAILABLE,
            message=runtime_message,
        )

    try:
        try:
            components = _load_mcp_scanner_components(blocked_root=plugin_dir)
        except TypeError as exc:
            if "blocked_root" not in str(exc):
                raise
            components = _load_mcp_scanner_components()
    except ImportError:
        if mode == "on":
            return _build_summary(
                status=CiscoIntegrationStatus.UNAVAILABLE,
                message="Cisco MCP scanner is required but not installed. Ensure package dependencies are installed.",
            )
        return _build_summary(
            status=CiscoIntegrationStatus.UNAVAILABLE,
            message="Cisco MCP scanner not installed; deep MCP scan skipped.",
        )
    except Exception as exc:
        return _build_summary(
            status=CiscoIntegrationStatus.FAILED,
            message=f"Cisco MCP scanner failed to load: {exc}",
        )

    try:
        analyzers: list[tuple[str, _CiscoAnalyzer]] = []
        for name, factory in components.items():
            analyzer_name = name.replace("Analyzer", "").lower()
            analyzers.append((analyzer_name, factory()))
        targets = _collect_static_targets(plugin_dir)
        scan_awaitable = _scan_targets_multi(plugin_dir, targets, tuple(analyzers))
        if timeout_seconds is not None:
            scan_awaitable = asyncio.wait_for(scan_awaitable, timeout=timeout_seconds)
        findings, targets_scanned, successful_analyzers, analyzer_errors = _run_awaitable(scan_awaitable)
    except (TimeoutError, asyncio.TimeoutError):
        return _build_summary(
            status=CiscoIntegrationStatus.TIMED_OUT,
            message="Cisco MCP scanner timed out before it could finish.",
        )
    except Exception as exc:
        return _build_summary(
            status=CiscoIntegrationStatus.FAILED,
            message=f"Cisco MCP scanner failed: {exc}",
        )

    # When all configured analyzers failed, report as failed
    if not successful_analyzers and analyzer_errors:
        error_details = "; ".join(f"{n}: {e}" for n, e in analyzer_errors.items())
        return _build_summary(
            status=CiscoIntegrationStatus.FAILED,
            message=f"All configured analyzers failed: {error_details}",
        )
    # When no targets were scanned, no analyzer actually ran
    if targets_scanned == 0:
        return _build_summary(
            status=CiscoIntegrationStatus.SKIPPED,
            message="No scannable MCP targets found; scan skipped.",
        )
    # Only report analyzers that actually ran successfully
    analyzer_names = successful_analyzers if successful_analyzers else tuple(name for name, _ in analyzers)
    error_suffix = f" (skipped: {', '.join(f'{n} ({e})' for n, e in analyzer_errors.items())})" if analyzer_errors else ""
    if findings:
        message = (
            f"Cisco MCP scanner completed static analysis for {targets_scanned} target(s) "
            f"using {', '.join(analyzer_names)} analyzer(s) "
            f"and reported {len(findings)} finding(s).{error_suffix}"
        )
    else:
        message = (
            f"Cisco MCP scanner completed static analysis for {targets_scanned} target(s) "
            f"using {', '.join(analyzer_names)} analyzer(s) with no findings.{error_suffix}"
        )
    return _build_summary(
        status=CiscoIntegrationStatus.ENABLED,
        message=message,
        findings=findings,
        targets_scanned=targets_scanned,
        analyzers_used=analyzer_names,
    )
