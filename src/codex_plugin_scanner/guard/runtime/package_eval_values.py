"""Package evaluation value normalization and result metadata."""

from __future__ import annotations


def _with_support_metadata(package: dict[str, object]) -> dict[str, object]:
    metadata = _eval.ecosystem_support_metadata(_eval._optional_string(package.get("ecosystem")) or "unsupported")
    enriched = dict(package)
    enriched["supportLevel"] = metadata["support_level"]
    enriched["supportLabel"] = metadata["support_label"]
    return enriched


def _with_package_reason(package: dict[str, object], reason: dict[str, object]) -> dict[str, object]:
    package_reasons = package.get("reasons")
    updated = dict(package)
    if isinstance(package_reasons, (tuple, list)):
        updated["reasons"] = (*tuple(item for item in package_reasons if isinstance(item, dict)), reason)
    else:
        updated["reasons"] = (reason,)
    return updated


def _normalized_supply_chain_evaluate_url(sync_url: str, workspace_id: str) -> str:
    parsed = _eval.urllib.parse.urlsplit(_eval._normalized_receipts_sync_url(sync_url))
    if parsed.path.rstrip("/") == "/api/guard/receipts/sync":
        next_path = "/api/guard/supply-chain/evaluate"
    elif parsed.path.rstrip("/") == "/guard/receipts/sync":
        next_path = "/guard/supply-chain/evaluate"
    else:
        next_path = parsed.path.rstrip("/") + "/supply-chain/evaluate"
    query_pairs = [
        (key, value)
        for key, value in _eval.urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        if key != "workspaceId"
    ]
    query_pairs.append(("workspaceId", workspace_id))
    return _eval.urllib.parse.urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            next_path,
            _eval.urllib.parse.urlencode(query_pairs),
            "",
        )
    )


def _dict_items(value: object) -> tuple[dict[str, object], ...]:
    if not isinstance(value, (list, tuple)):
        return ()
    return tuple(item for item in value if isinstance(item, dict))


def _first_dict_item(value: object) -> dict[str, object] | None:
    for item in _eval._dict_items(value):
        return item
    return None


def _string_tuple(value: object) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        return ()
    return tuple(item for item in value if isinstance(item, str))


def _optional_string(value: object) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _decision_rank(value: str) -> int:
    return _eval._DECISION_RANK.get(value, 1)


def _fix_command(package: dict[str, object]) -> str | None:
    package_name = _eval._package_install_target(package)
    fix_version = _eval._optional_string(package.get("recommendedFixVersion"))
    ecosystem = _eval._optional_string(package.get("ecosystem")) or "npm"
    package_manager = _eval._optional_string(package.get("packageManager")) or "npm"
    if not fix_version:
        return None
    if ecosystem == "pypi":
        if package_manager == "uv":
            if _eval._uses_uv_pip_install(package):
                return f"uv pip install {package_name}=={fix_version}"
            return f"uv add {package_name}=={fix_version}"
        if package_manager == "poetry":
            return f"poetry add {package_name}@{fix_version}"
        if package_manager == "pipenv":
            return f"pipenv install {package_name}=={fix_version}"
        return f"pip install {package_name}=={fix_version}"
    if package_manager == "pnpm":
        return f"pnpm add {package_name}@{fix_version}"
    if package_manager == "yarn":
        return f"yarn add {package_name}@{fix_version}"
    if package_manager == "bun":
        return f"bun add {package_name}@{fix_version}"
    return f"npm install {package_name}@{fix_version}"


def _uses_uv_pip_install(package: dict[str, object]) -> bool:
    command = (_eval._optional_string(package.get("redactedCommand")) or "").split()
    return len(command) >= 3 and tuple(command[:3]) == ("uv", "pip", "install")


def _package_install_target(package: dict[str, object]) -> str:
    alias = _eval._optional_string(package.get("alias"))
    package_name = _eval._package_display_name({**package, "alias": None})
    ecosystem = _eval._optional_string(package.get("ecosystem")) or "npm"
    if alias is not None and ecosystem == "npm":
        return f"{alias}@npm:{package_name}"
    return alias if alias is not None else package_name


def _package_display_name(package: dict[str, object]) -> str:
    alias = _eval._optional_string(package.get("alias"))
    if alias is not None:
        return alias
    namespace = _eval._optional_string(package.get("namespace"))
    name = _eval._optional_string(package.get("name")) or "package"
    return f"{namespace}/{name}" if namespace is not None else name


def _normalize_package_name(ecosystem: str, package_name: str) -> str:
    try:
        return _eval.normalize_qualified_package_name(ecosystem, package_name)
    except _eval.PackageIdentityError:
        return package_name.strip()


def _reason_severity(package: dict[str, object]) -> str:
    reasons = package.get("reasons")
    if isinstance(reasons, (tuple, list)):
        for item in reasons:
            if isinstance(item, dict):
                severity = _eval._optional_string(item.get("severity"))
                if severity is not None:
                    return severity
    return "unknown"


def _should_record_package(package: dict[str, object], decision: str) -> bool:
    package_decision = str(package.get("decision") or decision)
    return package_decision in {"block", "ask", "warn"} or decision == "monitor"


def _with_additional_reason(
    evaluation: _eval.PackageRequestEvaluation, reason: dict[str, object]
) -> _eval.PackageRequestEvaluation:
    updated_reasons = (*evaluation.reasons, reason)
    updated_packages = []
    for package in evaluation.packages:
        package_reasons = package.get("reasons")
        if isinstance(package_reasons, (tuple, list)):
            updated_package = dict(package)
            updated_package["reasons"] = (
                *tuple(item for item in package_reasons if isinstance(item, dict)),
                reason,
            )
            updated_packages.append(updated_package)
            continue
        updated_package = dict(package)
        updated_package["reasons"] = (reason,)
        updated_packages.append(updated_package)
    return _eval.replace(evaluation, reasons=updated_reasons, packages=tuple(updated_packages))


# Resolve the facade after declarations so direct helper imports retain the cycle.
from . import supply_chain_package_eval as _eval  # noqa: E402
