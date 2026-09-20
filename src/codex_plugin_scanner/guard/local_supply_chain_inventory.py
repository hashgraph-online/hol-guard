"""Inventory helpers using the original live supply-chain namespace."""

from __future__ import annotations


def _targets_from_workspace_manifests(
    workspace_dir: _api.Path,
    manifest_paths: _api.Sequence[str],
) -> tuple[_api.PackageIntentTarget, ...]:
    seen: set[tuple[str, str | None, str, str | None]] = set()
    targets: list[_api.PackageIntentTarget] = []
    for manifest_path in manifest_paths:
        disk_path = workspace_dir / manifest_path
        try:
            manifest_text = disk_path.read_text(encoding="utf-8")
        except OSError:
            continue
        dependency_map = _api.parse_manifest_dependencies(path=manifest_path, text=manifest_text)
        ecosystem = _api._ECOSYSTEM_BY_MANIFEST.get(_api.Path(manifest_path).name)
        if ecosystem is None:
            continue
        for package_name, version in dependency_map.items():
            target = _api._target_from_manifest_dependency(ecosystem, package_name, version)
            fingerprint = (target.ecosystem, target.package_name, target.raw_spec, target.source_url)
            if fingerprint in seen:
                continue
            seen.add(fingerprint)
            targets.append(target)
    return tuple(targets)


def _workspace_audit_inventory(
    workspace_dir: _api.Path,
    *,
    sbom_paths: _api.Sequence[str],
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...], tuple[dict[str, object], ...]]:
    manifest_paths, lockfile_paths = _api._workspace_files(workspace_dir)
    normalized_sbom_paths = _api._resolve_sbom_paths(workspace_dir, sbom_paths)
    inventory = _api._workspace_inventory_from_paths(workspace_dir, manifest_paths, lockfile_paths)
    inventory_map = {_api._inventory_key(item): dict(item) for item in inventory}
    for sbom_path in normalized_sbom_paths:
        disk_path = workspace_dir / sbom_path
        sbom_text = _api._read_sbom_text(disk_path)
        if sbom_text is None:
            continue
        try:
            parsed_items = _api._inventory_from_sbom_text(sbom_text)
        except ValueError:
            continue
        for item in parsed_items:
            _api._merge_inventory_item(inventory_map, item)
    return (manifest_paths, lockfile_paths, normalized_sbom_paths, tuple(inventory_map.values()))


def _workspace_diff_audit_inventory(
    *,
    before_workspace_dir: _api.Path,
    after_workspace_dir: _api.Path,
    sbom_paths: _api.Sequence[str],
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...], tuple[dict[str, object], ...], dict[str, object]]:
    manifest_paths, lockfile_paths = _api._workspace_files(after_workspace_dir)
    normalized_sbom_paths = _api._resolve_sbom_paths(after_workspace_dir, sbom_paths)
    inventory_map: dict[tuple[str, str | None, str], dict[str, object]] = {}
    changed_paths: list[str] = []
    changed_packages: list[str] = []
    for relative_path in (*manifest_paths, *lockfile_paths):
        before_path = before_workspace_dir / relative_path
        after_path = after_workspace_dir / relative_path
        before_text = before_path.read_text(encoding="utf-8") if before_path.exists() else None
        after_text = after_path.read_text(encoding="utf-8") if after_path.exists() else None
        if before_text is None and after_text is None:
            continue
        change_result = _api.parse_manifest_dependency_changes(
            path=relative_path,
            before_text=before_text,
            after_text=after_text,
        )
        if not change_result.changes:
            continue
        changed_paths.append(relative_path)
        ecosystem = _api._ECOSYSTEM_BY_MANIFEST.get(_api.Path(relative_path).name) or _api._ECOSYSTEM_BY_LOCKFILE.get(
            _api.Path(relative_path).name
        )
        if ecosystem is None:
            continue
        direct = _api.Path(relative_path).name in _api._ECOSYSTEM_BY_MANIFEST
        for change in change_result.changes:
            if change.after is None:
                continue
            namespace, name = _api._split_namespace_name(change.package_name)
            changed_packages.append(change.package_name)
            _api._merge_inventory_item(
                inventory_map,
                {
                    "ecosystem": ecosystem,
                    "namespace": namespace,
                    "name": name,
                    "direct": direct,
                    "range": change.after if direct else None,
                    "version": None if direct else change.after,
                },
            )
    for sbom_path in normalized_sbom_paths:
        disk_path = after_workspace_dir / sbom_path
        sbom_text = _api._read_sbom_text(disk_path)
        if sbom_text is None:
            continue
        try:
            parsed_items = _api._inventory_from_sbom_text(sbom_text)
        except ValueError:
            continue
        for item in parsed_items:
            _api._merge_inventory_item(inventory_map, item)
    summary: dict[str, object] = {
        "changed_package_count": len({item for item in changed_packages}),
        "changed_paths": changed_paths,
    }
    return (manifest_paths, lockfile_paths, normalized_sbom_paths, tuple(inventory_map.values()), summary)


def _workspace_inventory_from_paths(
    workspace_dir: _api.Path,
    manifest_paths: _api.Sequence[str],
    lockfile_paths: _api.Sequence[str],
) -> tuple[dict[str, object], ...]:
    inventory_map: dict[tuple[str, str | None, str], dict[str, object]] = {}
    for manifest_path in manifest_paths:
        ecosystem = _api._ECOSYSTEM_BY_MANIFEST.get(_api.Path(manifest_path).name)
        if ecosystem is None:
            continue
        manifest_text = _api._read_workspace_audit_text(workspace_dir, manifest_path)
        if manifest_text is None:
            continue
        for package_name, version in _api.parse_manifest_dependencies(path=manifest_path, text=manifest_text).items():
            namespace, name = _api._split_namespace_name(package_name)
            _api._merge_inventory_item(
                inventory_map,
                {
                    "ecosystem": ecosystem,
                    "namespace": namespace,
                    "name": name,
                    "direct": True,
                    "range": version.strip() or None,
                    "version": None,
                },
            )
    for lockfile_path in lockfile_paths:
        ecosystem = _api._ECOSYSTEM_BY_LOCKFILE.get(_api.Path(lockfile_path).name)
        if ecosystem is None:
            continue
        lockfile_text = _api._read_workspace_audit_text(workspace_dir, lockfile_path)
        if lockfile_text is None:
            continue
        for package_name, version in _api.parse_manifest_dependencies(path=lockfile_path, text=lockfile_text).items():
            namespace, name = _api._split_namespace_name(package_name)
            _api._merge_inventory_item(
                inventory_map,
                {
                    "ecosystem": ecosystem,
                    "namespace": namespace,
                    "name": name,
                    "direct": False,
                    "range": None,
                    "version": version.strip() or None,
                },
            )
    return tuple(inventory_map.values())


def _merge_inventory_item(
    inventory_map: dict[tuple[str, str | None, str], dict[str, object]],
    item: dict[str, object],
) -> None:
    key = _api._inventory_key(item)
    existing = inventory_map.get(key)
    if existing is None:
        inventory_map[key] = {
            "ecosystem": str(item["ecosystem"]),
            "namespace": item.get("namespace"),
            "name": str(item["name"]),
            "direct": bool(item.get("direct")),
            "range": item.get("range"),
            "version": item.get("version"),
        }
        return
    existing["direct"] = bool(existing.get("direct")) or bool(item.get("direct"))
    if existing.get("range") is None and item.get("range") is not None:
        existing["range"] = item["range"]
    if existing.get("version") is None and item.get("version") is not None:
        existing["version"] = item["version"]


def _inventory_key(item: dict[str, object]) -> tuple[str, str | None, str]:
    namespace = item.get("namespace")
    return (str(item["ecosystem"]), namespace if isinstance(namespace, str) else None, str(item["name"]))


def _split_namespace_name(package_name: str) -> tuple[str | None, str]:
    cleaned = package_name.strip()
    if cleaned.startswith("@") and "/" in cleaned:
        namespace, _, name = cleaned.partition("/")
        return (namespace, name)
    return (None, cleaned)


def _target_from_inventory_item(item: dict[str, object]) -> _api.PackageIntentTarget:
    qualified_name = (
        f"{item['namespace']}/{item['name']}" if isinstance(item.get("namespace"), str) else str(item["name"])
    )
    version = item.get("version")
    version_range = item.get("range")
    ecosystem = str(item["ecosystem"])
    if ecosystem == "npm":
        suffix = str(version) if isinstance(version, str) else str(version_range or "")
        spec = qualified_name if not suffix else f"{qualified_name}@{suffix}"
        return _api.js_target(spec)
    if ecosystem == "pypi":
        suffix = str(version) if isinstance(version, str) else str(version_range or "")
        spec = qualified_name if not suffix else f"{qualified_name}{suffix}"
        return _api.python_target(spec)
    if ecosystem == "maven":
        suffix = str(version) if isinstance(version, str) else str(version_range or "")
        spec = qualified_name if not suffix else f"{qualified_name}:{suffix}"
        return _api.coordinate_target(ecosystem, spec)
    if ecosystem == "packagist":
        suffix = str(version) if isinstance(version, str) else str(version_range or "")
        spec = qualified_name if not suffix else f"{qualified_name}:{suffix}"
        return _api.composer_target(spec)
    suffix = str(version) if isinstance(version, str) else str(version_range or "")
    spec = qualified_name if not suffix else f"{qualified_name}@{suffix}"
    return _api.version_target(ecosystem, spec)


def _resolve_sbom_paths(workspace_dir: _api.Path, sbom_paths: _api.Sequence[str]) -> tuple[str, ...]:
    resolved: list[str] = []
    for raw_path in sbom_paths:
        candidate = _api.Path(raw_path)
        disk_path = candidate if candidate.is_absolute() else workspace_dir / candidate
        if not disk_path.exists():
            continue
        try:
            normalized = str(disk_path.relative_to(workspace_dir))
        except ValueError:
            normalized = disk_path.name
        if normalized not in resolved:
            resolved.append(normalized)
    return tuple(resolved)


def _inventory_from_sbom_text(text: str) -> tuple[dict[str, object], ...]:
    payload = _api.json.loads(text)
    if not isinstance(payload, dict):
        raise ValueError("SBOM payload must be an object")
    if payload.get("bomFormat") == "CycloneDX":
        return _api._inventory_from_cyclonedx(payload)
    if payload.get("spdxVersion"):
        return _api._inventory_from_spdx(payload)
    raise ValueError("Unsupported SBOM format")


def _read_sbom_text(disk_path: _api.Path) -> str | None:
    try:
        if disk_path.stat().st_size > _api._MAX_SBOM_BYTES:
            return None
        return disk_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None


def _inventory_from_cyclonedx(payload: dict[str, object]) -> tuple[dict[str, object], ...]:
    components = payload.get("components")
    if not isinstance(components, list):
        return ()
    inventory: dict[tuple[str, str | None, str], dict[str, object]] = {}
    for component in components:
        if not isinstance(component, dict):
            continue
        item = _api._inventory_item_from_sbom_component(
            name=component.get("name"),
            version=component.get("version"),
            purl=component.get("purl"),
        )
        if item is None:
            continue
        _api._merge_inventory_item(inventory, item)
    return tuple(inventory.values())


def _inventory_from_spdx(payload: dict[str, object]) -> tuple[dict[str, object], ...]:
    packages = payload.get("packages")
    if not isinstance(packages, list):
        return ()
    inventory: dict[tuple[str, str | None, str], dict[str, object]] = {}
    for package in packages:
        if not isinstance(package, dict):
            continue
        purl = None
        external_refs = package.get("externalRefs")
        if isinstance(external_refs, list):
            for external_ref in external_refs:
                if not isinstance(external_ref, dict):
                    continue
                if str(external_ref.get("referenceType") or "").lower() != "purl":
                    continue
                locator = external_ref.get("referenceLocator")
                if isinstance(locator, str) and locator:
                    purl = locator
                    break
        item = _api._inventory_item_from_sbom_component(
            name=package.get("name"),
            version=package.get("versionInfo"),
            purl=purl,
        )
        if item is None:
            continue
        _api._merge_inventory_item(inventory, item)
    return tuple(inventory.values())


def _inventory_item_from_sbom_component(
    *,
    name: object,
    version: object,
    purl: object,
) -> dict[str, object] | None:
    purl_values = _api._inventory_from_purl(purl if isinstance(purl, str) else None)
    if purl_values is None and not isinstance(name, str):
        return None
    ecosystem = purl_values["ecosystem"] if purl_values is not None else "unsupported"
    namespace = purl_values["namespace"] if purl_values is not None else None
    package_name = purl_values["name"] if purl_values is not None else str(name).strip()
    package_version = (
        purl_values["version"]
        if purl_values is not None
        else (str(version).strip() if isinstance(version, str) else None)
    )
    if not package_name:
        return None
    return {
        "ecosystem": ecosystem,
        "namespace": namespace,
        "name": package_name,
        "direct": False,
        "range": None,
        "version": package_version,
    }


def _inventory_from_purl(purl: str | None) -> dict[str, object] | None:
    if purl is None or not purl.startswith("pkg:"):
        return None
    without_prefix = purl[4:]
    package_type, _, remainder = without_prefix.partition("/")
    ecosystem = _api._ECOSYSTEM_BY_PURL.get(package_type)
    if ecosystem is None or not remainder:
        return None
    package_ref = remainder.split("?", 1)[0].split("#", 1)[0]
    package_path, _, package_version = package_ref.partition("@")
    if not package_path:
        return None
    if "/" in package_path:
        namespace, _, name = package_path.rpartition("/")
        return {
            "ecosystem": ecosystem,
            "namespace": _api.urllib.parse.unquote(namespace) if namespace else None,
            "name": _api.urllib.parse.unquote(name),
            "version": _api.urllib.parse.unquote(package_version) if package_version else None,
        }
    return {
        "ecosystem": ecosystem,
        "namespace": None,
        "name": _api.urllib.parse.unquote(package_path),
        "version": _api.urllib.parse.unquote(package_version) if package_version else None,
    }


# Bind after declarations so importing this owner directly preserves the facade cycle.
from . import local_supply_chain as _api  # noqa: E402
