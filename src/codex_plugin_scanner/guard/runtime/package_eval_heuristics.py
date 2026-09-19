"""Local package heuristics through the live evaluator."""

from __future__ import annotations


def _heuristic_result(
    *,
    artifact: _eval.GuardArtifact,
    store: _eval.GuardStore,
    targets: tuple[dict[str, object], ...],
    workspace_dir: _eval.Path | None,
    external_archive_network_authorized: bool,
    retain_external_archive_blob: bool,
    external_archive_request_deadline: float | None = None,
) -> _eval._EvaluationDraft | None:
    packages: list[dict[str, object]] = []
    external_archive_downloads: list[_eval.RestrictedArchiveDownload] = []
    external_archive_source_hashes = [
        _eval.stable_digest_hex(source_url.encode("utf-8"))
        for target in targets
        if (source_url := _eval._optional_string(target.get("source_url"))) is not None
        and _eval._target_is_external_https_archive(target)
    ]
    retained_archive_bytes = 0
    for target in targets:
        source_url = _eval._optional_string(target.get("source_url"))
        if target.get("external_archive_source_integrity_invalid") is True:
            packages.append(
                _eval._heuristic_package_result(
                    target=target,
                    decision="block",
                    code="external_archive_source_integrity_invalid",
                    message="Package source private data no longer matches its approved public identity.",
                    severity="high",
                )
            )
            continue
        source_invalid_reason = _eval._optional_string(target.get("source_invalid_reason"))
        if source_invalid_reason is not None:
            packages.append(
                _eval._heuristic_package_result(
                    target=target,
                    decision="block",
                    code=source_invalid_reason,
                    message="Package source syntax is ambiguous or invalid and cannot be authenticated.",
                    severity="high",
                )
            )
            continue
        if source_url is not None and _eval._target_is_external_https_archive(target):
            try:
                package_result, external_archive_download = _eval._external_tarball_dependency_result(
                    target,
                    network_authorized=external_archive_network_authorized,
                    retain_download=retain_external_archive_blob,
                    request_deadline=external_archive_request_deadline,
                )
            except BaseException:
                for retained_archive in external_archive_downloads:
                    retained_archive.cleanup()
                raise
            if external_archive_download is not None:
                retained_archive_bytes += external_archive_download.size
                if retained_archive_bytes > _eval._EXTERNAL_ARCHIVE_MAX_AGGREGATE_BYTES:
                    external_archive_download.cleanup()
                    for retained_archive in external_archive_downloads:
                        retained_archive.cleanup()
                    external_archive_downloads.clear()
                    packages.append(
                        _eval._heuristic_package_result(
                            target=target,
                            decision="block",
                            code="external_archive_aggregate_size_limit",
                            message="External archives exceeded Guard's aggregate retained-byte limit.",
                            severity="high",
                        )
                    )
                    break
                external_archive_downloads.append(external_archive_download)
            if target.get("manifest_unsynced") is True:
                package_result = _eval._with_package_reason(
                    package_result,
                    {
                        "code": "manifest_lockfile_unsynced",
                        "message": (
                            f"{target['package_name']} is declared in the project manifest but is not pinned "
                            "in the existing lockfile yet, so Guard requires review before install."
                        ),
                        "severity": "high",
                        "source": "guard-local",
                    },
                )
            lockfile_parse_warning = _eval._lockfile_parse_warning_result(
                target=target,
                artifact=artifact,
                workspace_dir=workspace_dir,
            )
            if lockfile_parse_warning is not None:
                first_reason = _eval._first_dict_item(lockfile_parse_warning.get("reasons"))
                if first_reason is not None:
                    package_result = _eval._with_package_reason(package_result, first_reason)
            packages.append(package_result)
            continue
        if target.get("manifest_unsynced") is True:
            packages.append(
                _eval._heuristic_package_result(
                    target=target,
                    decision="ask",
                    code="manifest_lockfile_unsynced",
                    message=(
                        f"{target['package_name']} is declared in the project manifest but is not pinned "
                        "in the existing lockfile yet, so Guard requires review before install."
                    ),
                    severity="high",
                )
            )
            continue
        lockfile_parse_warning = _eval._lockfile_parse_warning_result(
            target=target,
            artifact=artifact,
            workspace_dir=workspace_dir,
        )
        package_result: dict[str, object] | None = None
        local_package_result = _eval._local_package_manifest_result(
            target=target,
            artifact=artifact,
            workspace_dir=workspace_dir,
        )
        if local_package_result is not None:
            package_result = local_package_result
        if package_result is None:
            local_python_result = _eval._local_python_build_result(target=target, workspace_dir=workspace_dir)
            if local_python_result is not None:
                package_result = local_python_result
        ecosystem = _eval._optional_string(target.get("ecosystem")) or "npm"
        if package_result is None and ecosystem in {"homebrew", "homebrew-cask", "homebrew-tap"}:
            package_result = _eval._homebrew_package_monitor_result(target)
        if package_result is None and ecosystem == "system":
            package_result = _eval._system_package_monitor_result(target)
        if package_result is None and ecosystem == "unsupported":
            package_result = _eval._unsupported_ecosystem_result(target)
        if package_result is None:
            go_replace_result = _eval._go_replace_result(target=target, artifact=artifact, workspace_dir=workspace_dir)
            if go_replace_result is not None:
                package_result = go_replace_result
        if package_result is None:
            local_source_result = _eval._local_source_dependency_result(target)
            if local_source_result is not None:
                package_result = local_source_result
        if package_result is None and source_url is not None and source_url.lower().startswith("http:"):
            package_result = _eval._heuristic_package_result(
                target=target,
                decision="block",
                code="insecure_source_url",
                message="Package source uses insecure HTTP transport.",
                severity="high",
            )
        if package_result is None and source_url is not None and _eval._is_git_source_url(source_url):
            repository = _eval._optional_string(target.get("source_repository")) or "Git repository"
            revision_kind = _eval._optional_string(target.get("source_revision_kind")) or "missing"
            package_result = _eval._heuristic_package_result(
                target=target,
                decision="ask",
                code="git_dependency_source",
                message=f"Git package source {repository} ({revision_kind}) requires review before install.",
                severity="high",
            )
        if package_result is None:
            if lockfile_parse_warning is not None:
                packages.append(lockfile_parse_warning)
            continue
        if lockfile_parse_warning is not None:
            first_reason = _eval._first_dict_item(lockfile_parse_warning.get("reasons"))
            if first_reason is not None:
                package_result = _eval._with_package_reason(package_result, first_reason)
        packages.append(package_result)
    if not packages:
        return None
    packages.sort(key=lambda item: _eval._decision_rank(str(item.get("decision") or "monitor")), reverse=True)
    decision = str(packages[0].get("decision") or "monitor")
    if decision == "block":
        for retained_archive in external_archive_downloads:
            retained_archive.cleanup()
        external_archive_downloads.clear()
    return _eval._EvaluationDraft(
        decision=decision,
        enforcement="free_local",
        entitlement_state="free",
        cache_status="miss",
        packages=tuple(packages),
        reasons=tuple(reason for package in packages for reason in _eval._dict_items(package.get("reasons"))),
        matched_rule_id=None,
        exception_id=None,
        refresh_required=False,
        record_monitor_evidence=decision == "monitor",
        bundle_version=None,
        policy_version="local:none",
        external_archive_downloads=tuple(external_archive_downloads),
        external_archive_source_hashes=tuple(external_archive_source_hashes),
    )


# Resolve the facade after declarations so direct helper imports retain the cycle.
from . import supply_chain_package_eval as _eval  # noqa: E402
