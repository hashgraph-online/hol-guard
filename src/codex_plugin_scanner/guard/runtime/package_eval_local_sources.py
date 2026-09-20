"""Local package source and manifest evaluation."""

from __future__ import annotations


def _local_package_manifest_result(
    *,
    target: dict[str, object],
    artifact: _eval.GuardArtifact,
    workspace_dir: _eval.Path | None,
) -> dict[str, object] | None:
    manifest_path = _eval._local_package_manifest_path(target, workspace_dir)
    if manifest_path is None:
        return None
    try:
        manifest_text = manifest_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    signals = tuple(
        signal
        for signal in _eval.detect_supply_chain_risk(manifest_text)
        if signal.signal_id.startswith("supply-chain.postinstall")
        or signal.signal_id.endswith("install-lifecycle-exec")
    )
    if not signals:
        return None
    manifest_target = dict(target)
    manifest_package_name = _eval._manifest_package_name(manifest_text)
    if manifest_package_name is not None:
        namespace, name = _eval._split_namespace_name(
            manifest_package_name,
            ecosystem=_eval._optional_string(target.get("ecosystem")) or "npm",
        )
        manifest_target["namespace"] = namespace
        manifest_target["name"] = name
    if _eval._artifact_has_flag(artifact, "--ignore-scripts"):
        return _eval._heuristic_package_result(
            target=manifest_target,
            decision="allow",
            code="ignore_scripts_applied",
            message="`--ignore-scripts` disables lifecycle hooks for this local package install.",
            severity="low",
        )
    strongest_signal = sorted(signals, key=lambda item: _eval._severity_rank_value(item.severity), reverse=True)[0]
    return _eval._heuristic_package_result(
        target=manifest_target,
        decision="block",
        code="install_script_risk",
        message=strongest_signal.plain_reason,
        severity=strongest_signal.severity,
    )


def _local_package_manifest_path(target: dict[str, object], workspace_dir: _eval.Path | None) -> _eval.Path | None:
    if workspace_dir is None:
        return None
    raw_spec = _eval._optional_string(target.get("raw_spec"))
    source_url = _eval._optional_string(target.get("source_url"))
    if source_url is not None and source_url.startswith("file:"):
        raw_spec = source_url.partition("file:")[2]
    source_spec = _eval._npm_source_spec(raw_spec, ecosystem="npm")
    if raw_spec is None or (source_spec is not None and source_spec.source_kind != "local"):
        return None
    if raw_spec.startswith("file:"):
        raw_spec = raw_spec.partition("file:")[2]
    candidate_path = _eval.Path(raw_spec)
    disk_path = candidate_path if candidate_path.is_absolute() else workspace_dir / candidate_path
    if disk_path.is_dir():
        manifest_path = disk_path / "package.json"
        return manifest_path if manifest_path.exists() else None
    if disk_path.name == "package.json" and disk_path.exists():
        return disk_path
    return None


def _local_python_build_result(target: dict[str, object], workspace_dir: _eval.Path | None) -> dict[str, object] | None:
    if workspace_dir is None or (_eval._optional_string(target.get("ecosystem")) or "npm") != "pypi":
        return None
    project_path = _eval._local_python_project_path(target, workspace_dir)
    if project_path is None:
        return None
    setup_py_path = project_path / "setup.py"
    if setup_py_path.exists():
        try:
            setup_py_text = setup_py_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            setup_py_text = ""
        if _eval._python_setup_script_looks_suspicious(setup_py_text):
            return _eval._heuristic_package_result(
                target=target,
                decision="block",
                code="setup_py_exec_risk",
                message="Local setup.py executes commands or network behavior during packaging.",
                severity="high",
            )
    pyproject_path = project_path / "pyproject.toml"
    if pyproject_path.exists():
        try:
            pyproject_text = pyproject_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            pyproject_text = ""
        if "[build-system]" in pyproject_text and "build-backend" in pyproject_text:
            if _eval._python_setup_script_looks_suspicious(pyproject_text):
                return _eval._heuristic_package_result(
                    target=target,
                    decision="block",
                    code="build_backend_exec_risk",
                    message="Local pyproject build backend references execution or network bootstrap behavior.",
                    severity="high",
                )
            return _eval._heuristic_package_result(
                target=target,
                decision="ask",
                code="local_build_backend_risk",
                message="Editable local Python installs can invoke pyproject build backend hooks from this workspace.",
                severity="medium",
            )
    return None


def _looks_like_explicit_local_python_path(raw_spec: str) -> bool:
    normalized, _extras = _eval.split_python_extras(_eval._local_python_path_text(raw_spec))
    return (
        normalized == "."
        or normalized == "~"
        or normalized.startswith(("./", "../", "/", "~/", ".\\", "..\\", "~\\", "\\\\", "//"))
        or "/" in normalized
        or "\\" in normalized
        or bool(_eval.re.match(r"^[A-Za-z]:[\\\\/]", normalized))
    )


def _local_python_path_text(raw_spec: str) -> str:
    path_text = raw_spec.partition("file:")[2] if raw_spec.startswith("file:") else raw_spec
    normalized_path, _extras = _eval.split_python_extras(path_text)
    return normalized_path or path_text


def _local_python_project_path(target: dict[str, object], workspace_dir: _eval.Path) -> _eval.Path | None:
    raw_spec = _eval._optional_string(target.get("raw_spec"))
    source_url = _eval._optional_string(target.get("source_url"))
    editable = bool(target.get("editable"))
    if source_url is not None and source_url.startswith("file:"):
        raw_spec = source_url.partition("file:")[2]
    if raw_spec is None:
        return workspace_dir if editable else None
    if raw_spec.startswith(("http://", "https://", "git+", "github:", "gitlab:", "bitbucket:")):
        return None
    if not _eval._looks_like_explicit_local_python_path(raw_spec):
        workspace_has_python_project = (workspace_dir / "pyproject.toml").exists() or (
            workspace_dir / "setup.py"
        ).exists()
        return workspace_dir if editable and workspace_has_python_project else None
    path_text = _eval._local_python_path_text(raw_spec)
    try:
        candidate_path = _eval.Path(path_text).expanduser()
    except RuntimeError:
        candidate_path = _eval.Path(path_text)
    disk_path = candidate_path if candidate_path.is_absolute() else workspace_dir / candidate_path
    if disk_path.is_dir():
        if (disk_path / "pyproject.toml").exists() or (disk_path / "setup.py").exists():
            return disk_path
        return None
    parent = disk_path.parent
    if disk_path.name in {"pyproject.toml", "setup.py"} and disk_path.exists():
        return parent
    workspace_has_python_project = (workspace_dir / "pyproject.toml").exists() or (workspace_dir / "setup.py").exists()
    return workspace_dir if editable and workspace_has_python_project else None


def _python_setup_script_looks_suspicious(content: str) -> bool:
    return bool(
        _eval.re.search(
            r"\b(?:os\.system|subprocess\.(?:run|Popen|call|check_output)|requests\.(?:get|post)|urllib\.request\.)",
            content,
        )
        or _eval.re.search(r"\b(?:curl|wget)\b", content)
    )


def _manifest_package_name(manifest_text: str) -> str | None:
    try:
        payload = _eval.json.loads(manifest_text or "{}")
    except _eval.json.JSONDecodeError:
        return None
    package_name = payload.get("name")
    return package_name.strip() if isinstance(package_name, str) and package_name.strip() else None


def _artifact_has_flag(artifact: _eval.GuardArtifact, flag: str) -> bool:
    raw_flags = artifact.metadata.get("flags")
    return isinstance(raw_flags, list) and flag in raw_flags


def _dependency_confusion_policy_package_result(
    rules: tuple[_eval.SupplyChainBundlePolicyRule, ...],
    *,
    target: dict[str, object],
) -> dict[str, object] | None:
    if (_eval._optional_string(target.get("ecosystem")) or "npm") != "npm" or _eval._optional_string(
        target.get("namespace")
    ) is not None:
        return None
    current_time = _eval.datetime.now(_eval.timezone.utc).timestamp()
    target_name = str(target["name"]).lower()
    sorted_rules = sorted(
        rules, key=lambda item: (item.priority if item.priority is not None else 10_000, item.rule_id)
    )
    for rule in sorted_rules:
        if rule.enabled is False:
            continue
        if rule.expires_at is not None:
            try:
                if _eval.datetime.fromisoformat(rule.expires_at.replace("Z", "+00:00")).timestamp() <= current_time:
                    continue
            except ValueError:
                pass
        if rule.ecosystem_selector is not None and rule.ecosystem_selector != "npm":
            continue
        selector = (rule.package_selector or "").strip().lower()
        if not selector or not _eval._dependency_confusion_selector_matches(selector, target_name):
            continue
        decision = _eval._normalize_bundle_action(rule.action)
        if decision not in {"block", "ask", "warn"}:
            decision = "warn"
        return _eval._package_target_result(
            target,
            decision=decision,
            reasons=(
                {
                    "code": "dependency_confusion_risk",
                    "message": (
                        f"Policy reserves internal package selector {rule.package_selector}; "
                        f"installing public package {target_name} may cause dependency confusion."
                    ),
                    "severity": "high",
                    "source": "policy",
                },
            ),
            rule_id=rule.rule_id,
        )
    return None


def _dependency_confusion_selector_matches(selector: str, target_name: str) -> bool:
    if not selector.startswith("@") or "/" not in selector:
        return False
    selector = selector.split("/", 1)[1]
    if selector in {"", "*"}:
        return False
    if selector.endswith("*"):
        return target_name.startswith(selector[:-1])
    return target_name == selector


def _heuristic_package_result(
    *,
    target: dict[str, object],
    decision: str,
    code: str,
    message: str,
    severity: str,
    resolved_version: str | None = None,
    recommended_fix_version: str | None = None,
) -> dict[str, object]:
    return {
        "decision": decision,
        "ecosystem": target["ecosystem"],
        "name": target["name"],
        "namespace": target["namespace"],
        "requestedVersion": _eval._optional_string(target.get("range"))
        or _eval._optional_string(target.get("version")),
        "resolvedVersion": (
            resolved_version if resolved_version is not None else _eval._optional_string(target.get("version"))
        ),
        "recommendedFixVersion": recommended_fix_version,
        "riskScore": None,
        "direct": True,
        "dependencyPath": None,
        "packageManager": _eval._optional_string(target.get("package_manager")) or "npm",
        "redactedCommand": _eval._optional_string(target.get("redacted_command")),
        "alias": _eval._optional_string(target.get("alias")),
        "sourceIdentity": _eval._optional_string(target.get("source_identity")),
        "sourceRepository": _eval._optional_string(target.get("source_repository")),
        "sourceRevisionKind": _eval._optional_string(target.get("source_revision_kind")),
        "reasons": (
            {
                "code": code,
                "message": message,
                "severity": severity,
                "source": "guard-local",
            },
        ),
    }


def _go_replace_result(
    *,
    target: dict[str, object],
    artifact: _eval.GuardArtifact,
    workspace_dir: _eval.Path | None,
) -> dict[str, object] | None:
    if workspace_dir is None or (_eval._optional_string(target.get("ecosystem")) or "npm") != "go":
        return None
    manifest_paths = artifact.metadata.get("manifest_paths")
    if not isinstance(manifest_paths, list):
        return None
    go_mod_relative_path = next(
        (
            str(path)
            for path in manifest_paths
            if _eval.Path(str(path)).name == "go.mod" and _eval.path_exists_within_workspace(workspace_dir, str(path))
        ),
        None,
    )
    if go_mod_relative_path is None:
        return None
    go_mod_text = _eval.read_text_within_workspace(workspace_dir, go_mod_relative_path)
    if go_mod_text is None:
        return None
    replacements = _eval._go_mod_replace_map(go_mod_text)
    for candidate in _eval._target_candidate_names(target):
        replacement = replacements.get(candidate)
        if replacement is None:
            continue
        if replacement.startswith(("file:", "./", "../", "/", "~", ".\\", "..\\")):
            return _eval._heuristic_package_result(
                target=target,
                decision="ask",
                code="go_replace_local_source",
                message="Go replace directive reroutes this module to a local path.",
                severity="medium",
            )
        if _eval._exact_version(replacement) is None:
            return _eval._heuristic_package_result(
                target=target,
                decision="ask",
                code="go_replace_mutable_source",
                message="Go replace directive reroutes this module away from proxy-pinned version resolution.",
                severity="medium",
            )
    return None


def _go_mod_replace_map(text: str) -> dict[str, str]:
    replacements: dict[str, str] = {}
    in_replace_block = False
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line.startswith("replace ("):
            in_replace_block = True
            continue
        if in_replace_block and line == ")":
            in_replace_block = False
            continue
        if line.startswith("replace "):
            line = line.removeprefix("replace ").strip()
        elif not in_replace_block:
            continue
        if "=>" not in line:
            continue
        original, _, replacement = line.partition("=>")
        normalized_original = original.strip().split()[0]
        normalized_replacement = replacement.strip().split()[0]
        if normalized_original and normalized_replacement:
            replacements[_eval._normalize_package_name("go", normalized_original)] = normalized_replacement
    return replacements


def _is_git_source_url(source_url: str) -> bool:
    source = _eval.parse_npm_source_spec(source_url)
    return source is not None and source.is_git


# Resolve the facade after declarations so direct helper imports retain the cycle.
from . import supply_chain_package_eval as _eval  # noqa: E402
