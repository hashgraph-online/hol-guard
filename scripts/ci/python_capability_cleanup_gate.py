#!/usr/bin/env python3
"""Prove Python hook ownership, oracle reachability, and package cleanup."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tarfile
from hashlib import sha256
from pathlib import Path
from typing import Final
from zipfile import ZipFile

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 compatibility
    import tomli as tomllib

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from scripts.ci.python_capability_cleanup_analysis import (  # noqa: E402
    DynamicImport as _DynamicImport,
)
from scripts.ci.python_capability_cleanup_analysis import (  # noqa: E402
    _analyze_import_graph as _analyze_import_graph,
)
from scripts.ci.python_capability_cleanup_analysis import (  # noqa: E402, F401
    dynamic_import_destinations as _dynamic_import_destinations,
)
from scripts.ci.python_capability_cleanup_analysis import (  # noqa: E402, F401
    module_imports as _module_imports,
)
from scripts.ci.python_capability_cleanup_analysis import (  # noqa: E402
    module_name as _module_name,
)
from scripts.ci.python_capability_cleanup_analysis import (  # noqa: E402
    production_importers as _production_importers,
)
from scripts.ci.python_capability_cleanup_analysis import (  # noqa: E402
    reachable as _reachable,
)

SCHEMA: Final = "hol-guard.python-capability-cleanup.v1"
CONTRACT: Final = "docs/guard/contracts/python-capability-ownership.v1.json"
_ALLOWED_CLASSES: Final = frozenset({"required_control_plane", "named_reference_oracle", "dead_duplicate"})
_MAX_DYNAMIC_IMPORT_DESTINATION: Final = 256
_IMPORT_ROOTS: Final = (
    "codex_plugin_scanner.cli",
    "codex_plugin_scanner.guard.cli.commands",
    "codex_plugin_scanner.guard.daemon.server",
    "codex_plugin_scanner.guard.daemon.hook_process_entrypoint",
)


def _read_json(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError(f"expected JSON object: {path}")
    return value


def _paths(root: Path, patterns: list[str], excludes: list[str] | None = None) -> set[str]:
    excluded = {path for pattern in excludes or [] for path in root.glob(pattern) if path.is_file()}
    return {
        path.relative_to(root).as_posix()
        for pattern in patterns
        for path in root.glob(pattern)
        if path.is_file() and path not in excluded
    }


def _validate_contract(root: Path) -> tuple[dict[str, object], dict[str, str], set[str]]:
    contract = _read_json(root / CONTRACT)
    if contract.get("schema") != "hol-guard.python-capability-ownership.v1":
        raise RuntimeError("unexpected Python capability ownership schema")
    classes = contract.get("classes")
    if not isinstance(classes, list) or set(classes) != _ALLOWED_CLASSES:
        raise RuntimeError("ownership classes do not match the cleanup gate")
    scope_globs = contract.get("scope_globs")
    dynamic_import_policy = contract.get("dynamic_import_policy")
    if not isinstance(dynamic_import_policy, dict):
        raise RuntimeError("dynamic_import_policy must be an object")
    if dynamic_import_policy.get("mode") != "literal_or_bounded":
        raise RuntimeError("unsupported dynamic import policy")
    max_destination_length = dynamic_import_policy.get("max_destination_length")
    if max_destination_length != _MAX_DYNAMIC_IMPORT_DESTINATION:
        raise RuntimeError("dynamic import destination bound is out of sync")
    capabilities = contract.get("capabilities")
    if not isinstance(scope_globs, list) or not all(isinstance(item, str) for item in scope_globs):
        raise RuntimeError("scope_globs must be a list of strings")
    if not isinstance(capabilities, list) or not capabilities:
        raise RuntimeError("capabilities must be a non-empty list")
    scope = _paths(root, scope_globs)
    owners: dict[str, str] = {}
    for capability in capabilities:
        if not isinstance(capability, dict):
            raise RuntimeError("capability entries must be objects")
        capability_id = capability.get("id")
        capability_class = capability.get("class")
        patterns = capability.get("patterns")
        if not isinstance(capability_id, str) or not capability_id:
            raise RuntimeError("capability id is required")
        if capability_class not in _ALLOWED_CLASSES:
            raise RuntimeError(f"invalid class for {capability_id}: {capability_class}")
        if not isinstance(patterns, list) or not all(isinstance(item, str) for item in patterns):
            raise RuntimeError(f"patterns missing for {capability_id}")
        files = _paths(root, patterns, capability.get("exclude_patterns"))
        if not files:
            raise RuntimeError(f"capability has no files: {capability_id}")
        for path in files:
            previous = owners.get(path)
            if previous is not None:
                raise RuntimeError(f"capability overlap for {path}: {previous}, {capability_id}")
            owners[path] = capability_id
    missing = sorted(scope - set(owners))
    extra = sorted(set(owners) - scope)
    if missing or extra:
        raise RuntimeError(f"ownership coverage mismatch: missing={missing}, extra={extra}")
    return contract, owners, scope


def _pyproject_excludes(root: Path) -> list[str]:
    with (root / "pyproject.toml").open("rb") as stream:
        document = tomllib.load(stream)
    value = document.get("tool", {}).get("hatch", {}).get("build", {}).get("exclude", [])
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise RuntimeError("tool.hatch.build.exclude must be a list of strings")
    return value


def _artifact_contains(artifact: Path, package_name: str) -> bool:
    if artifact.name.endswith(".whl"):
        with ZipFile(artifact) as archive:
            return package_name in archive.namelist()
    if artifact.name.endswith(".tar.gz"):
        with tarfile.open(artifact, "r:gz") as archive:
            return any(name.endswith(f"/{package_name}") or name == package_name for name in archive.getnames())
    raise RuntimeError(f"unsupported package artifact: {artifact}")


def _validate_fixture(root: Path, relative: str) -> dict[str, object]:
    fixture = _read_json(root / relative)
    if fixture.get("schema") != "hol-guard.native-hook-parity.v1" or fixture.get("version") != 1:
        raise RuntimeError("invalid native hook parity fixture header")
    cases = fixture.get("cases")
    if not isinstance(cases, list) or not cases:
        raise RuntimeError("parity fixture must contain cases")
    ids: set[str] = set()
    allowed_actions = {"allow", "review", "block", "require-reapproval", "sandbox-required"}
    for case in cases:
        if not isinstance(case, dict):
            raise RuntimeError("parity fixture cases must be objects")
        required = {"id", "event", "input_class", "expected_action"}
        if set(case) != required:
            raise RuntimeError(f"parity case fields must be language-neutral: {case}")
        case_id = case["id"]
        if not isinstance(case_id, str) or not case_id or case_id in ids:
            raise RuntimeError("parity case ids must be unique non-empty strings")
        if case["event"] not in {"PreToolUse", "PostToolUse", "Unknown"}:
            raise RuntimeError(f"unsupported parity event: {case['event']}")
        if case["expected_action"] not in allowed_actions:
            raise RuntimeError(f"unsupported parity action: {case['expected_action']}")
        ids.add(case_id)
    return {"case_count": len(cases), "sha256": sha256((root / relative).read_bytes()).hexdigest()}


def _verify_import_surface(root: Path, oracle_modules: list[str], candidate_module: str) -> None:
    source = root / "src"
    clean_env = os.environ.copy()
    for key in (
        "HOL_GUARD_NATIVE",
        "HOL_GUARD_NATIVE_DIAGNOSTIC",
        "HOL_GUARD_PYTHON_ORACLE",
        "HOL_GUARD_TEST_MODE",
        "PYTEST_CURRENT_TEST",
    ):
        clean_env.pop(key, None)
    code = (
        "import sys; "
        "import codex_plugin_scanner.guard.cli.commands_support; "
        "loaded = set(sys.modules); "
        f"forbidden = {oracle_modules!r} + [{candidate_module!r}]; "
        "assert not (loaded & set(forbidden)), sorted(loaded & set(forbidden))"
    )
    completed = subprocess.run(
        [sys.executable, "-c", code],
        cwd=root,
        env={**clean_env, "PYTHONPATH": str(source)},
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise RuntimeError(f"production import surface reached retired Python hook code: {detail}")


def _candidate_evidence(
    root: Path,
    candidate: str,
    owners: dict[str, str],
    capability_classes: dict[str, str],
    exclusions: list[str],
) -> tuple[str, dict[str, object]]:
    path = root / candidate
    if not path.is_file():
        raise RuntimeError(f"retained deletion candidate is missing: {candidate}")
    owner = owners.get(candidate)
    if owner is None or capability_classes.get(owner) != "dead_duplicate":
        raise RuntimeError(f"candidate is not classified as dead_duplicate: {candidate}")
    if candidate not in exclusions:
        raise RuntimeError(f"dead candidate is not excluded from Hatch builds: {candidate}")
    module = _module_name(root, path)
    importers = _production_importers(root, module)
    if importers:
        raise RuntimeError(f"dead candidate still has source import reachability: {candidate}: {importers}")
    return module, {
        "path": candidate,
        "module": module,
        "loc": len(path.read_text(encoding="utf-8").splitlines()),
        "source_importers": [],
        "package_excluded": True,
    }


def _capability_classes(contract: dict[str, object]) -> dict[str, str]:
    capabilities = contract.get("capabilities")
    if not isinstance(capabilities, list):
        raise RuntimeError("capabilities must be a list")
    return {
        capability["id"]: capability["class"]
        for capability in capabilities
        if isinstance(capability, dict)
        and isinstance(capability.get("id"), str)
        and isinstance(capability.get("class"), str)
    }


def _run_inputs(
    root: Path,
    contract: dict[str, object],
) -> tuple[list[str], list[str], list[str], str, list[str]]:
    excluded_candidates = contract.get("package_excluded_candidates")
    deletion_candidates = contract.get("deletion_candidates")
    oracle_tests = contract.get("oracle_tests")
    if (
        not isinstance(excluded_candidates, list)
        or not excluded_candidates
        or not all(isinstance(item, str) for item in excluded_candidates)
    ):
        raise RuntimeError("package_excluded_candidates must be a non-empty list")
    if not isinstance(deletion_candidates, list) or not deletion_candidates:
        raise RuntimeError("deletion candidates must be recorded")
    if not isinstance(oracle_tests, list) or not all(isinstance(item, str) for item in oracle_tests):
        raise RuntimeError("oracle_tests must be a list")
    missing_tests = [path for path in oracle_tests if not (root / path).is_file()]
    if missing_tests:
        raise RuntimeError(f"named oracle tests are missing: {missing_tests}")
    fixture_relative = contract.get("parity_fixture")
    if not isinstance(fixture_relative, str):
        raise RuntimeError("parity_fixture is required")
    return excluded_candidates, deletion_candidates, oracle_tests, fixture_relative, _pyproject_excludes(root)


def _candidate_records(
    root: Path,
    candidates: list[str],
    owners: dict[str, str],
    capability_classes: dict[str, str],
    exclusions: list[str],
) -> tuple[list[str], list[dict[str, object]]]:
    modules: list[str] = []
    evidence: list[dict[str, object]] = []
    for candidate in candidates:
        module, item = _candidate_evidence(root, candidate, owners, capability_classes, exclusions)
        modules.append(module)
        evidence.append(item)
    return modules, evidence


def _validate_artifact_exclusions(root: Path, wheel: Path | None, candidates: list[str]) -> None:
    if wheel is None:
        return
    for candidate in candidates:
        package_name = candidate.removeprefix("src/")
        if _artifact_contains(wheel, package_name):
            raise RuntimeError(f"package artifact contains excluded dead module: {package_name}")


def _source_analysis(
    root: Path,
    owners: dict[str, str],
) -> tuple[dict[str, int], int, list[_DynamicImport], list[str]]:
    source_loc: dict[str, int] = {}
    for path, capability_id in owners.items():
        source_loc[capability_id] = source_loc.get(capability_id, 0) + len(
            (root / path).read_text(encoding="utf-8").splitlines()
        )
    import_graph, _dynamic, dynamic_imports, dynamic_unbounded = _analyze_import_graph(root)
    if dynamic_unbounded:
        raise RuntimeError(
            "dynamic import destination is not literal or statically bounded: " + ", ".join(sorted(dynamic_unbounded))
        )
    return source_loc, len(_reachable(_IMPORT_ROOTS, import_graph)), dynamic_imports, dynamic_unbounded


def _dynamic_import_evidence(dynamic_imports: list[_DynamicImport]) -> list[dict[str, object]]:
    return [
        {
            "module": item.module,
            "line": item.line,
            "destination_kind": item.destination_kind,
            "destination_count": item.destination_count,
        }
        for item in dynamic_imports
    ]


def run(root: Path, wheel: Path | None = None) -> dict[str, object]:
    root = root.resolve()
    contract, owners, scope = _validate_contract(root)
    capability_classes = _capability_classes(contract)
    excluded_candidates, _deletion_candidates, _oracle_tests, fixture_relative, exclusions = _run_inputs(root, contract)
    fixture = _validate_fixture(root, fixture_relative)
    candidate_modules, candidate_evidence = _candidate_records(
        root,
        excluded_candidates,
        owners,
        capability_classes,
        exclusions,
    )
    oracle_modules = contract.get("lazy_oracle_modules", [])
    if not isinstance(oracle_modules, list) or not all(isinstance(item, str) for item in oracle_modules):
        raise RuntimeError("lazy_oracle_modules must be a list")
    _verify_import_surface(root, oracle_modules, candidate_modules[0])
    _validate_artifact_exclusions(root, wheel, excluded_candidates)
    source_loc, reached, dynamic_imports, dynamic_unbounded = _source_analysis(root, owners)
    return {
        "schema": SCHEMA,
        "status": "passed",
        "slice": contract.get("slice"),
        "scope_files": len(scope),
        "capabilities": {
            capability: sum(1 for owner in owners.values() if owner == capability)
            for capability in set(owners.values())
        },
        "source_loc_by_capability": source_loc,
        "production_import_roots": list(_IMPORT_ROOTS),
        "production_reachable_modules": reached,
        "lazy_oracle_modules": oracle_modules,
        "fixture": fixture,
        "candidate_evidence": candidate_evidence,
        "package_exclusions": [candidate for candidate in excluded_candidates if candidate in exclusions],
        "dependency_delta": contract.get("dependency_delta"),
        "dynamic_import_count": len(dynamic_imports),
        "dynamic_import_destinations_checked": True,
        "dynamic_import_unbounded": dynamic_unbounded,
        "dynamic_import_evidence": _dynamic_import_evidence(dynamic_imports),
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--wheel", "--artifact", dest="artifact", type=Path)
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()
    try:
        payload = run(args.root, args.artifact)
    except (OSError, RuntimeError, tomllib.TOMLDecodeError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1) from error
    rendered = json.dumps(payload, indent=2, sort_keys=True)
    print(rendered)
    if args.json is not None:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(rendered + "\n", encoding="utf-8")
