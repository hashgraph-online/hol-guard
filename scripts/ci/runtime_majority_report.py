#!/usr/bin/env python3
"""Report the Rust share of runtime lines of code (the runtime-majority metric).

Scope is declared in ``docs/guard/contracts/runtime-majority-scope.v1.json``.
Rust scope is the crate graph linked into ``hol-guard-runtime`` (see
``runtime_majority_rust``); Python scope is the static import closure from the
declared runtime roots minus reviewed exclusions (see
``runtime_majority_python``).  Output is deterministic for a given tree and
pinned to the git HEAD it was computed from.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Final

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from scripts.ci.runtime_majority_python import (  # noqa: E402
    ImportGraph,
    build_graph,
    closure,
    count_python_loc,
    path_matches,
)
from scripts.ci.runtime_majority_rust import measure_rust  # noqa: E402

SCHEMA: Final = "hol-guard.runtime-majority-report.v1"
SCOPE_SCHEMA: Final = "hol-guard.runtime-majority-scope.v1"
DEFAULT_SCOPE: Final = "docs/guard/contracts/runtime-majority-scope.v1.json"


class ScopeError(RuntimeError):
    """The scope configuration is malformed or names a missing root."""


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, check=False)
    return result.stdout.rstrip("\n") if result.returncode == 0 else ""


def load_scope(path: Path) -> dict[str, Any]:
    scope = json.loads(path.read_text(encoding="utf-8"))
    if scope.get("schema") != SCOPE_SCHEMA:
        raise ScopeError(f"scope schema must be {SCOPE_SCHEMA}")
    target = scope.get("metric", {}).get("target_share")
    if isinstance(target, bool) or not isinstance(target, int | float) or not 0 < target <= 1:
        raise ScopeError("metric.target_share must be a number with 0 < target_share <= 1")
    for entry in scope["python"]["exclusions"]:
        paths = entry.get("path")
        if not (isinstance(paths, list) and paths and all(isinstance(item, str) and item for item in paths)):
            raise ScopeError(f"exclusion {entry.get('id')!r} needs a non-empty path list")
        if not str(entry.get("reason", "")).strip() or not str(entry.get("category", "")).strip():
            raise ScopeError(f"exclusion {entry.get('id')!r} needs a category and a reason")
    for item in scope["rust"].get("exclude_paths", []):
        if not str(item.get("reason", "")).strip():
            raise ScopeError(f"rust exclusion {item.get('path')!r} needs a reason")
    return scope


def _dirty_paths(repo: Path, scope: dict[str, Any], scope_path: Path) -> list[str]:
    """Tracked changes and untracked files under every tree the report reads."""
    pathspecs = [scope["python"]["package_root"], scope["rust"]["workspace"], "tests"]
    if scope_path.is_relative_to(repo):
        pathspecs.append(scope_path.relative_to(repo).as_posix())
    output = _git(repo, "status", "--porcelain", "--untracked-files=all", "--", *pathspecs)
    return sorted(line[3:] for line in output.splitlines())


def _matches_any(path: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatchcase(path, pattern) for pattern in patterns)


def _first_entry(path: str, entries: list[dict[str, Any]]) -> dict[str, Any] | None:
    return next((entry for entry in entries if path_matches(path, entry)), None)


def _in_scope_importers(graph: ImportGraph, in_scope: dict[str, str], name: str) -> tuple[list[str], list[str]]:
    """Paths of every in-scope module importing ``name``: ``(all importers, import-time importers)``."""
    every = [m for m in sorted(in_scope) if name in graph.eager.get(m, set()) | graph.lazy.get(m, set())]
    eager = [m for m in every if name in graph.eager.get(m, set())]
    return [graph.modules[m].path for m in every], [graph.modules[m].path for m in eager]


def _python_exclusions(
    graph: ImportGraph,
    unpruned_parent: dict[str, str],
    in_scope: dict[str, str],
    entries: list[dict[str, Any]],
    direct_hits: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for name in sorted(set(unpruned_parent) - set(in_scope)):
        module = graph.modules[name]
        entry = _first_entry(module.path, entries)
        if entry is not None:
            via = direct_hits.get(name, {}).get("via") or unpruned_parent.get(name, "")
            importers, eager_importers = _in_scope_importers(graph, in_scope, name)
            records.append(
                {
                    "language": "python",
                    "path": module.path,
                    "loc": module.loc,
                    "kind": "direct",
                    "exclusion_id": entry["id"],
                    "category": entry["category"],
                    "reason": entry["reason"],
                    "imported_by": graph.modules[via].path if via in graph.modules else "",
                    "in_scope_importers": importers,
                    "imported_at_import_time_by_in_scope": bool(eager_importers),
                }
            )
            continue
        ancestor = unpruned_parent.get(name, "")
        while ancestor and _first_entry(graph.modules[ancestor].path, entries) is None:
            ancestor = unpruned_parent.get(ancestor, "")
        gateway = _first_entry(graph.modules[ancestor].path, entries) if ancestor else None
        records.append(
            {
                "language": "python",
                "path": module.path,
                "loc": module.loc,
                "kind": "transitive",
                "exclusion_id": gateway["id"] if gateway else "",
                "category": gateway["category"] if gateway else "unknown",
                "reason": (
                    f"reachable only through excluded {graph.modules[ancestor].path}: {gateway['reason']}"
                    if gateway
                    else "reachable only through an excluded module"
                ),
                "imported_by": graph.modules[unpruned_parent[name]].path if unpruned_parent.get(name) else "",
                "in_scope_importers": [],
                "imported_at_import_time_by_in_scope": False,
            }
        )
    return records


def _summarize_exclusions(records: list[dict[str, Any]], entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    summary = []
    for entry in entries:
        mine = [item for item in records if item.get("exclusion_id") == entry["id"] and item["language"] == "python"]
        summary.append(
            {
                "id": entry["id"],
                "category": entry["category"],
                "reason": entry["reason"],
                "direct_modules": sum(1 for item in mine if item["kind"] == "direct"),
                "transitive_modules": sum(1 for item in mine if item["kind"] == "transitive"),
                "loc": sum(item["loc"] for item in mine),
                "eager_imported_direct_modules": sorted(
                    item["path"] for item in mine if item.get("imported_at_import_time_by_in_scope")
                ),
                "matches_nothing_in_closure": not mine,
            }
        )
    return summary


def _tree_total(repo: Path, patterns: list[str]) -> int:
    total = 0
    for path in sorted((repo / "tests").rglob("*.py")) if (repo / "tests").is_dir() else []:
        if _matches_any(path.relative_to(repo).as_posix(), patterns):
            total += count_python_loc(path.read_text(encoding="utf-8"))
    return total


def build_report(repo: Path, scope_path: Path, *, top: int = 40) -> dict[str, Any]:
    scope = load_scope(scope_path)
    python_scope = scope["python"]
    graph = build_graph(repo, python_scope["package_root"])
    roots = [str(item["module"]) for item in python_scope["roots"]]
    missing = [root for root in roots if root not in graph.modules]
    if missing:
        raise ScopeError(f"runtime roots not found: {missing}")
    entries = list(python_scope["exclusions"])
    unpruned, _, _ = closure(graph, roots, exclusions=[])
    in_scope, direct_hits, kind = closure(graph, roots, exclusions=entries)
    reviewed = python_scope["reviewed_runtime"]
    root_set = set(roots)

    files: list[dict[str, Any]] = []
    pending: list[dict[str, Any]] = []
    for name in sorted(in_scope):
        module = graph.modules[name]
        is_reviewed = name in root_set or _first_entry(module.path, reviewed) is not None
        record = {
            "path": module.path,
            "module": name,
            "loc": module.loc,
            "reach": "root" if name in root_set else kind[name],
            "reviewed": is_reviewed,
            "imported_by": graph.modules[in_scope[name]].path if in_scope[name] else "",
        }
        files.append(record)
        if kind[name] == "lazy" and not is_reviewed:
            pending.append({k: record[k] for k in ("path", "module", "loc", "imported_by")})

    rust_counts, rust_exclusions, rust_totals, rust_meta = measure_rust(repo, scope["rust"])
    rust_loc = sum(item.loc for item in rust_counts)
    python_loc = sum(item["loc"] for item in files)
    share = rust_loc / (rust_loc + python_loc) if rust_loc + python_loc else 0.0

    exclusions = _python_exclusions(graph, unpruned, in_scope, entries, direct_hits) + rust_exclusions
    exclusions.sort(key=lambda item: (item["language"], item["path"]))
    package_total = sum(module.loc for module in graph.modules.values())
    in_scope_paths = {item["path"] for item in files}

    def _group(patterns: list[str]) -> dict[str, int]:
        matched = [m for m in graph.modules.values() if _matches_any(m.path, patterns)]
        return {
            "python_loc": sum(m.loc for m in matched),
            "python_in_scope_loc": sum(m.loc for m in matched if m.path in in_scope_paths),
            "python_modules": len(matched),
        }

    dirty = _dirty_paths(repo, scope, scope_path)
    ranked = sorted(files, key=lambda item: (-item["loc"], item["path"]))[:top]
    scope_bytes = scope_path.read_bytes()
    return {
        "schema": SCHEMA,
        "git_head": _git(repo, "rev-parse", "HEAD"),
        "git_dirty": bool(dirty),
        "git_dirty_paths": dirty,
        "scope_file": scope_path.relative_to(repo).as_posix() if scope_path.is_relative_to(repo) else str(scope_path),
        "scope_sha256": hashlib.sha256(scope_bytes).hexdigest(),
        "metric": {
            "formula": scope["metric"]["formula"],
            "rust_runtime_loc": rust_loc,
            "python_runtime_loc": python_loc,
            "share": share,
            "target_share": scope["metric"]["target_share"],
            "meets_target": share >= scope["metric"]["target_share"],
            "python_loc_needed_for_target": max(
                0, int(rust_loc * (1 - scope["metric"]["target_share"]) / scope["metric"]["target_share"])
            ),
        },
        "rust": {
            "binary_crate": rust_meta["binary_crate"],
            "linked_crates": rust_meta["linked_crates"],
            "unresolved_modules": rust_meta["unresolved_modules"],
            "per_crate_loc": {
                crate: sum(item.loc for item in rust_counts if item.crate == crate)
                for crate in sorted({item.crate for item in rust_counts})
            },
            "files": [
                {"path": item.path, "crate": item.crate, "loc": item.loc}
                for item in sorted(rust_counts, key=lambda item: item.path)
            ],
        },
        "python": {
            "roots": python_scope["roots"],
            "module_count": len(files),
            "eager_loc": sum(item["loc"] for item in files if item["reach"] in {"root", "eager"}),
            "lazy_loc": sum(item["loc"] for item in files if item["reach"] == "lazy"),
            "package_total_loc": package_total,
            "not_reached_from_roots_loc": package_total - sum(graph.modules[n].loc for n in unpruned),
            "files": files,
            "pending_unclassified_modules": pending,
            "pending_unclassified_loc": sum(item["loc"] for item in pending),
            "dynamic_import_sites_unresolved": sum(graph.dynamic_unresolved.get(name, 0) for name in in_scope),
        },
        "exclusion_summary": _summarize_exclusions(exclusions, entries),
        "exclusions": exclusions,
        "non_runtime_totals": {
            "tests": {"rust_loc": rust_totals["tests"], "python_loc": _tree_total(repo, python_scope["tests"]["path"])},
            "generated": {"rust_loc": rust_totals["generated"], **_group(python_scope["generated"]["path"])},
            "adapters": {"rust_loc": rust_totals["adapters"], **_group(python_scope["adapters"]["path"])},
            "rust_unlinked_or_authoring_loc": rust_totals["unlinked"],
        },
        "retirement_worklist": [
            {"rank": index, "path": item["path"], "loc": item["loc"], "reach": item["reach"]}
            for index, item in enumerate(ranked, start=1)
        ],
    }


def render_summary(report: dict[str, Any]) -> str:
    metric = report["metric"]
    lines = [
        f"runtime majority share: {metric['share']:.2%} (target {metric['target_share']:.0%}, "
        f"{'MET' if metric['meets_target'] else 'NOT MET'})",
        f"  rust_runtime_loc   {metric['rust_runtime_loc']}",
        f"  python_runtime_loc {metric['python_runtime_loc']} "
        f"(pending/unclassified {report['python']['pending_unclassified_loc']})",
        f"  python LOC allowed at target: {metric['python_loc_needed_for_target']}",
        f"  git head {report['git_head']}  scope sha256 {report['scope_sha256'][:12]}",
        "exclusions (python, by reviewed entry):",
    ]
    for item in sorted(report["exclusion_summary"], key=lambda entry: -entry["loc"]):
        lines.append(f"  {item['loc']:>7}  {item['id']} [{item['category']}]")
    totals = report["non_runtime_totals"]
    lines.append(
        f"non-runtime totals: tests rust={totals['tests']['rust_loc']} python={totals['tests']['python_loc']}; "
        f"generated python={totals['generated']['python_loc']}; adapters python={totals['adapters']['python_loc']}"
    )
    lines.append("retirement worklist (largest in-scope Python modules):")
    for item in report["retirement_worklist"]:
        lines.append(f"  {item['rank']:>2}. {item['loc']:>6}  {item['path']}")
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=_REPO_ROOT)
    parser.add_argument("--scope", type=Path, default=None, help=f"scope JSON (default {DEFAULT_SCOPE})")
    parser.add_argument("--json", action="store_true", help="print the full JSON report to stdout")
    parser.add_argument("--output", type=Path, default=None, help="also write the full JSON report here")
    parser.add_argument("--top", type=int, default=40, help="retirement worklist length")
    parser.add_argument("--min-share", type=float, default=None, help="exit 1 when the share is below this value")
    args = parser.parse_args(argv)
    repo = args.repo.resolve()
    scope_path = (args.scope or repo / DEFAULT_SCOPE).resolve()
    try:
        report = build_report(repo, scope_path, top=args.top)
    except (ScopeError, OSError, KeyError, json.JSONDecodeError) as error:
        print(f"runtime-majority: {error}", file=sys.stderr)
        return 2
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output is not None:
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered if args.json else render_summary(report), end="" if args.json else "\n")
    if args.min_share is not None and report["metric"]["share"] < args.min_share:
        print(
            f"runtime-majority: share {report['metric']['share']:.4f} is below --min-share {args.min_share:.4f}",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
