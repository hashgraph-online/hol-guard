#!/usr/bin/env python3
"""Report exact pytest test-body duplicates for manual consolidation review."""

from __future__ import annotations

import argparse
import ast
import copy
import json
from collections import defaultdict
from collections.abc import Iterable, Iterator
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class TestBody:
    """A concrete pytest test function and its normalized executable body."""

    node_id: str
    body_fingerprint: str


@dataclass(frozen=True)
class DuplicateCandidate:
    """Tests with identical executable AST bodies that require human review."""

    body_fingerprint: str
    node_ids: tuple[str, ...]


def iter_test_bodies(path: Path, *, root: Path) -> Iterator[TestBody]:
    """Yield test functions with their decorators and class context."""

    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    relative_path = path.relative_to(root).as_posix()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_"):
            yield TestBody(
                node_id=f"{relative_path}::{node.name}",
                body_fingerprint=_test_fingerprint(node),
            )
        elif isinstance(node, ast.ClassDef):
            for child in node.body:
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) and child.name.startswith("test_"):
                    yield TestBody(
                        node_id=f"{relative_path}::{node.name}::{child.name}",
                        body_fingerprint=_test_fingerprint(child, class_node=node),
                    )


def _test_fingerprint(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    *,
    class_node: ast.ClassDef | None = None,
) -> str:
    """Include decorators, signature, and class setup so matrices are not conflated."""

    test_node = copy.deepcopy(node)
    test_node.name = ""
    parts = [ast.dump(test_node, include_attributes=False)]
    if class_node is not None:
        class_context = ast.ClassDef(
            name="",
            bases=copy.deepcopy(class_node.bases),
            keywords=copy.deepcopy(class_node.keywords),
            body=[],
            decorator_list=copy.deepcopy(class_node.decorator_list),
        )
        parts.append(ast.dump(class_context, include_attributes=False))
    return "\n".join(parts)


def duplicate_candidates(paths: Iterable[Path], *, root: Path) -> tuple[DuplicateCandidate, ...]:
    """Return stable groups with exactly equal test bodies, excluding singletons."""

    grouped: dict[str, list[str]] = defaultdict(list)
    for path in sorted(paths):
        for test_body in iter_test_bodies(path, root=root):
            grouped[test_body.body_fingerprint].append(test_body.node_id)
    return tuple(
        DuplicateCandidate(body_fingerprint=fingerprint, node_ids=tuple(sorted(node_ids)))
        for fingerprint, node_ids in sorted(grouped.items())
        if len(node_ids) > 1
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    _ = parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    candidates = duplicate_candidates((root / "tests").rglob("test_*.py"), root=root)
    payload = json.dumps([asdict(candidate) for candidate in candidates], indent=2, sort_keys=True) + "\n"
    if args.output is None:
        print(payload, end="")
    else:
        args.output.write_text(payload, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
