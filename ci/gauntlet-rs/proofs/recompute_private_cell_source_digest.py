"""Recompute the embedded private-cell source map from Python declarations."""

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path


REPOSITORY = Path(__file__).resolve().parents[3]
SOURCE = REPOSITORY / "ci/gauntlet/benchmark"
DECLARATION = SOURCE / "private_cell_campaign_inputs.py"


def declared_modules() -> tuple[tuple[str, ...], tuple[str, ...]]:
    tree = ast.parse(DECLARATION.read_text(encoding="utf-8"))
    values = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            if node.targets[0].id in {"ROOT_MODULES", "PUBLIC_MODULES"}:
                values[node.targets[0].id] = ast.literal_eval(node.value)
    root, public = values["ROOT_MODULES"], values["PUBLIC_MODULES"]
    if not all(isinstance(name, str) and name.isidentifier() for name in (*root, *public)):
        raise ValueError("invalid Python private-cell module declarations")
    if not set(public).issubset(root):
        raise ValueError("public module is absent from Root modules")
    return root, public


def main() -> None:
    root, public = declared_modules()
    files = {}
    for folder, modules in (("code", root), ("public", public)):
        for name in modules:
            files[f"{folder}/ci/gauntlet/benchmark/{name}.py"] = (SOURCE / f"{name}.py").read_bytes()
        for relative in ("ci/__init__.py", "ci/gauntlet/__init__.py", "ci/gauntlet/benchmark/__init__.py"):
            files[f"{folder}/{relative}"] = (
                (REPOSITORY / relative).read_bytes() if relative == "ci/gauntlet/__init__.py" else b""
            )
    files["product_vm.apparmor"] = (SOURCE / "product_vm.apparmor").read_bytes()
    files["public/product_vm_seccomp_oci_v1.json"] = (SOURCE / "product_vm_seccomp_oci_v1.json").read_bytes()
    hashes = {name: hashlib.sha256(raw).hexdigest() for name, raw in files.items()}
    canonical = json.dumps(hashes, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    print(json.dumps({"files": len(files), "digest": hashlib.sha256(canonical).hexdigest()}, sort_keys=True))


if __name__ == "__main__":
    main()
