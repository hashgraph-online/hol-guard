"""Freeze Python's primary CLI and nested hook-child sample relation."""

from __future__ import annotations

import ast
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / "ci/gauntlet/benchmark/private_cell_custody.py"
PRODUCT = ROOT / "ci/gauntlet/benchmark/product_custody.py"
OUTPUT = ROOT / "ci/gauntlet-rs/crates/gauntlet-evidence/tests/fixtures/private_hook_samples_v1.json"


def extracted(path, names):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
    if {node.name for node in functions} != names:
        raise ValueError("hook sample source functions changed")
    return functions, tree


def source_function():
    product, tree = extracted(PRODUCT, {"_require", "_kernel"})
    namespaces = next(node for node in tree.body if isinstance(node, ast.Assign)
                      and any(isinstance(target, ast.Name) and target.id == "_NAMESPACES"
                              for target in node.targets))
    hook, _ = extracted(SOURCE, {"_hook_samples"})
    scope = {"re": re}
    for body, path in [([namespaces, *product], PRODUCT), (hook, SOURCE)]:
        exec(compile(ast.fix_missing_locations(ast.Module(body=body, type_ignores=[])),
                     str(path), "exec"), scope)
    return scope["_hook_samples"]


def base():
    controller = {"boot_id": "boot", "mount_namespace": "mnt-controller",
                  "pid_namespace": "pid-controller", "network_namespace": "net-controller"}
    agent = {"mount_namespace": "mnt-agent", "pid_namespace": "pid-agent",
             "network_namespace": "net-agent"}
    identity = {"effective_uid": 10004, "effective_gid": 10004,
                "effective_capabilities": "0000000000000000", "no_new_privileges": 1,
                "boot_id": "boot", "start_time": "12345", "mount_namespace": "mnt-product",
                "pid_namespace": "pid-product", "network_namespace": "net-product"}
    sample = {"identity": identity, "user_namespace": "user:[101]",
              "command_sha256": "a" * 64}
    return {"samples": [sample], "controller": controller, "agent": agent,
            "product_user_namespace": "user:[101]", "command_hash": "a" * 64}


def descendant():
    identity = {"effective_uid": 10004, "effective_gid": 10004,
                "effective_capabilities": "0000000000000001", "no_new_privileges": 1,
                "boot_id": "boot", "start_time": "12346", "mount_namespace": "mnt-nested",
                "pid_namespace": "pid-nested", "network_namespace": "net-nested",
                "uid_slots": [10004] * 4, "gid_slots": [10004] * 4,
                "supplementary_groups": [],
                "capability_sets": {"CapEff": "0000000000000001",
                                    "CapPrm": "0000000000000001",
                                    "CapBnd": "0000000000000000",
                                    "CapInh": "0000000000000000",
                                    "CapAmb": "0000000000000000"}}
    return {"identity": identity, "user_namespace": "user:[202]",
            "command_sha256": "b" * 64}


def cases():
    root = base()
    yield "valid-primary", root

    def altered(name, edit):
        row = deepcopy(root)
        edit(row)
        return name, row

    yield altered("valid-two-primary-samples", lambda row: row["samples"].append(
        deepcopy(row["samples"][0])))
    yield altered("valid-nested-child", lambda row: row["samples"].append(descendant()))
    yield altered("valid-no-agent", lambda row: row.update(agent=None))
    yield altered("missing-primary", lambda row: row.update(samples=[descendant()]))
    yield altered("empty-samples", lambda row: row.update(samples=[]))
    yield altered("wrong-primary-command", lambda row: row["samples"][0].update(
        command_sha256="b" * 64))
    yield altered("bad-user-namespace", lambda row: row["samples"][0].update(
        user_namespace="bad"))
    yield altered("bad-capability-mask", lambda row: row["samples"][0]["identity"].update(
        effective_capabilities="1"))
    yield altered("primary-changed-user-namespace", lambda row: row["samples"][0].update(
        user_namespace="user:[202]"))
    yield altered("primary-wrong-uid", lambda row: row["samples"][0]["identity"].update(
        effective_uid=0))
    yield altered("primary-shares-agent", lambda row: row["samples"][0]["identity"].update(
        pid_namespace=row["agent"]["pid_namespace"]))

    def with_child(row, edit):
        row["samples"].append(descendant())
        edit(row["samples"][1])

    yield altered("nested-same-user-namespace", lambda row: with_child(row,
        lambda child: child.update(user_namespace="user:[101]")))
    yield altered("nested-wrong-uid", lambda row: with_child(row,
        lambda child: child["identity"].update(effective_uid=0)))
    yield altered("nested-wrong-slots", lambda row: with_child(row,
        lambda child: child["identity"].update(uid_slots=[0] * 4)))
    yield altered("nested-wrong-groups", lambda row: with_child(row,
        lambda child: child["identity"].update(supplementary_groups=[0])))
    yield altered("nested-no-new-privileges-bool", lambda row: with_child(row,
        lambda child: child["identity"].update(no_new_privileges=True)))
    yield altered("nested-wrong-boot", lambda row: with_child(row,
        lambda child: child["identity"].update(boot_id="other")))
    yield altered("nested-bad-start-time", lambda row: with_child(row,
        lambda child: child["identity"].update(start_time="bad")))
    yield altered("nested-wrong-capability-sets", lambda row: with_child(row,
        lambda child: child["identity"]["capability_sets"].update(CapBnd="0000000000000001")))
    yield altered("nested-shares-controller-namespace", lambda row: with_child(row,
        lambda child: child["identity"].update(
            mount_namespace=row["controller"]["mount_namespace"])))
    yield altered("nested-shares-agent-namespace", lambda row: with_child(row,
        lambda child: child["identity"].update(
            network_namespace=row["agent"]["network_namespace"])))
    yield altered("nested-claims-primary-command", lambda row: with_child(row,
        lambda child: child.update(command_sha256=row["command_hash"])))


def main():
    hook_samples = source_function()
    rows = []
    for name, row in cases():
        try:
            hook_samples(row["samples"], controller=row["controller"], agent=row["agent"],
                         product_user_namespace=row["product_user_namespace"],
                         command_hash=row["command_hash"])
            accepted, reason = True, None
        except (ValueError, KeyError, TypeError) as error:
            accepted, reason = False, str(error)
        rows.append({"name": name, **row, "accepted": accepted, "reason": reason})
    OUTPUT.write_text(json.dumps({"schema": "gauntlet-python-private-hook-samples.v1",
                                  "source_sha256": hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
                                  "product_sha256": hashlib.sha256(PRODUCT.read_bytes()).hexdigest(),
                                  "cases": rows}, sort_keys=True, separators=(",", ":")) + "\n",
                      encoding="utf-8")
    print(f"frozen {len(rows)} Python hook sample cases: "
          f"{sum(row['accepted'] for row in rows)} accepted")


if __name__ == "__main__":
    main()
