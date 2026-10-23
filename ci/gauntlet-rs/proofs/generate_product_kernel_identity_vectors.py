"""Freeze Python's controller-observed product identity relation."""

from __future__ import annotations

import ast
from copy import deepcopy
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / "ci/gauntlet/benchmark/product_custody.py"
OUTPUT = ROOT / "ci/gauntlet-rs/crates/gauntlet-evidence/tests/fixtures/product_kernel_identity_v1.json"


def source_function():
    tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
    names = {"_require", "_kernel"}
    selected = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
    namespace = next(node for node in tree.body if isinstance(node, ast.Assign)
                     and any(isinstance(target, ast.Name) and target.id == "_NAMESPACES"
                             for target in node.targets))
    if {node.name for node in selected} != names:
        raise ValueError("product kernel identity source changed")
    scope = {}
    exec(compile(ast.fix_missing_locations(ast.Module(body=[namespace, *selected], type_ignores=[])),
                 str(SOURCE), "exec"), scope)
    return scope["_kernel"]


def base():
    controller = {"boot_id": "boot", "mount_namespace": "mnt-controller",
                  "pid_namespace": "pid-controller", "network_namespace": "net-controller"}
    agent = {"mount_namespace": "mnt-agent", "pid_namespace": "pid-agent",
             "network_namespace": "net-agent"}
    identity = {"effective_uid": 10004, "effective_gid": 10004,
                "effective_capabilities": "0000000000000000", "no_new_privileges": 1,
                "boot_id": "boot", "start_time": "12345",
                "mount_namespace": "mnt-product", "pid_namespace": "pid-product",
                "network_namespace": "net-product"}
    return {"identity": identity, "controller": controller, "agent": agent, "product_uid": 10004}


def cases():
    root = base()
    yield "valid-v1", root

    def altered(name, edit):
        row = deepcopy(root)
        edit(row)
        return name, row

    yield altered("valid-no-agent", lambda row: row.update(agent=None))
    yield altered("missing-identity", lambda row: row.update(identity=None))
    yield altered("wrong-uid", lambda row: row["identity"].update(effective_uid=0))
    yield altered("boolean-uid", lambda row: row["identity"].update(effective_uid=True))
    yield altered("wrong-gid", lambda row: row["identity"].update(effective_gid=0))
    yield altered("nonzero-capabilities", lambda row: row["identity"].update(
        effective_capabilities="0000000000000001"))
    yield altered("missing-no-new-privileges", lambda row: row["identity"].pop("no_new_privileges"))
    yield altered("boolean-no-new-privileges", lambda row: row["identity"].update(no_new_privileges=True))
    yield altered("wrong-boot", lambda row: row["identity"].update(boot_id="other"))
    yield altered("nonstring-boot", lambda row: row["identity"].update(boot_id=1))
    yield altered("bad-start-time", lambda row: row["identity"].update(start_time="abc"))
    yield altered("shared-controller-mount", lambda row: row["identity"].update(
        mount_namespace=row["controller"]["mount_namespace"]))
    yield altered("shared-controller-pid", lambda row: row["identity"].update(
        pid_namespace=row["controller"]["pid_namespace"]))
    yield altered("shared-controller-network", lambda row: row["identity"].update(
        network_namespace=row["controller"]["network_namespace"]))
    yield altered("missing-product-namespace", lambda row: row["identity"].update(mount_namespace=""))
    yield altered("shared-agent-mount", lambda row: row["identity"].update(
        mount_namespace=row["agent"]["mount_namespace"]))
    yield altered("shared-agent-pid", lambda row: row["identity"].update(
        pid_namespace=row["agent"]["pid_namespace"]))
    yield altered("shared-agent-network", lambda row: row["identity"].update(
        network_namespace=row["agent"]["network_namespace"]))
    yield altered("bad-product-uid-profile", lambda row: row.update(product_uid=42))

    def v2(row):
        row["product_uid"] = 10005
        identity = row["identity"]
        identity.update(effective_uid=10005, effective_gid=10005,
                        uid_slots=[10005] * 4, gid_slots=[10005] * 4,
                        supplementary_groups=[],
                        capability_sets=dict.fromkeys(
                            ("CapEff", "CapPrm", "CapInh", "CapBnd", "CapAmb"),
                            "0000000000000000"))
    yield altered("valid-v2", v2)
    yield altered("valid-v2-single-group", lambda row: (v2(row), row["identity"].update(
        supplementary_groups=[10005])))
    yield altered("v2-wrong-uid-slots", lambda row: (v2(row), row["identity"].update(
        uid_slots=[10005, 10005, 0, 10005])))
    yield altered("v2-wrong-groups", lambda row: (v2(row), row["identity"].update(
        supplementary_groups=[0])))
    yield altered("v2-nonzero-capset", lambda row: (v2(row), row["identity"][
        "capability_sets"].update(CapAmb="0000000000000001")))


def main():
    kernel = source_function()
    rows = []
    for name, row in cases():
        try:
            kernel(row["identity"], row["controller"], row["agent"],
                   product_uid=row["product_uid"])
            accepted, reason = True, None
        except (ValueError, KeyError, TypeError) as error:
            accepted, reason = False, str(error)
        rows.append({"name": name, **row, "accepted": accepted, "reason": reason})
    OUTPUT.write_text(json.dumps({"schema": "gauntlet-python-product-kernel-identity.v1",
                                  "source_sha256": hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
                                  "cases": rows}, sort_keys=True, separators=(",", ":")) + "\n",
                      encoding="utf-8")
    print(f"frozen {len(rows)} Python kernel-identity cases: "
          f"{sum(row['accepted'] for row in rows)} accepted")


if __name__ == "__main__":
    main()
