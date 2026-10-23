"""Freeze Python's private-cell actor process privilege relation."""

from __future__ import annotations

import ast
from copy import deepcopy
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / "ci/gauntlet/benchmark/private_cell_custody.py"
OUTPUT = ROOT / "ci/gauntlet-rs/crates/gauntlet-evidence/tests/fixtures/private_actor_v1.json"


def source_function():
    tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
    names = {"_actor"}
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
    if len(functions) != 1:
        raise ValueError("private actor source function changed")
    scope = {"_require": lambda condition, message: None if condition else
             (_ for _ in ()).throw(ValueError(message))}
    exec(compile(ast.fix_missing_locations(ast.Module(body=functions, type_ignores=[])),
                 str(SOURCE), "exec"), scope)
    return scope["_actor"]


def base():
    namespaces = {"mnt": "mnt-product", "net": "net-product", "pid": "pid-product",
                  "ipc": "ipc-product", "uts": "uts-product", "cgroup": "cgroup-product"}
    status = {"Uid": "10004 10004 10004 10004", "Gid": "10004 10004 10004 10004",
              "Groups": "", "NoNewPrivs": "1", "CapEff": "0000000000000000",
              "CapPrm": "0000000000000000", "CapBnd": "0000000000000000",
              "CapInh": "0000000000000000", "CapAmb": "0000000000000000",
              "Seccomp": "2", "Seccomp_filters": "2"}
    label = "hol-product-cell-" + "a" * 32 + " (enforce)"
    identity = {"pid": 123, "start_time": "12345", "lsm_label": label,
                "namespaces": deepcopy(namespaces), "fds": {"0": "stdin", "1": "stdout", "2": "stderr"},
                "status": status}
    return {"identity": identity, "label": label, "namespaces": namespaces,
            "filtered": True}


def cases():
    root = base()
    yield "valid-filtered", root

    def altered(name, edit):
        row = deepcopy(root)
        edit(row)
        return name, row

    def identity(row):
        return row["identity"]

    def status(row):
        return identity(row)["status"]

    yield altered("valid-initial-unfiltered", lambda row: (row.update(filtered=False),
        status(row).update(Seccomp="0", Seccomp_filters="0")))
    yield altered("valid-extra-filters", lambda row: status(row).update(Seccomp_filters="3"))
    yield altered("boolean-pid", lambda row: identity(row).update(pid=True))
    yield altered("zero-pid", lambda row: identity(row).update(pid=0))
    yield altered("bad-start-time", lambda row: identity(row).update(start_time="bad"))
    yield altered("wrong-lsm-label", lambda row: identity(row).update(lsm_label="unconfined"))
    yield altered("wrong-namespaces", lambda row: identity(row)["namespaces"].update(pid="other"))
    yield altered("extra-fd", lambda row: identity(row)["fds"].update({"3": "secret"}))
    yield altered("missing-fd", lambda row: identity(row)["fds"].pop("2"))
    yield altered("wrong-uid", lambda row: status(row).update(Uid="0 0 0 0"))
    yield altered("wrong-gid", lambda row: status(row).update(Gid="0 0 0 0"))
    yield altered("supplementary-group", lambda row: status(row).update(Groups="10004"))
    yield altered("new-privileges", lambda row: status(row).update(NoNewPrivs="0"))
    yield altered("effective-capability", lambda row: status(row).update(CapEff="1"))
    yield altered("permitted-capability", lambda row: status(row).update(CapPrm="1"))
    yield altered("ambient-capability", lambda row: status(row).update(CapAmb="1"))
    yield altered("seccomp-disabled", lambda row: status(row).update(Seccomp="0"))
    yield altered("one-filter", lambda row: status(row).update(Seccomp_filters="1"))
    yield altered("unfiltered-one-filter-allowed", lambda row: (row.update(filtered=False),
        status(row).update(Seccomp="0", Seccomp_filters="1")))


def main():
    actor = source_function()
    rows = []
    for name, row in cases():
        try:
            actor(row["identity"], label=row["label"], namespaces=row["namespaces"],
                  filtered=row["filtered"])
            accepted, reason = True, None
        except (ValueError, KeyError, TypeError, AttributeError) as error:
            accepted, reason = False, str(error)
        rows.append({"name": name, **row, "accepted": accepted, "reason": reason})
    OUTPUT.write_text(json.dumps({"schema": "gauntlet-python-private-actor.v1",
                                  "source_sha256": hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
                                  "cases": rows}, sort_keys=True, separators=(",", ":")) + "\n",
                      encoding="utf-8")
    print(f"frozen {len(rows)} Python private actor cases: "
          f"{sum(row['accepted'] for row in rows)} accepted")


if __name__ == "__main__":
    main()
