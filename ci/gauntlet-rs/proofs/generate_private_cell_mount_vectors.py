"""Freeze Python task/idmap and mountinfo relations without starting a cell."""

from __future__ import annotations

import ast
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / "ci/gauntlet/benchmark/private_cell_custody.py"
OUTPUT = ROOT / "ci/gauntlet-rs/crates/gauntlet-evidence/tests/fixtures/private_cell_mount_v1.json"


def source_functions():
    tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
    names = {"_sha", "_one", "_tasks", "_mountinfo"}
    selected = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
    if {node.name for node in selected} != names:
        raise ValueError("private-cell task/mount source changed")
    scope = {"re": re, "_require": lambda condition, message: None if condition else
             (_ for _ in ()).throw(ValueError(message))}
    exec(compile(ast.fix_missing_locations(ast.Module(body=selected, type_ignores=[])),
                 str(SOURCE), "exec"), scope)
    return scope


def mount_line(path, options, fs="ext4"):
    return f"1 0 0:1 / {path} {options} - {fs} disk rw"


def base():
    workspace_source = "/gauntlet/session/tasks/checkout"
    provider = "/gauntlet/session/tasks/home"
    tasks = [
        {"source": workspace_source, "destination": "/runtime/home/project",
         "device": 9, "inode": 100, "mode": 0o700},
        {"source": provider, "destination": provider,
         "device": 9, "inode": 101, "mode": 0o700},
    ]
    mounts = []
    for row in tasks:
        physical = {key: row[key] for key in ("device", "inode", "mode")}
        mounts.append({"source": row["source"], "destination": row["destination"],
                       "physical": {**physical, "uid": 10001, "gid": 10001},
                       "product_view": {**physical, "uid": 10004, "gid": 10004},
                       "observer_pid": 123})
    lines = [mount_line(path, "ro,nosuid,nodev")
             for path in ("/", "/usr", "/opt/node", "/public", "/etc/alternatives",
                          "/runtime/installed")]
    lines.append(mount_line("/dev", "ro,nosuid"))
    lines.extend(mount_line(path, "rw,nosuid,nodev")
                 for path in ("/product", "/tmp", *(row["destination"] for row in tasks)))
    return {"plane": {"workspace_path": "/runtime/home/project", "task_mounts": tasks,
                      "task_digest": "a" * 64},
            "rows": [{"kind": "idmapped-task-mounts", "declaration_digest": "a" * 64,
                      "mounts": mounts}],
            "workspace_source": workspace_source, "provider_mounts": [provider],
            "pid": 123, "prefix": "/runtime/installed", "mountinfo": "\n".join(lines) + "\n"}


def cases():
    root = base()
    yield "valid", root

    def altered(name, edit):
        row = deepcopy(root)
        edit(row)
        return name, row

    def tasks(row):
        return row["plane"]["task_mounts"]

    def observed(row):
        return row["rows"][0]

    yield altered("valid-extra-ordinary-mount", lambda row: row.update(
        mountinfo=row["mountinfo"] + mount_line("/run/ordinary", "rw,nosuid,nodev") + "\n"))
    yield altered("valid-escaped-space", lambda row: row.update(
        mountinfo=row["mountinfo"] + mount_line("/run/a\\040b", "rw,nosuid,nodev") + "\n"))
    yield altered("valid-crlf", lambda row: row.update(
        mountinfo=row["mountinfo"].replace("\n", "\r\n")))
    yield altered("missing-task", lambda row: tasks(row).pop())
    yield altered("duplicate-task-destination", lambda row: tasks(row)[1].update(
        destination=tasks(row)[0]["destination"]))
    yield altered("wrong-task-source", lambda row: tasks(row)[0].update(source="other"))
    yield altered("unsafe-task-mode", lambda row: tasks(row)[0].update(mode=0o777))
    yield altered("zero-task-inode", lambda row: tasks(row)[0].update(inode=0))
    yield altered("wrong-task-declaration", lambda row: observed(row).update(
        declaration_digest="b" * 64))
    yield altered("missing-idmap-observation", lambda row: row.update(rows=[]))
    yield altered("duplicate-idmap-destination", lambda row: observed(row)["mounts"][1].update(
        destination=observed(row)["mounts"][0]["destination"]))
    yield altered("wrong-observer-pid", lambda row: observed(row)["mounts"][0].update(observer_pid=124))
    yield altered("wrong-physical-uid", lambda row: observed(row)["mounts"][0]["physical"].update(uid=0))
    yield altered("wrong-product-view", lambda row: observed(row)["mounts"][0]["product_view"].update(gid=0))
    yield altered("missing-readonly-mount", lambda row: row.update(mountinfo=row["mountinfo"].replace(
        mount_line("/usr", "ro,nosuid,nodev") + "\n", "")))
    yield altered("writable-prefix", lambda row: row.update(mountinfo=row["mountinfo"].replace(
        mount_line("/runtime/installed", "ro,nosuid,nodev"),
        mount_line("/runtime/installed", "rw,nosuid,nodev"))))
    yield altered("device-not-readonly", lambda row: row.update(mountinfo=row["mountinfo"].replace(
        mount_line("/dev", "ro,nosuid"), mount_line("/dev", "rw,nosuid"))))
    yield altered("mutable-task-readonly", lambda row: row.update(mountinfo=row["mountinfo"].replace(
        mount_line("/runtime/home/project", "rw,nosuid,nodev"),
        mount_line("/runtime/home/project", "ro,nosuid,nodev"))))
    yield altered("malformed-mount-line", lambda row: row.update(mountinfo=row["mountinfo"] + "bad\n"))
    yield altered("malformed-bare-cr", lambda row: row.update(mountinfo=row["mountinfo"] + "\rbad"))
    yield altered("malformed-unicode-separator", lambda row: row.update(
        mountinfo=row["mountinfo"] + "\u2028bad"))
    yield altered("duplicate-mount-path", lambda row: row.update(mountinfo=row["mountinfo"] +
        mount_line("/usr", "ro,nosuid,nodev") + "\n"))
    yield altered("kernel-filesystem", lambda row: row.update(mountinfo=row["mountinfo"] +
        mount_line("/run/extra", "ro,nosuid,nodev", "cgroup2") + "\n"))
    yield altered("sys-mount", lambda row: row.update(mountinfo=row["mountinfo"] +
        mount_line("/sys/new", "ro,nosuid,nodev") + "\n"))
    yield altered("oldroot-mount", lambda row: row.update(mountinfo=row["mountinfo"] +
        mount_line("/oldroot/host", "ro,nosuid,nodev") + "\n"))


def main():
    scope = source_functions()
    rows = []
    for name, row in cases():
        try:
            scope["_tasks"](row["plane"], row["rows"],
                            workspace_source=row["workspace_source"],
                            provider_mounts=row["provider_mounts"], pid=row["pid"])
            scope["_mountinfo"](row["mountinfo"], prefix=row["prefix"],
                                tasks=row["plane"]["task_mounts"])
            accepted, reason = True, None
        except (ValueError, KeyError, TypeError, IndexError) as error:
            accepted, reason = False, str(error)
        rows.append({"name": name, **row, "accepted": accepted, "reason": reason})
    OUTPUT.write_text(json.dumps({"schema": "gauntlet-python-private-cell-mount.v1",
                                  "source_sha256": hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
                                  "cases": rows}, sort_keys=True, separators=(",", ":")) + "\n",
                      encoding="utf-8")
    print(f"frozen {len(rows)} Python task/mount cases: "
          f"{sum(row['accepted'] for row in rows)} accepted")


if __name__ == "__main__":
    main()
