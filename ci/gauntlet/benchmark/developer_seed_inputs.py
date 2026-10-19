"""Public seed bytes retained from the original six-workflow source contract.

Only known literal task inputs are parsed as inert data; the original provider
lane's code is neither imported nor executed or modified.
"""

from __future__ import annotations

import ast
import hashlib
import os
from pathlib import Path

from .contracts import canonical_json


def _source_bytes():
    path=Path(__file__).resolve().parent.parent/'full_tasks.py'
    if path.is_symlink() or not path.is_file():
        raise ValueError('original public developer seed source is missing or not ordinary')
    descriptor=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    with os.fdopen(descriptor,'rb') as stream:
        before=os.fstat(stream.fileno())
        content=stream.read(128*1024+1)
        after=os.fstat(stream.fileno())
    if (len(content)>128*1024 or len(content)!=before.st_size or
            (before.st_dev,before.st_ino,before.st_mtime_ns,before.st_ctime_ns)!=
            (after.st_dev,after.st_ino,after.st_mtime_ns,after.st_ctime_ns)):
        raise ValueError('public developer seed source exceeds bound or changed while reading')
    return path,content


def legacy_seed_literals():
    return _parse_literals(_source_bytes()[1])


def seed_source_identity():
    path,content=_source_bytes()
    values=_parse_literals(content)
    return {'path':str(path),'sha256':hashlib.sha256(content).hexdigest(),'constants':sorted(values)}


def _parse_literals(content):
    wanted = {"BUGGY_SUM", "SUM_TEST", "USER_STUB", "REPORT_EVENTS", "REPORT_SCRIPT", "TALLY_MODULE", "WEEKLY_REPORT"}
    values = {}
    for node in ast.parse(content).body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            name = node.targets[0].id
            if name in wanted:
                if name in values:
                    raise ValueError("duplicate public developer seed constant")
                value = ast.literal_eval(node.value)
                if type(value) is not str or len(value) > 8192:
                    raise ValueError("incompatible public fixture literal")
                values[name] = value
    if set(values) != wanted:
        raise ValueError("public developer seed constants are incomplete")
    return values


def default_seed_files(workflow_id):
    """Public task inputs; expected behavior is supplied in the user contract."""
    source = legacy_seed_literals()
    package = {
        "name": "synthetic-benchmark-project",
        "version": "1.0.0",
        "type": "module",
        "scripts": {"test": "node --test", "report": "node src/report.js"},
    }
    files = {
        "README.md": "This is a local synthetic Git/PR fixture. No GitHub delivery occurs.\n",
        ".gitignore": "node_modules/\n",
        "package.json": canonical_json(package) + "\n",
    }
    if workflow_id == "fix-failing-node-test":
        files["src/sum.js"] = source["BUGGY_SUM"]
        files["test/sum.test.js"] = source["SUM_TEST"]
    elif workflow_id == "add-validation-dependency":
        files["src/user.js"] = source["USER_STUB"]
        files["SPEC.md"] = (
            "Use exactly zod 3.23.8. validateUser returns a boolean: nonempty string name, "
            "valid email, optional nonnegative numeric age; do not coerce strings.\n"
        )
    elif workflow_id == "worktree-report-branch":
        package["scripts"] = {"report": "node scripts/report.mjs"}
        files["package.json"] = canonical_json(package) + "\n"
        files["data/events.json"] = source["REPORT_EVENTS"]
        files["scripts/report.mjs"] = source["REPORT_SCRIPT"]
        files["node_modules/event-tally/package.json"] = (
            canonical_json({"name": "event-tally", "type": "module", "main": "index.js"}) + "\n"
        )
        files["node_modules/event-tally/index.js"] = source["TALLY_MODULE"]
        files["SPEC.md"] = (
            "Create weekly-report in a linked worktree, publish reports/weekly.md with signup=2 "
            "and upgrade=1, preserve main and reuse its event-tally dependency.\n"
        )
    elif workflow_id == "python-cli-with-tests":
        files["SPEC.md"] = (
            "Build a C/F temperature conversion CLI; numeric precision 0.01, invalid inputs fail with diagnostics.\n"
        )
    elif workflow_id == "todo-app-to-github":
        files["SPEC.md"] = (
            "Build add/edit/complete/delete, reject blank todos and persist across reload; "
            "publish to this local Git remote.\n"
        )
    else:
        files["SPEC.md"] = (
            "Create CONTRIBUTING.md with actual setup/test/contribution guidance and open one local fixture PR.\n"
        )
    return files
