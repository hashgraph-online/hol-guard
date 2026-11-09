"""Failure-only replay evidence without commands, environment values or host paths."""

from __future__ import annotations

import errno
import hashlib
import json
import re
import stat
from pathlib import Path
from typing import Any


def _path_proof(path: Path, home: Path) -> dict[str, object]:
    try:
        metadata = path.stat()
        owner = home.stat().st_uid
    except OSError as error:
        return {"available": False, "error": errno.errorcode.get(error.errno, "UNKNOWN")}
    return {
        "available": True,
        "directory": stat.S_ISDIR(metadata.st_mode),
        "same_owner_as_home": metadata.st_uid == owner,
        "mode": oct(stat.S_IMODE(metadata.st_mode)),
        "group_or_other_writable": bool(metadata.st_mode & 0o022),
        "symlink": path.is_symlink(),
    }


def _code(value: object) -> str | None:
    return value if isinstance(value, str) and re.fullmatch(r"native_[a-z0-9_]{1,120}", value) else None


def replay_diagnostics(fixture: Any, cwd: Path, result: dict[str, object], rows: list[dict], elapsed: float) -> str:
    """Inspect only synthetic fixture metadata, and only after a failed assertion.

    Native prose can echo commands or paths, so retain its digest, not its text.
    Policy settings are an explicit vocabulary rather than arbitrary extracted prose.
    """
    reason = result.get("reason")
    settings = ("changed artifact", "command execution", "subprocess", "package script")
    policy_setting = next(
        (
            setting
            for setting in settings
            if reason == f"HOL Guard requires fresh approval under the installed policy's {setting} setting."
        ),
        None,
    )
    paths = {
        "home": fixture.home,
        "workspace": fixture.worktree,
        "cwd": cwd,
        "tmp_parent": fixture.tmp_org.parent,
        "tmp_org": fixture.tmp_org,
        "tmp_checkout": fixture.tmp_org / "app",
        "tmp_sibling": fixture.tmp_org.parent / "app-followup",
    }
    relations: dict[str, object] = {}
    try:
        canonical = cwd.resolve(strict=True)
        relations = {
            "cwd_equals_workspace": canonical == fixture.worktree.resolve(strict=True),
            "cwd_below_home": canonical.is_relative_to(fixture.home.resolve(strict=True)),
            "cwd_below_tmp_parent": canonical.is_relative_to(fixture.tmp_org.parent.resolve(strict=True)),
            "tmp_aliases_equal": Path("/tmp").resolve() == Path("/private/tmp").resolve(),
        }
    except OSError as error:
        relations["error"] = errno.errorcode.get(error.errno, "UNKNOWN")
    evidence = {
        "elapsed_seconds": round(elapsed, 3),
        "reason_code": _code(result.get("reason_code")),
        "reason_sha256": hashlib.sha256(reason.encode()).hexdigest() if isinstance(reason, str) else None,
        "policy_setting": policy_setting,
        "decision": result.get("decision") if result.get("decision") in ("allow", "deny", "review", "block") else None,
        "minimum_action": result.get("minimum_action")
        if result.get("minimum_action")
        in ("allow", "warn", "review", "require-reapproval", "block", "sandbox-required")
        else None,
        "approval_count": len(rows),
        "approval_reason_codes": sorted({code for row in rows if (code := _code(row.get("reason_code")))}),
        "relations": relations,
        "paths": {name: _path_proof(path, fixture.home) for name, path in paths.items()},
    }
    return json.dumps(evidence, sort_keys=True)
