"""A stand-in for the native ``desktop_hook_proxy`` kind on hosts without a signed app bundle.

The kind's own path, bundle and signature checks are covered by its Rust tests; these
helpers let Python tests drive the launch it answers.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_runner_authority as authority
from codex_plugin_scanner.guard.native_runner_authority import native_runner_authority


def launch_script() -> tuple[str, str]:
    """The kind's launch script and its ``$0``."""
    answer = native_runner_authority("desktop_hook_proxy", {"op": "script"})
    return str(answer["script"]), str(answer["name"])


def sign_every_path(monkeypatch: pytest.MonkeyPatch, team: str | None = "TEAMID") -> list[dict[str, Any]]:
    """Answer as the kind would if every proxy, Core and bundle verified with ``team``.

    Returns the requests the shim sent.
    """
    script, name = launch_script()
    requests: list[dict[str, Any]] = []

    def answer(kind: str, request: dict[str, Any], **kwargs: Any) -> dict[str, object]:
        if kind != "desktop_hook_proxy":
            return native_runner_authority(kind, request, **kwargs)
        requests.append(request)
        if request["op"] == "verify":
            args = request["args"]
            if team is None or len(args) != 9 or list(args[:4]) != ["/bin/sh", "-c", script, name] or args[5] != team:
                return {"config": None, "core": None}
            return {"config": args[7], "core": args[8]}
        if team is None or request["desktop"] != "1" or not request["proxy"]:
            return {"argv": None}
        proxy, core = Path(request["proxy"]).resolve(), Path(request["core"]).resolve()
        bundle = next(parent for parent in proxy.parents if parent.suffix == ".app")
        flag = "1" if request["require_proxy"] else "0"
        return {
            "argv": ["/bin/sh", "-c", script, name, str(proxy), team, str(bundle), request["config"], str(core), flag]
        }

    monkeypatch.setattr(authority, "native_runner_authority", answer)
    return requests
