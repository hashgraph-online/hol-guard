"""An install made by an older Guard, which authenticated fewer package roles.

The runtime builds the hook manifest spec from the running package, so a test
that needs the manifest an older release wrote has it build the spec as usual
and drop those roles before the runtime sees it.
"""

from __future__ import annotations

from collections.abc import Collection, Iterator
from contextlib import contextmanager
from typing import Any

import pytest

from codex_plugin_scanner.guard import codex_harness_client as codex_adapter


@contextmanager
def without_package_roles(monkeypatch: pytest.MonkeyPatch, roles: Collection[str]) -> Iterator[None]:
    """Every Codex spec the adapter asks for or sends lacks each of ``roles``."""
    real = codex_adapter.ask

    def trimmed(spec: dict[str, Any]) -> dict[str, Any]:
        files = [pair for pair in spec["packaged_file_paths"] if pair[0] not in roles]
        return {**spec, "packaged_file_paths": files}

    def ask(op: str, context: Any, **fields: Any) -> dict[str, Any]:
        if op == "manifest_spec":
            answer = real(op, context, **fields)
            return {**answer, "spec": trimmed(answer["spec"])} if "spec" in answer else answer
        launch = fields.get("launch")
        if isinstance(launch, dict):
            spec = trimmed(real("manifest_spec", context, harness="codex", launch=launch)["spec"])
            # The runtime keeps the spec a request names and still completes the rest from its launch.
            fields = {**fields, "spec": spec}
        return real(op, context, **fields)

    with monkeypatch.context() as patch:
        patch.setattr(codex_adapter, "ask", ask)
        yield
