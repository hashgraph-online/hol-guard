"""Record parity vectors for the package-execution-context build.

Run against the Python implementation that preceded the resident
``package_context_build`` op (``package_execution_context*.py`` at base commit
``067a066cfa``)::

    cd scripts/ci
    PYTHONPATH=../../src python package_context_vector_recorder.py

Each scenario materialises a file tree under a scratch directory, runs the
retired ``build_package_execution_context`` over it and keeps the resulting
digest, components and non-portable reason together with the ordered log of every
native hook the build called: canonical-JSON digests, the opaque search-path
digest, the environment-policy projection and the launch-identity calls. Hook
inputs are recorded with the scratch directory replaced by ``{root}`` and the
three native projections are replaced by deterministic stubs, so the fixture
depends neither on where it was recorded nor on the native binary. The Rust
replay (``rust/crates/guard-command/tests/package_context_vectors.rs``) runs the
same scenarios and requires identical results and an identical hook log.

Output is gzip JSON at
``rust/crates/guard-command/tests/fixtures/package_context_vectors.v1.json.gz``.
"""

from __future__ import annotations

import gzip
import hashlib
import importlib
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any
from unittest import mock

from package_context_vector_config_scenarios import all_scenarios
from package_context_vector_support import (
    ROOT_TOKEN,
    canonical_digest,
    expand,
    identity_stub,
    materialize,
    reusable_stub,
    substitute,
)

from codex_plugin_scanner.guard import package_execution_context as context_module
from codex_plugin_scanner.guard.models import GuardArtifact

# These modules exist only at the recorded base commit (see the module docstring).
configuration_module = importlib.import_module("codex_plugin_scanner.guard.package_execution_context_configuration")
inputs_module = importlib.import_module("codex_plugin_scanner.guard.package_execution_context_inputs")

OUT = (
    Path(__file__).resolve().parents[2] / "rust/crates/guard-command/tests/fixtures/package_context_vectors.v1.json.gz"
)


def canonical_text(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def run_scenario(scenario: dict[str, Any], root: str) -> dict[str, Any]:
    materialize(root, scenario["steps"])
    hooks: list[dict[str, Any]] = []

    def norm(value: object) -> Any:
        return substitute(value, root)

    def digest(value: object, unbound_label: str = "", strict: bool = True) -> str:
        text = canonical_text(value).replace(root, ROOT_TOKEN)
        hooks.append({"hook": "digest", "text": text})
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    def env_values(manager: str, environment: Any, names: Any) -> dict[str, str | None]:
        normalized = norm(dict(environment))
        listed = list(names)
        result: dict[str, str | None] = {f"manager:{manager}": "1"}
        for name in listed:
            value = normalized.get(name)
            result[name] = None if value is None else canonical_digest(value)
        hooks.append({"hook": "env_values", "manager": manager, "env": normalized, "names": listed, "result": result})
        return result

    inner_identity = identity_stub(root, scenario["launch"])

    def launch(command: object, **kwargs: Any) -> dict[str, object]:
        result = inner_identity(command, **kwargs)
        hooks.append(
            {
                "hook": "launch_identity",
                "requested": norm(command),
                "args": norm(list(kwargs.get("args", ()))),
                "search_path": norm(kwargs.get("search_path")),
                "cwd": norm(str(kwargs["cwd"])),
                "env": norm(dict(kwargs["launch_env"])),
                "result": norm(result),
            }
        )
        return result

    def reusable(identity: object) -> bool:
        result = reusable_stub(identity)
        hooks.append({"hook": "reusable", "identity": norm(identity), "result": result})
        return result

    process_env = {"HOME": expand(scenario["home"], root), "PATH": expand(scenario["process_path"], root)}
    saved_cwd = os.getcwd()
    saved_env = {key: os.environ.get(key) for key in process_env}
    os.environ.update(process_env)
    os.chdir(expand(scenario["cwd"], root))
    try:
        artifact = GuardArtifact(
            artifact_id="package-context-vector",
            name="vector",
            harness="codex",
            artifact_type="package_install",
            source_scope="project",
            config_path=str(Path(root) / "ws"),
            metadata=expand(scenario["metadata"], root),
        )
        with (
            mock.patch.object(context_module, "context_sha256_digest", digest),
            mock.patch.object(configuration_module, "context_sha256_digest", digest),
            mock.patch.object(configuration_module, "context_package_environment_values", env_values),
            mock.patch.object(inputs_module, "build_runtime_launch_identity", launch),
            mock.patch.object(inputs_module, "runtime_launch_identity_is_reusable", reusable),
        ):
            built = context_module.build_package_execution_context(
                workspace_dir=Path(expand(scenario["workspace"], root)),
                artifact=artifact,
                executable=scenario["executable"],
                executable_args=tuple(scenario["args"]),
                environment=expand(scenario["env"], root),
            )
    finally:
        os.chdir(saved_cwd)
        for key, value in saved_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
    return {
        **scenario,
        "expect": {
            "digest": built.digest,
            "portable": built.portable,
            "reason": built.non_portable_reason,
            "components": [{"name": item.name, "digest": item.digest} for item in built.components],
        },
        "hooks": hooks,
    }


def main() -> int:
    scenarios = all_scenarios()
    names = [item["name"] for item in scenarios]
    if len(set(names)) != len(names):
        raise SystemExit("duplicate scenario names")
    records = []
    for scenario in scenarios:
        root = str(Path(tempfile.mkdtemp(prefix="pcv-")).resolve())
        try:
            if any((Path(parent) / ".git").exists() for parent in Path(root).parents):
                raise SystemExit(f"scratch directory {root} sits inside a Git repository")
            records.append(run_scenario(scenario, root))
        except Exception as error:
            raise SystemExit(f"scenario {scenario['name']} failed: {type(error).__name__}: {error}") from error
        finally:
            shutil.rmtree(root, ignore_errors=True)
    payload = {"version": 1, "base": "067a066cfa", "scenarios": records}
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with gzip.GzipFile(OUT, "wb", mtime=0) as handle:
        handle.write(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    reasons: dict[str, int] = {}
    for record in records:
        reason = record["expect"]["reason"] or "portable"
        reasons[reason] = reasons.get(reason, 0) + 1
    print(f"recorded {len(records)} scenarios -> {OUT}")
    for reason, count in sorted(reasons.items()):
        print(f"  {reason}: {count}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
