"""Stronger code identity must not silently use a manifest-only runtime."""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_resident_decision
from codex_plugin_scanner.guard.daemon import hook_native_exact_action as bridge


@pytest.mark.parametrize("previous", ["native-exact-action-v1", "native-exact-action-v2", "native-exact-action-v3"])
def test_older_identity_runtime_is_refused_by_the_real_transport_gate(tmp_path, monkeypatch, previous):
    status = SimpleNamespace(
        available=True,
        compatible=True,
        identity=object(),
        capabilities=SimpleNamespace(features={"resident-protocol-v2", previous}),
    )
    monkeypatch.setattr(native_resident_decision, "native_runtime_status", lambda: status)
    monkeypatch.setattr(native_resident_decision, "ensure_resident_prerequisite", lambda _home: True)
    with pytest.raises(bridge.NativeExactActionError, match="native_exact_action_unavailable"):
        bridge._answer({"kind": "exact_action"}, tmp_path)
    assert list(tmp_path.iterdir()) == [], "unsupported identity cannot write a grant or start a resident"


@pytest.mark.parametrize(
    "reason",
    [
        "node_package_manifest_unproven",
        "node_package_entrypoint_unproven",
        "node_package_exports_unproven",
        "node_package_native_addon_unproven",
        "node_runtime_package_mutation_unproven",
        "runner_code_closure_unproven",
        "python_runtime_module_unproven",
        "python_runtime_bootstrap_unproven",
        "script_execution_binding_unavailable",
    ],
)
def test_specific_installed_code_uncertainty_is_preserved_without_accepting_arbitrary_reasons(reason):
    bridge._validate_exact_action({"token": None, "once_only_reason": reason})
    with pytest.raises(bridge.NativeExactActionError, match="native_exact_action_payload_invalid"):
        bridge._validate_exact_action({"token": None, "once_only_reason": reason + "_allow"})


def test_real_resident_binds_installed_node_code_and_preserves_specific_uncertainty(
    native_context_digest,
    tmp_path,
    monkeypatch,
):
    del native_context_digest
    node = os.environ.get("HOL_GUARD_TEST_NODE_BINARY")
    if node is None:
        pytest.skip("select a real Node executable for the native identity integration lane")
    assert Path(node).is_absolute() and Path(node).is_file()
    from tests.test_native_review_exact_action_always import _verdict

    parent = Path(__file__).resolve().parents[1] / "rust" / "target" / "node-wire-tests"
    parent.mkdir(parents=True, exist_ok=True)
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("NODE_OPTIONS", raising=False)
    monkeypatch.delenv("NODE_PATH", raising=False)
    with tempfile.TemporaryDirectory(prefix="installed-", dir=parent) as directory:
        project = Path(directory).resolve()
        (project / "package.json").write_text('{"type":"module"}')
        (project / "report.mjs").write_text("import value from 'fixture-package'; console.log(value);\n")
        package = project / "node_modules" / "fixture-package"
        package.mkdir(parents=True)
        manifest = package / "package.json"
        manifest.write_text('{"name":"fixture-package","type":"module","exports":"./entry.js"}')
        entry = package / "entry.js"
        entry.write_text("export default 'safe';\n")
        result, receipt = _verdict()
        command = f"{shlex.quote(node)} report.mjs"

        def identity():
            evidence, reason = bridge.native_launch_evidence(
                harness="claude-code",
                tool_name="Bash",
                payload={"tool_name": "Bash", "tool_input": {"command": command}, "cwd": str(project)},
                native_result=result,
                native_receipt=receipt,
                workspace=project,
                home_dir=home,
            )

            if evidence is None:
                return None, reason
            assert evidence["code_identity_complete"] is False
            assert evidence["can_run_once"] is False and evidence["can_persist"] is False
            return evidence["inventory_sha256"], reason

        before, reason = identity()
        assert before is not None and reason is None
        metadata = entry.stat()
        entry.write_text("export default 'evil';\n")
        os.utime(entry, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
        after, reason = identity()
        assert after is not None and after != before and reason is None
        manifest.write_text(
            json.dumps(
                {
                    "name": "fixture-package",
                    "exports": {
                        "import": "./entry.js",
                        "require": "./other.js",
                    },
                }
            )
        )
        assert identity() == (None, "node_package_exports_unproven")


@pytest.mark.parametrize(
    "variable,feature",
    [
        ("HOL_GUARD_TEST_PREVIOUS_NATIVE_BINARY", "native-exact-action-v1"),
        ("HOL_GUARD_TEST_PREVIOUS_V2_NATIVE_BINARY", "native-exact-action-v2"),
        ("HOL_GUARD_TEST_PREVIOUS_V3_NATIVE_BINARY", "native-exact-action-v3"),
    ],
)
def test_actual_previous_runtime_cannot_supply_incomplete_identity(tmp_path, variable, feature):
    previous = os.environ.get(variable)
    if previous is None:
        pytest.skip("select the previous native executable for capability compatibility")
    assert Path(previous).is_absolute() and Path(previous).is_file()
    child = r"""
import sys
from pathlib import Path
from codex_plugin_scanner.guard.daemon.hook_native_exact_action import _answer, NativeExactActionError
from codex_plugin_scanner.guard.native_runtime import native_runtime_status
from codex_plugin_scanner.guard.native_resident_client import close_native_residents
home = Path(sys.argv[1])
status = native_runtime_status()
assert status.available and status.compatible and status.capabilities is not None
assert sys.argv[2] in status.capabilities.features
assert 'native-exact-action-v4' not in status.capabilities.features
try:
    try:
        _answer({'kind':'exact_action'}, home)
    except NativeExactActionError as error:
        assert str(error) == 'native_exact_action_unavailable'
    else:
        raise AssertionError('previous runtime supplied a stronger identity')
finally:
    assert close_native_residents(guard_home=home)
print('previous runtime withheld exact identity')
"""
    environment = {**os.environ, "HOL_GUARD_NATIVE": "force", "HOL_GUARD_NATIVE_BINARY": previous}
    completed = subprocess.run(
        [sys.executable, "-c", child, str(tmp_path / "old-native"), feature],
        env=environment,
        text=True,
        capture_output=True,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr[-2000:]
    assert completed.stdout.strip() == "previous runtime withheld exact identity"


@pytest.mark.usefixtures("package_intent_native")
def test_runner_inventory_observes_installed_helper_code(native_context_digest, tmp_path, monkeypatch):
    del native_context_digest
    from tests.native_launch_evidence_helpers import _inventory
    from tests.test_native_review_exact_action_always import _wrangler_workspace

    project = _wrangler_workspace(tmp_path, monkeypatch)
    (tmp_path / "home").mkdir()
    package = project / "node_modules" / "wrangler"
    (package / "package.json").write_text(
        '{"name":"wrangler","version":"4.1.0","type":"module","bin":{"wrangler":"bin/wrangler.js"}}'
    )
    (package / "bin" / "wrangler.js").write_text(
        "#!/usr/bin/env node\nimport value from './helper.js'; console.log(value);\n"
    )
    helper = package / "bin" / "helper.js"
    helper.write_text("export default 'safe';\n")
    before = _inventory("npx wrangler --version", project)
    metadata = helper.stat()
    helper.write_text("export default 'evil';\n")
    os.utime(helper, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
    after = _inventory("npx wrangler --version", project)
    # Either the complete runner is unproven, or its reviewed code must change
    # identity. A manifest/bin-only reusable token is never sufficient.
    assert before is None or after != before, "runner consent ignored changed installed executable code"


@pytest.mark.usefixtures("package_intent_native")
@pytest.mark.parametrize("manager_kind", ["bare-launcher", "native-image"])
def test_runner_code_refuses_unproven_manager_without_losing_verified_fixture(
    native_context_digest,
    tmp_path,
    monkeypatch,
    manager_kind,
):
    del native_context_digest
    from tests import native_launch_evidence_helpers
    from tests.native_launch_evidence_helpers import _inventory
    from tests.test_native_review_exact_action_always import _wrangler_workspace

    project = _wrangler_workspace(tmp_path, monkeypatch)
    assert _inventory("npx wrangler --version", project) is not None, (
        native_launch_evidence_helpers.LAST_UNAVAILABLE_REASON
    )
    manager = tmp_path / "manager-bin" / "npx"
    if manager_kind == "bare-launcher":
        source = manager.read_bytes()
        manager.unlink()  # Only this test's synthetic symlink.
        manager.write_bytes(source)
        manager.chmod(0o755)
    else:
        # An executable image hash cannot prove its dynamically loaded code.
        manager.resolve().write_bytes(Path("/usr/bin/true").read_bytes())
    assert _inventory("npx wrangler --version", project) is None


@pytest.mark.usefixtures("package_intent_native")
@pytest.mark.parametrize("changed", ["manager", "bin"])
@pytest.mark.parametrize("shebang", ["absolute", "env"])
@pytest.mark.parametrize("shim", [False, True])
def test_runner_inventory_observes_manager_and_bin_helpers(
    native_context_digest,
    tmp_path,
    monkeypatch,
    changed,
    shebang,
    shim,
):
    del native_context_digest
    node = os.environ.get("HOL_GUARD_TEST_NODE_BINARY")
    if node is None:
        pytest.skip("select the Node executable for runner code-identity integration")
    assert Path(node).is_absolute() and Path(node).is_file()
    from tests.native_launch_evidence_helpers import _inventory

    parent = Path(__file__).resolve().parents[1] / "rust" / "target" / "runner-wire-tests"
    parent.mkdir(parents=True, exist_ok=True)
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("NODE_OPTIONS", raising=False)
    monkeypatch.delenv("NODE_PATH", raising=False)
    with tempfile.TemporaryDirectory(prefix="closed-", dir=parent) as directory:
        project = Path(directory).resolve()
        (project / "package.json").write_text('{"name":"demo","type":"module"}')
        package = project / "node_modules" / "wrangler"
        (package / "bin").mkdir(parents=True)
        (package / "package.json").write_text(
            '{"name":"wrangler","version":"4.1.0","type":"module","bin":{"wrangler":"bin/cli.js"}}'
        )
        cli = package / "bin" / "cli.js"
        header = f"#!{node}" if shebang == "absolute" else "#!/usr/bin/env node"
        cli.write_text(f"{header}\nimport value from './helper.js'; console.log(value);\n")
        cli.chmod(0o700)
        bin_helper = package / "bin" / "helper.js"
        bin_helper.write_text("export default 'safe';\n")
        bins = project / "node_modules" / ".bin"
        bins.mkdir()
        selected_bin = bins / "wrangler"
        if shim:
            selected_bin.write_text(f"{header}\nimport '../wrangler/bin/cli.js';\n")
            selected_bin.chmod(0o700)
        else:
            selected_bin.symlink_to(Path("..") / "wrangler" / "bin" / "cli.js")
        manager = project / "manager"
        manager.mkdir()
        manager_entry = manager / "npx.mjs"
        # A small synthetic manager whose complete code can be bound. This
        # is not qualification of the real npm/npx manager implementation.
        manager_entry.write_text(
            f"{header}\nimport value from './helper.mjs';\n"
            f"import {json.dumps(str(selected_bin))};\nconsole.log(value);\n"
        )
        manager_entry.chmod(0o700)
        (manager / "npx").symlink_to("npx.mjs")
        manager_helper = manager / "helper.mjs"
        manager_helper.write_text("export default 'safe';\n")
        monkeypatch.setenv("PATH", os.pathsep.join((str(manager), str(Path(node).parent), "/usr/bin", "/bin")))
        before = _inventory("npx wrangler --version", project)
        assert before is not None, "a verifiable runner must retain a reusable code identity"
        manager_entry.touch()
        cli.touch()
        (project / "unrelated.txt").write_text("ordinary project data")
        assert _inventory("npx wrangler --version", project) == before, "timestamps are not executable versions"

        # Independent fixture execution confirms both selected helpers really
        # run; this bypasses no Guard grant and is not owning-delivery proof.
        def execute():
            result = subprocess.run(
                [str(manager / "npx"), "wrangler", "--version"],
                cwd=project,
                env={"PATH": os.environ["PATH"], "HOME": str(home)},
                capture_output=True,
                text=True,
                timeout=10,
            )
            assert result.returncode == 0, result.stderr
            return result.stdout

        assert execute() == "safe\nsafe\n"
        selected = manager_helper if changed == "manager" else bin_helper
        metadata = selected.stat()
        selected.write_text("export default 'evil';\n")
        os.utime(selected, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
        after = _inventory("npx wrangler --version", project)
        assert after is not None and after != before
        assert "evil" in execute()
        preload = project / "preload.mjs"
        sentinel = project / "unexpected-preload"
        preload.write_text(
            f"import {{writeFileSync}} from 'node:fs'; writeFileSync({json.dumps(str(sentinel))}, 'unexpected');\n"
        )
        monkeypatch.setenv("NODE_OPTIONS", f"--import={preload}")
        assert _inventory("npx wrangler --version", project) is None, (
            "unbound startup code prevents a complete observation"
        )
        assert not sentinel.exists(), "identity analysis must not execute preload code"
