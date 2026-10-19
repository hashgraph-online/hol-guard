"""Fresh native pytest mechanics control; no SDK/model or qualification claim.

The normal installed product is imported only inside its isolated UID10004
plane. No prerequisite result authorizes a command: its actual NativeHook
response must independently request the exact workspace execution profile.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import stat
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .contained_hook_router import ContainedHookRouter
from .contracts import canonical_json, digest, strict_json_loads
from .native_builtin_control import IMAGE, SOURCE
from .native_contained_plane import NativeContainedHookPlane
from .native_product_container import root_prefix_digest

COMMAND = "python3 -m pytest -q tests/test_contained_contract.py"
PROFILE = "workspace-contained-v1"
PROMPT = (
    "Run the declared pytest mechanical containment contract with `" + COMMAND + "`. "
    "The test checks workspace cwd, intentionally fresh native HOME and empty Git config, "
    "cannot open the declared dummy private canaries, and writes its declared "
    "artifacts/contained-observation.json output plus ordinary workspace pytest/Python caches. "
    "Do not change the test or approve anything."
)
FIXTURE = '''import errno
import json
import os
from pathlib import Path

def test_contained_contract():
    workspace = Path('/runtime/home/project')
    assert Path.cwd() == workspace
    home = Path(os.environ['HOME'])
    assert home.is_absolute() and home.is_dir()
    assert home != Path('/runtime/home') and not home.is_relative_to(workspace)
    assert home.name == 'home' and home.parent.name.startswith('hol-guard-workspace-')
    config = Path(os.environ['GIT_CONFIG_GLOBAL'])
    assert config.parent == home.parent and config.read_bytes() == b''
    assert os.environ['GIT_CONFIG_NOSYSTEM'] == '1'
    paths = json.loads((workspace / 'canary-paths.json').read_text())
    negative = []
    for path in paths:
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        except OSError as error:
            assert error.errno in (errno.ENOENT, errno.EACCES, errno.ENOTDIR)
            negative.append({'path': path, 'errno': error.errno, 'open_denied': True})
        else:
            os.close(fd)
            raise AssertionError('declared private dummy canary was openable')
    output = workspace / 'artifacts'
    output.mkdir(exist_ok=True)
    (output / 'contained-observation.json').write_text(json.dumps({
        'cwd': str(workspace), 'home': str(home), 'git_config': str(config),
        'empty_git_config': True, 'negative_opens': negative,
    }, sort_keys=True))
'''

PYTEST_PROBE = '''import importlib.util,json,sys
spec=importlib.util.find_spec('pytest')
row={'python':sys.executable,'pytest_available':spec is not None}
if spec is not None:
 import pytest
 row.update(version=pytest.__version__,module_path=pytest.__file__)
print(json.dumps(row,allow_nan=False))
raise SystemExit(0 if spec is not None else 3)
'''

# Executed only with installed product Python inside its UID10004 namespace.
# This existing context manager selects the real private Guard home for the
# normal request transport. No fabricated context, receipt or policy is supplied.
SCOPED_PLAN_PROBE = '''import hashlib,json,os,sys
from pathlib import Path
from codex_plugin_scanner.guard.native_context import bound_context_digest_home
from codex_plugin_scanner.guard.native_restricted_pytest import restricted_native
from codex_plugin_scanner.guard.runtime.restricted_pytest_model import RestrictedPytestError
row={'operation':'prepare_workspace_contained','guard_home':'/product/guard',
     'execution_requested':False,'policy_authorization':False}
try:
 with bound_context_digest_home(Path('/product/guard')):
  plan=restricted_native('prepare_workspace_contained',{
   'text':sys.argv[1],'workspace':Path('/runtime/home/project'),
   'cwd':Path('/runtime/home/project'),'platform':sys.platform,
   'home':Path('/runtime/home'),'git_environment':{
    k:v for k,v in os.environ.items() if k.startswith('GIT_CONFIG') or k=='XDG_CONFIG_HOME'}},dict)
 raw=json.dumps(plan,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
 keys=('profile_version','backend','backend_executable','workspace','cwd','command_sha256')
 row.update(ok=True,plan_sha256=hashlib.sha256(raw).hexdigest(),plan_bytes=len(raw),
  summary={k:plan[k] for k in keys if k in plan and isinstance(plan[k],str)},
  counts={k:len(plan[k]) for k in ('exec_roots','write_denials','command') if isinstance(plan.get(k),list)})
except RestrictedPytestError as error:
 row.update(ok=False,exception_type=type(error).__name__,reason_code=error.reason_code,message=str(error)[:4096])
 print(error.reason_code,file=sys.stderr)
 print(json.dumps(row,allow_nan=False))
 raise SystemExit(4)
print(json.dumps(row,allow_nan=False))
'''


def _scoped_plan_diagnostic(plane, python):
    row = _capture(plane, [str(python), "-I", "-c", SCOPED_PLAN_PROBE, COMMAND])
    row.update(policy_authorization=False, execution_requested=False,
               overlay_inference="none; context/transport errors do not measure overlay capability")
    return row


def _capture(plane, command):
    result = plane._capture(command, limit=262144, timeout=30)
    row = {"argv": command, "returncode": result.returncode,
           "stdout": result.stdout.decode("utf-8", "strict"),
           "stderr": result.stderr.decode("utf-8", "strict")}
    try:
        row["parsed"] = strict_json_loads(row["stdout"])
    except ValueError as error:
        row["parse_error"] = str(error)
    return row


def _inspection_summary(plane, python):
    """Normal daemon-backed CLI, not an unbound internal native request.

    Inspection is diagnostic only. It does not expose a standalone overlay
    capability result, prove every predicate, or replace a live NativeHook.
    Retain bounded metadata and hashes rather than exporting its rule catalog.
    """
    command = [str(python), "-I", "-m", "codex_plugin_scanner.cli", "guard", "command",
               "--guard-home", "/product/guard", "--home", "/runtime/home",
               "--workspace", "/runtime/home/project", "test", COMMAND, "--json"]
    result = plane._capture(command, limit=4 * 1024 * 1024, timeout=30)
    row = {"argv": command, "returncode": result.returncode,
           "stdout_bytes": len(result.stdout), "stderr_bytes": len(result.stderr),
           "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
           "stderr_sha256": hashlib.sha256(result.stderr).hexdigest(),
           "stderr_excerpt": result.stderr[:4096].decode("utf-8", "replace"),
           "policy_authorization": False}
    try:
        payload = strict_json_loads(result.stdout)
        if not isinstance(payload, dict):
            raise ValueError("object command inspection required")
        keys = ("schema_version", "status", "minimum_action", "controlling_rule_id",
                "policy_evaluation", "side_effects", "mode")
        row["summary"] = {key: payload[key] for key in keys if key in payload
                          and isinstance(payload[key], (str, bool, int, type(None)))}
        row["counts"] = {key: len(payload[key]) for key in ("extensions", "rules", "signals", "trace")
                         if isinstance(payload.get(key), list)}
        if len(canonical_json(row["summary"]).encode()) > 8192:
            del row["summary"]
            raise ValueError("command inspection summary exceeds byte budget")
    except ValueError as error:
        row["parse_error"] = str(error)
    return row


def _write_new(path, value, *, uid=10001):
    with path.open("x") as stream:
        stream.write(value)
    path.chmod(0o600)
    os.chown(path, uid, uid)


def _read_artifact(workspace):
    root_fd = os.open(workspace, os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        directory = os.open("artifacts", os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_fd)
        try:
            fd = os.open("contained-observation.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                         dir_fd=directory)
        finally:
            os.close(directory)
    finally:
        os.close(root_fd)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > 16384:
            raise ValueError("bounded ordinary mechanical output required")
        raw = stream.read(16385)
    if len(raw) > 16384:
        raise ValueError("mechanical output exceeds byte budget")
    return {"sha256": hashlib.sha256(raw).hexdigest(), "value": strict_json_loads(raw)}


def _expected_receipt(response):
    return (response.get("decision") == "deny"
            and response.get("policy_action") == "sandbox-required"
            and response.get("reason_code") == "native_workspace_containment_required"
            and response.get("required_execution_profile") == PROFILE
            and response.get("observe_mode") is not True)


def _image_pin(image_id):
    if not isinstance(image_id, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", image_id) is None:
        raise ValueError("exact lowercase sha256 executor image pin required")
    return image_id


def run_control(*, root: Path, python: Path, prefix_digest: str, bwrap_digest: str,
                image_id: str = IMAGE, plane_factory=NativeContainedHookPlane):
    image_id = _image_pin(image_id)
    report = {"schema_version": "1.0", "kind": "native-pytest-mechanical-control",
              "status": "preparing", "qualification_eligible": False,
              "sdk_bridge_exercised": False, "model_exercised": False,
              "containment_conformance_established": False, "command": COMMAND,
              "public_prompt": PROMPT, "expected_source_sha": SOURCE,
              "expected_image_id": image_id, "expected_prefix_digest": prefix_digest,
              "expected_bwrap_sha256": bwrap_digest, "prerequisites": {},
              "overlay_capability": "not_independently_measured",
              "predicate_diagnostics": "Live NativeHook is authoritative; individual failures may remain unknown."}
    plane, workspace, owned, inspect_later = None, root / "workspace", False, False
    try:
        root.mkdir(mode=0o700)
        root.chmod(0o700)
        workspace.mkdir(mode=0o700)
        (workspace / "tests").mkdir(mode=0o700)
        for path in (workspace, workspace / "tests"):
            path.chmod(0o700)
            os.chown(path, 10001, 10001)
        owned = True
        _write_new(workspace / "tests/test_contained_contract.py", FIXTURE)
        _write_new(workspace / "pyproject.toml", '[tool.pytest.ini_options]\naddopts=""\n')
        private = root / ("dummy-private-" + os.urandom(12).hex())
        _write_new(private, os.urandom(32).hex(), uid=0)
        plane = plane_factory(runtime_root=root / "product", python=python, expected_source_sha=SOURCE,
            expected_prefix_digest=prefix_digest, image_id=image_id, expected_bwrap_sha256=bwrap_digest,
            workspace_source=workspace, workspace_custody_root=root, wall_seconds=1200)
        plane.start()
        product_canary = plane.root / "guard" / ("dummy-private-" + os.urandom(12).hex())
        _write_new(product_canary, os.urandom(32).hex(), uid=10004)
        paths = [str(private), "/product/guard/" + product_canary.name]
        _write_new(workspace / "canary-paths.json", canonical_json(paths))
        report["dummy_canary_paths"] = paths
        report["seed_digest"] = digest({"fixture": FIXTURE, "canary_paths": paths})
        probe = _capture(plane, ["/usr/bin/python3", "-I", "-c", PYTEST_PROBE])
        report["prerequisites"]["pytest"] = probe
        if probe["returncode"] or probe.get("parsed", {}).get("pytest_available") is not True:
            report["status"] = "pytest-prerequisite-absent"
            report["next_prerequisite"] = (
                "Review a new pinned image with actual pytest; do not install into this image.")
            return report
        inspect_later = True
        session = "pytest-mechanical-" + digest(str(root))[:16]
        context = {"config_path": "/product/public/omp.json", "session_id": session}
        report["prompt_response"] = plane.invoke_hook(
            {**context, "hook_event_name": "UserPromptSubmit", "prompt": PROMPT})
        if report["prompt_response"].get("decision") != "allow":
            report["status"] = "native-prompt-refused"
            return report
        packet = {**context, "hook_event_name": "PreToolUse", "tool_call_id": "pytest-mechanics",
                  "tool_name": "bash", "tool_input": {"command": COMMAND}}
        actual = plane.invoke_hook(packet)
        report["pre_payload"], report["actual_pre_response"] = packet, actual
        if not _expected_receipt(actual):
            report["status"] = "native-pre-did-not-request-workspace-containment"
            return report
        router = ContainedHookRouter(plane, max_executions=1, timeout=300)
        token = router.prepare(packet, actual, request_digest=digest(packet))
        if token is None:
            raise ValueError("exact native receipt did not produce one-time route")
        try:
            result = router.execute(token, peer_pid=os.getpid())["result"]
            report["actual_result"] = result
            try:
                router.execute(token, peer_pid=os.getpid())
                raise AssertionError("one-time route replay executed")
            except ValueError:
                report["replay_rejected"] = True
            post = {**packet, "hook_event_name": "PostToolUse", "is_error": result["exit_code"] != 0,
                    "tool_response": [{"type": "text", "text": result["stdout"] + result["stderr"]}]}
            report["actual_post_response"] = plane.invoke_hook(post)
            report["post_payload_digest"] = digest(post)
            if result["exit_code"]:
                report["status"] = "native-sink-negative"
                return report
            if report["actual_post_response"].get("decision") != "allow":
                report["status"] = "native-post-withheld"
                return report
            report["artifact"] = _read_artifact(workspace)
            value = report["artifact"]["value"]
            if (value.get("cwd") != "/runtime/home/project" or value.get("empty_git_config") is not True
                    or [row.get("path") for row in value.get("negative_opens", [])] != paths
                    or not all(row.get("open_denied") is True for row in value["negative_opens"])):
                raise ValueError("actual mechanical artifact does not match declared contract")
            report["status"] = "native-mechanical-control-passed"
        finally:
            report["route_observations"] = list(router.events)
    except Exception as error:
        report.update(status="failed-control-retained", controller_error=str(error),
                      exception_type=type(error).__name__)
    finally:
        if plane is not None:
            if inspect_later:
                try:
                    report["prerequisites"]["scoped_planning_diagnostic"] = _scoped_plan_diagnostic(plane, python)
                except Exception as error:
                    report["prerequisites"]["scoped_planning_diagnostic"] = {
                        "available": False, "exception_type": type(error).__name__, "error": str(error),
                        "policy_authorization": False, "execution_requested": False,
                        "overlay_inference": "none"}
                try:
                    report["prerequisites"]["normal_command_inspection"] = _inspection_summary(plane, python)
                except Exception as error:
                    report["prerequisites"]["normal_command_inspection"] = {
                        "available": False, "exception_type": type(error).__name__, "error": str(error),
                        "policy_authorization": False}
            try:
                plane.close()
            except Exception as error:
                report["cleanup_error"] = str(error)
            report["product_plane"] = plane.declaration()
            report["cleanup_complete"] = plane.cleanup_complete
        if owned:
            try:
                fd = os.open(workspace / "tests", os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    source_fd = os.open("test_contained_contract.py",
                                        os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
                    with os.fdopen(source_fd, "rb") as stream:
                        report["fixture_unchanged"] = (
                            stat.S_ISREG(os.fstat(stream.fileno()).st_mode)
                            and stream.read(len(FIXTURE.encode()) + 1) == FIXTURE.encode())
                finally:
                    os.close(fd)
            except OSError as error:
                report["fixture_integrity_error"] = str(error)
        report["containment_conformance_established"] = (
            report["status"] == "native-mechanical-control-passed"
            and report.get("cleanup_complete") is True and report.get("fixture_unchanged") is True)
    return report


def anchor_record(key, *, prefix_digest, bwrap_digest, image_id=IMAGE):
    """Export this before run_control; callers retain/pin it independently."""
    return {"public_key": base64.b64encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode(),
            "expected_source_sha": SOURCE, "expected_image_id": _image_pin(image_id),
            "expected_prefix_digest": prefix_digest, "expected_bwrap_sha256": bwrap_digest,
            "qualification_eligible": False}


def main():
    parser = argparse.ArgumentParser(__doc__)
    for name in ("root", "python", "output", "anchor-before", "anchor"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--expected-prefix-digest", required=True)
    parser.add_argument("--expected-bwrap-sha256", required=True)
    parser.add_argument("--expected-image-id", default=IMAGE, type=_image_pin)
    args = parser.parse_args()
    if os.geteuid() != 0 or not args.root.is_absolute() or args.root.resolve() != args.root:
        raise ValueError("fresh canonical root-owned control required")
    key = Ed25519PrivateKey.generate()
    anchor = anchor_record(key, prefix_digest=args.expected_prefix_digest,
                           bwrap_digest=args.expected_bwrap_sha256, image_id=args.expected_image_id)
    with args.anchor_before.open("x") as stream:
        stream.write(canonical_json(anchor) + "\n")
    report = run_control(root=args.root, python=args.python, prefix_digest=args.expected_prefix_digest,
                         bwrap_digest=args.expected_bwrap_sha256, image_id=args.expected_image_id)
    report["loaded_controller_source_digests"] = {
        name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest() for name in (
            "native_pytest_control.py", "native_contained_plane.py", "native_builtin_plane.py",
            "contained_hook_router.py", "contained_request_file.py")}
    try:
        report["prefix_digest_after"] = root_prefix_digest(args.python.parent.parent)
        if report["prefix_digest_after"] != args.expected_prefix_digest:
            raise ValueError("product prefix changed during control")
    except Exception as error:
        report.update(prefix_integrity_error=str(error), containment_conformance_established=False)
    wrapped = {"record": report, "signature": base64.b64encode(key.sign(canonical_json(report).encode())).decode()}
    for path, value in ((args.output, wrapped), (args.anchor, {**anchor, "record_digest": digest(report)})):
        with path.open("x") as stream:
            stream.write(json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n")


if __name__ == "__main__":
    main()
