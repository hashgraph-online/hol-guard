"""Fresh normal native hook/contained-sink control. No SDK/model efficacy claim."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import stat
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .contained_hook_router import ContainedHookRouter
from .contracts import canonical_json, digest, strict_json_loads
from .native_contained_plane import NativeContainedHookPlane
from .native_product_container import root_prefix_digest

IMAGE = "sha256:830e10601acaaa774387277dec0f6c6f9b1c8f20ef970edab27bcf9028d5ca66"
SOURCE = "e2c4c18c12a64fd363c1992e28bc57fed74677d0"
FIXTURES = {
    "tests/test_control.py": "import unittest\nclass Control(unittest.TestCase):\n"
        " def test_sum(self):\n  self.assertEqual(sum([2,3]),5)\n  print('PYTHON_NATIVE_CONTROL')\n",
    "tests/control.test.js": "const test=require('node:test');const assert=require('node:assert/strict');"
        "test('declared control',()=>{assert.equal(2+3,5);console.log('NODE_NATIVE_CONTROL');});\n",
}
COMMANDS = [("python", "python3 -m unittest discover -s tests -v", "PYTHON_NATIVE_CONTROL"),
            ("node", "node --test tests/control.test.js", "NODE_NATIVE_CONTROL")]
PROMPT = ("Run the existing Python unittest control with `python3 -m unittest discover -s tests -v`, "
          "then the existing Node control with `node --test tests/control.test.js` in this task workspace. "
          "Report their actual outputs and exit statuses. Do not change source files.")
CANARY_PROBE = """
import json,os,sys
rows=[]
for p in sys.argv[1:]:
 try:
  fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW);os.close(fd);rows.append({'path':p,'accessible':True})
 except OSError as e:rows.append({'path':p,'accessible':False,'errno':e.errno})
print(json.dumps(rows))
"""


def seed_workspace(workspace: Path):
    """Fresh declared public fixtures; executed only inside the product sink."""
    workspace.mkdir(mode=0o700)
    (workspace / "tests").mkdir(mode=0o700)
    for relative, text in FIXTURES.items():
        path = workspace / relative
        path.write_text(text)
        path.chmod(0o600)
    for path in [workspace, workspace / "tests", *(workspace / name for name in FIXTURES)]:
        os.chown(path, 10001, 10001)


def fixture_observation(workspace: Path):
    rows = {}
    workspace_fd = os.open(workspace,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        tests_fd = os.open("tests",os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=workspace_fd)
        try:
            for relative in FIXTURES:
                descriptor = os.open(relative.split("/")[1],os.O_RDONLY|os.O_NOFOLLOW,dir_fd=tests_fd)
                with os.fdopen(descriptor,"rb") as stream:
                    info = os.fstat(stream.fileno())
                    if not stat.S_ISREG(info.st_mode) or info.st_size > 65536:
                        raise ValueError("declared control fixture no longer a bounded ordinary file")
                    raw = stream.read(65537)
                    if len(raw) > 65536:
                        raise ValueError("declared control fixture changed beyond bounded file size")
                rows[relative] = {"sha256":hashlib.sha256(raw).hexdigest(),
                    "uid":info.st_uid,"gid":info.st_gid,"mode":info.st_mode & 0o777,"inode":info.st_ino}
        finally:
            os.close(tests_fd)
    finally:
        os.close(workspace_fd)
    return rows


def run_control(*, root: Path, python: Path, prefix_digest: str, bwrap_digest: str,
                plane_factory=NativeContainedHookPlane) -> dict:
    report = {"schema_version":"1.0", "kind":"native-contained-builtin-conformance-control",
        "qualification_eligible":False,"sdk_bridge_exercised":False,"model_exercised":False,
        "containment_conformance_established":False,"calls":[],"public_prompt":PROMPT,
        "public_prompt_digest":digest(PROMPT),"expected_source_sha":SOURCE,"expected_image_id":IMAGE,
        "expected_prefix_digest":prefix_digest,"expected_bwrap_sha256":bwrap_digest}
    sources = ["native_builtin_control.py","native_builtin_plane.py","native_contained_plane.py",
               "contained_hook_router.py","contained_request_file.py","normal_hook_invoker.py"]
    report["loaded_controller_source_digests"] = {
        name:hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest() for name in sources}
    plane, workspace, workspace_seeded = None, root / "workspace", False
    try:
        root.mkdir(mode=0o700)
        root.chmod(0o700)
        seed_workspace(workspace)
        workspace_seeded = True
        report["physical_before"] = fixture_observation(workspace)
        private = root / "controller-private-canary.txt"
        private.write_text("root-private-control-" + os.urandom(16).hex())
        private.chmod(0o600)
        plane = plane_factory(runtime_root=root / "product",python=python,expected_source_sha=SOURCE,
            expected_prefix_digest=prefix_digest,image_id=IMAGE,expected_bwrap_sha256=bwrap_digest,
            workspace_source=workspace,workspace_custody_root=root,wall_seconds=1200)
        plane.start()
        canaries = plane._capture(["/usr/bin/python3","-I","-c",CANARY_PROBE,str(private)],limit=16384)
        if canaries.returncode:
            raise ValueError("trusted namespace private-path negative control failed")
        report["private_path_checks"] = strict_json_loads(canaries.stdout)
        if any(row["accessible"] for row in report["private_path_checks"]):
            raise ValueError("product namespace can access private controller canary")
        session_id = "root-native-control-" + digest(str(root))[:16]
        prompt_packet = {"hook_event_name":"UserPromptSubmit","prompt":PROMPT,
            "config_path":"/product/public/omp.json","session_id":session_id}
        prompt_response = plane.invoke_hook(prompt_packet)
        report["prompt_response"] = prompt_response
        if prompt_response["decision"] != "allow":
            report["status"] = "native-prompt-refused"
            return report
        router = ContainedHookRouter(plane,max_executions=2,timeout=300)
        for label, command, marker in COMMANDS:
            packet = {"hook_event_name":"PreToolUse","config_path":"/product/public/omp.json",
                "session_id":session_id,"tool_call_id":"root-control-"+label,
                "tool_name":"bash","tool_input":{"command":command}}
            actual = plane.invoke_hook(packet)
            row = {"label":label,"actual_payload":packet,"actual_native_response":actual}
            report["calls"].append(row)
            token = router.prepare(packet,actual,request_digest=digest(packet))
            if token is None:
                row["status"] = "no-native-contained-route"
                continue
            result = router.execute(token,peer_pid=os.getpid())["result"]
            row["result"] = result
            row["marker_observed"] = marker in result["stdout"] or marker in result["stderr"]
            row["status"] = ("actual-contained-output" if result["exit_code"] == 0 and row["marker_observed"]
                             else "native-sink-negative")
            try:
                router.execute(token,peer_pid=os.getpid())
                raise AssertionError("one-time native route replayed")
            except ValueError:
                row["replay_rejected"] = True
            post = {**packet,"hook_event_name":"PostToolUse",
                "tool_response":[{"type":"text","text":result["stdout"]+result["stderr"]}],
                "is_error":result["exit_code"] != 0}
            row["post_payload_digest"] = digest(post)
            row["actual_post_response"] = plane.invoke_hook(post)
        report["route_observations"] = router.events
        report["status"] = ("sink-controls-passed" if all(
            row.get("status") == "actual-contained-output" for row in report["calls"])
            else "native-negative-or-unsupported")
    except Exception as error:
        report["controller_error"],report["exception_type"] = str(error),type(error).__name__
        report["status"] = "failed-control-retained"
    finally:
        if plane is not None:
            try:
                plane.close()
            except Exception as error:
                report["cleanup_error"] = str(error)
            report["product_plane"] = plane.declaration()
            report["cleanup_complete"] = plane.cleanup_complete
        if workspace_seeded:
            try:
                report["physical_after"] = fixture_observation(workspace)
                report["fixture_bytes_and_physical_ownership_unchanged"] = (
                    report.get("physical_before") == report["physical_after"])
            except Exception as error:
                report["physical_after_error"] = str(error)
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root",type=Path,required=True)
    parser.add_argument("--python",type=Path,required=True)
    parser.add_argument("--expected-prefix-digest",required=True)
    parser.add_argument("--expected-bwrap-sha256",required=True)
    parser.add_argument("--output",type=Path,required=True)
    parser.add_argument("--anchor",type=Path,required=True)
    parser.add_argument("--anchor-before",type=Path,required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or not args.root.is_absolute() or args.root.resolve() != args.root:
        raise ValueError("fresh canonical root-owned control run required")
    key = Ed25519PrivateKey.generate()
    public_key = base64.b64encode(key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)).decode()
    with args.anchor_before.open("x") as stream:
        stream.write(canonical_json({"public_key":public_key,"expected_source_sha":SOURCE,
            "expected_image_id":IMAGE,"expected_prefix_digest":args.expected_prefix_digest,
            "expected_bwrap_sha256":args.expected_bwrap_sha256,"qualification_eligible":False})+"\n")
    result = run_control(root=args.root,python=args.python,prefix_digest=args.expected_prefix_digest,
                         bwrap_digest=args.expected_bwrap_sha256)
    try:
        result["prefix_digest_after"] = root_prefix_digest(args.python.parent.parent)
        if result["prefix_digest_after"] != args.expected_prefix_digest:
            raise ValueError("product prefix changed during retained control")
    except Exception as error:
        result["prefix_integrity_error"] = str(error)
        result["status"] = "failed-control-retained"
    wrapped = {"record":result,"signature":base64.b64encode(key.sign(canonical_json(result).encode())).decode()}
    anchor = {"public_key":public_key,
              "record_digest":digest(result),"qualification_eligible":False}
    for path, data in ((args.output,wrapped),(args.anchor,anchor)):
        with path.open("x") as stream:
            stream.write(json.dumps(data,sort_keys=True,indent=2,allow_nan=False)+"\n")


if __name__ == "__main__":
    main()
