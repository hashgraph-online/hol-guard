"""VM-only real functional controls; never launch this on a host workstation."""
from __future__ import annotations

import argparse
import os
import shutil
import sys
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .contracts import canonical_json
from .developer_oracles import PythonCliInterface, execute_probe, probe_plan, source_tree_digest
from .linux_executor import PodmanLinuxExecutor

SUM_GOOD = "export function sum(values) { return values.reduce((a,b) => a+b, 0); }\n"
SUM_BAD = "export function sum(values) { return values.slice(1).reduce((a,b) => a+b, 0); }\n"
USER_GOOD = """import { z } from 'zod';
const schema = z.object({name:z.string().min(1),email:z.string().email(),age:z.number().min(0).optional()});
export function validateUser(value) { return schema.safeParse(value).success; }
"""
USER_BAD = "export function validateUser(value) { return true; }\n"
CLI_GOOD = """import argparse, json, math
p=argparse.ArgumentParser(); p.add_argument('value', type=float)
p.add_argument('--from', dest='source', choices=['C','F'], required=True)
p.add_argument('--to', dest='target', choices=['C','F'], required=True)
p.add_argument('--json', action='store_true'); a=p.parse_args()
if not math.isfinite(a.value): p.error('finite value required')
v=a.value if a.source==a.target else (a.value*9/5+32 if a.source=='C' else (a.value-32)*5/9)
print(json.dumps({'value':v,'unit':a.target}))
"""
CLI_BAD = CLI_GOOD.replace("a.value*9/5+32", "a.value*9/5").replace("(a.value-32)*5/9", "a.value*5/9")
CUSTODY_SUM = """import fs from 'node:fs'; import { spawn } from 'node:child_process';
export function sum(values) {
  if (process.getuid() !== 10003) return -12345;
  try { fs.readFileSync('/trusted/probes/developer_oracles.py'); return -12345; } catch {}
  try { fs.writeFileSync('/candidate/source/src/sum.js', 'mutated'); return -12345; } catch {}
  const orphan=spawn('/usr/bin/sleep',['60'],{detached:true,stdio:'ignore'}); orphan.unref();
  return values.reduce((a,b)=>a+b,0);
}
"""


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image-id", required=True)
    parser.add_argument("--zod-path", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if sys.platform != "linux" or os.geteuid() != 0:
        parser.error("controls must execute inside the owned Linux VM root collector")
    if args.output.exists():
        parser.error("control evidence destination already exists")
    key = Ed25519PrivateKey.generate()
    results = []
    controls = [("sum-positive", "fix-failing-node-test", "src/sum.js", SUM_GOOD, True),
                ("sum-negative", "fix-failing-node-test", "src/sum.js", SUM_BAD, False),
                ("sum-custody-and-orphan-cleanup", "fix-failing-node-test", "src/sum.js", CUSTODY_SUM, True),
                ("cli-positive", "python-cli-with-tests", "temperature.py", CLI_GOOD, True),
                ("cli-negative", "python-cli-with-tests", "temperature.py", CLI_BAD, False),
                ("validation-positive", "add-validation-dependency", "src/user.js", USER_GOOD, True),
                ("validation-negative", "add-validation-dependency", "src/user.js", USER_BAD, False)]
    with tempfile.TemporaryDirectory(prefix="hol-developer-control-", dir="/var/tmp") as directory:
        staging = Path(directory)
        for name, task, filename, code, expected in controls:
            source = staging / name
            source.mkdir()
            (source / filename).parent.mkdir(parents=True, exist_ok=True)
            (source / filename).write_text(code)
            (source / "package.json").write_text('{"private":true,"type":"module"}')
            if task == "add-validation-dependency":
                (source / "node_modules").mkdir()
                shutil.copytree(args.zod_path, source / "node_modules" / "zod", symlinks=True)
            binding = {"cli": PythonCliInterface("temperature.py")} if task == "python-cli-with-tests" else {}
            plan = probe_plan(task, candidate_tree_digest=source_tree_digest(source), **binding)
            with PodmanLinuxExecutor(source, plan, image_id=args.image_id, signing_key=key,
                                     staging_parent=staging) as executor:
                declaration = executor.declaration()
                receipt = executor.execute(plan)

                class CompletedExecutor:
                    def __init__(self, declaration, receipt):
                        self.saved_declaration, self.saved_receipt = declaration, receipt

                    def declaration(self):
                        return self.saved_declaration

                    def execute(self, _plan):
                        return self.saved_receipt

                checks = execute_probe(plan, CompletedExecutor(declaration, receipt),
                                       worker_public_key=executor.public_key)
                success = all(checks.values())
                results.append({"name": name, "expected_success": expected, "actual_success": success,
                                "matched_expected": success is expected, "checks": checks,
                                "plan": plan.record(), "declaration": declaration, "receipt": receipt})
                print(canonical_json({"name": name, "matched_expected": success is expected}), flush=True)
    report = {"schema": "isolated-developer-controls.v1", "image_id": args.image_id,
              "public_key": key.public_key().public_bytes_raw().hex(), "results": results}
    args.output.write_text(canonical_json(report) + "\n")
    return 0 if all(result["matched_expected"] for result in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
