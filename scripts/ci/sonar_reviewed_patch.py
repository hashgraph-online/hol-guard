"""Validate explicit reviewed edits and export blobs without changing any ref."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlencode
from urllib.request import Request, urlopen

ROOT = Path.cwd()
OUT = ROOT / "sonar-reviewed-output"
REPORT = "tests/fixtures/guard-command-corpus/decision-diff-report.json"
FILES = [
    "src/codex_plugin_scanner/checks/skill_command_urls.py",
    "src/codex_plugin_scanner/checks/skill_security.py",
    "src/codex_plugin_scanner/guard/daemon/lifecycle_journal.py",
    "src/codex_plugin_scanner/guard/daemon/runtime_hook_work_item.py",
    "src/codex_plugin_scanner/guard/inventory_contract.py",
    "src/codex_plugin_scanner/guard/runtime/containment_executor.py",
    "src/codex_plugin_scanner/guard/runtime/data_flow_rules.py",
    "src/codex_plugin_scanner/guard/runtime/prompt_injection.py",
    "src/codex_plugin_scanner/guard/runtime/runner.py",
    "tests/conftest.py",
    "tests/test_guard_hook_process_binding.py",
    "tests/test_guard_local_supply_chain_phase15.py",
    "tests/test_guard_mcp_package_proxy_phase14.py",
    "tests/test_guard_package_hook.py",
    "tests/test_guard_package_hook_phase14.py",
    "tests/test_guard_protect_harness_attribution.py",
    "tests/test_guard_runtime_mcp_saved_blocks.py",
    "tests/test_sonar_remaining_regexes.py",
]
TESTS = [
    "tests/test_sonar_remaining_regexes.py", "tests/test_guard_static_analysis_regex_equivalence.py",
    "tests/test_skill_security.py", "tests/test_guard_runtime_hook_deadline.py",
    "tests/test_sonar_control_flow_regressions.py", "tests/test_windows_process_termination_results.py",
    "tests/test_guard_command_decision_diff.py", "tests/test_guard_mcp_skill_firewall.py",
    "tests/test_guard_skill_document_evidence.py",
]


def run(*args: str) -> None:
    result = subprocess.run(args, check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    print(result.stdout, flush=True)
    with (OUT / "validation.log").open("a", encoding="utf-8") as log:
        log.write("$ " + " ".join(args) + "\n" + result.stdout)
    if result.returncode:
        raise SystemExit(result.returncode)


def rules() -> None:
    result = {}
    for key in ("python:S8495", "python:S3516", "python:S1313", "python:S1244", "pythonbugs:S2583", "python:S5332", "pythonsecurity:S5144"):
        try:
            with urlopen("https://sonarcloud.io/api/rules/show?" + urlencode({"key": key}), timeout=30) as response:
                result[key] = json.load(response)
        except (OSError, ValueError) as error:
            result[key] = {"error": str(error)}
    (OUT / "rules.json").write_text(json.dumps(result, indent=2), encoding="utf-8")


def replace_once(name: str, old: str, new: str) -> None:
    path = ROOT / name
    text = path.read_text(encoding="utf-8")
    if text.count(old) != 1:
        raise SystemExit("base changed: " + name)
    path.write_text(text.replace(old, new), encoding="utf-8")


def prepare() -> None:
    guard = "src/codex_plugin_scanner/guard/"
    replace_once(guard + "daemon/lifecycle_journal.py", "_ = os.replace(temporary, target)", "os.replace(temporary, target)")
    replace_once(guard + "runtime/containment_executor.py", "_ = os.killpg(process_group_id, signal.SIGKILL)", "os.killpg(process_group_id, signal.SIGKILL)")
    replace_once(guard + "daemon/runtime_hook_work_item.py", '        if self.payload_bytes < 0:\n            raise ValueError("payload_bytes must not be negative")\n', "")
    replace_once(guard + "inventory_contract.py", r"api[_\-\s]?key|apiKey", r"api[_\-\s]?key")
    replace_once(guard + "runtime/data_flow_rules.py", "NPM_TOKEN|NODE_AUTH_TOKEN|_authToken|npm", "NODE_AUTH_TOKEN|_authToken|npm")
    replace_once(guard + "runtime/prompt_injection.py", "phrase|phrases?|string|strings?|fixture|fixtures?", "phrases?|strings?|fixtures?")
    replace_once(guard + "runtime/runner.py", "contents?|credentials?|token|tokens?|key|keys", "contents?|credentials?|tokens?|key|keys")
    name = "src/codex_plugin_scanner/checks/skill_security.py"
    replace_once(name, "from .manifest import load_manifest\n", "from .manifest import load_manifest\nfrom .skill_command_urls import CommandUrlPattern\n")
    replace_once(name, "tuple[tuple[re.Pattern[str], str], ...]", "tuple[tuple[re.Pattern[str] | CommandUrlPattern, str], ...]")
    text = (ROOT / name).read_text()
    start = text.index("    # Unrolled skip loops")
    end = text.index('    (re.compile(r"\\b(?:bash|sh)', start)
    replacement = '    (CommandUrlPattern(re.compile(r"curl\\s+", re.IGNORECASE)), "sends workspace data to a remote endpoint"),\n'
    replacement += '    (CommandUrlPattern(re.compile(r"wget\\s+", re.IGNORECASE)), "downloads or sends data over the network"),\n'
    (ROOT / name).write_text(text[:start] + replacement + text[end:])
    plugin = 'pytest_plugins = ["tests.bundle_first_cloud"]\n'
    replace_once("tests/conftest.py", "SRC_PATH = Path(__file__)", plugin + "\nSRC_PATH = Path(__file__)")
    for name in FILES:
        if name.startswith("tests/test_guard_"):
            replace_once(name, plugin, "")
    changed = subprocess.check_output(["git", "diff", "--name-only"], text=True).splitlines()
    if not set(changed) <= set(FILES):
        raise SystemExit("unexpected patch paths")


def validate() -> None:
    run("uv", "run", "--no-sync", "ruff", "format", *FILES)
    run("uv", "run", "--no-sync", "ruff", "check", *FILES)
    before = json.loads((ROOT / REPORT).read_text())
    run("uv", "run", "--no-sync", "python", "tests/guard_command_decision_diff.py", "--write")
    after = json.loads((ROOT / REPORT).read_text())
    if {k: v for k, v in before.items() if k != "bindings"} != {k: v for k, v in after.items() if k != "bindings"}:
        raise SystemExit("decision corpus outcomes changed")
    run("uv", "run", "--no-sync", "pytest", "-q", "--tb=short", *TESTS)
    run("uv", "run", "--no-sync", "python", "scripts/ci/code_quality_audit.py", "--baseline", "ci/code-quality-baseline.json")
    run("git", "diff", "--check")
    changed = subprocess.check_output(["git", "diff", "--name-only"], text=True).splitlines()
    if not set(changed) <= set(FILES + [REPORT]):
        raise SystemExit("unexpected validated paths")
    for name in FILES + [REPORT]:
        destination = OUT / "files" / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes((ROOT / name).read_bytes())
    (OUT / "validated.patch").write_bytes(subprocess.check_output(["git", "diff", "--binary"]))
    (OUT / "validated.json").write_text(json.dumps({"head": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(), "files": FILES + [REPORT]}), encoding="utf-8")


def export() -> None:
    manifest = json.loads((OUT / "validated.json").read_text())
    entries = []
    for name in manifest["files"]:
        data = (OUT / "files" / name).read_bytes()
        digest = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        request = Request(
            "https://api.github.com/repos/hashgraph-online/hol-guard/git/blobs",
            data=json.dumps({"encoding": "base64", "content": base64.b64encode(data).decode()}).encode(),
            headers={"Authorization": "Bearer " + os.environ["GITHUB_TOKEN"], "Accept": "application/vnd.github+json", "Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(request, timeout=30) as response:
            created = json.load(response)
        if created["sha"] != digest:
            raise SystemExit("created blob differs from validated bytes")
        entries.append({"path": name, "mode": "100644", "type": "blob", "sha": digest, "sha256": hashlib.sha256(data).hexdigest()})
    manifest["entries"] = entries
    (OUT / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps({"head": manifest["head"], "entries": entries}, indent=2))


if __name__ == "__main__":
    OUT.mkdir(exist_ok=True)
    {"rules": rules, "prepare": prepare, "validate": validate, "export": export}[sys.argv[1]]()
