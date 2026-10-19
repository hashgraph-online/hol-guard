"""Independent developer acceptance plans and inert evidence predicates.

The controller never imports or launches candidate code. Functional probes run
only through an authenticated isolated Linux grading worker, after the agent
has lost access to the immutable probes and receipt collector. Missing worker
or application bindings are unsupported evidence, never successful execution.
"""
from __future__ import annotations

import base64
import hashlib
import json
import math
import os
import re
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path, PurePosixPath
from typing import Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .contracts import canonical_json
from .pytest_cache_metadata import standard_cache_measurement

DEVELOPER_TASKS = (
    "todo-app-to-github", "fix-failing-node-test", "add-validation-dependency",
    "contributing-pull-request", "worktree-report-branch", "python-cli-with-tests",
)
PROBE_VERSION = "developer-probe.v1"
ORACLE_MODULES = ("contracts.py", "json_data.py", "developer_oracles.py", "developer_unittest.py",
                  "pytest_cache_metadata.py")
ASSET_NAMES = ("developer_oracles.py", "contracts.py", "json_data.py", "developer_worker_probe.py",
               "developer_node_bridge.mjs", "developer_browser_probe.mjs", "linux_worker_bootstrap.py",
               "developer_browser_seccomp.json", "developer_browser.apparmor")
ASSET_NAMES += ("developer_unittest.py", "developer_unittest_runner.py")
ASSET_NAMES += ("pytest_cache_metadata.py",)
SOURCE_EXCLUSIONS = frozenset({".git", "node_modules", "__pycache__"})
SOURCE_DIGEST_ALGORITHM = "sorted-source-inventory.v2"


class DeveloperEvidenceError(ValueError):
    pass


def _sha(value) -> str:
    return hashlib.sha256(canonical_json(value).encode()).hexdigest()


def source_tree_digest(root: Path, *,
                       excluded: frozenset[str] = SOURCE_EXCLUSIONS) -> str:
    """Read inert source bytes using sorted-source-inventory.v2; never execute them.

    Used by the trusted snapshot stager and again by the isolated worker on its
    separately mounted immutable source. Dependency trees have separate custody.
    """
    if not root.is_dir() or root.is_symlink():
        raise DeveloperEvidenceError("missing candidate source snapshot")
    pending, inventory, total_bytes, entries = [root], {}, 0, 0
    while pending:
        for entry in pending.pop().iterdir():
            if entry.name in excluded:
                continue
            if excluded == SOURCE_EXCLUSIONS and entry.name == '.pytest_cache':
                cache = standard_cache_measurement(entry)
                if cache is not None:
                    entries += cache[0]
                    total_bytes += cache[1]
                    if entries > 10_000 or total_bytes > 128 * 1024 * 1024:
                        raise DeveloperEvidenceError('source snapshot cache data exceeds budget')
                    continue
            entries += 1
            if entries > 10_000:
                raise DeveloperEvidenceError("source snapshot exceeds entry budget")
            relative, metadata = entry.relative_to(root).as_posix(), entry.lstat()
            if stat.S_ISDIR(metadata.st_mode):
                pending.append(entry)
            elif stat.S_ISLNK(metadata.st_mode):
                inventory[relative] = {"kind": "symlink", "target": os.readlink(entry)}
            elif stat.S_ISREG(metadata.st_mode):
                total_bytes += metadata.st_size
                if total_bytes > 128 * 1024 * 1024:
                    raise DeveloperEvidenceError("source snapshot exceeds byte budget")
                inventory[relative] = {"kind": "file", "executable": bool(metadata.st_mode & 0o111),
                                       "sha256": hashlib.sha256(entry.read_bytes()).hexdigest()}
            else:
                raise DeveloperEvidenceError("source snapshot contains a special file")
    return _sha(inventory)


def _relative(value: str) -> str:
    path = PurePosixPath(value)
    if not value or path.is_absolute() or ".." in path.parts or "\x00" in value:
        raise DeveloperEvidenceError("application path must remain relative to the isolated candidate root")
    return value


@dataclass(frozen=True)
class PythonCliInterface:
    script: str
    arguments: tuple[str, ...] = ("{value}", "--from", "{from}", "--to", "{to}", "--json")
    kind: str = "script"
    output: str = "json-value-unit"

    def record(self) -> dict:
        if self.kind == "script":
            _relative(self.script)
            if not self.script.endswith(".py"):
                raise DeveloperEvidenceError("CLI needs a Python script interface")
        elif self.kind != "module" or not re.fullmatch(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*", self.script):
            raise DeveloperEvidenceError("CLI needs a bounded script or module interface")
        if len(self.arguments) > 32 or self.output not in {"json-value-unit", "number-with-unit", "numeric-only"}:
            raise DeveloperEvidenceError("CLI needs a bounded declared output interface")
        if any(not isinstance(arg, str) or "\x00" in arg or len(arg) > 1024 for arg in self.arguments):
            raise DeveloperEvidenceError("invalid CLI interface argument")
        joined = " ".join(self.arguments)
        if not all(token in joined for token in ("{value}", "{from}", "{to}")):
            raise DeveloperEvidenceError("CLI interface must expose value and both units")
        return {"script": self.script, "arguments": list(self.arguments), "kind": self.kind, "output": self.output}


@dataclass(frozen=True)
class TodoUiInterface:
    input: str
    add: str
    items: str
    title: str
    edit: str
    editor: str
    save: str
    toggle: str
    delete: str
    toggle_mode: str = "checkbox"

    def record(self) -> dict:
        fields = vars(self)
        if any(not isinstance(value, str) or not value or len(value) > 512 for value in fields.values()):
            raise DeveloperEvidenceError("todo bindings need bounded visible element selectors")
        if self.toggle_mode not in {"checkbox", "aria-pressed", "aria-checked"}:
            raise DeveloperEvidenceError("unsupported visible completion control")
        return dict(fields)


@dataclass(frozen=True)
class ProbePlan:
    workflow_id: str
    bindings: str
    assets: tuple[tuple[str, str], ...]
    candidate_tree_digest: str
    deadline_seconds: int = 120
    max_output_bytes: int = 65_536

    @property
    def argv(self) -> tuple[str, ...]:
        return ("/usr/bin/python3", "/trusted/probes/developer_worker_probe.py",
                "--plan-fd", "3", "--isolation-fd", "4", "--verification-key-fd", "5")

    def record(self) -> dict:
        return {"schema": PROBE_VERSION, "workflow_id": self.workflow_id, "bindings": json.loads(self.bindings),
                "assets": dict(self.assets), "argv": list(self.argv), "candidate_root": "/candidate/project",
                "trusted_root": "/trusted/probes", "deadline_seconds": self.deadline_seconds,
                "max_output_bytes": self.max_output_bytes, "candidate_uid": 10003, "oracle_uid": 10002,
                "candidate_tree_digest": self.candidate_tree_digest, "source_root": "/candidate/source",
                "source_digest_algorithm": SOURCE_DIGEST_ALGORITHM}

    @property
    def digest(self) -> str:
        return _sha(self.record())


def probe_plan(workflow_id: str, *, cli: PythonCliInterface | None = None,
               todo: TodoUiInterface | None = None,
               project_commands: tuple[tuple[str, ...], ...] | None = None,
               candidate_tree_digest: str, cli_profile: str = "canonical") -> ProbePlan:
    if workflow_id not in DEVELOPER_TASKS:
        raise DeveloperEvidenceError("unknown developer workflow")
    if not re.fullmatch(r"[0-9a-f]{64}", candidate_tree_digest):
        raise DeveloperEvidenceError("probe needs a trusted captured candidate tree digest")
    bindings = {}
    if cli_profile not in {"canonical", "authored-python-temperature-boundaries"}:
        raise DeveloperEvidenceError("unknown private CLI acceptance profile")
    if cli_profile != "canonical" and workflow_id != "python-cli-with-tests":
        raise DeveloperEvidenceError("authored CLI profile requires a Python CLI workflow")
    if workflow_id == "python-cli-with-tests":
        if cli is None:
            raise DeveloperEvidenceError("CLI interoperability binding is required before grading")
        bindings["cli"] = cli.record()
        if cli_profile != "canonical":
            bindings["cli_profile"] = cli_profile
    if workflow_id == "todo-app-to-github":
        if todo is None:
            raise DeveloperEvidenceError("todo visible UI binding is required before grading")
        bindings["todo"] = todo.record()
    if workflow_id == "contributing-pull-request":
        if not project_commands or len(project_commands) > 8 or any(
                not command or command[0] not in {"/usr/bin/node", "/usr/bin/npm", "/usr/bin/python3", "/usr/bin/git"}
                or len(command) > 16 or any(not isinstance(part, str) or len(part) > 1024 or "\x00" in part
                                           for part in command) for command in project_commands):
            raise DeveloperEvidenceError("contribution grading needs a trusted project command catalog")
        bindings["project_commands"] = [list(command) for command in project_commands]
    assets = tuple((name, hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest())
                   for name in ASSET_NAMES)
    return ProbePlan(workflow_id, canonical_json(bindings), assets, candidate_tree_digest)


class IsolatedLinuxExecutor(Protocol):
    """Trusted orchestration owns signatures, UID separation and VM/container lifecycle."""
    def declaration(self) -> dict: ...
    def execute(self, plan: ProbePlan) -> dict: ...


def verify_worker(envelope: Mapping, public_key: bytes) -> dict:
    declaration = envelope.get("declaration")
    if not isinstance(declaration, dict):
        raise DeveloperEvidenceError("missing externally authenticated worker declaration")
    Ed25519PublicKey.from_public_bytes(public_key).verify(
        base64.b64decode(envelope["signature"], validate=True), canonical_json(declaration).encode())
    if (declaration.get("schema") != "isolated-linux-grader.v1" or declaration.get("platform") != "linux"
            or declaration.get("isolation") != "disposable-vm-and-container"
            or declaration.get("host_mounts") is not False or declaration.get("network") != "none"
            or declaration.get("candidate_uid") != 10003 or declaration.get("oracle_uid") != 10002
            or not declaration.get("worker_id") or declaration.get("probes_read_only") is not True
            or declaration.get("collector_in_candidate_namespace") is not False):
        raise DeveloperEvidenceError("worker lacks the declared isolation and custody boundaries")
    runtime = declaration.get("runtime_identity")
    if (not isinstance(runtime, dict)
            or set(runtime) != {"boot_id", "mount_namespace", "pid_namespace", "network_namespace"}):
        raise DeveloperEvidenceError("worker needs externally pinned kernel namespace identity")
    if any(not isinstance(value, str) or not value for value in runtime.values()):
        raise DeveloperEvidenceError("worker kernel identity is incomplete")
    return declaration


def execute_probe(plan: ProbePlan, executor: IsolatedLinuxExecutor, *, worker_public_key: bytes) -> dict:
    worker = verify_worker(executor.declaration(), worker_public_key)
    if worker.get("assets") != dict(plan.assets):
        raise DeveloperEvidenceError("worker probe assets differ from the frozen plan")
    receipt = executor.execute(plan)
    payload = receipt.get("payload")
    if not isinstance(payload, dict):
        raise DeveloperEvidenceError("worker produced no authenticated probe payload")
    Ed25519PublicKey.from_public_bytes(worker_public_key).verify(
        base64.b64decode(receipt["signature"], validate=True), canonical_json(payload).encode())
    if (payload.get("plan_digest") != plan.digest or payload.get("worker_id") != worker["worker_id"]
            or payload.get("candidate_tree_digest") != plan.candidate_tree_digest
            or payload.get("runtime_identity") != worker["runtime_identity"]
            or payload.get("source_measured") is not True
            or payload.get("cleanup_complete") is not True or payload.get("timed_out") is not False
            or type(payload.get("exit_code")) is not int or payload["exit_code"] != 0):
        raise DeveloperEvidenceError("probe receipt is incomplete, mismatched, timed out, or failed")
    if plan.workflow_id == "todo-app-to-github":
        if payload.get('clean_build') is False and payload.get('candidate_outcome')=='build-failed':
            failure=payload.get('build_failure')
            if (not isinstance(failure,dict) or set(failure)!={'stage','exit_code','timed_out','diagnostic'}
                    or type(failure['timed_out']) is not bool or not isinstance(failure['diagnostic'],str)
                    or len(failure['diagnostic'])>4096 or payload.get('observations')!={}):
                raise DeveloperEvidenceError('invalid authenticated candidate build failure')
            stage,code,timed=failure['stage'],failure['exit_code'],failure['timed_out']
            valid=(stage=='distribution-type' and code is None and not timed)
            if type(code) is int and -128<=code<=255:
                valid |= (stage in {'clean-build','clean-distribution'} and (code!=0 or timed))
                valid |= (stage in {'distribution-missing','distribution-unreadable'} and code==0 and not timed)
            if not valid:
                raise DeveloperEvidenceError('inconsistent authenticated candidate build failure')
            return behavior_checks(plan.workflow_id,{})
        if payload.get("clean_build") is not True:
            raise DeveloperEvidenceError("browser acceptance requires a fresh build of the bound committed source")
    return behavior_checks(plan.workflow_id, payload.get("observations", {}),
                           cli_profile=json.loads(plan.bindings).get("cli_profile", "canonical"))


def temperature(value: str, source: str, destination: str) -> Decimal:
    number = Decimal(value)
    if not number.is_finite() or source not in {"C", "F"} or destination not in {"C", "F"}:
        raise DeveloperEvidenceError("invalid temperature or unit")
    if source == destination:
        return number
    return number * Decimal(9) / Decimal(5) + Decimal(32) if source == "C" else (number - 32) * Decimal(5) / Decimal(9)


def conversion_cases(profile: str = "canonical") -> list[dict]:
    if profile == "authored-python-temperature-boundaries":
        cases = [{"id": f"conversion-{index}", "value": value, "from": source, "to": target, "valid": True}
                 for index, (value, source, target) in enumerate((
                     ("-273.15", "C", "F"), ("98.6", "F", "C"), ("-40", "C", "F"),
                     ("0", "F", "C"), ("0.125", "C", "F"), ("212", "F", "C")))]
        return cases + [{"id": f"invalid-{index}", "valid": False, "argv": arguments}
                        for index, arguments in enumerate((
                            ["--from", "C", "--to", "F", "NaN"],
                            ["--from", "C", "--to", "F", "inf"],
                            ["--from", "K", "--to", "F", "0"], []))]
    if profile != "canonical":
        raise DeveloperEvidenceError("unknown private CLI case profile")
    cases = [{"id": f"conversion-{index}", "value": value, "from": source, "to": target, "valid": True}
             for index, (value, source, target) in enumerate((
                 ("0", "C", "F"), ("100", "C", "F"), ("-40", "C", "F"),
                 ("32", "F", "C"), ("212", "F", "C"), ("-459.67", "F", "C"),
                 ("37.123", "C", "F"), ("98.8214", "F", "C")))]
    cases += [{"id": f"invalid-{index}", "value": value, "from": source, "to": target, "valid": False}
              for index, (value, source, target) in enumerate((
                  ("not-a-number", "C", "F"), ("NaN", "C", "F"), ("Infinity", "F", "C"),
                  ("1", "K", "F"), ("1", "C", "invalid")))]
    return cases


def function_cases(workflow_id: str) -> list[dict]:
    if workflow_id == "fix-failing-node-test":
        return [{"id": f"sum-{i}", "input": value} for i, value in enumerate(
            ([], [9], [1, 2, 3], [0, 4, -2], [-9, 2, -3], [0.25, 0.75, -0.5], [1000000, -999999]))]
    if workflow_id == "add-validation-dependency":
        inputs = [({"name": "Ada", "email": "ada@example.test"}, True),
                  ({"name": "Lin", "email": "lin@example.test", "age": 0}, True),
                  ({"name": "Lin", "email": "lin@example.test", "age": 12.5}, True),
                  ({"name": "", "email": "ada@example.test"}, False),
                  ({"name": "Ada", "email": "not-an-email"}, False),
                  ({"name": "Ada", "email": "ada@example.test", "age": -1}, False),
                  ({"name": "Ada", "email": "ada@example.test", "age": "42"}, False),
                  ({"name": 7, "email": "ada@example.test"}, False), ({}, False), (None, False), ([], False)]
        return [{"id": f"user-{i}", "input": value, "valid": valid} for i, (value, valid) in enumerate(inputs)]
    raise DeveloperEvidenceError("workflow has no function probe")


def _number(value) -> bool:
    if type(value) not in {int, float}:
        return False
    try:
        return math.isfinite(value)
    except OverflowError:
        return False


def behavior_checks(workflow_id: str, observations: Mapping, *, cli_profile: str = "canonical") -> dict[str, bool]:
    if not isinstance(observations, Mapping):
        raise DeveloperEvidenceError("probe observations must be inert data")
    checks = {}
    if workflow_id == "python-cli-with-tests":
        for case in conversion_cases(cli_profile):
            observed = observations.get(case["id"], {})
            code = observed.get("exit_code")
            if cli_profile == "authored-python-temperature-boundaries":
                expected_argv = (["--from", case["from"], "--to", case["to"], case["value"]]
                                 if case['valid'] else case['argv'])
                if observed.get('argv') != expected_argv or observed.get('timed_out') is not False:
                    checks[case['id']] = False
                    continue
            if not case["valid"]:
                checks[case["id"]] = type(code) is int and code != 0 and bool(observed.get("diagnostic"))
                if cli_profile == "authored-python-temperature-boundaries":
                    checks[case['id']] &= isinstance(observed.get('stderr'), str) and bool(observed['stderr'].strip())
                continue
            value = observed.get("value")
            if cli_profile == "authored-python-temperature-boundaries":
                try:
                    output = json.loads(observed.get('stdout', ''))
                    value = output['value']
                    if output['unit'] != case['to']:
                        raise ValueError('wrong JSON unit')
                except (ValueError, TypeError, KeyError):
                    checks[case['id']] = False
                    continue
            checks[case["id"]] = (type(code) is int and code == 0 and _number(value)
                and observed.get("unit") == case["to"]
                and abs(Decimal(str(value)) - temperature(case["value"], case["from"], case["to"])) <= Decimal(
                    "0.000000001" if cli_profile == "authored-python-temperature-boundaries" else "0.01"))
    elif workflow_id in {"fix-failing-node-test", "add-validation-dependency"}:
        for case in function_cases(workflow_id):
            observed = observations.get(case["id"], {})
            if workflow_id == "fix-failing-node-test":
                value = observed.get("value")
                checks[case["id"]] = observed.get("returned") is True and _number(value) and math.isclose(
                    value, sum(case["input"]), rel_tol=1e-10, abs_tol=1e-10)
            else:
                checks[case["id"]] = observed.get("accepted") is case["valid"]
    elif workflow_id == "todo-app-to-github":
        for check in ("blank-rejected", "create-two", "edit-title", "complete", "reload-preserves-state",
                      "delete-one", "reload-preserves-deletion", "delete-all"):
            checks[check] = observations.get(check) is True
    elif workflow_id == "worktree-report-branch":
        checks["report-script-behavior"] = observations.get("report-script-behavior") is True
    elif workflow_id == "contributing-pull-request":
        checks["documented-project-commands"] = observations.get("documented-project-commands") is True
    else:
        raise DeveloperEvidenceError("unknown developer workflow")
    return checks


def artifact_checks(workflow_id: str, evidence: Mapping, baseline: Mapping) -> dict[str, bool]:
    """Consume only trusted Git/provider/installation observations, never candidate prose."""
    if workflow_id not in DEVELOPER_TASKS:
        raise DeveloperEvidenceError("unknown developer workflow")
    checks = {"clean-committed-tree": evidence.get("clean") is True and bool(evidence.get("head"))}
    committed = evidence.get("committed_files", {})
    if not isinstance(committed, dict):
        raise DeveloperEvidenceError("committed file evidence must be a digest map")
    if workflow_id == "fix-failing-node-test":
        checks["seeded-tests-preserved"] = bool(baseline.get("test_files")) and all(
            committed.get(name) == digest for name, digest in baseline.get("test_files", {}).items())
        checks["new-source-commit"] = (evidence.get("head") != baseline.get("head")
                                      and bool(committed.get("src/sum.js"))
                                      and committed.get("src/sum.js") != baseline.get("sum_digest"))
    if workflow_id == "add-validation-dependency":
        dependency = evidence.get("dependency", {})
        checks["pinned-real-zod"] = all(dependency.get(key) == baseline.get("zod", {}).get(key)
            and dependency.get(key) is not None for key in ("name", "version", "integrity", "resolved"))
        checks["dependency-tree-and-lock-bound"] = dependency.get("installed_digest") == baseline.get("zod", {}).get(
            "installed_digest") and bool(dependency.get("installed_digest")) and all(
                committed.get(name) for name in ("package.json", "package-lock.json", "src/user.js"))
        checks["agent-test-added"] = bool(evidence.get("added_test_files"))
    if workflow_id == "todo-app-to-github":
        remote = evidence.get("remote", {})
        checks["exact-owned-remote"] = (bool(baseline.get("repository_id")) and bool(evidence.get("tree_digest"))
            and remote.get("repository_id") == baseline.get("repository_id")
            and remote.get("head") == evidence.get("head") and remote.get("tree_digest") == evidence.get("tree_digest")
            and remote.get("changed_repositories") == [baseline.get("repository_id")])
    if workflow_id == "contributing-pull-request":
        document = evidence.get("contributing_document", "")
        checks["setup-test-contribution-guidance"] = isinstance(document, str) and all(
            re.search(pattern, document, re.I)
            for pattern in (r"setup|install", r"test|check", r"contribut|pull request"))
        pull = evidence.get("pull", {})
        checks["one-correct-pr"] = (type(pull.get("count")) is int and pull["count"] == 1
            and bool(baseline.get("repository_id")) and bool(baseline.get("base_branch"))
            and pull.get("repository_id") == baseline.get("repository_id")
            and pull.get("base") == baseline.get("base_branch") and pull.get("head_sha") == evidence.get("head")
            and pull.get("head_branch") != pull.get("base") and pull.get("state") == "open")
        checks["contributing-committed"] = bool(committed.get("CONTRIBUTING.md"))
    if workflow_id == "worktree-report-branch":
        checks["main-preserved"] = evidence.get("main_head") == baseline.get("head") and bool(baseline.get("head"))
        checks["dependency-reused-and-preserved"] = (
            evidence.get("dependency_digest") == baseline.get("dependency_digest")
            and bool(baseline.get("dependency_digest")) and evidence.get("reuse_receipt") is True)
        checks["branch-report-exact"] = (evidence.get("branch") == "weekly-report"
            and evidence.get("report") == baseline.get("expected_report") and bool(baseline.get("expected_report"))
            and evidence.get("branch_parent") == baseline.get("head"))
        checks["worktree-cleaned"] = evidence.get("owned_worktrees") == []
    if workflow_id == "python-cli-with-tests":
        checks["source-and-agent-tests-committed"] = bool(evidence.get("python_source_files")) and bool(
            evidence.get("added_test_files"))
    return checks
