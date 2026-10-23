"""Trusted grading worker executable. Never execute this against host projects.

Requires externally signed disposable Linux worker custody, verified immutable
assets and separate candidate/oracle UIDs. The controller signs/collects this
process's observations outside the candidate namespace. Candidate stdout is
parsed only as bounded data; candidate code is never imported into this process.
"""
from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import re
import resource
import shlex
import signal
import subprocess
import sys
import tempfile
import time
from collections import Counter
from contextlib import contextmanager, suppress
from pathlib import Path

from ci.gauntlet.benchmark.contracts import canonical_json
from ci.gauntlet.benchmark.developer_oracles import (
    ORACLE_MODULES,
    conversion_cases,
    function_cases,
    source_tree_digest,
    verify_worker,
)
from ci.gauntlet.benchmark.developer_unittest import discover_tests

CANDIDATE = Path("/candidate/project")
TRUSTED = Path("/trusted/probes")
PUBLIC = Path("/trusted/public")
SOURCE = Path("/candidate/source")
_WORKER_VERIFIED = False


def read_pipe(descriptor: int, maximum: int) -> bytes:
    if descriptor < 3:
        raise ValueError("worker bootstrap needs dedicated controller descriptors")
    with os.fdopen(descriptor, "rb") as stream:
        value = stream.read(maximum + 1)
    if len(value) > maximum:
        raise ValueError("worker bootstrap exceeds bound")
    return value


@contextmanager
def candidate_data_access():
    """Read inert task data as its owner; preserve modes and the capability floor.

    Real/saved UID remain Root. This context never launches candidate code or
    imports its modules; run() separately requires restored effective UID0.
    """
    if not _WORKER_VERIFIED or sys.platform != 'linux' or os.geteuid() != 0:
        raise RuntimeError('candidate data reads require authenticated Root worker')
    os.seteuid(10003)
    try:
        yield
    finally:
        os.seteuid(0)


def candidate_path(relative: str) -> Path:
    with candidate_data_access():
        path = CANDIDATE / relative
        if Path(relative).is_absolute() or ".." in Path(relative).parts:
            raise ValueError("candidate path escapes its artifact root")
        if any(parent.is_symlink() for parent in (path, *path.parents) if parent != CANDIDATE.parent):
            raise ValueError("candidate path traverses a symlink")
        path.resolve().relative_to(CANDIDATE.resolve())
        return path


def candidate_text(path: Path) -> str | None:
    if not path.is_relative_to(CANDIDATE):
        raise ValueError('candidate text must remain inside its artifact root')
    path=candidate_path(str(path.relative_to(CANDIDATE)))
    with candidate_data_access():
        if not path.is_file():
            return None
        with path.open('rb') as stream:
            data=stream.read(65_537)
        if len(data)>65_536:
            return None
        try:
            return data.decode('utf-8')
        except UnicodeDecodeError:
            return None


def limits(*, file_bytes: int = 1024 * 1024, cpu: int = 10):
    resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu))
    resource.setrlimit(resource.RLIMIT_FSIZE, (file_bytes, file_bytes))
    resource.setrlimit(resource.RLIMIT_NOFILE, (1024, 1024))


def browser_limits():
    limits(file_bytes=64 * 1024 * 1024, cpu=60)


def measure_source_tree() -> str:
    """Measure the separately mounted source snapshot, never an echoed plan hash.

The external stager must preserve execute bits and use this same inventory
algorithm. Git metadata and separately bound dependency trees are excluded.
Symlink targets are hashed as inert link data and are never followed.
"""
    if not _WORKER_VERIFIED or sys.platform != "linux" or os.geteuid() != 0:
        raise RuntimeError("source measurement requires authenticated isolated worker bootstrap")
    return source_tree_digest(SOURCE)


def run(command: list[str], *, payload: dict | None = None, uid: int = 10003,
        seconds: int = 5) -> dict:
    """Only called after authenticated Linux isolation checks in ``main``."""
    if not _WORKER_VERIFIED or sys.platform != "linux" or os.geteuid() != 0:
        raise RuntimeError("candidate execution requires authenticated isolated worker bootstrap")
    environment = {"PATH": "/usr/bin:/bin", "HOME": "/tmp", "NO_COLOR": "1",
                   "PYTHONNOUSERSITE": "1", "NODE_OPTIONS": "", "NPM_CONFIG_OFFLINE": "true",
                   "NPM_CONFIG_CACHE": "/tmp/npm-cache", "PLAYWRIGHT_BROWSERS_PATH": "/opt/browser/browsers"}
    if uid == 10002:
        environment["DEBUG"] = "pw:browser"
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=stdout, stderr=stderr,
                                   cwd=CANDIDATE, env=environment, user=uid, group=uid, extra_groups=(),
                                   start_new_session=True, preexec_fn=browser_limits if uid == 10002 else limits,
                                   close_fds=True)
        timed_out = False
        try:
            process.communicate(None if payload is None else canonical_json(payload).encode(), timeout=seconds)
        except subprocess.TimeoutExpired:
            timed_out = True
        finally:
            with suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
        stdout.seek(0)
        stderr.seek(0)
        output, error = stdout.read(65_537), stderr.read(65_537)
        if len(output) > 65_536 or len(error) > 65_536:
            return {"exit_code": -1, "timed_out": timed_out, "diagnostic": "output-budget"}
        return {"exit_code": process.returncode, "timed_out": timed_out,
                "pid": process.pid, "candidate_uid": uid,
                "stdout": output.decode("utf-8", errors="replace"),
                "diagnostic": error.decode("utf-8", errors="replace")}


def json_output(result: dict) -> dict:
    if result["exit_code"] != 0 or result["timed_out"]:
        return {}
    try:
        parsed = json.loads(result["stdout"], parse_constant=lambda _: None)
    except ValueError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def invoke_function(task: str) -> dict:
    export, filename = ("sum", "src/sum.js") if task == "fix-failing-node-test" else ("validateUser", "src/user.js")
    module = str(candidate_path(filename))
    observations = {}
    for case in function_cases(task):
        result = run(["/usr/bin/node", str(PUBLIC / "developer_node_bridge.mjs")], payload={
            "module": module, "export": export, "input": case["input"]})
        data = json_output(result)
        if task == "add-validation-dependency":
            value = data.get("value")
            accepted = None
            if data.get("threw") is True:
                accepted = False
            elif type(value) is bool:
                accepted = value
            elif isinstance(value, dict):
                accepted = (value.get("success") if type(value.get("success")) is bool
                            else "name" in value and "email" in value)
            elif value is None and data.get("returned") is True:
                accepted = False
            data = {"accepted": accepted}
        observations[case["id"]] = data
    return observations


def invoke_candidate_tests():
    """Count actual selected child invocations, never a candidate printed count."""
    rows = []
    for selected in discover_tests(SOURCE):
        actual = run(selected['argv'], seconds=2)
        rows.append({**selected, 'pid': actual.get('pid'), 'candidate_uid': actual.get('candidate_uid'),
            'exit_code': actual['exit_code'], 'timed_out': actual['timed_out'],
            'stdout_digest': hashlib.sha256(actual.get('stdout', '').encode()).hexdigest(),
            'stderr_digest': hashlib.sha256(actual.get('diagnostic', '').encode()).hexdigest()})
    return rows


def invoke_cli(bindings: dict) -> dict:
    interface = bindings["cli"]
    command = (["/usr/bin/python3", "-m", interface["script"]] if interface["kind"] == "module"
               else ["/usr/bin/python3", str(candidate_path(interface["script"]))])
    if bindings.get('cli_profile') == 'authored-python-temperature-boundaries':
        command = ['/usr/bin/python3', str(SOURCE / interface['script'])]
    observations = {}
    for case in conversion_cases(bindings.get("cli_profile", "canonical")):
        substitutions = {"{value}": case.get("value", ""), "{from}": case.get("from", ""),
                         "{to}": case.get("to", "")}
        arguments = []
        for argument in interface["arguments"]:
            for token, value in substitutions.items():
                argument = argument.replace(token, value)
            arguments.append(argument)
        if "argv" in case:
            arguments = case["argv"]
        result = run([*command, *arguments])
        parsed = json_output(result)
        if interface["output"] != "json-value-unit" and result["exit_code"] == 0:
            pattern = r"\s*([-+]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][-+]?\d+)?)\s*"
            if interface["output"] == "number-with-unit":
                pattern += r"(?:°\s*)?(C|F|Celsius|Fahrenheit)\s*"
            match = re.fullmatch(pattern, result.get("stdout", ""), re.I)
            parsed = {"value": float(match.group(1)), "unit": match.group(2)
                      if interface["output"] == "number-with-unit" else case.get("to")} if match else {}
        unit = parsed.get("unit")
        unit = {"celsius": "C", "fahrenheit": "F", "c": "C", "f": "F"}.get(str(unit).lower(), unit)
        observations[case["id"]] = {"exit_code": result["exit_code"], "value": parsed.get("value"),
            "unit": unit, "diagnostic": result.get("diagnostic") or result.get("stdout"),
            "argv": arguments, "stdout": result.get("stdout"), "stderr": result.get("diagnostic"),
            "timed_out": result.get("timed_out")}
    return observations


def invoke_report() -> dict:
    successful = True
    for kinds in ([], ["signup", "upgrade", "signup"], ["review", "review", "signup", "done", "review"]):
        events = candidate_path("data/events.json")
        seeded = run(["/usr/bin/python3", "-I", "-c", "import json,sys; from pathlib import Path; "
                      "value=json.loads(sys.stdin.read(65536)); "
                      "Path('data/events.json').write_text(json.dumps(value['events']))"],
                     payload={"events": [{"kind": kind} for kind in kinds]})
        with candidate_data_access():
            events_present=events.is_file()
        if seeded["exit_code"] != 0 or seeded["timed_out"] or not events_present:
            successful = False
            continue
        result = run(["/usr/bin/npm", "run", "report"])
        report = candidate_path("reports/weekly.md")
        observed = {}
        text=candidate_text(report)
        if result["exit_code"] != 0 or result["timed_out"] or text is None:
            successful = False
            continue
        lines = text.splitlines()
        if not lines or lines[0].strip().lower() != "# weekly report":
            successful = False
            continue
        for line in lines[1:]:
            if not line.strip():
                continue
            try:
                name, number = line.removeprefix("- ").rsplit(": ", 1)
                if not line.startswith("- ") or name in observed:
                    raise ValueError("invalid report row")
                observed[name] = int(number)
            except ValueError:
                successful = False
        successful = successful and observed == dict(Counter(kinds))
    return {"report-script-behavior": successful}


def invoke_contribution(bindings: dict) -> dict:
    document = candidate_path("CONTRIBUTING.md")
    text=candidate_text(document)
    if text is None:
        return {"documented-project-commands": False}
    samples = re.findall(r"`([^`\n]+)`", text)
    samples += [line for block in re.findall(r"```[^\n]*\n(.*?)```", text, re.S) for line in block.splitlines()]
    commands = []
    for sample in samples:
        try:
            commands.append(shlex.split(sample.removeprefix("$ ").strip(), comments=True))
        except ValueError:
            continue
    valid = True
    for command in bindings["project_commands"]:
        documented = [Path(command[0]).name, *command[1:]]
        if documented not in commands:
            valid = False
            continue
        result = run(command)
        valid = valid and result["exit_code"] == 0 and result["timed_out"] is False
    return {"documented-project-commands": valid}


def invoke_browser(bindings: dict) -> tuple[dict, dict]:
    """Build candidate as app UID, serve built bytes, drive sandboxed browser UID."""
    def failed(stage, result=None, diagnostic=''):
        result=result or {}
        return {}, {'clean_build':False,'candidate_outcome':'build-failed','build_failure':{
            'stage':stage,'exit_code':result.get('exit_code'),'timed_out':result.get('timed_out',False),
            'diagnostic':(diagnostic or result.get('diagnostic',''))[:4096]}}
    distribution = candidate_path("dist")
    with candidate_data_access():
        exists, directory=distribution.exists(), distribution.is_dir()
    if exists:
        if not directory:
            return failed('distribution-type',diagnostic='candidate dist is not a directory')
        removed=run(['/usr/bin/python3','-I','-c',"import shutil;shutil.rmtree('dist')"])
        if removed['exit_code']!=0 or removed['timed_out']:
            return failed('clean-distribution',removed)
    build = run(["/usr/bin/npm", "run", "build"], seconds=20)
    if build["exit_code"] != 0 or build["timed_out"]:
        return failed('clean-build',build)
    with candidate_data_access():
        if not distribution.is_dir():
            return failed('distribution-missing',build)
        try:
            built_digest = source_tree_digest(distribution, excluded=frozenset())
        except (OSError,ValueError) as error:
            return failed('distribution-unreadable',build,diagnostic=type(error).__name__+': '+str(error))
    with tempfile.TemporaryFile() as output:
        server = subprocess.Popen(["/usr/bin/python3", "-m", "http.server", "4173", "--bind", "127.0.0.1"],
                                  cwd=distribution, user=10003, group=10003, extra_groups=(), close_fds=True,
                                  stdin=subprocess.DEVNULL, stdout=output, stderr=output,
                                  env={"PATH": "/usr/bin:/bin", "HOME": "/tmp", "PYTHONNOUSERSITE": "1"},
                                  start_new_session=True, preexec_fn=limits)
        try:
            for _ in range(100):
                try:
                    connection = http.client.HTTPConnection("127.0.0.1", 4173, timeout=0.1)
                    connection.request("GET", "/")
                    response = connection.getresponse()
                    ready = response.status == 200
                    connection.close()
                    if ready:
                        break
                except OSError:
                    pass
                if server.poll() is not None:
                    output.seek(0)
                    raise RuntimeError("isolated application service exited before browser probe: "
                                       + output.read(4096).decode(errors="replace"))
                time.sleep(0.05)
            else:
                raise RuntimeError("isolated application service did not become ready")
            result = run(["/usr/bin/node", str(PUBLIC / "developer_browser_probe.mjs")],
                         uid=10002, seconds=90, payload={"url": "http://127.0.0.1:4173", "bindings": bindings["todo"]})
            if result["exit_code"] != 0 or result["timed_out"]:
                raise RuntimeError("browser infrastructure failed: " + result.get("diagnostic", ""))
            observations = json_output(result)
            observations["browser_diagnostic"] = result.get("diagnostic", "")
            return observations, {"clean_build": True, "build_exit_code": build["exit_code"],
                                         "built_distribution_digest": built_digest}
        finally:
            # The external collector forcibly destroys the entire container
            # cgroup even when an LSM denies cross-UID signaling here.
            with suppress(ProcessLookupError, PermissionError):
                os.killpg(server.pid, signal.SIGKILL)
            with suppress(subprocess.TimeoutExpired):
                server.wait(timeout=1)


def main(argv=None) -> int:
    global _WORKER_VERIFIED
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("plan", "isolation", "verification-key"):
        parser.add_argument(f"--{name}-fd", type=int, required=True)
    args = parser.parse_args(argv)
    if sys.platform != "linux" or os.geteuid() != 0:
        parser.error("candidate execution requires the declared isolated Linux controller UID")
    if len({args.plan_fd, args.isolation_fd, args.verification_key_fd}) != 3:
        parser.error("bootstrap descriptors must be distinct")
    plan = json.loads(read_pipe(args.plan_fd, 1024 * 1024))
    isolation = json.loads(read_pipe(args.isolation_fd, 1024 * 1024))
    key = read_pipe(args.verification_key_fd, 32)
    worker = verify_worker(isolation, key)
    runtime_identity = {"boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
                        "mount_namespace": os.readlink("/proc/self/ns/mnt"),
                        "pid_namespace": os.readlink("/proc/self/ns/pid"),
                        "network_namespace": os.readlink("/proc/self/ns/net")}
    if worker["runtime_identity"] != runtime_identity:
        raise ValueError("worker is outside its authenticated kernel namespace")
    if worker["assets"] != plan["assets"]:
        raise ValueError("worker assets differ from plan")
    for name, digest in plan["assets"].items():
        if Path(name).name != name or hashlib.sha256((TRUSTED / name).read_bytes()).hexdigest() != digest:
            raise ValueError("trusted probe source changed")
        if ((name.endswith(".mjs") or name == 'developer_unittest_runner.py')
                and hashlib.sha256((PUBLIC / name).read_bytes()).hexdigest() != digest):
            raise ValueError("public client bridge differs from pinned source")
    for module_name in ("ci.gauntlet.benchmark."+Path(name).stem for name in ORACLE_MODULES):
        source = Path(sys.modules[module_name].__file__)
        if hashlib.sha256(source.read_bytes()).hexdigest() != plan["assets"][source.name]:
            raise ValueError("loaded oracle module differs from frozen source")
    if hashlib.sha256(Path(__file__).read_bytes()).hexdigest() != plan["assets"]["developer_worker_probe.py"]:
        raise ValueError("running worker probe differs from frozen source")
    _WORKER_VERIFIED = True
    measured_digest = measure_source_tree()
    if measured_digest != plan["candidate_tree_digest"]:
        raise ValueError("measured source snapshot differs from the captured candidate artifact")
    with candidate_data_access():
        runtime_digest = source_tree_digest(CANDIDATE)
    if runtime_digest != measured_digest:
        raise ValueError("runtime source does not derive from measured frozen artifact")
    dependency_digest = None
    if (SOURCE / "node_modules").is_dir():
        dependency_digest = source_tree_digest(SOURCE / "node_modules", excluded=frozenset())
        with candidate_data_access():
            runtime_dependencies=source_tree_digest(CANDIDATE / "node_modules", excluded=frozenset())
        if dependency_digest != runtime_dependencies:
            raise ValueError("runtime dependencies differ from measured frozen installation")
    if dependency_digest != worker.get("dependency_digest"):
        raise ValueError("actual dependencies differ from externally measured installation")
    task, bindings = plan["workflow_id"], plan["bindings"]
    build_proof = {}
    if task in {"fix-failing-node-test", "add-validation-dependency"}:
        observations = invoke_function(task)
    elif task == "python-cli-with-tests":
        observations = invoke_cli(bindings)
        if bindings.get('cli_profile') == 'authored-python-temperature-boundaries':
            build_proof['agent_test_execution'] = invoke_candidate_tests()
    elif task == "worktree-report-branch":
        observations = invoke_report()
    elif task == "todo-app-to-github":
        observations, build_proof = invoke_browser(bindings)
    elif task == "contributing-pull-request":
        observations = invoke_contribution(bindings)
    else:
        raise ValueError("unknown developer workflow")
    print(canonical_json({"schema": "developer-observations.v1", "workflow_id": task,
                          "runtime_identity": runtime_identity, "candidate_tree_digest": measured_digest,
                          "runtime_tree_digest": runtime_digest, "dependency_digest": dependency_digest,
                          "source_measured": True, "observations": observations, **build_proof}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
