"""Turn CIGAR on in the rig's own Guard home, in the one-click order, and wait until it is ready.

Run with the rig venv's python and HOME set to the rig Guard home:
    HOME=$W/ghome $W/gvenv/bin/python -I cigar_setup.py <work dir>
Installs Guard's Codex hooks into <work>/ghome/.codex/config.toml (make_arms.py copies the prompt hook
from there), sets up the private Python and the CIGAR runtime from the signed catalog, saves the
preferences and activates. Touches nothing outside <work>.
"""

import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

work = Path(sys.argv[1]).resolve()
home = work / "ghome"
guard = home / ".hol-guard"
exe = str(work / "gvenv/bin/hol-guard")
assert Path(os.environ.get("HOME", "")).resolve() == home, "run with HOME=<work>/ghome"
env = dict(os.environ, HOME=str(home), USERPROFILE=str(home))


def log(*parts):
    print(*parts, flush=True)


def ctx(*args):
    out = subprocess.run(
        [exe, "context", *args, "--guard-home", str(guard), "--json"],
        env=env,
        capture_output=True,
        text=True,
        timeout=900,
    )
    try:
        return json.loads(out.stdout)
    except json.JSONDecodeError:
        log("bad json from context", args[0], out.stdout[-300:], out.stderr[-300:])
        sys.exit(1)


def wait_job(job, field):
    deadline = time.monotonic() + 900
    while time.monotonic() < deadline:
        result = ctx("job", job).get("result") or {}
        if result.get("phase") in ("ready", "completed"):
            return result.get(field)
        if result.get("phase") in ("failed", "cancelled", "blocked"):
            log("job", job, result.get("phase"), result.get("code"))
            sys.exit(1)
        time.sleep(2)
    log("timeout", job)
    sys.exit(1)


def post(url, body, session):
    request = urllib.request.Request(
        url,
        data=json.dumps(body).encode(),
        method="POST",
        headers={"X-Guard-Dashboard-Session": session, "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            return json.loads(response.read())
    except urllib.error.HTTPError as error:
        return {"http": error.code}


def dash(path, body):
    from codex_plugin_scanner.guard.local_dashboard_session import build_local_dashboard_session_token
    from codex_plugin_scanner.guard.native_daemon_client import load_guard_surface_daemon_client

    client = load_guard_surface_daemon_client(guard)
    seed = build_local_dashboard_session_token(auth_token=client.auth_token, surface="dashboard")
    init = post(
        f"{client.daemon_url}/v1/initialize",
        {
            "client_name": "guard-dashboard-web",
            "surface": "dashboard",
            "supported_protocol_versions": ["1.1", "1.0"],
        },
        seed,
    )
    if "dashboard_session_token" not in init:
        log("dashboard initialize failed", init)
        sys.exit(1)
    return post(f"{client.daemon_url}{path}", body, init["dashboard_session_token"])


def builds():
    found = set()

    def walk(o):
        if isinstance(o, dict):
            if "build_id" in o:
                found.add(o["build_id"])
            for v in o.values():
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)

    walk(ctx("versions"))
    return found


from codex_plugin_scanner.guard.adapters.base import HarnessContext  # noqa: E402
from codex_plugin_scanner.guard.adapters.codex import CodexHarnessAdapter  # noqa: E402

guard.mkdir(parents=True, exist_ok=True)
CodexHarnessAdapter().install(HarnessContext(home_dir=home, workspace_dir=None, guard_home=guard))
log("codex hooks installed in rig home")
subprocess.run([exe, "daemon", "ensure", "--guard-home", str(guard)], env=env, capture_output=True, timeout=300)
if ctx("status").get("requested_enabled") is not True:
    ids = builds()
    machine = "darwin-arm64" if os.uname().machine == "arm64" else "darwin-x64"
    py = sorted(b for b in ids if b.startswith("cpython-") and b.endswith(machine))[-1]
    cigar = sorted(b for b in ids if b.startswith("cigar-"))[-1]
    log("builds", py, cigar)
    job = f"cli:{uuid.uuid4()}"
    ctx("setup-python", py, "--job-id", job)
    interp = wait_job(job, "interpreter_id")
    job = f"cli:{uuid.uuid4()}"
    ctx("install", cigar, "--job-id", job, "--interpreter-id", interp)
    runtime = wait_job(job, "runtime_id")
    job = f"cli:{uuid.uuid4()}"
    ctx("switch", runtime, "--job-id", job, "--generation", str(ctx("status").get("generation")))
    expected = wait_job(job, "expected_generation")
    ctx("commit", job, "--generation", str(expected))
    wait_job(job, "phase")
    prefs = ctx("status")["preferences"]
    prefs.update(enabled=True)
    prefs["sources"].update(workspace_documents=True, source_set_id="selected-workspaces")
    prefs["features"].update(agent_context=True)
    log("preferences saved", "http" not in dash("/v1/settings", {"settings": {"context_assistance": prefs}}))
    dash("/v1/context-assistance/activate", {})
status = {}
for _ in range(60):
    status = ctx("status")
    if status.get("availability") == "ready" or status.get("diagnostic") == "runtime_resting":
        break
    time.sleep(3)
log("cigar", status.get("availability"), status.get("diagnostic"), "requested", status.get("requested_enabled"))
# requested_enabled is only the saved setting; the arm is ready only once CIGAR actually runs.
running = status.get("availability") == "ready" or status.get("diagnostic") == "runtime_resting"
sys.exit(0 if status.get("requested_enabled") and running else 1)
