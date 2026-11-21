"""Turn CIGAR on in the rig's own Guard home, in the one-click order, and wait until it is ready.

Run with the rig venv's python and HOME set to the rig Guard home:
    HOME=$W/ghome $W/gvenv/bin/python -I cigar_setup.py <work dir>
Installs Guard's Codex hooks into <work>/ghome/.codex/config.toml (make_arms.py copies the prompt hook
from there), selects the CIGAR engine built into Guard, saves the
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
exe = str(work / ("gvenv/Scripts/hol-guard.exe" if os.name == "nt" else "gvenv/bin/hol-guard"))
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
    try:
        from codex_plugin_scanner.guard.native_daemon_client import load_guard_surface_daemon_client
    except ImportError:  # published wheels keep it in the daemon package
        from codex_plugin_scanner.guard.daemon.client import load_guard_surface_daemon_client

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


from codex_plugin_scanner.guard.harness_context import HarnessContext  # noqa: E402
from codex_plugin_scanner.guard.native_harness_install_ops import install as install_harness  # noqa: E402
from codex_plugin_scanner.guard.native_owned import owner_request  # noqa: E402

guard.mkdir(parents=True, exist_ok=True)
# Installing hooks asks the resident daemon, so start it first on a fresh home.
subprocess.run([exe, "daemon", "ensure", "--guard-home", str(guard)], env=env, capture_output=True, timeout=300)
install_harness(
    "codex",
    HarnessContext(home_dir=home, workspace_dir=None, guard_home=guard),
    owner=owner_request(guard, actor="adapter.codex.adapter_install"),
)
log("codex hooks installed in rig home")
subprocess.run([exe, "daemon", "ensure", "--guard-home", str(guard)], env=env, capture_output=True, timeout=300)
if ctx("status").get("requested_enabled") is not True:
    job = f"cli:{uuid.uuid4()}"
    ctx("switch", "builtin", "--job-id", job, "--generation", str(ctx("status").get("generation")))
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
