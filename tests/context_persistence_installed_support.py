"""Bounded disposable process/HTTP/MCP helpers; never print private readiness."""

from __future__ import annotations

import asyncio
import json
import os
import select
import subprocess
import sys
import time
import urllib.error
import urllib.request
from contextlib import asynccontextmanager
from datetime import timedelta
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

REPO = Path(__file__).resolve().parents[1]


class Host:
    def __init__(self, root: Path, generation: int):
        self._errors = (root / f"host-{generation}.stderr.log").open("x")
        self.process = subprocess.Popen(
            [sys.executable, "-B", str(REPO / "scripts/ci/context_persistence_restart_host.py")],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=self._errors,
            text=True,
            env=os.environ.copy(),
        )
        assert self.process.stdin and self.process.stdout
        self.process.stdin.write(json.dumps({"schema": "guard-cigar-restart-fixture.v1", "root": str(root)}) + "\n")
        self.process.stdin.flush()
        if not select.select([self.process.stdout], [], [], 30)[0]:
            self.process.kill()
            self.process.wait(timeout=5)
            raise RuntimeError("isolated daemon readiness timed out; inspect its private stderr artifact")
        line = self.process.stdout.readline(16 * 1024)
        if not line:
            self.process.wait(timeout=5)
            raise RuntimeError("isolated daemon exited before readiness; inspect its private stderr artifact")
        ready = json.loads(line)
        assert ready["schema"] == "guard-cigar-restart-ready.v1"
        assert ready["pid"] == self.process.pid and type(ready["port"]) is int
        self.pid = ready["pid"]
        self.origin = f"http://127.0.0.1:{ready['port']}"
        self._credential = ready["auth_token"]

    def request(self, operation: str = "", payload: dict | None = None) -> tuple[int, dict]:
        data = None if payload is None else json.dumps(payload).encode()
        request = urllib.request.Request(
            self.origin + "/v1/context-assistance" + operation,
            data=data,
            headers={"x-guard-token": self._credential, "content-type": "application/json"},
        )
        try:
            response = urllib.request.urlopen(request, timeout=12)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            return response.status, json.loads(response.read(256 * 1024))

    async def activate(self) -> dict:
        code, _ = self.request("/activate", {})
        assert code == 200
        deadline = time.monotonic() + 70
        while True:
            code, state = self.request()
            assert code == 200
            if state["effective_enabled"]:
                assert state["runtime"]["shared_compile_verified"] is True
                assert state["runtime"]["persistence_compile_verified"] is True
                return state
            assert time.monotonic() < deadline, "actual shared/persistence verification did not become ready"
            assert state["job"] is not None, state["diagnostic"]
            await asyncio.sleep(0.05)

    def stop(self) -> None:
        if self.process.poll() is None:
            assert self.process.stdin
            self.process.stdin.write("stop\n")
            self.process.stdin.flush()
            try:
                self.process.communicate(timeout=15)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.communicate(timeout=5)
                raise RuntimeError("isolated daemon failed to acknowledge shutdown") from None
        self._credential = ""
        self._errors.close()
        assert self.process.returncode == 0


def operator(runtime: Path, command: str, request: dict) -> dict:
    result = subprocess.run(
        [str(runtime), command, "--stdin"], input=json.dumps(request), capture_output=True, text=True, timeout=60
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def stop_resident(runtime: Path, guard_path: Path) -> None:
    result = subprocess.run(
        [str(runtime), "resident-stop", "--state-dir", str(guard_path / "native-runtime")],
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert result.returncode == 0, "native fixture resident containment was not acknowledged"


@asynccontextmanager
async def agent(guard_path: Path):
    parameters = StdioServerParameters(
        command=sys.executable,
        args=[
            "-B",
            str(REPO / "scripts/ci/dashboard_context_agent_probe.py"),
            "--guard-home",
            str(guard_path),
            "--server",
        ],
        env=os.environ.copy(),
    )
    async with stdio_client(parameters) as (read, write), ClientSession(read, write) as client:
        initialized = await client.initialize()
        assert initialized.capabilities.tools and initialized.capabilities.tools.listChanged
        yield client


async def call(client: ClientSession, name: str, arguments: dict | None = None) -> dict:
    result = await client.call_tool(name, arguments or {}, read_timeout_seconds=timedelta(seconds=12))
    assert not result.isError
    return json.loads(result.content[0].text)
