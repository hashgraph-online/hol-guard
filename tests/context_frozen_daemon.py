"""Own one disposable frozen daemon; read only its public health endpoint."""

from __future__ import annotations

import http.client
import re
import signal
import socket
import subprocess
import time
from pathlib import Path

from scripts.cigar_benchmark_processes import kernel_image


class FrozenDaemon:
    def __init__(self, executable: Path, root: Path, guard: Path, project: Path, environment: dict):
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        self.executable = executable.resolve(strict=True)
        self.output = (root / "frozen-daemon.stdout.log").open("x")
        self.errors = (root / "frozen-daemon.stderr.log").open("x")
        self.fallback_used = False
        self.sent_interrupt = False
        self.process = subprocess.Popen(
            [
                str(executable),
                "daemon",
                "--serve",
                "--guard-home",
                str(guard),
                "--home",
                environment["HOME"],
                "--port",
                str(port),
            ],
            cwd=project,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=self.output,
            stderr=self.errors,
        )
        self.port = port
        self.ready = False

    def wait_ready(self) -> None:
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            assert self.process.poll() is None, "owned frozen daemon exited; inspect its retained stderr"
            connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=0.5)
            try:
                connection.request("GET", "/healthz")
                response = connection.getresponse()
                body = response.read(4097)
                assert len(body) <= 4096
                if response.status == 200:
                    assert kernel_image(self.process.pid) == self.executable
                    self.ready = True
                    return
            except (OSError, http.client.HTTPException):
                pass
            finally:
                connection.close()
            time.sleep(0.05)
        raise AssertionError("owned frozen daemon did not reach its public health endpoint")

    def stop(self) -> int:
        try:
            if self.process.poll() is None:
                assert kernel_image(self.process.pid) == self.executable
                self.process.send_signal(signal.SIGINT)
                self.sent_interrupt = True
                try:
                    self.process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    assert kernel_image(self.process.pid) == self.executable
                    self.fallback_used = True
                    self.process.kill()
                    self.process.wait(timeout=5)
            return self.process.returncode
        finally:
            self.output.close()
            self.errors.close()

    def exit_metadata(self) -> dict:
        body = Path(self.errors.name).read_text()
        exception_types = re.findall(
            r"^([A-Za-z_][A-Za-z0-9_.]*(?:Error|Exception|ExceptionGroup)|KeyboardInterrupt|SystemExit)(?::|$)",
            body,
            re.MULTILINE,
        )
        frames = re.findall(r'\s*File "([^"]+)", line [0-9]+, in ([A-Za-z0-9_<>.]+)', body)
        tail = [(Path(path).name, function) for path, function in frames[-3:]]
        expected_interrupt = (
            self.sent_interrupt
            and self.process.returncode == 1
            and exception_types == ["KeyboardInterrupt"]
            and body.count("Traceback (most recent call last):") == 1
            and tail == [("server.py", "serve"), ("threading.py", "join"), ("threading.py", "_wait_for_tstate_lock")]
            and "Failed to execute script 'hol-guard-entry' due to unhandled exception" in body
        )
        return {
            "returncode": self.process.returncode,
            "requested_signal": "SIGINT" if self.sent_interrupt else None,
            "fallback_used": self.fallback_used,
            "exception_types": exception_types,
            "expected_join_interrupt": expected_interrupt,
            "graceful_zero_exit": self.process.returncode == 0,
        }
