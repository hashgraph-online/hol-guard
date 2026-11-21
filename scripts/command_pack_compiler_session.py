"""Process-local native compilation reuse; accepts no serialized cache input."""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from contextlib import ExitStack, contextmanager, suppress
from pathlib import Path
from threading import Lock, get_ident


class PackCompilerSession:
    """Own one compiler process and discard every cached value on close."""

    def __init__(self, compiler: Path):
        self.compiler = compiler.resolve()
        self.resources = ExitStack()
        self.errors = self.resources.enter_context(tempfile.TemporaryFile())  # noqa: SIM115 - owned by ExitStack
        self.closed = False
        self.request_lock = Lock()
        self.request_owner = None
        try:
            self.process = subprocess.Popen(
                [str(self.compiler), "compile-packs-session"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=self.errors,
            )
        except BaseException:
            self.resources.close()
            raise

    @contextmanager
    def request(self):
        if not self.request_lock.acquire(blocking=False):
            raise ValueError("native compiler session already has a request in progress")
        self.request_owner = get_ident()
        try:
            if self.closed:
                raise ValueError("native compiler session is closed")
            yield
        except BaseException:
            self.close()
            raise
        finally:
            self.request_owner = None
            self.request_lock.release()

    def submit(self, compiler: Path, source):
        if self.request_owner != get_ident():
            raise ValueError("native compiler session requires an exclusive request")
        if self.closed or compiler.resolve() != self.compiler or self.process.poll() is not None:
            raise ValueError("native compiler session is unavailable or differs")
        source.seek(0, 2)
        length = source.tell()
        source.seek(0)
        assert self.process.stdin is not None
        try:
            self.process.stdin.write(length.to_bytes(8, "big"))
            shutil.copyfileobj(source, self.process.stdin, length=64 * 1024)
            self.process.stdin.flush()
        except BrokenPipeError as error:
            code = "command_pack_session_write_failed"
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
            else:
                assert self.process.stdout is not None
                line = self.process.stdout.readline(4097)
                try:
                    result = json.loads(line) if len(line) <= 4096 else None
                except (ValueError, UnicodeDecodeError):
                    result = None
                if isinstance(result, dict) and isinstance(result.get("code"), str):
                    code = result["code"][:256]
            raise ValueError(f"native compiler session failed: {code}; {self.error()}") from error
        return self.process

    def error(self) -> str:
        self.errors.seek(0)
        return self.errors.read(2048).decode(errors="replace")

    def close(self):
        if self.request_owner is not None and self.request_owner != get_ident():
            raise ValueError("native compiler session has a request in progress")
        if self.closed:
            return
        self.closed = True
        if self.process.stdin is not None:
            with suppress(BrokenPipeError):
                self.process.stdin.close()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
        if self.process.stdout is not None:
            self.process.stdout.close()
        self.resources.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
