"""Transport native index output; contains no selection or index algorithm."""

from __future__ import annotations

import base64
import json
import subprocess
import tempfile
import threading


def exchange(compiler, operation, records, directory, *, fetch=None, archive=None):
    from ..catalog_delivery.pack_store import publish_object
    from .native_source_compiler import NativeSourceCompilerError

    directory.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryFile() as errors:
        process = subprocess.Popen(
            [str(compiler), operation], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=errors
        )
        timer = threading.Timer(120, process.kill)
        timer.start()
        try:
            assert process.stdin is not None and process.stdout is not None
            input_stream = process.stdin

            def send(value):
                input_stream.write(json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode() + b"\n")
                input_stream.flush()

            failures = []

            def feed():
                try:
                    for record in records:
                        send(record)
                except (OSError, ValueError) as exc:
                    failures.append(exc)

            feeder = threading.Thread(target=feed)
            feeder.start()
            result = None
            payloads = []
            for _ in range(600_000):
                line = process.stdout.readline(64 * 1024 * 1024 + 1)
                if not line:
                    break
                if len(line) > 64 * 1024 * 1024 or not line.endswith(b"\n"):
                    raise ValueError("native authoring output exceeds record budget")
                row = json.loads(line)
                kind = row.get("kind")
                if kind == "fetch" and fetch is not None:
                    send({"data": base64.b64encode(fetch(row["reference"])).decode()})
                elif kind == "archive" and archive is not None:
                    archive(row["reference"])
                    send({"ok": True})
                elif kind == "object":
                    data = base64.b64decode(row["data"], validate=True)
                    if len(data) > 64 * 1024:
                        raise ValueError("native authoring object exceeds budget")
                    publish_object(directory, row["sha256"], data)
                elif kind == "compatibility-record":
                    payloads.append(row["payload"])
                elif kind in {"context", "index", "admission", "compatibility"}:
                    result = row
                    if kind == "compatibility":
                        result["payloads"] = payloads
                    break
                else:
                    raise NativeSourceCompilerError(
                        "native authoring failed: " + str(row.get("code", "invalid response")), code=row.get("code")
                    )
            feeder.join(timeout=1)
            if failures:
                raise failures[0]
            if result is None:
                raise ValueError("native authoring context is incomplete")
            process.stdin.close()
            if process.wait(timeout=10) != 0:
                raise ValueError("native authoring compiler failed")
            for path in directory.iterdir():
                path.chmod(0o400)
            if "metadata_index" in result:
                result["metadata_index"]["directory"] = str(directory.resolve())
            return result
        finally:
            timer.cancel()
            if process.poll() is None:
                process.kill()
            process.wait()
            if process.stdin and not process.stdin.closed:
                process.stdin.close()
            if process.stdout:
                process.stdout.close()
