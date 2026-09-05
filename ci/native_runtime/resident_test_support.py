from __future__ import annotations

import os
import sys
from pathlib import Path


def process_is_alive(process_id: int) -> bool:
    if os.name == "nt":
        from codex_plugin_scanner.guard.windows_paths import windows_process_is_running

        return windows_process_is_running(process_id)
    try:
        os.kill(process_id, 0)
    except ProcessLookupError:
        return False
    return True


def fake_runtime(path: Path) -> Path:
    executable = path / "fake-native-runtime"
    executable.write_text(
        f"""#!{sys.executable}
import hashlib
import hmac
import socket
import sys
import tempfile

REQUEST_MAGIC = b'HGR2'
RESPONSE_MAGIC = b'HGS2'
SERVER_LABEL = b'hol-guard-resident-server-v1\\x00'
CLIENT_LABEL = b'hol-guard-resident-client-v1\\x00'
HEADER_BYTES = 72

def read_exact(client, length):
    chunks = []
    while length:
        chunk = client.recv(length)
        if not chunk:
            return None
        chunks.append(chunk)
        length -= len(chunk)
    return b''.join(chunks)

token = bytes.fromhex(sys.stdin.readline().strip())
assert len(token) == 32
socket_path = sys.argv[3]
server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
server.bind(socket_path)
server.listen(8)
while True:
    client, _ = server.accept()
    with client:
        client.settimeout(1.0)
        nonce = read_exact(client, 32)
        if nonce is None:
            continue
        client.sendall(hmac.new(token, SERVER_LABEL + nonce, hashlib.sha256).digest())
        proof = read_exact(client, 32)
        expected = hmac.new(token, CLIENT_LABEL + nonce, hashlib.sha256).digest()
        if proof is None or not hmac.compare_digest(proof, expected):
            continue
        header = read_exact(client, HEADER_BYTES)
        if header is None or header[:4] != REQUEST_MAGIC:
            continue
        request_id = header[4:36]
        request_digest = header[36:68]
        length = int.from_bytes(header[68:72], 'big')
        request = read_exact(client, length)
        if request is None or hashlib.sha256(request).digest() != request_digest:
            continue
        if request == b'{{"operation":"health","request":{{}}}}':
            response = b'{{"status":"ready","protocol_version":2}}'
        else:
            response = (
                b'{{"decision":"allow","model_output_action":'
                b'"allow_original","notice":"none",'
                b'"reason_code":"ok"}}'
            )
        response_header = (
            RESPONSE_MAGIC
            + request_id
            + hashlib.sha256(response).digest()
            + len(response).to_bytes(4, 'big')
        )
        client.sendall(response_header + response)
""",
        encoding="utf-8",
    )
    executable.chmod(0o700)
    return executable


def socket_replacing_fake_runtime(path: Path, starts_path: Path) -> Path:
    executable = path / "fake-native-runtime-race"
    executable.write_text(
        fake_runtime(path)
        .read_text(encoding="utf-8")
        .replace(
            "server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\nserver.bind(socket_path)",
            (
                f"with open({str(starts_path)!r}, 'a', encoding='utf-8') as starts:\n"
                "    starts.write(str(os.getpid()) + '\\n')\n"
                "try:\n"
                "    os.unlink(socket_path)\n"
                "except FileNotFoundError:\n"
                "    pass\n"
                "server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n"
                "server.bind(socket_path)"
            ),
        )
        .replace("import hmac\n", "import hmac\nimport os\n"),
        encoding="utf-8",
    )
    executable.chmod(0o700)
    return executable
