"""Release the real Bun SDK only after its kernel identity is controller bound."""
from __future__ import annotations

import os
import socket
import stat
import struct
import threading
from pathlib import Path

from .native_product_container import process_identity

SDK_SCRIPTS=frozenset({'/runtime/public/developer_omp_episode.ts',
                       '/runtime/public/private_cell_sdk_conformance.ts'})


def observe_sdk(pid, *, bun, agent_identity,script='/runtime/public/developer_omp_episode.ts'):
    if script not in SDK_SCRIPTS:
        raise ValueError('explicit supported SDK entrypoint required')
    actual = process_identity(pid)
    executable = Path(f'/proc/{pid}/exe').stat()
    expected = bun.stat()
    argv = Path(f'/proc/{pid}/cmdline').read_bytes().rstrip(b'\0').split(b'\0')
    if (executable.st_dev, executable.st_ino) != (expected.st_dev, expected.st_ino):
        raise ValueError('ready peer is not the externally frozen Bun executable')
    if argv != [b'/runtime/bun', script.encode(), b'/runtime/public/episode.json']:
        raise ValueError('ready peer differs from the controller-launched SDK command')
    if (actual['effective_uid'] != 10001 or actual['effective_gid'] != 10001
            or actual['effective_capabilities'] != '0000000000000000' or actual['no_new_privileges'] != 1
            or any(actual[field] != agent_identity[field] for field in (
                'boot_id', 'mount_namespace', 'pid_namespace', 'network_namespace'))):
        raise ValueError('ready SDK peer differs from the measured agent boundary')
    return actual


class DeveloperSdkGate:
    def __init__(self, directory, *, bun, product,script='/runtime/public/developer_omp_episode.ts'):
        if script not in SDK_SCRIPTS:
            raise ValueError('explicit supported SDK entrypoint required')
        self.script=script
        self.directory, self.bun, self.product = directory, bun, product
        self.agent_identity = None
        self.bound = threading.Event()
        self.stopped = threading.Event()
        self.observation = None
        self.error = None
        self.thread = None
        self.server = None

    def prepare(self):
        self.directory.mkdir(mode=0o710)
        os.chown(self.directory, 0, 10001)
        self.directory.chmod(0o710)

    def start(self, agent_identity):
        self.agent_identity = agent_identity
        if not self.directory.exists():
            self.prepare()
        info = self.directory.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 10001
                or stat.S_IMODE(info.st_mode) != 0o710):
            raise ValueError('SDK gate directory requires exact controller ownership and agent-group traverse access')
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.bind(str(self.directory / 'ready.sock'))
        os.chmod(self.directory / 'ready.sock', 0o660)
        os.chown(self.directory / 'ready.sock', 0, 10001)
        self.server.listen(1)
        self.server.settimeout(0.2)
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        while not self.stopped.is_set() and not self.bound.is_set():
            try:
                connection, _ = self.server.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            with connection:
                try:
                    connection.settimeout(10)
                    pid, uid, _ = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                    request = b''
                    while len(request) < 128 and not request.endswith(b'\n'):
                        chunk = connection.recv(128 - len(request))
                        if not chunk:
                            break
                        request += chunk
                    if uid != 10001 or request != b'developer-sdk-ready.v1\n':
                        raise ValueError('SDK gate authentication or protocol mismatch')
                    actual = (observe_sdk(pid,bun=self.bun,agent_identity=self.agent_identity)
                        if self.script=='/runtime/public/developer_omp_episode.ts' else
                        observe_sdk(pid,bun=self.bun,agent_identity=self.agent_identity,script=self.script))
                    self.product.bind_sdk(pid, expected_identity=actual)
                    if process_identity(pid) != actual:
                        raise ValueError('SDK identity changed during product binding')
                    self.observation = {'schema': 'developer-sdk-bound.v1', 'pid': pid, 'identity': actual,
                                        'kernel_peer_authenticated': True, 'bound_before_sdk_import': True}
                    connection.sendall(b'developer-sdk-bound.v1\n')
                    self.bound.set()
                except (OSError, ValueError, RuntimeError) as error:
                    self.error = f'{type(error).__name__}: {error}'
                    self.stopped.set()

    def close(self):
        self.stopped.set()
        if self.server is not None:
            self.server.close()
        if self.thread is not None:
            self.thread.join(timeout=11)
            if self.thread.is_alive():
                raise ValueError('SDK ready gate retains an active connection')
        socket_path = self.directory / 'ready.sock'
        if socket_path.exists():
            socket_path.unlink()

    def evidence(self):
        return {'observation': self.observation, 'error': self.error,
                'cleanup_complete': self.stopped.is_set() and (self.thread is None or not self.thread.is_alive())}
