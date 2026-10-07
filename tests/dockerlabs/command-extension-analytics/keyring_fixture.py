"""File-backed keyring for the isolated installed dashboard lab."""

import hashlib
import os
from pathlib import Path

from keyring.backend import KeyringBackend
from keyring.errors import PasswordDeleteError


class GuardLabKeyring(KeyringBackend):
    priority = 1
    _root = Path("/guard-home/lab-keyring")

    def _path(self, service, username):
        identity = f"{service}\0{username}".encode()
        return self._root / hashlib.sha256(identity).hexdigest()

    def get_password(self, service, username):
        try:
            return self._path(service, username).read_text(encoding="utf-8")
        except FileNotFoundError:
            return None

    def set_password(self, service, username, password):
        self._root.mkdir(mode=0o700, exist_ok=True)
        path = self._path(service, username)
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(password)

    def delete_password(self, service, username):
        try:
            self._path(service, username).unlink()
        except FileNotFoundError as error:
            raise PasswordDeleteError("credential unavailable") from error
