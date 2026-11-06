from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class Registry(str, Enum):
    PYPI = "pypi"
    TESTPYPI = "testpypi"

    @property
    def api_host(self) -> str:
        return "pypi.org" if self is Registry.PYPI else "test.pypi.org"

    @property
    def file_host(self) -> str:
        return "files.pythonhosted.org" if self is Registry.PYPI else "test-files.pythonhosted.org"


class RegistryVerificationError(RuntimeError):
    pass


@dataclass(frozen=True)
class ReleaseFile:
    filename: str
    sha256: str
    download_url: str


@dataclass(frozen=True)
class ReleaseInspection:
    registry: Registry
    version: str
    exists: bool
    files: tuple[ReleaseFile, ...] = ()

    @property
    def digests(self) -> dict[str, str]:
        return {item.filename: item.sha256 for item in self.files}


@dataclass(frozen=True)
class RegistryResult:
    registry: Registry
    status: str
    version: str
    files: tuple[str, ...]
    downloaded_paths: tuple[Path, ...] = ()


TestPyPIResult = RegistryResult
