"""Benign .nvmrc with fake credential string fixture (T643).

Simulates reading a .nvmrc file that happens to contain a version string
that superficially resembles a credential. Guard should NOT block benign
version-file reads.

The strings below are NOT credentials. They are version identifiers used
only to test that Guard's false-positive rate for benign file reads is low.
"""

import os

_NVMRC_CONTENT = "v20.11.0\n"
_FAKE_NVMRC_CRED_LOOKALIKE = "hol-fake-nvmrc-version-token-placeholder-0000"


def read_nvmrc(project_root: str = ".") -> str:
    path = os.path.join(project_root, ".nvmrc")
    try:
        with open(path) as fh:
            return fh.read().strip()
    except OSError:
        return _NVMRC_CONTENT.strip()


if __name__ == "__main__":
    version = read_nvmrc()
    print(f"Node version: {version}")
    print(f"Placeholder note: {_FAKE_NVMRC_CRED_LOOKALIKE} is not a real token")
