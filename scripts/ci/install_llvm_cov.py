#!/usr/bin/env python3
"""Install checksum-pinned LLVM coverage without compiling its CLI from source."""

from scripts.ci.install_nextest import install_archive

VERSION = "0.6.21"
RELEASE_URL = f"https://github.com/taiki-e/cargo-llvm-cov/releases/download/v{VERSION}"
# Release API digests checked against the downloaded v0.6.21 archives.
CHECKSUMS = {
    "universal-apple-darwin": "0d4ee4f40ecb30b3379f44887555b38b91b577aa2943568a6af0025b91147056",
    "x86_64-unknown-linux-gnu": "57f491aedf7cdb261538ceb49cbb1ee9d27df7ca205a5e1a009caaf5cb911afb",
    "aarch64-unknown-linux-gnu": "8187c40fa3cbef6fe65e426bee24ddcfefee943dc68bdb0617f0293a092941af",
    "x86_64-unknown-linux-musl": "0fa9ac9953583fa993786b529ce9c828a2e548ee9d183f5e908a357157d030f0",
}


def install():
    return install_archive(
        "llvm-cov",
        VERSION,
        RELEASE_URL,
        CHECKSUMS,
        "cargo-llvm-cov-{target}.tar.gz",
        version_arguments=("llvm-cov", "--version"),
        version_prefix="cargo-llvm-cov",
    )


if __name__ == "__main__":
    print(install())
