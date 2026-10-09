#!/usr/bin/env python3
"""Install a checksum-pinned nextest into this checkout's CI tool directory."""

import hashlib
import platform
import shutil
import subprocess
import sysconfig
import tarfile
import tempfile
from pathlib import Path
from urllib.request import urlopen

VERSION = "0.9.100"
RELEASE_URL = f"https://github.com/nextest-rs/nextest/releases/download/cargo-nextest-{VERSION}"
# Official release .sha256 manifests at RELEASE_URL/<archive stem>.sha256.
CHECKSUMS = {
    "universal-apple-darwin": "0d8c1fc024a6a72ebe8a76f3db9220f8c01c7247dc3e68747838393bb7adc957",
    "x86_64-unknown-linux-gnu": "de8843f9d4cd72ba7ff3995679536b8a5638ebc8f94848cb988c7549d9dc4e7d",
    "aarch64-unknown-linux-gnu": "53c2e65b61a3736304b3784f1300aaef61fc1538e0b36b7bc7461d4a1c690556",
    "x86_64-unknown-linux-musl": "fbc4f0989a1b58bc23c335f8e1dc656f60efb854246aaa869a88543494e5b0ce",
}


def host_target() -> str:
    system = platform.system()
    machine = {"arm64": "aarch64", "AMD64": "x86_64"}.get(platform.machine(), platform.machine())
    if system == "Darwin" and machine in {"aarch64", "x86_64"}:
        return "universal-apple-darwin"
    if system == "Linux":
        libc = platform.libc_ver()[0]
        # CPython's libc_ver scans GNU symbols and can be empty on musl.
        if libc not in {"glibc", "musl"} and any(
            "musl" in (sysconfig.get_config_var(name) or "") for name in ("HOST_GNU_TYPE", "MULTIARCH")
        ):
            libc = "musl"
        if libc == "glibc":
            target = f"{machine}-unknown-linux-gnu"
        elif libc == "musl":
            target = f"{machine}-unknown-linux-musl"
        else:
            raise RuntimeError(f"unsupported CI Rust tool Linux libc: {libc!r}")
        if target in CHECKSUMS:
            return target
    raise RuntimeError(f"unsupported CI Rust tool host: {system}/{machine}")


def verify_archive(path: Path, checksum: str, name: str) -> None:
    with path.open("rb") as handle:
        digest = hashlib.sha256()
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
        actual = digest.hexdigest()
    if actual != checksum:
        raise RuntimeError(f"{name} archive checksum mismatch: {path} (got {actual})")


def install_archive(
    name: str,
    version: str,
    release_url: str,
    checksums: dict[str, str],
    archive_name: str,
    *,
    version_arguments: tuple[str, ...],
    version_prefix: str,
) -> Path:
    target = host_target()
    root = Path(__file__).resolve().parents[2] / "rust" / "target" / "ci-tools" / f"{name}-{version}" / target
    root.mkdir(parents=True, exist_ok=True)
    archive = root / archive_name.format(target=target, version=version)
    with tempfile.TemporaryDirectory(prefix="install-", dir=root) as temporary:
        temporary = Path(temporary)
        if not archive.exists():
            download = temporary / archive.name
            with urlopen(f"{release_url}/{archive.name}", timeout=60) as response, download.open("wb") as output:
                shutil.copyfileobj(response, output)
            verify_archive(download, checksums[target], name)
            download.replace(archive)
        else:
            verify_archive(archive, checksums[target], name)
        # Extract only the regular executable, never archive paths or links.
        with tarfile.open(archive, "r:gz") as contents:
            members = [member for member in contents.getmembers() if member.name == f"cargo-{name}"]
            if len(members) != 1 or not members[0].isfile():
                raise RuntimeError(f"{name} archive must contain one regular cargo-{name} executable")
            executable = temporary / f"cargo-{name}"
            with contents.extractfile(members[0]) as source, executable.open("wb") as output:
                shutil.copyfileobj(source, output)
        executable.chmod(0o755)
        try:
            reported = subprocess.check_output([str(executable), *version_arguments], text=True, timeout=10).strip()
        except subprocess.TimeoutExpired as error:
            raise RuntimeError(f"{name} --version timed out") from error
        if not reported.startswith(f"{version_prefix} {version} ") and reported != f"{version_prefix} {version}":
            raise RuntimeError(f"unexpected {name} version: {reported}")
        binary_dir = root / "bin"
        binary_dir.mkdir(exist_ok=True)
        executable.replace(binary_dir / f"cargo-{name}")
    return binary_dir


def install() -> Path:
    return install_archive(
        "nextest",
        VERSION,
        RELEASE_URL,
        CHECKSUMS,
        "cargo-nextest-{version}-{target}.tar.gz",
        version_arguments=("nextest", "--version"),
        version_prefix="cargo-nextest",
    )


if __name__ == "__main__":
    print(install())
