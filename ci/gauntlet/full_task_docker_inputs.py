"""Build the read-only inputs and the pinned image for container-run full tasks.

Guard comes from one of two sources: a released PyPI version, or a pull-request head whose CI
already built the wheel and the native runtime. Nothing is compiled here.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
DOCKER_DIR = HERE / "docker"
PIN_DIR = REPO / "ci" / "pi-exact-continuation"
PLATFORM = "linux/amd64"
ARM_PLATFORM = "linux/arm64"
ARM_WHEEL_TAG = "manylinux_2_17_aarch64"
SLUG = "hashgraph-online/hol-guard"
GATEWAY_FILES = (
    "full_task_gateway.py",
    "full_task_gateway_policy.py",
    "full_task_graphql.py",
    "full_task_graphql_schema.py",
)
# Where the read-only inputs mount in the agent container; a wheel requirement is a path there.
WHEELHOUSE_MOUNT = "/inputs/wheelhouse"
SHA = re.compile(r"[0-9a-f]{40}")


@dataclass(frozen=True)
class GuardSource:
    """What the container installs, and the build identity the executor must find."""

    label: str
    requirement: str
    expected_sha: str
    runtime: Path | None = None
    platform: str = PLATFORM
    wheel_sha256: str | None = None


def run(args: list[str], *, timeout: float = 600, cwd: Path | None = None) -> str:
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, cwd=cwd)
    if result.returncode != 0:
        raise RuntimeError(f"{args[0]} {args[1] if len(args) > 1 else ''} failed: {result.stderr.strip()[-400:]}")
    return result.stdout.strip()


def image_tag(platform: str = PLATFORM) -> str:
    """A tag derived from everything the image is built from, so a changed pin rebuilds it."""
    digest = hashlib.sha256()
    if platform != PLATFORM:
        digest.update(platform.encode())
    for path in (
        DOCKER_DIR / "Dockerfile",
        DOCKER_DIR / "entrypoint.sh",
        PIN_DIR / "package.json",
        PIN_DIR / "package-lock.json",
    ):
        digest.update(path.read_bytes())
    return "hol-guard-gauntlet-ft:" + digest.hexdigest()[:12]


def ensure_image(platform: str = PLATFORM) -> str:
    tag = image_tag(platform)
    if subprocess.run(["docker", "image", "inspect", tag], capture_output=True).returncode != 0:
        run(
            [
                "docker",
                "build",
                "--platform",
                platform,
                "--build-context",
                f"pin={PIN_DIR}",
                "-t",
                tag,
                str(DOCKER_DIR),
            ],
            timeout=1800,
        )
    return tag


def resolve_release_sha(version: str) -> str:
    """The commit a released version was cut from, read from the public tag."""
    for tag in (f"v{version}", version):
        out = run(["git", "ls-remote", f"https://github.com/{SLUG}.git", f"refs/tags/{tag}", f"refs/tags/{tag}^{{}}"])
        rows = dict(line.split("\t")[::-1] for line in out.splitlines())
        found = rows.get(f"refs/tags/{tag}^{{}}") or rows.get(f"refs/tags/{tag}")
        if found and SHA.fullmatch(found):
            return found
    raise RuntimeError(f"no public tag found for Guard {version}; pass --guard-build-sha")


def download_wheelhouse(
    image: str, spec: str, wheelhouse: Path, *, mount: Path | None = None, platform: str = PLATFORM
) -> None:
    """Fetch the wheel and every dependency for the image platform with a plain, credential-free container."""
    mounts = ["-v", f"{wheelhouse}:/out"] + (["-v", f"{mount}:/in:ro"] if mount else [])
    run(
        [
            "docker",
            "run",
            "--rm",
            "--platform",
            platform,
            *mounts,
            image,
            "pip",
            "download",
            "--quiet",
            "--only-binary=:all:",
            "--dest",
            "/out",
            spec,
        ],
        timeout=900,
    )


def pypi_source(version: str, inputs: Path, image: str, expected_sha: str | None = None) -> GuardSource:
    wheelhouse = inputs / "wheelhouse"
    wheelhouse.mkdir(parents=True)
    download_wheelhouse(image, f"hol-guard=={version}", wheelhouse)
    return GuardSource(f"pypi:{version}", f"hol-guard=={version}", expected_sha or resolve_release_sha(version))


def pr_head_source(sha: str, inputs: Path, image: str) -> GuardSource:
    """The CI wheel and native runtime built from a PR head, downloaded by head SHA."""
    if not SHA.fullmatch(sha):
        raise ValueError("--guard-pr-head needs a full 40-hex commit")
    rows = json.loads(
        run(
            [
                "gh",
                "run",
                "list",
                "--repo",
                SLUG,
                "--workflow",
                "ci.yml",
                "--commit",
                sha,
                "--limit",
                "5",
                "--json",
                "databaseId,conclusion,status",
            ]
        )
    )
    runs = [row for row in rows if row.get("status") == "completed" and row.get("conclusion") == "success"]
    if not runs:
        raise RuntimeError("no successful CI run for that head yet")
    with tempfile.TemporaryDirectory(prefix="ft-artifacts-") as scratch:
        base = Path(scratch)
        run(
            [
                "gh",
                "run",
                "download",
                str(runs[0]["databaseId"]),
                "--repo",
                SLUG,
                "-n",
                "distributions",
                "-D",
                str(base / "dist"),
            ]
        )
        run(
            [
                "gh",
                "run",
                "download",
                str(runs[0]["databaseId"]),
                "--repo",
                SLUG,
                "-n",
                "pytest-native-command-evaluators",
                "-D",
                str(base / "native"),
            ]
        )
        wheels = sorted((base / "dist").rglob("hol_guard-*-py3-none-any.whl"))
        runtime = next(iter((base / "native").rglob("hol-guard-runtime")), None)
        if len(wheels) != 1 or runtime is None:
            raise RuntimeError("expected one hol-guard wheel and one hol-guard-runtime in the CI artifacts")
        wheelhouse = inputs / "wheelhouse"
        wheelhouse.mkdir(parents=True)
        shutil.copy2(wheels[0], wheelhouse / wheels[0].name)
        (inputs / "runtime").mkdir()
        shutil.copy2(runtime, inputs / "runtime" / "hol-guard-runtime")
        # Dependencies only: pip resolves them from the local wheel inside a credential-free container.
        download_wheelhouse(image, f"/in/{wheels[0].name}", wheelhouse, mount=wheelhouse)
    return GuardSource(
        f"pr-head:{sha[:12]}", f"{WHEELHOUSE_MOUNT}/{wheels[0].name}", sha, inputs / "runtime" / "hol-guard-runtime"
    )


def wheel_source(wheel: Path, expected_sha: str, inputs: Path, image: str) -> GuardSource:
    """An externally built arm64 native wheel, checked against the head it must have been built from."""
    if not SHA.fullmatch(expected_sha):
        raise ValueError("--guard-wheel needs --guard-pr-head with the full 40-hex commit it was built from")
    wheel = wheel.resolve()
    if not wheel.is_file() or not wheel.name.endswith(f"-{ARM_WHEEL_TAG}.whl"):
        raise ValueError(f"--guard-wheel must be a {ARM_WHEEL_TAG} hol-guard wheel")
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        manifests = [name for name in names if name.endswith("runtime-manifest.json")]
        runtimes = [name for name in names if name.endswith("/hol-guard-runtime")]
        if len(manifests) != 1 or len(runtimes) != 1:
            raise RuntimeError("the wheel does not carry exactly one native runtime and manifest")
        manifest = json.loads(archive.read(manifests[0]))
        runtime_sha = hashlib.sha256(archive.read(runtimes[0])).hexdigest()
    if manifest.get("source_sha") != expected_sha:
        raise RuntimeError("the wheel's embedded source sha does not match the requested head")
    if manifest.get("platform_tag") != ARM_WHEEL_TAG or manifest.get("runtime_sha256") != runtime_sha:
        raise RuntimeError("the wheel's runtime manifest does not describe its runtime")
    wheelhouse = inputs / "wheelhouse"
    wheelhouse.mkdir(parents=True)
    shutil.copy2(wheel, wheelhouse / wheel.name)
    download_wheelhouse(image, f"/in/{wheel.name}", wheelhouse, mount=wheelhouse, platform=ARM_PLATFORM)
    digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
    return GuardSource(
        f"wheel:{expected_sha[:12]}", f"{WHEELHOUSE_MOUNT}/{wheel.name}", expected_sha, None, ARM_PLATFORM, digest
    )


def write_repo_inputs(inputs: Path) -> None:
    """The checkout under test as a bundle (same HEAD, clean tree) and the gateway modules as a package."""
    run(["git", "bundle", "create", str(inputs / "repo.bundle"), "HEAD"], cwd=REPO)
    package = inputs / "gateway" / "ftgw"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("")
    for name in GATEWAY_FILES:
        shutil.copy2(HERE / name, package / name)
