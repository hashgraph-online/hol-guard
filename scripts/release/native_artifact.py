"""Retain bounded stable-release inputs outside the evictable compiler cache.

Artifacts are only a transport: exact build identity, both executable hashes,
enrollment checks and native self-tests remain mandatory in the caller.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import stat
import subprocess
import tempfile
import urllib.parse
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from scripts.release.prepared_native import verify

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib  # type: ignore[no-redef]

WORKFLOW = ".github/workflows/release-native-prepare.yml"
PREFIX = "release-native-warm-"
MAX_ARTIFACT_BYTES = 128 * 1024 * 1024
MAX_WARM_BYTES = 5 * MAX_ARTIFACT_BYTES
# Stored ZIP entries add names, headers and a central directory, not a second
# copy of the binaries. This reserve exceeds the overhead for our three files.
ZIP_RESERVE = 64 * 1024
TARGETS = {
    "x86_64-unknown-linux-musl",
    "x86_64-apple-darwin",
    "aarch64-apple-darwin",
    "x86_64-pc-windows-msvc",
    "aarch64-pc-windows-msvc",
}


class RetentionDeniedError(ValueError):
    """A fixed resource policy declined a new retained artifact."""


class SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urllib.parse.urlparse(newurl).scheme != "https":
            raise ValueError("artifact redirect must use HTTPS")
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if redirected is not None:
            redirected.remove_header("Authorization")
        return redirected


class API:
    def __init__(self):
        self.repo = os.environ["GITHUB_REPOSITORY"]
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", self.repo):
            raise ValueError("invalid repository")
        self.opener = urllib.request.build_opener(SafeRedirect())

    def read(self, route: str, limit: int) -> bytes:
        request = urllib.request.Request(
            f"https://api.github.com/repos/{self.repo}/{route}",
            headers={
                "Authorization": f"Bearer {os.environ['GITHUB_TOKEN']}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        with self.opener.open(request, timeout=30) as response:
            data = response.read(limit + 1)
        if len(data) > limit:
            raise ValueError("API response exceeds size bound")
        return data

    def get(self, route: str) -> dict:
        return json.loads(self.read(route, 2 * 1024 * 1024))


def timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def names() -> set[str]:
    return {"identity.json", Path(os.environ["RUNTIME"]).name, Path(os.environ["SOURCE_COMPILER"]).name}


def stable_version_change() -> bool:
    if (
        os.environ.get("GITHUB_EVENT_NAME") != "push"
        or os.environ.get("GITHUB_REF") != "refs/heads/main"
        or os.environ.get("FAST_CODEGEN") != "false"
        or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", os.environ["VERSION"])
    ):
        return False
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    if head != os.environ["SOURCE_SHA"]:
        raise ValueError("source checkout mismatch")
    current = tomllib.loads(Path("pyproject.toml").read_text())["project"]["version"]
    previous = tomllib.loads(subprocess.check_output(["git", "show", "HEAD^1:pyproject.toml"], text=True))["project"][
        "version"
    ]
    return current == os.environ["VERSION"] and current != previous


def upload_allowed(api: API, directory: Path) -> bool:
    if not stable_version_change():
        return False
    verify(directory)
    entries = list(directory.iterdir())
    if {entry.name for entry in entries} != names() or any(not p.is_file() or p.is_symlink() for p in entries):
        raise ValueError("unexpected prepared artifact files")
    if sum(entry.stat().st_size for entry in entries) + ZIP_RESERVE > MAX_ARTIFACT_BYTES:
        raise RetentionDeniedError("prepared artifact exceeds 128 MiB ceiling")
    # The feature reservation concerns only these five names, independently of
    # unrelated CI artifacts. A repository allocation additionally needs a full
    # bounded inventory; an incomplete or changing snapshot cannot admit storage.
    warm_bytes = 0
    for target in sorted(TARGETS):
        name = PREFIX + target
        listing = api.get(f"actions/artifacts?name={name}&per_page=100")
        artifacts = listing["artifacts"]
        if (
            listing["total_count"] > 100
            or len(artifacts) != listing["total_count"]
            or any(artifact["name"] != name for artifact in artifacts)
        ):
            raise RetentionDeniedError("warm artifact family exceeds bounded admission scan")
        warm_bytes += retained_bytes(artifacts)
    if warm_bytes + MAX_WARM_BYTES > MAX_WARM_BYTES:
        raise RetentionDeniedError("retained warm artifacts consume the 640 MiB admission budget")
    budget = os.environ.get("RELEASE_NATIVE_ARTIFACT_BUDGET_BYTES", "")
    if budget and repository_artifact_bytes(api) + MAX_WARM_BYTES > int(budget):
        raise RetentionDeniedError("repository artifact budget cannot admit a warm run")
    return True


def retained_bytes(artifacts: list[dict]) -> int:
    return sum(
        artifact["size_in_bytes"]
        for artifact in artifacts
        if not artifact["expired"] and artifact["workflow_run"]["id"] != int(os.environ["GITHUB_RUN_ID"])
    )


def repository_artifact_bytes(api: API) -> int:
    artifacts = {}
    expected_count = None
    for page in range(1, 11):
        listing = api.get(f"actions/artifacts?per_page=100&page={page}")
        count = listing["total_count"]
        if count > 1000 or (expected_count is not None and count != expected_count):
            raise RetentionDeniedError("repository artifact inventory exceeds bound or changed during admission")
        expected_count = count
        for artifact in listing["artifacts"]:
            if artifact["id"] in artifacts:
                raise RetentionDeniedError("repository artifact inventory changed during admission")
            artifacts[artifact["id"]] = artifact
        if page * 100 >= count:
            break
    if len(artifacts) != expected_count:
        raise RetentionDeniedError("repository artifact inventory is incomplete")
    return retained_bytes(list(artifacts.values()))


def trusted_artifact(api: API) -> dict:
    source = os.environ["SOURCE_SHA"]
    target = os.environ["RUST_TARGET"]
    if (
        target not in TARGETS
        or not re.fullmatch(r"[0-9a-f]{40}", source)
        or os.environ["GITHUB_SHA"] != source
        or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", os.environ["VERSION"])
        or os.environ.get("FAST_CODEGEN") != "false"
        or os.environ.get("GITHUB_EVENT_NAME") != "workflow_dispatch"
        or os.environ.get("GITHUB_REF") != f"refs/tags/v{os.environ['VERSION']}"
        or not re.fullmatch(r"[0-9a-f]{64}", os.environ["PREPARED_NATIVE_BUILD_ID"])
    ):
        raise ValueError("artifact reuse requires an exact stable tag build")
    workflow = api.get("actions/workflows/release-native-prepare.yml")
    if workflow["path"] != WORKFLOW:
        raise ValueError("unexpected preparation workflow")
    listing = api.get(f"actions/workflows/{workflow['id']}/runs?event=push&branch=main&head_sha={source}&per_page=10")
    if listing["total_count"] > 10:
        raise ValueError("ambiguous preparation run inventory")
    candidates = []
    for run in listing["workflow_runs"]:
        if not (
            run["workflow_id"] == workflow["id"]
            and run["path"] == WORKFLOW
            and run["event"] == "push"
            and run["head_branch"] == "main"
            and run["head_sha"] == source
            and run["repository"]["full_name"] == api.repo
            and run["repository"]["id"] == int(os.environ["GITHUB_REPOSITORY_ID"])
            and run["head_repository"]["id"] == run["repository"]["id"]
        ):
            continue
        attempt = run["run_attempt"]
        jobs = api.get(f"actions/runs/{run['id']}/attempts/{attempt}/jobs?per_page=100")
        if jobs["total_count"] > 100:
            continue
        compile_name = f"Compile release ({target})"
        job_names = {compile_name, f"Prepare native release binaries ({target}) / {compile_name}"}
        matching = [job for job in jobs["jobs"] if job["name"] in job_names]
        if len(matching) != 1:
            continue
        job = matching[0]
        if not (
            job["run_id"] == run["id"]
            and job["run_attempt"] == attempt
            and job["head_sha"] == source
            and job["status"] == "completed"
            and job["conclusion"] == "success"
        ):
            continue
        artifacts = api.get(f"actions/runs/{run['id']}/artifacts?per_page=100")
        if artifacts["total_count"] > 100:
            continue
        matches = [a for a in artifacts["artifacts"] if a["name"] == PREFIX + target]
        if len(matches) != 1:
            continue
        artifact = matches[0]
        origin = artifact["workflow_run"]
        if (
            not artifact["expired"]
            and isinstance(artifact["id"], int)
            and artifact["id"] > 0
            and timestamp(artifact["expires_at"]) > datetime.now(timezone.utc)
            and timestamp(job["started_at"]) <= timestamp(artifact["created_at"]) <= timestamp(job["completed_at"])
            and origin["id"] == run["id"]
            and origin["repository_id"] == run["repository"]["id"]
            and origin["head_repository_id"] == run["repository"]["id"]
            and origin["head_branch"] == "main"
            and origin["head_sha"] == source
            and 0 < artifact["size_in_bytes"] <= MAX_ARTIFACT_BYTES
            and re.fullmatch(r"sha256:[0-9a-f]{64}", artifact.get("digest", ""))
        ):
            candidates.append(artifact)
    if len(candidates) != 1:
        raise ValueError("no unique successful target preparation artifact")
    return candidates[0]


def extract(data: bytes, directory: Path) -> None:
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        entries = archive.infolist()
        if len(entries) != 3 or {entry.filename for entry in entries} != names():
            raise ValueError("artifact must contain exactly the three flat prepared files")
        if sum(entry.file_size for entry in entries) > MAX_ARTIFACT_BYTES - ZIP_RESERVE:
            raise ValueError("artifact expands beyond size ceiling")
        for entry in entries:
            mode = entry.external_attr >> 16
            if (
                entry.flag_bits & 1
                or entry.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                or (stat.S_IFMT(mode) not in (0, stat.S_IFREG))
            ):
                raise ValueError("unsupported archive entry")
            with archive.open(entry) as source, (directory / entry.filename).open("xb") as destination:
                remaining = entry.file_size
                while chunk := source.read(min(1024 * 1024, remaining + 1)):
                    remaining -= len(chunk)
                    if remaining < 0:
                        raise ValueError("artifact entry exceeds declared size")
                    destination.write(chunk)
                if remaining:
                    raise ValueError("truncated artifact entry")


def restore(api: API, directory: Path) -> bool:
    artifact = trusted_artifact(api)
    data = api.read(f"actions/artifacts/{artifact['id']}/zip", MAX_ARTIFACT_BYTES)
    if len(data) != artifact["size_in_bytes"] or "sha256:" + hashlib.sha256(data).hexdigest() != artifact["digest"]:
        raise ValueError("artifact API digest/size mismatch")
    with tempfile.TemporaryDirectory(prefix="native-artifact-", dir=directory.parent) as temporary:
        staged = Path(temporary) / "prepared"
        staged.mkdir()
        extract(data, staged)
        verify(staged)
        staged.rename(directory)
    print("Verified prepared artifact from its successful trusted target job")
    return True


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("admit-upload", "restore"))
    parser.add_argument("--directory", type=Path, default=Path("prepared-native"))
    args = parser.parse_args()
    accepted = False
    try:
        api = API()
        accepted = (
            upload_allowed(api, args.directory) if args.action == "admit-upload" else restore(api, args.directory)
        )
    except Exception as error:
        # Do not expose response bodies/URLs/tokens; every refusal compiles normally.
        reason = str(error) if isinstance(error, RetentionDeniedError) else type(error).__name__
        print(f"Prepared artifact unavailable ({reason}); using normal compilation/retention")
    with Path(os.environ["GITHUB_OUTPUT"]).open("a") as output:
        output.write(f"accepted={str(accepted).lower()}\n")


if __name__ == "__main__":
    main()
