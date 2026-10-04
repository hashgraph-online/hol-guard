"""Tests for data-only PR gating and safe evidence transport."""

from __future__ import annotations

import hashlib
import io
import json
import stat
import zipfile

import pytest

from ci.gauntlet.bundle import download, pack, unpack
from ci.gauntlet.github_ci import initialize_gate, requires_gauntlet
from ci.gauntlet.source_identity import validate_identity


@pytest.mark.parametrize(
    "path",
    [
        "rust/crates/guard-command/src/pretool.rs",
        "src/codex_plugin_scanner/guard/adapters/pi_extension_source.py",
        "contracts/guard-hooks.json",
        "ci/gauntlet/evidence.py",
        ".github/workflows/guard-gauntlet-evidence.yml",
        "uv.lock",
    ],
)
def test_enforcement_and_qualification_changes_require_live_evidence(path):
    """Require Gauntlet evidence for changes to enforcement or qualification inputs."""
    assert requires_gauntlet([path])


def test_unrelated_documentation_does_not_require_a_new_product_run():
    """Leave unrelated documentation outside the live-evidence path scope."""
    assert not requires_gauntlet(["README.md", "docs/marketing.md"])


class MetadataAPI:
    def __init__(self, rows, count):
        """Store a synthetic PR file inventory and initialize captured status writes."""
        self.rows, self.count, self.statuses = rows, count, []

    def pull(self, number, sha):
        """Validate the fixture PR identity and return its declared changed-file count."""
        assert number == 1 and sha == "a" * 40
        return {"changed_files": self.count}

    def request(self, path):
        """Return fixture file rows or an empty status history for expected API routes."""
        if "/statuses?" in path:
            return []
        assert path == "/pulls/1/files?per_page=100&page=1"
        return self.rows

    def status(self, *args):
        """Capture a proposed status update without contacting GitHub."""
        self.statuses.append(args)


def test_renaming_enforcement_out_of_the_scoped_directory_still_requires_evidence():
    """Include previous filenames when deciding whether a renamed file needs evidence."""
    api = MetadataAPI([{"filename": "retired.txt", "previous_filename": "rust/crates/guard-command/src/pretool.rs"}], 1)
    initialize_gate(api, {"inputs": {"pr_number": "1", "candidate_sha": "a" * 40}})
    assert api.statuses[0][1] == "pending"


def test_incomplete_file_inventory_cannot_waive_the_gate():
    """Reject a file count mismatch before publishing a gate status."""
    api = MetadataAPI([{"filename": "README.md"}], 2)
    with pytest.raises(ValueError, match="incomplete"):
        initialize_gate(api, {"pull_request": {"number": 1, "head": {"sha": "a" * 40}}})
    assert not api.statuses


def archive(entries):
    """Return an in-memory ZIP archive containing the supplied test entries."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as result:
        for name, body in entries:
            result.writestr(name, body)
    return buffer.getvalue()


def test_public_evidence_roundtrip(tmp_path):
    """Preserve public case JSON through evidence packaging and digest-checked extraction."""
    source = tmp_path / "source"
    (source / "cases").mkdir(parents=True)
    (source / "summary.json").write_text(json.dumps({"schema": "unit-fixture"}))
    (source / "cases/ordinary.json").write_text("{}")
    output = tmp_path / "evidence.zip"
    digest = pack(source, output)
    unpack(output.read_bytes(), tmp_path / "restored", digest)
    assert (tmp_path / "restored/cases/ordinary.json").read_text() == "{}"


@pytest.mark.parametrize(
    "name", ["../outside.json", "/absolute.json", "raw-prompts.json", "runner.py", "cases\\bad.json"]
)
def test_archive_never_extracts_code_private_logs_or_path_traversal(tmp_path, name):
    """Reject disallowed archive paths before creating an extraction directory."""
    data = archive([("summary.json", "{}"), (name, "bad")])
    with pytest.raises(ValueError, match="unsafe"):
        unpack(data, tmp_path / "extracted", hashlib.sha256(data).hexdigest())
    assert not (tmp_path / "extracted").exists()


def test_archive_digest_and_symlinks_are_verified(tmp_path):
    """Reject symlink archive entries and archives with mismatched digests."""
    info = zipfile.ZipInfo("cases/link.json")
    info.create_system = 3
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    data = archive([("summary.json", "{}"), (info, "../../outside")])
    with pytest.raises(ValueError):
        unpack(data, tmp_path / "extracted", hashlib.sha256(data).hexdigest())
    with pytest.raises(ValueError, match="digest"):
        unpack(data, tmp_path / "other", "0" * 64)


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost/bundle.zip",
        "https://127.0.0.1/bundle.zip",
        "https://example.com/bundle.zip",
        "https://u:p@test.s3.amazonaws.com/bundle.zip",
    ],
)
def test_evidence_downloader_rejects_internal_or_unapproved_origins(url):
    """Reject evidence URLs outside the approved credential-free HTTPS origins."""
    with pytest.raises(ValueError):
        download(url)


def test_exact_candidate_or_current_test_merge_is_required():
    """Reject stale bases and parentage that does not bind a test merge to the candidate."""
    candidate, base, source = "a" * 40, "b" * 40, "c" * 40
    report = {
        "source_dirty": False,
        "candidate_sha": candidate,
        "tested_source_sha": source,
        "installed_source_sha": source,
        "source_parents": [base, candidate],
        "tested_base_sha": base,
    }
    validate_identity(report, expected_sha=candidate, expected_base_sha=base)
    with pytest.raises(ValueError):
        validate_identity(report, expected_sha=candidate, expected_base_sha="d" * 40)
    report["source_parents"] = [base]
    with pytest.raises(ValueError):
        validate_identity(report, expected_sha=candidate)


class QualifiedAPI(MetadataAPI):
    repo = "hashgraph-online/hol-guard"

    def __init__(self):
        """Initialize synthetic metadata for a successful source-bound evidence workflow."""
        super().__init__([{"filename": "rust/crates/guard-command/src/pretool.rs"}], 1)
        self.state = "success"
        self.conclusion = "success"
        self.path = ".github/workflows/guard-gauntlet-evidence.yml"
        self.artifact = "guard-gauntlet-" + "a" * 40
        self.description = "Real-agent evidence verified; source=" + "a" * 40
        self.base = "b" * 40
        self.tested_base = self.base
        self.verifier = self.base
        self.source_checks = []
        self.source = "a" * 40

    def pull(self, number, sha):
        """Extend fixture PR metadata with the independently resolved destination tip."""
        return {**super().pull(number, sha), "base": {"sha": self.base}, "gauntlet_base_sha": self.base}

    def prove_source(self, source, candidate, base):
        """Record source checks and reject test merges inconsistent with the fixture base."""
        self.source_checks.append((source, candidate, base))
        if source != candidate and (source != self.source or base != self.tested_base):
            raise ValueError("evidence is not for the current test merge")

    def request(self, path):
        """Serve synthetic status, artifact and workflow metadata for qualification tests."""
        if path == "":
            return {"default_branch": "main"}
        if path.startswith("/compare/"):
            return {"status": "ahead" if path == f"/compare/{self.base}...{self.verifier}" else "behind"}
        if path.startswith("/pulls/"):
            return self.rows
        if "/statuses?" in path:
            return [
                {
                    "context": "Guard Gauntlet",
                    "state": self.state,
                    "description": self.description,
                    "target_url": "https://github.com/" + self.repo + "/actions/runs/123",
                }
            ]
        if "/artifacts?" in path:
            return {"artifacts": [{"name": self.artifact, "expired": False}]}
        if path == "/actions/runs/123":
            return {
                "event": "workflow_dispatch",
                "head_sha": self.verifier,
                "conclusion": self.conclusion,
                "path": self.path,
                "head_repository": {"full_name": self.repo},
            }
        raise AssertionError(path)


def test_required_ci_accepts_only_successful_real_evidence_producer():
    """Accept synthetic metadata satisfying the successful evidence-producer contract."""
    from ci.gauntlet.pr_requirement import require_evidence

    require_evidence(QualifiedAPI(), {"pull_request": {"number": 1, "head": {"sha": "a" * 40}}})


@pytest.mark.parametrize(
    "field,value",
    [
        ("state", "pending"),
        ("conclusion", None),
        ("path", ".github/workflows/unrelated.yml"),
        ("artifact", "guard-gauntlet-" + "b" * 40),
    ],
)
def test_required_ci_rejects_status_without_matching_successful_producer(field, value):
    """Reject pending status, invalid producer metadata or artifacts for a different candidate."""
    from ci.gauntlet.pr_requirement import require_evidence

    api = QualifiedAPI()
    setattr(api, field, value)
    with pytest.raises(RuntimeError):
        require_evidence(api, {"pull_request": {"number": 1, "head": {"sha": "a" * 40}}})


@pytest.mark.parametrize("dirty", [True, None])
def test_identity_rejects_dirty_or_unrecorded_worktrees(dirty):
    """Require an explicit clean-worktree assertion in the source identity report."""
    report = {
        "candidate_sha": "a" * 40,
        "tested_source_sha": "a" * 40,
        "installed_source_sha": "a" * 40,
        "source_parents": ["b" * 40],
        "tested_base_sha": None,
        "source_dirty": dirty,
    }
    with pytest.raises(ValueError, match="dirty"):
        validate_identity(report, expected_sha="a" * 40)


def test_immutable_source_manifest_hashes_api_blobs_without_checkout():
    """Derive runner digests and ancestry from immutable API data without checking out code."""
    import base64

    from ci.gauntlet.github_source import source_manifest

    class API:
        def request(self, path):
            """Serve synthetic commit, directory and encoded blob responses for manifest construction."""
            if path.startswith("/git/commits/"):
                return {"sha": "a" * 40, "parents": [{"sha": "b" * 40}]}
            if path.startswith("/contents/ci/gauntlet?"):
                return [
                    {"name": "runner.py", "path": "ci/gauntlet/runner.py", "type": "file", "sha": "c" * 40},
                    {"name": "scenarios.json", "path": "ci/gauntlet/scenarios.json", "type": "file", "sha": "e" * 40},
                ]
            if path.startswith("/contents/ci/pi-exact-continuation/"):
                return {"path": "ci/pi-exact-continuation/package-lock.json", "type": "file", "sha": "d" * 40}
            if path.startswith("/git/blobs/"):
                raw = b"immutable source bytes"
                return {
                    "sha": path.rsplit("/", 1)[1],
                    "encoding": "base64",
                    "size": len(raw),
                    "content": base64.b64encode(raw).decode(),
                }
            raise AssertionError(path)

    manifest = source_manifest(API(), "a" * 40, "a" * 40)
    assert manifest["runner_files"] == {
        name: hashlib.sha256(b"immutable source bytes").hexdigest() for name in ("runner.py", "scenarios.json")
    }
    assert manifest["catalog_json"] == "immutable source bytes"
    assert manifest["source_parents"] == ["b" * 40]


def test_public_bundle_can_be_submitted_inline_without_storage_credentials(tmp_path):
    """Round-trip an attested inline archive and reject submission without attestation."""
    from ci.gauntlet.submission import inline_dispatch_inputs, submitted_archive

    path = tmp_path / "evidence.zip"
    path.write_bytes(archive([("summary.json", "{}")]))
    inputs = inline_dispatch_inputs(path, candidate_sha="a" * 40, pr_number=1, attested=True)
    assert submitted_archive(inputs) == path.read_bytes()
    assert len(json.dumps(inputs)) < 60000
    with pytest.raises(ValueError):
        inline_dispatch_inputs(path, candidate_sha="a" * 40, pr_number=1, attested=False)


@pytest.mark.parametrize(
    "inputs",
    [
        {},
        {"evidence_base64": "bad!"},
        {"evidence_base64": "AAAA", "evidence_url": "https://example.com"},
        {"evidence_base64": "A" * 55001},
    ],
)
def test_inline_submission_rejects_ambiguous_malformed_or_oversized_data(inputs):
    """Reject missing, conflicting, invalid or oversized inline archive inputs."""
    from ci.gauntlet.submission import submitted_archive

    with pytest.raises(ValueError):
        submitted_archive(inputs)


@pytest.mark.parametrize("parents", [["b" * 40], ["b" * 40, "c" * 40], ["bad-parent"], [None]])
def test_github_manifest_rejects_unrelated_or_malformed_parentage_before_reading_blobs(parents):
    """Reject invalid source ancestry before requesting any candidate file contents."""
    from ci.gauntlet.github_source import source_manifest

    class API:
        def request(self, path):
            """Return the tested parentage and fail if manifest validation requests another route."""
            assert path == "/git/commits/" + "d" * 40
            return {"sha": "d" * 40, "parents": [{"sha": p} for p in parents]}

    with pytest.raises(ValueError):
        source_manifest(API(), "d" * 40, "a" * 40)


def test_required_ci_rechecks_verified_test_merge_against_current_base():
    """Invalidate previously verified merge evidence after the destination branch advances."""
    from ci.gauntlet.pr_requirement import require_evidence

    api = QualifiedAPI()
    api.source = "c" * 40
    api.description = "Real-agent evidence verified; source=" + api.source
    event = {"pull_request": {"number": 1, "head": {"sha": "a" * 40}}}
    require_evidence(api, event)
    assert api.source_checks == [(api.source, "a" * 40, "b" * 40)]
    api.base = "d" * 40
    api.verifier = api.base
    with pytest.raises(ValueError, match="current test merge"):
        require_evidence(api, event)


@pytest.mark.parametrize("description", [None, "verified", "Real-agent evidence verified; source=invalid"])
def test_required_ci_rejects_unbound_legacy_status(description):
    """Reject success descriptions that do not identify a full verified source commit."""
    from ci.gauntlet.pr_requirement import require_evidence

    api = QualifiedAPI()
    api.description = description
    with pytest.raises(RuntimeError, match="verified source binding"):
        require_evidence(api, {"pull_request": {"number": 1, "head": {"sha": "a" * 40}}})


def test_gate_reinitialization_preserves_an_unchanged_qualified_head():
    """Preserve valid existing qualification without publishing a replacement pending status."""
    api = QualifiedAPI()
    initialize_gate(api, {"inputs": {"pr_number": "1", "candidate_sha": "a" * 40}})
    assert api.statuses == []


def test_candidate_branch_verifier_cannot_qualify_itself():
    """Reject evidence produced by an untrusted verifier on the candidate branch."""
    from ci.gauntlet.pr_requirement import require_evidence

    api = QualifiedAPI()
    api.verifier = "a" * 40
    with pytest.raises(RuntimeError, match="trusted base"):
        require_evidence(api, {"pull_request": {"number": 1, "head": {"sha": "a" * 40}}})


def test_initial_installation_requires_the_explicit_pinned_verifier(monkeypatch):
    """Limit bootstrap verification to the pinned revision, designated PR and preinstallation base."""
    from ci.gauntlet.trust import validate_producer_revision

    class API:
        repo = "hashgraph-online/hol-guard"
        installed = False

        def gauntlet_installed_at(self, revision):
            # PR metadata can retain the pre-installation base indefinitely.
            """Check installation state at the independently resolved destination tip."""
            assert revision == "d" * 40
            return self.installed

        def request(self, path):
            """Serve trusted default-branch and ancestry metadata for the bootstrap fixture."""
            if path == "":
                return {"default_branch": "main"}
            if path.startswith("/compare/"):
                return {"status": "behind"}
            raise AssertionError(path)

    api = API()
    pull = {"base": {"sha": "b" * 40}, "gauntlet_base_sha": "d" * 40}
    run = {"head_sha": "c" * 40}
    monkeypatch.setenv("GUARD_GAUNTLET_BOOTSTRAP_VERIFIER_SHA", "c" * 40)
    validate_producer_revision(api, 3463, pull, run)
    with pytest.raises(RuntimeError, match="trusted base"):
        validate_producer_revision(api, 3464, pull, run)
    api.installed = True
    with pytest.raises(RuntimeError, match="trusted base"):
        validate_producer_revision(api, 3463, pull, run)
    api.installed = False
    for tip in (None, "not-a-sha"):
        with pytest.raises(RuntimeError, match="trusted base"):
            validate_producer_revision(api, 3463, {**pull, "gauntlet_base_sha": tip}, run)
    monkeypatch.delenv("GUARD_GAUNTLET_BOOTSTRAP_VERIFIER_SHA")
    with pytest.raises(RuntimeError, match="trusted base"):
        validate_producer_revision(api, 3463, pull, run)


def test_candidate_catalog_may_add_but_not_weaken_trusted_cases():
    """Allow added cases and prompt edits while rejecting removal or altered trusted commands."""
    from dataclasses import replace

    from ci.gauntlet.catalog import Scenario, retain_trusted_cases

    baseline = Scenario("ordinary", "allow", "commands", "old prompt", ("echo fixture",))
    addition = Scenario("additional", "allow", "commands", "new task", ("pwd",))
    retain_trusted_cases((replace(baseline, prompt="clearer prompt"), addition), (baseline,))
    with pytest.raises(ValueError, match="trusted scenario"):
        retain_trusted_cases((addition,), (baseline,))
    with pytest.raises(ValueError, match="trusted scenario"):
        retain_trusted_cases((replace(baseline, commands=("pwd",)),), (baseline,))


@pytest.mark.parametrize("previous", ["", 7, False])
def test_malformed_previous_paths_do_not_waive_enforcement(previous):
    """Reject invalid previous filenames instead of using them to bypass path scoping."""
    api = MetadataAPI([{"filename": "README.md", "previous_filename": previous}], 1)
    with pytest.raises(ValueError, match="previous"):
        initialize_gate(api, {"inputs": {"pr_number": "1", "candidate_sha": "a" * 40}})


def test_evidence_jobs_run_only_from_trusted_default_or_pinned_bootstrap():
    """Require privileged evidence jobs to use reviewed workflow-dispatch refs and verifier bindings."""
    from pathlib import Path

    import yaml

    path = Path(__file__).resolve().parents[1] / ".github/workflows/guard-gauntlet-evidence.yml"
    workflow = yaml.safe_load(path.read_text())
    for name in ("verify", "publish"):
        condition = workflow["jobs"][name]["if"]
        assert "github.event.repository.default_branch" in condition
        assert "refs/tags/guard-gauntlet-bootstrap-v3" in condition
        assert "github.event_name == 'workflow_dispatch'" in condition
        assert "GUARD_GAUNTLET_BOOTSTRAP_VERIFIER_SHA" in workflow["jobs"][name]["env"]


def test_required_ci_uses_trusted_base_or_exact_initial_verifier():
    """Check that required CI invokes the verifier from its trusted checkout and pinned bootstrap."""
    from pathlib import Path

    import yaml

    path = Path(__file__).resolve().parents[1] / ".github/workflows/ci.yml"
    job = yaml.safe_load(path.read_text())["jobs"]["ci-python-312"]
    checkouts = [step["with"] for step in job["steps"] if step.get("uses", "").startswith("actions/checkout@")]
    assert checkouts == [
        {"ref": "${{ github.event.pull_request.base.sha }}", "path": "gauntlet-trusted", "persist-credentials": False},
        {"ref": "69de8c263514933786d5816b7a4ae8b239326a65", "path": "gauntlet-trusted", "persist-credentials": False},
    ]
    requirement = next(step for step in job["steps"] if step.get("run") == "python3 -m ci.gauntlet.github_ci require")
    assert requirement["working-directory"] == "gauntlet-trusted"
    assert requirement["env"]["GUARD_GAUNTLET_BOOTSTRAP_VERIFIER_SHA"] == checkouts[1]["ref"]
