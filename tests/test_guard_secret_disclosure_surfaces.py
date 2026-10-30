"""No secret the scanner finds reaches a response, an artifact or a log.

The scanner reads credentials out of a repository, so every surface it writes
afterwards is a place those bytes could escape to: the rendered text, the JSON
payload, stderr, and any file the run leaves behind under the user's home or
the temporary directory.  Each case below plants secrets of several families,
proves the scan actually found them, and then looks for the planted bytes in
every one of those surfaces.

The sweep walks whole directory trees rather than named files, so a log,
journal, cache or crash report added later is covered the day it appears.  It
cannot see what never lands in those places: counters held in memory and sent
elsewhere are outside its reach, and so is the pre-commit hook's own execution,
which runs the installed ``hol-guard`` console script.  The command that hook
runs is exercised directly here instead.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

_POSIX_ONLY = pytest.mark.skipif(os.name != "posix", reason="Guard refuses Git hook management off POSIX")


def _join(*parts: str) -> str:
    """Assemble a synthetic credential at runtime.

    No whole provider-shaped token appears in this file's source, so planting
    one costs nothing in the repository's own secret scanning.
    """

    return "".join(parts)


def _samples() -> dict[str, str]:
    """Synthetic credentials, one per detector family that has to find them."""

    return {
        "GITHUB_TOKEN": _join("ghp_", "A" * 36),
        "AWS_ACCESS_KEY_ID": _join("AKIA", "ABCDEFGHIJKLMNOP"),
        "SLACK_TOKEN": _join("xoxb-", "1111111111", "-", "2222222222", "-", "abcdefghijklmnopqrstuvwx"),
        "OPENAI_API_KEY": _join("sk-", "B" * 48),
        "STRIPE_KEY": _join("sk_live_", "C" * 24),
        "PEM_HEADER": _join("-----BEGIN ", "RSA", " PRIVATE KEY-----"),
    }


_EXPECTED_RULES = {
    "github-token",
    "aws-access-key",
    "slack-token",
    "openai-api-key",
    "stripe-secret-key",
    "pem-private-key",
}


def _git(root: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True)


def _plant(root: Path, samples: dict[str, str]) -> Path:
    _git(root, "init")
    _git(root, "config", "user.email", "guard@example.invalid")
    _git(root, "config", "user.name", "Guard Test")
    # A developer's global core.hooksPath must not leak into this repository.
    _git(root, "config", "core.hooksPath", "")
    target = root / "config.env"
    target.write_text("".join(f"{name}={value}\n" for name, value in samples.items()), encoding="utf-8")
    return target


@pytest.fixture
def sandbox(tmp_path: Path) -> tuple[Path, Path, Path, dict[str, str]]:
    """A repository holding planted secrets, beside an empty home and tmp dir."""

    repo = tmp_path / "repo"
    home = tmp_path / "home"
    scratch = tmp_path / "scratch"
    for directory in (repo, home, scratch):
        directory.mkdir()
    samples = _samples()
    _plant(repo, samples)
    return repo, home, scratch, samples


def _run(args: list[str], *, home: Path, scratch: Path) -> subprocess.CompletedProcess[str]:
    """Run the Secrets shim in its own process, with its own home and tmp dir."""

    environment = dict(os.environ)
    environment["HOME"] = str(home)
    environment["TMPDIR"] = str(scratch)
    return subprocess.run(
        [sys.executable, "-m", "codex_plugin_scanner.guard.secrets.cli", *args],
        capture_output=True,
        text=True,
        env=environment,
    )


def _files_under(root: Path) -> list[Path]:
    return [path for path in root.rglob("*") if path.is_file() and not path.is_symlink()]


def _assert_absent(samples: dict[str, str], *, texts: dict[str, str], roots: dict[str, Path]) -> None:
    """No planted secret appears in any rendered text or any file written."""

    for name, value in samples.items():
        for surface, text in texts.items():
            assert value not in text, f"{name} reached {surface}"
        for surface, root in roots.items():
            for path in _files_under(root):
                try:
                    content = path.read_bytes()
                except OSError:  # pragma: no cover - a file the run already removed
                    continue
                assert value.encode("utf-8") not in content, f"{name} reached {surface}:{path.relative_to(root)}"


def _assert_found_every_family(payload: dict[str, object]) -> None:
    findings = payload["findings"]
    assert isinstance(findings, list)
    assert {finding["rule_id"] for finding in findings} == _EXPECTED_RULES, findings
    # The absence checks below only mean something because the scan really
    # held these secrets while it rendered. A history scan reports each one
    # twice, once from the working tree and once from the commit that holds it.
    assert payload["finding_count"] == len(findings) >= len(_EXPECTED_RULES)


def test_the_sweep_would_catch_a_leak(sandbox: tuple[Path, Path, Path, dict[str, str]]) -> None:
    """The absence check fails when a secret really is written somewhere."""

    _repo, home, scratch, samples = sandbox
    (home / "leaked.log").write_text(samples["GITHUB_TOKEN"], encoding="utf-8")

    with pytest.raises(AssertionError, match="GITHUB_TOKEN reached home"):
        _assert_absent(samples, texts={}, roots={"home": home, "scratch": scratch})


def test_working_tree_json_scan_discloses_no_secret(
    sandbox: tuple[Path, Path, Path, dict[str, str]],
) -> None:
    repo, home, scratch, samples = sandbox

    completed = _run(["scan", str(repo), "--format", "json"], home=home, scratch=scratch)

    assert completed.returncode == 0, completed.stderr
    payload = json.loads(completed.stdout)
    _assert_found_every_family(payload)
    _assert_absent(
        samples,
        texts={"stdout": completed.stdout, "stderr": completed.stderr},
        roots={"home": home, "scratch": scratch},
    )


def test_working_tree_text_scan_discloses_no_secret(
    sandbox: tuple[Path, Path, Path, dict[str, str]],
) -> None:
    repo, home, scratch, samples = sandbox

    completed = _run(["scan", str(repo)], home=home, scratch=scratch)

    assert completed.returncode == 0, completed.stderr
    # The render names the families it found; it must name them without
    # quoting what it found.
    assert "GitHub token" in completed.stdout
    assert "config.env:1" in completed.stdout
    _assert_absent(
        samples,
        texts={"stdout": completed.stdout, "stderr": completed.stderr},
        roots={"home": home, "scratch": scratch},
    )


@_POSIX_ONLY
def test_staged_failing_scan_discloses_no_secret(
    sandbox: tuple[Path, Path, Path, dict[str, str]],
) -> None:
    """This is the command the installed pre-commit hook runs."""

    repo, home, scratch, samples = sandbox
    _git(repo, "add", "config.env")

    completed = _run(["scan", str(repo), "--staged", "--fail-on-findings"], home=home, scratch=scratch)

    assert completed.returncode == 3, completed.stderr
    assert "GitHub token" in completed.stdout
    _assert_absent(
        samples,
        texts={"stdout": completed.stdout, "stderr": completed.stderr},
        roots={"home": home, "scratch": scratch},
    )


def test_history_scan_discloses_no_secret(
    sandbox: tuple[Path, Path, Path, dict[str, str]],
) -> None:
    """A finding read out of a commit carries the commit, never the secret."""

    repo, home, scratch, samples = sandbox
    _git(repo, "add", "config.env")
    _git(repo, "commit", "-m", "add config")

    completed = _run(["scan", str(repo), "--history", "--format", "json"], home=home, scratch=scratch)

    assert completed.returncode == 0, completed.stderr
    payload = json.loads(completed.stdout)
    assert payload["history_enabled"] is True
    assert payload["commits_scanned"] >= 1
    assert all(finding["commit"] for finding in payload["findings"] if finding["source"] == "history")
    _assert_found_every_family(payload)
    _assert_absent(
        samples,
        texts={"stdout": completed.stdout, "stderr": completed.stderr},
        roots={"home": home, "scratch": scratch},
    )
