"""Contract checks for the pull-request TestPyPI canary workflow."""

import ast
import fnmatch
from pathlib import Path

import tomllib
import yaml

ROOT = Path(__file__).resolve().parents[1]
PUBLISH_PR_PATHS = [
    "**",
    "!tests/**",
    "!docs/**",
    "!fuzzers/**",
    "!**/*.md",
    "!.github/workflows/**",
    ".github/workflows/publish.yml",
    "README.md",
    "src/**",
    "scripts/**",
    "rust/**",
    "contracts/**",
    "contributions/**",
    "docs/guard/contracts/guard-cloud-review.md",
    "tests/__init__.py",
    "tests/guard_command_corpus*.py",
    "tests/harness_attribution_env.py",
    "tests/native_command_test_support.py",
    "tests/native_github_offline.py",
    "tests/fixtures/guard-command-corpus/**",
    "tests/dockerlabs/**",
]


def _publish_runs_for(path: str) -> bool:
    """Evaluate GitHub's ordered include/exclude path filter for one file."""
    selected = False
    for pattern in PUBLISH_PR_PATHS:
        negated = pattern.startswith("!")
        glob = pattern[1:] if negated else pattern
        if glob.endswith("/**"):
            matched = path.startswith(glob[:-2])
        elif glob.startswith("**/"):
            matched = fnmatch.fnmatch(path.rsplit("/", 1)[-1], glob[3:])
        else:
            matched = glob == "**" or fnmatch.fnmatch(path, glob)
        if matched:
            selected = not negated
    return selected


def _canary_test_modules() -> set[str]:
    pending = ["tests.guard_command_corpus_runner"]
    for script in ("scripts/run_installed_canary.py", "scripts/run_installed_native_corpus.py"):
        for node in ast.walk(ast.parse((ROOT / script).read_text(encoding="utf-8"))):
            if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("tests"):
                pending.append(node.module)
    seen: set[str] = set()
    while pending:
        module = pending.pop()
        path = ROOT / (module.replace(".", "/") + ".py")
        if module in seen or not path.exists():
            continue
        seen.add(module)
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("tests"):
                pending.append(node.module)
            elif isinstance(node, ast.Import):
                pending.extend(alias.name for alias in node.names if alias.name.startswith("tests"))
    return {module.replace(".", "/") + ".py" for module in seen}


def test_publish_path_filter_keeps_every_shipped_and_canary_input() -> None:
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    hatch = pyproject["tool"]["hatch"]["build"]
    shipped = [*hatch["targets"]["sdist"]["only-include"], *hatch["targets"]["wheel"]["force-include"]]
    probes = {
        "src/codex_plugin_scanner/guard/agent-safety-guidance.md",
        "tests/__init__.py",
        "tests/fixtures/guard-command-corpus/seed-manifest.json",
        "tests/dockerlabs/command-extension-analytics/package.json",
        *_canary_test_modules(),
    }
    for entry in shipped:
        probes.add(entry if (ROOT / entry).is_file() else f"{entry}/README.md")
    missing = sorted(path for path in probes if not _publish_runs_for(path))
    assert missing == []
    for skipped in ("tests/test_cli.py", "docs/guard/overview.md", "fuzzers/fuzz_policy.py", "CHANGELOG.md"):
        assert not _publish_runs_for(skipped)


def test_native_pr_base_wheel_rebuild_has_uv_available() -> None:
    workflow = yaml.safe_load((ROOT / ".github/workflows/publish.yml").read_text(encoding="utf-8"))
    steps = workflow["jobs"]["build-native-guard-wheels"]["steps"]
    rebuild_index = next(
        index
        for index, step in enumerate(steps)
        if step.get("name") == "Rebuild Guard base wheel after projection regeneration"
    )
    rebuild = steps[rebuild_index]
    assert "if" not in rebuild
    assert "uv build" in rebuild["run"]
    setup = next(step for step in steps[:rebuild_index] if step.get("uses", "").startswith("astral-sh/setup-uv@"))
    assert "if" not in setup
    assert setup["with"]["version"] == "0.9.26"


def test_pr_canary_requires_maintainer_opt_in_for_same_repository_prs() -> None:
    workflow_path = ROOT / ".github/workflows/publish.yml"
    workflow = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))

    assert workflow[True]["pull_request"] == {
        "branches": ["main", "release/3.0", "release/3.2"],
        "types": ["opened", "synchronize", "reopened", "labeled"],
        "paths": PUBLISH_PR_PATHS,
    }
    assert workflow["permissions"] == {"contents": "read", "pull-requests": "read"}
    job = workflow["jobs"]["publish-testpypi"]
    assert job["permissions"] == {"id-token": "write"}
    assert "vars.PR_CANARY_PUBLISHING_ENABLED == 'true'" in job["if"]
    assert "github.event.pull_request.head.repo.full_name == github.repository" in job["if"]
    assert "vars.PR_CANARY_PUBLISHING_ENABLED == 'true'" in job["if"]
    assert "contains(github.event.pull_request.labels.*.name, 'publish-testpypi-canary')" in job["if"]
    installed_job = workflow["jobs"]["pr-installed-canary"]
    assert "vars.PR_CANARY_PUBLISHING_ENABLED == 'true'" in installed_job["if"]
    assert "contains(github.event.pull_request.labels.*.name, 'publish-testpypi-canary')" in installed_job["if"]
    assert job["environment"] == "testpypi"
    assert "github.event_name == 'pull_request'" in job["if"]
    assert (
        "github.event.action != 'labeled' || github.event.label.name == 'publish-testpypi-canary'"
        in workflow["jobs"]["build"]["if"]
    )
    publish_step = next(
        step
        for step in job["steps"]
        if isinstance(step, dict) and step.get("uses", "").startswith("pypa/gh-action-pypi-publish")
    )
    assert "password" not in publish_step.get("with", {})
    assert "token" not in publish_step.get("with", {})
    assert "username" not in publish_step.get("with", {})
    assert any(
        step.get("name") == "Keep only the Guard canary distribution" for step in job["steps"] if isinstance(step, dict)
    )
    assert "rm -f dist/plugin_scanner-* dist/plugin-scanner-*" in (ROOT / ".github/workflows/publish.yml").read_text(
        encoding="utf-8"
    )


def test_pr_canary_builds_a_unique_pep440_dev_release() -> None:
    workflow_path = ROOT / ".github/workflows/publish.yml"
    workflow_text = workflow_path.read_text(encoding="utf-8")

    assert "def pair(left: int, right: int) -> int:" in workflow_text
    assert "pair(pair(int(os.environ['PR_NUMBER']), int(os.environ['GITHUB_RUN_NUMBER']))" in workflow_text
    assert "scripts/sync_repo_version.py --version" in workflow_text
    assert "python -m build" in workflow_text
    assert "twine check dist/*" in workflow_text
    assert "repository-url: https://test.pypi.org/legacy/" in workflow_text
    assert "TestPyPI canary" in workflow_text
    assert "uv tool install --force --index https://pypi.org/simple" in workflow_text
    assert "--extra-index-url" not in workflow_text
