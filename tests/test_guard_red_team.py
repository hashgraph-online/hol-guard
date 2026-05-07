"""Red-team test runner for all guard-red-team fixtures (T644).

Validates:
- All malicious fixtures use only fake key material
- All benign fixtures are free of network exfil patterns targeting evil.hol.org
- All fixtures listed in expected-decisions.json exist on disk
- No local usernames, real paths, or real tokens appear in any committed fixture
"""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "guard-red-team"
DECISIONS_PATH = FIXTURES_DIR / "expected-decisions.json"

_REAL_KEY_PREFIXES = ("sk-", "ghp_", "ghs_", "glpat-", "xoxb-", "xoxp-", "AIza")
_ALLOWED_FAKE_PREFIX = "hol-fake-"
_CANARY_COLLECT_URL = "https://evil.hol.org/collect"
_REAL_ENDPOINT_PATTERNS = (
    "openai.com",
    "api.github.com",
    "hooks.slack.com",
    "discord.com/api",
    "api.anthropic.com",
)
_HOME_PATH_RE = re.compile(r"/home/[a-z_][a-z0-9_-]{0,31}|/Users/[A-Za-z][A-Za-z0-9_-]{0,31}")


def _load_decisions() -> dict[str, object]:
    return json.loads(DECISIONS_PATH.read_text(encoding="utf-8"))


def _all_string_literals(source: str, fixture_name: str) -> list[str]:
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        raise AssertionError(
            f"{fixture_name}: Python syntax error — cannot safely scan for real key material: {exc}"
        ) from exc
    return [
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    ]


def _all_text_tokens(text: str) -> list[str]:
    return re.findall(r"[\w.:\-/]+", text)


_NON_FIXTURE_NAMES = {"README.md", "expected-decisions.json", "smoke-evidence-template.json"}


class TestRedTeamManifest:
    def test_expected_decisions_file_exists(self) -> None:
        assert DECISIONS_PATH.exists(), f"Missing {DECISIONS_PATH}"

    def test_all_manifest_fixtures_exist_on_disk(self) -> None:
        decisions = _load_decisions()
        fixtures: dict[str, object] = decisions["fixtures"]
        missing = [name for name in fixtures if not (FIXTURES_DIR / name).exists()]
        assert not missing, f"Manifest lists missing fixture files: {missing}"

    def test_all_disk_fixtures_covered_by_manifest(self) -> None:
        decisions = _load_decisions()
        manifest_names: set[str] = set(decisions["fixtures"].keys())
        disk_names = {
            p.name
            for p in FIXTURES_DIR.iterdir()
            if p.is_file() and p.name not in _NON_FIXTURE_NAMES
        }
        uncovered = sorted(disk_names - manifest_names)
        assert not uncovered, (
            f"Fixture files on disk not covered by manifest: {uncovered}. "
            "Add them to expected-decisions.json or to _NON_FIXTURE_NAMES."
        )

    def test_manifest_version_is_present(self) -> None:
        decisions = _load_decisions()
        assert "version" in decisions
        assert isinstance(decisions["version"], int)


class TestMaliciousFixtures:
    def _malicious_fixtures(self) -> list[tuple[str, Path]]:
        decisions = _load_decisions()
        return [
            (name, FIXTURES_DIR / name)
            for name, meta in decisions["fixtures"].items()
            if not meta["benign"]
        ]

    def test_malicious_fixtures_use_only_fake_keys(self) -> None:
        for fixture_name, fixture_path in self._malicious_fixtures():
            source = fixture_path.read_text(encoding="utf-8")
            if fixture_path.suffix == ".py":
                literals = _all_string_literals(source, fixture_name)
                for literal in literals:
                    for prefix in _REAL_KEY_PREFIXES:
                        assert prefix not in literal, (
                            f"{fixture_name}: found real key prefix '{prefix}' in literal: {literal!r}"
                        )
            else:
                tokens = _all_text_tokens(source)
                for token in tokens:
                    for prefix in _REAL_KEY_PREFIXES:
                        if token.startswith(prefix) and _ALLOWED_FAKE_PREFIX not in token:
                            raise AssertionError(
                                f"{fixture_name}: found real key prefix '{prefix}' in token: {token!r}"
                            )

    def test_malicious_fixtures_only_exfil_to_canary_endpoint(self) -> None:
        for fixture_name, fixture_path in self._malicious_fixtures():
            source = fixture_path.read_text(encoding="utf-8")
            for pattern in _REAL_ENDPOINT_PATTERNS:
                assert pattern not in source, (
                    f"{fixture_name}: contains real endpoint pattern '{pattern}'"
                )

    def test_no_local_user_paths_in_malicious_fixtures(self) -> None:
        for fixture_name, fixture_path in self._malicious_fixtures():
            source = fixture_path.read_text(encoding="utf-8")
            match = _HOME_PATH_RE.search(source)
            assert match is None, (
                f"{fixture_name}: contains local path '{match.group()}' — use os.path.expanduser('~') or $HOME"
            )


class TestBenignFixtures:
    def _benign_fixtures(self) -> list[tuple[str, Path]]:
        decisions = _load_decisions()
        return [
            (name, FIXTURES_DIR / name)
            for name, meta in decisions["fixtures"].items()
            if meta["benign"] and (FIXTURES_DIR / name).suffix == ".py"
        ]

    def test_benign_fixtures_do_not_target_exfil_endpoint(self) -> None:
        for fixture_name, fixture_path in self._benign_fixtures():
            source = fixture_path.read_text(encoding="utf-8")
            assert _CANARY_COLLECT_URL not in source, (
                f"{fixture_name}: benign fixture contains canary exfil URL"
            )

    def test_benign_fixtures_do_not_use_real_key_prefixes(self) -> None:
        for fixture_name, fixture_path in self._benign_fixtures():
            source = fixture_path.read_text(encoding="utf-8")
            for prefix in _REAL_KEY_PREFIXES:
                assert prefix not in source, (
                    f"{fixture_name}: benign fixture contains real key prefix '{prefix}'"
                )

    def test_no_local_user_paths_in_benign_fixtures(self) -> None:
        for fixture_name, fixture_path in self._benign_fixtures():
            source = fixture_path.read_text(encoding="utf-8")
            match = _HOME_PATH_RE.search(source)
            assert match is None, (
                f"{fixture_name}: contains local path '{match.group()}'"
            )


class TestAllFixturesNoLocalSecrets:
    def test_no_env_file_contents_in_any_fixture(self) -> None:
        decisions = _load_decisions()
        env_var_pattern = re.compile(r"^[A-Z_]{4,}=[^\n]{8,}", re.MULTILINE)
        for name in decisions["fixtures"]:
            path = FIXTURES_DIR / name
            if not path.exists():
                continue
            if path.suffix not in {".py", ".js", ".yml", ".json", ".md", ".txt"}:
                continue
            source = path.read_text(encoding="utf-8")
            real_env_matches = [
                m.group()
                for m in env_var_pattern.finditer(source)
                if "hol-fake" not in m.group().lower() and "placeholder" not in m.group().lower()
            ]
            assert not real_env_matches, (
                f"{name}: looks like real env var contents: {real_env_matches[:2]}"
            )
