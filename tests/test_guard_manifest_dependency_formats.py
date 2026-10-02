"""Manifest dependency format tests."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.runtime import package_manifest_diff


def test_parse_manifest_dependency_changes_supports_primary_manifests_lockfiles_and_tier2_formats(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Format correctness must not depend on runner scheduling.
    monkeypatch.setattr(package_manifest_diff, "time", SimpleNamespace(monotonic=lambda: 0.0))
    cases = [
        (
            "package.json",
            '{"dependencies":{"react":"18.2.0"}}',
            '{"dependencies":{"react":"18.3.0","lodash":"4.17.21"}}',
            {"react": ("18.2.0", "18.3.0"), "lodash": (None, "4.17.21")},
        ),
        (
            "pyproject.toml",
            '[project]\ndependencies = ["fastapi==0.110.0"]\n',
            '[project]\ndependencies = ["fastapi==0.115.0", "httpx>=0.27"]\n',
            {"fastapi": ("0.110.0", "0.115.0"), "httpx": (None, ">=0.27")},
        ),
        (
            "requirements.txt",
            "flask==3.0.0\n",
            "flask==3.1.0\nrequests==2.32.0\n",
            {"flask": ("3.0.0", "3.1.0"), "requests": (None, "2.32.0")},
        ),
        (
            "package-lock.json",
            '{"packages":{"node_modules/react":{"version":"18.2.0"}}}',
            '{"packages":{"node_modules/react":{"version":"18.3.0"},"node_modules/lodash":{"version":"4.17.21"}}}',
            {"react": ("18.2.0", "18.3.0"), "lodash": (None, "4.17.21")},
        ),
        (
            "Cargo.toml",
            '[dependencies]\nclap = "4.4"\n',
            '[dependencies]\nclap = "4.5"\nserde = "1.0"\n',
            {"clap": ("4.4", "4.5"), "serde": (None, "1.0")},
        ),
        (
            "go.mod",
            "require github.com/gin-gonic/gin v1.9.0\n",
            "require (\n github.com/gin-gonic/gin v1.10.0\n github.com/spf13/cobra v1.8.0\n)\n",
            {"github.com/gin-gonic/gin": ("v1.9.0", "v1.10.0"), "github.com/spf13/cobra": (None, "v1.8.0")},
        ),
        (
            "pom.xml",
            "<project><dependencies><dependency><groupId>org.example</groupId><artifactId>demo</artifactId><version>1.0.0</version></dependency></dependencies></project>",
            "<project><dependencies><dependency><groupId>org.example</groupId><artifactId>demo</artifactId><version>1.2.0</version></dependency><dependency><groupId>org.example</groupId><artifactId>extra</artifactId><version>2.0.0</version></dependency></dependencies></project>",
            {"org.example:demo": ("1.0.0", "1.2.0"), "org.example:extra": (None, "2.0.0")},
        ),
        (
            "pom.xml",
            '<project xmlns="http://maven.apache.org/POM/4.0.0"><dependencies><dependency><groupId>org.example</groupId><artifactId>demo</artifactId><version>1.0.0</version></dependency></dependencies></project>',
            '<project xmlns="http://maven.apache.org/POM/4.0.0"><dependencies><dependency><groupId>org.example</groupId><artifactId>demo</artifactId><version>1.1.0</version></dependency></dependencies></project>',
            {"org.example:demo": ("1.0.0", "1.1.0")},
        ),
        (
            "build.gradle.kts",
            'dependencies { implementation("org.example:demo:1.0.0") }\n',
            'dependencies { implementation("org.example:demo:1.2.0") implementation("org.example:extra:2.0.0") }\n',
            {"org.example:demo": ("1.0.0", "1.2.0"), "org.example:extra": (None, "2.0.0")},
        ),
        (
            "composer.json",
            '{"require":{"laravel/framework":"^10.0"}}',
            '{"require":{"laravel/framework":"^11.0","guzzlehttp/guzzle":"^7.0"}}',
            {"laravel/framework": ("^10.0", "^11.0"), "guzzlehttp/guzzle": (None, "^7.0")},
        ),
        (
            "Gemfile",
            'gem "rails", "7.1.2"\n',
            'gem "rails", "7.1.3"\ngem "rspec", "3.13.0"\n',
            {"rails": ("7.1.2", "7.1.3"), "rspec": (None, "3.13.0")},
        ),
    ]

    for path, before_text, after_text, expected in cases:
        result = package_manifest_diff.parse_manifest_dependency_changes(
            path=path,
            before_text=before_text,
            after_text=after_text,
        )

        assert result.truncated is False
        assert result.parse_errors == ()
        actual = {change.package_name: (change.before, change.after) for change in result.changes}
        assert actual == expected


def test_parse_manifest_dependency_changes_enforces_default_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    clock = iter((0.0, 0.051))
    monkeypatch.setattr(package_manifest_diff, "time", SimpleNamespace(monotonic=lambda: next(clock, 0.051)))

    result = package_manifest_diff.parse_manifest_dependency_changes(
        path="package-lock.json",
        before_text='{"packages":{"node_modules/react":{"version":"18.2.0"}}}',
        after_text='{"packages":{"node_modules/react":{"version":"18.3.0"}}}',
    )

    assert result.changes == ()
    assert result.truncated is True
    assert result.parse_errors == ("deadline_exceeded",)
