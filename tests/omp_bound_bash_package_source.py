"""Installed Bash dependency variation of the realistic SDK report fixture."""

import json
from pathlib import Path


def setup(directory: Path) -> None:
    package = directory / "node_modules" / "captured-dep"
    package.mkdir(parents=True)
    (package / "package.json").write_text(json.dumps({"name": "captured-dep", "version": "1.0.0"}))
    (package / "library.sh").write_text("DEPENDENCY_MARKER='loaded'\n")
    script = directory / "maintenance.sh"
    text = script.read_text()
    marker = ': > "$report"\n'
    assert text.count(marker) == 1
    script.write_text(
        text.replace(
            marker, marker + ("source './node_modules/captured-dep/library.sh'\ntest \"$DEPENDENCY_MARKER\" = loaded\n")
        )
    )


def between_invocations(directory: Path, duration: str, iteration: int) -> None:
    if iteration != 5:
        return
    manifest = directory / "node_modules/captured-dep/package.json"
    if duration == "quiet":
        manifest.unlink()  # Missing attribution must not invent local consent friction.
    else:
        manifest.write_text(
            json.dumps(
                {
                    "name": "captured-dep",
                    "version": "1.0.0",
                    "description": "ordinary package documentation",
                },
                indent=2,
            )
        )


def assert_pending_subject(subject: dict) -> None:
    bindings = subject["package_bindings"]
    assert len(bindings) == 1
    assert bindings[0]["state"] == "declared"
    assert (bindings[0]["name"], bindings[0]["version"]) == ("captured-dep", "1.0.0")
    assert any(subject["code_inputs"][index]["kind"] == "source" for index in bindings[0]["code_input_indices"])


def assert_changed_version_requires_consent(directory: Path, report: Path, store, refused) -> None:
    manifest = directory / "node_modules/captured-dep/package.json"
    manifest.write_text(json.dumps({"name": "captured-dep", "version": "1.0.1"}))
    report.write_text("preserve report across package version change")
    refused("package-version-changed", "native_bash_consent_required")
    assert report.read_text() == "preserve report across package version change"
    pending = store.list_approval_requests()
    assert len(pending) == 1
    assert pending[0]["action_envelope_json"]["native_bash"]["subject"]["package_bindings"][0]["version"] == "1.0.1"
