from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, cast

import pytest

from codex_plugin_scanner.guard.inventory_contract import (
    _bind_skill_document_evidence,
    _capabilities_for_artifact,
    inventory_snapshot_from_detection,
    serialize_inventory_snapshot,
)
from codex_plugin_scanner.guard.models import GuardArtifact, HarnessDetection
from codex_plugin_scanner.guard.skill_document_evidence import (
    MAX_SKILL_DOCUMENT_BYTES,
    enrich_skill_document_metadata,
)


def _write_skill(home: Path, content: str) -> Path:
    path = home / ".codex" / "skills" / "demo" / "SKILL.md"
    path.parent.mkdir(parents=True)
    path.write_text(content, encoding="utf-8")
    return path


def _metadata_for(path: Path, home: Path) -> dict[str, object]:
    return enrich_skill_document_metadata(path.as_posix(), {}, home_dir=home, workspace_dir=None)


@pytest.mark.parametrize(
    ("content", "evidence_code"),
    (
        ("Run `curl -X POST https://api.example.test/v1/upload` to publish results.\n", "explicit_http_client"),
        ("This skill uploads scan results to the remote API.\n", "explicit_remote_api_statement"),
        ("The workflow calls the external service endpoint.\n", "explicit_remote_api_statement"),
        ('fetch("https://api.example.test/v1/data")\n', "explicit_http_client"),
        ("axios.get('https://api.example.test/v1/data')\n", "explicit_http_client"),
        ('requests.get("https://api.example.test/v1/data")\n', "explicit_http_client"),
        ('The skill\'s requests.get("https://api.example.test/v1/data")\n', "explicit_http_client"),
        ('The skills\' requests.get("https://api.example.test/v1/data")\n', "explicit_http_client"),
    ),
)
def test_explicit_remote_behavior_adds_documented_capability(
    tmp_path: Path,
    content: str,
    evidence_code: str,
) -> None:
    home = tmp_path / "home"
    metadata = _metadata_for(_write_skill(home, content), home)

    assert metadata["documentedCapabilities"] == [
        {
            "capability": "network_egress",
            "source": "skill_documentation",
            "confidence": "high",
            "evidenceCode": evidence_code,
            "inferenceVersion": "1",
        }
    ]


@pytest.mark.parametrize(
    "content",
    (
        "API documentation: https://api.example.test/reference\n",
        "Print full URLs when presenting responsive image examples.\n",
        "Do not run:\ncurl https://api.example.test/v1/data\n",
        "Never call the remote API.\n",
        "Counterexample: fetch('https://api.example.test/v1/data')\n",
        "fetch('http://localhost:8000/test')\n",
        "Use a connection-aware layout and test browser network throttling.\n",
        'fetch("' + "https" + "://[" + chr(58) * 2 + '1]:8080/endpoint")\n',
        "Queries supported by the API are listed below.\n",
        "## Do not make network requests\n```sh\ncurl https://api.example.test/v1/data\n```\n",
        "> curl https://api.example.test/v1/reference\n",
        "## Counterexample\n```js\nfetch('https://api.example.test/v1/data')\n```\n",
        'Example: "This skill calls the remote API."\n',
        'The phrase "This skill calls the remote API" is a sample, not a capability.\n',
        "The sample says \"fetch('https://api.example.test/v1/data')\".\n",
        "'The client won't call requests.get(\"https://api.example.test/v1/data\")'\n",
        "Example: curl https://api.example.test/v1/data\n",
    ),
)
def test_incidental_or_prohibited_network_language_does_not_infer_capability(
    tmp_path: Path,
    content: str,
) -> None:
    home = tmp_path / "home"
    metadata = _metadata_for(_write_skill(home, content), home)

    assert "documentedCapabilities" not in metadata


def test_adapter_metadata_cannot_claim_documented_capabilities(tmp_path: Path) -> None:
    home = tmp_path / "home"
    path = _write_skill(home, "A local formatting skill.\n")

    metadata = enrich_skill_document_metadata(
        path.as_posix(),
        {
            "documentedCapabilities": [{"capability": "network_egress"}],
            "skillDocumentEvidence": {"rawContent": "untrusted"},
            "contentEvidence": {"rawContent": "untrusted"},
        },
        home_dir=home,
        workspace_dir=None,
    )
    expected_hash = hashlib.sha256(b"A local formatting skill.\n").hexdigest()

    assert "documentedCapabilities" not in metadata
    assert "skillDocumentEvidence" not in metadata
    assert metadata["contentEvidence"] == {
        "analysisVersion": "1",
        "readabilityStatus": "readable",
        "byteLength": 26,
        "contentHash": f"sha256:{expected_hash}",
        "schemaVersion": "guard.skill.content-evidence.v1",
        "evidenceAuthority": "device_claim",
        "affectsV4Score": False,
        "lineCount": 1,
        "headingCount": 0,
        "frontmatterPresent": False,
        "truncatedForAnalysis": False,
    }


def test_skill_document_evidence_contains_counts_but_no_content(tmp_path: Path) -> None:
    home = tmp_path / "home"
    content = "---\nname: private-demo\ndescription: Secret heading test\n---\n# Private heading\nBody\n"
    path = _write_skill(home, content)

    metadata = _metadata_for(path, home)

    assert metadata["contentEvidence"] == {
        "analysisVersion": "1",
        "readabilityStatus": "readable",
        "byteLength": len(content.encode("utf-8")),
        "contentHash": f"sha256:{hashlib.sha256(content.encode('utf-8')).hexdigest()}",
        "schemaVersion": "guard.skill.content-evidence.v1",
        "evidenceAuthority": "device_claim",
        "affectsV4Score": False,
        "lineCount": 6,
        "headingCount": 1,
        "frontmatterPresent": True,
        "truncatedForAnalysis": False,
    }
    encoded = json.dumps(metadata, sort_keys=True)
    assert "private-demo" not in encoded
    assert "Private heading" not in encoded
    assert path.as_posix() not in encoded


def test_multiple_explicit_signals_are_deduplicated(tmp_path: Path) -> None:
    home = tmp_path / "home"
    path = _write_skill(
        home,
        "curl https://api.example.test/v1/data\nThis skill calls the remote API.\n",
    )

    metadata = _metadata_for(path, home)

    assert len(cast(list[object], metadata["documentedCapabilities"])) == 1


def test_symlinked_skill_document_is_not_read(tmp_path: Path) -> None:
    home = tmp_path / "home"
    target = _write_skill(home, "curl https://secret.example.test/v1/data\n")
    link = home / ".codex" / "skills" / "linked" / "SKILL.md"
    link.parent.mkdir(parents=True)
    link.symlink_to(target)

    metadata = _metadata_for(link, home)

    assert metadata["contentEvidence"] == {
        "analysisVersion": "1",
        "readabilityStatus": "symlink_rejected",
    }
    assert "documentedCapabilities" not in metadata


def test_symlinked_skill_directory_is_not_read(tmp_path: Path) -> None:
    home = tmp_path / "home"
    real_skill_dir = home / ".codex" / "real-skills" / "linked"
    real_skill_dir.mkdir(parents=True)
    (real_skill_dir / "SKILL.md").write_text(
        "curl https://secret.example.test/v1/data\n",
        encoding="utf-8",
    )
    linked_skill_dir = home / ".codex" / "skills" / "linked"
    linked_skill_dir.parent.mkdir(parents=True)
    linked_skill_dir.symlink_to(real_skill_dir, target_is_directory=True)

    metadata = _metadata_for(linked_skill_dir / "SKILL.md", home)

    assert metadata["contentEvidence"] == {
        "analysisVersion": "1",
        "readabilityStatus": "symlink_rejected",
    }
    assert "documentedCapabilities" not in metadata


def test_skill_document_outside_skills_root_is_not_read(tmp_path: Path) -> None:
    home = tmp_path / "home"
    path = home / ".codex" / "demo" / "SKILL.md"
    path.parent.mkdir(parents=True)
    path.write_text("curl https://secret.example.test/v1/data\n", encoding="utf-8")

    metadata = _metadata_for(path, home)

    assert metadata["contentEvidence"] == {
        "analysisVersion": "1",
        "readabilityStatus": "not_primary_skill_document",
    }
    assert "documentedCapabilities" not in metadata


def test_skill_document_outside_safe_roots_is_not_read(tmp_path: Path) -> None:
    home = tmp_path / "home"
    outside = _write_skill(tmp_path / "outside", "curl https://secret.example.test/v1/data\n")

    metadata = _metadata_for(outside, home)

    assert metadata["contentEvidence"] == {
        "analysisVersion": "1",
        "readabilityStatus": "outside_safe_roots",
    }
    assert "documentedCapabilities" not in metadata


def test_oversized_skill_document_is_not_read(tmp_path: Path) -> None:
    home = tmp_path / "home"
    path = _write_skill(home, "x" * (MAX_SKILL_DOCUMENT_BYTES + 1))

    metadata = _metadata_for(path, home)

    assert metadata["contentEvidence"] == {
        "analysisVersion": "1",
        "readabilityStatus": "too_large",
        "byteLength": MAX_SKILL_DOCUMENT_BYTES + 1,
    }
    assert "documentedCapabilities" not in metadata


def test_documented_behavior_serializes_separately_from_observed_capabilities(tmp_path: Path) -> None:
    home = tmp_path / "home"
    skill_path = _write_skill(
        home,
        "# Upload\nRun curl https://private-hostname.example.test/v1/upload?token=private-token\n",
    )
    detection = HarnessDetection(
        harness="codex",
        installed=True,
        command_available=True,
        config_paths=(skill_path.as_posix(),),
        artifacts=(
            GuardArtifact(
                artifact_id="codex:user:skill:demo",
                name="demo",
                harness="codex",
                artifact_type="skill",
                source_scope="user",
                config_path=skill_path.as_posix(),
            ),
        ),
    )

    snapshot = inventory_snapshot_from_detection(
        detection,
        generated_at="2026-07-10T00:00:00Z",
        home_dir=home,
    )
    item = next(item for item in snapshot.items if item.item_kind == "skill")
    encoded = json.dumps(serialize_inventory_snapshot(snapshot), sort_keys=True)
    payload = cast(dict[str, Any], serialize_inventory_snapshot(snapshot))

    assert item.capability_categories == ("unknown",)
    assert item.metadata["documentedCapabilities"] == [
        {
            "capability": "network_egress",
            "source": "skill_documentation",
            "confidence": "high",
            "evidenceCode": "explicit_http_client",
            "inferenceVersion": "1",
        }
    ]
    assert payload["items"][0]["capabilityCategories"] == ["unknown"]
    assert "private-hostname" not in encoded
    assert "private-token" not in encoded
    assert skill_path.as_posix() not in encoded


def test_skill_types_do_not_claim_observed_file_reading() -> None:
    assert _capabilities_for_artifact("skill", {}) == ("unknown",)
    assert _capabilities_for_artifact("skill_file", {}) == ("unknown",)


@pytest.mark.parametrize(
    "readability_status",
    ("symlink_rejected", "too_large", "invalid_utf8", "outside_safe_roots"),
)
def test_rejected_document_evidence_is_preserved_without_capabilities(
    readability_status: str,
) -> None:
    metadata = {
        "contentEvidence": {"readabilityStatus": readability_status},
        "documentedCapabilities": [{"capability": "network_egress"}],
    }

    assert _bind_skill_document_evidence(metadata, primary_content_hash=None) == {
        "contentEvidence": {"readabilityStatus": readability_status},
    }


def test_unbound_document_evidence_is_removed_before_inventory_serialization() -> None:
    metadata = {
        "contentEvidence": {"contentHash": "sha256:first"},
        "documentedCapabilities": [{"capability": "network_egress"}],
    }

    assert (
        _bind_skill_document_evidence(
            metadata,
            primary_content_hash="sha256:second",
        )
        == {}
    )
    assert (
        _bind_skill_document_evidence(
            metadata,
            primary_content_hash="sha256:first",
        )
        == metadata
    )
