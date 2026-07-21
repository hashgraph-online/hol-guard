"""Contracts for immutable alpha container publication."""

from pathlib import Path

import yaml

PUBLISH_WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "publish.yml"


def test_container_refuses_to_mutate_an_existing_alpha_image() -> None:
    workflow = yaml.safe_load(PUBLISH_WORKFLOW.read_text(encoding="utf-8"))
    steps = workflow["jobs"]["publish-container"]["steps"]
    inspect_step = next(step for step in steps if step.get("name") == "Inspect existing immutable image")
    publish_step = next(step for step in steps if str(step.get("uses", "")).startswith("docker/build-push-action@"))

    assert inspect_step["env"]["CHANNEL"] == "${{ needs.build.outputs.channel }}"
    assert 'docker pull "$image"' in inspect_step["run"]
    assert '"$CHANNEL" != "alpha"' in inspect_step["run"]
    assert "org.opencontainers.image.revision" in inspect_step["run"]
    assert '"$revision" != "$SOURCE_SHA"' in inspect_step["run"]
    assert 'echo "push=false"' in inspect_step["run"]
    assert "manifest unknown" in inspect_step["run"]
    assert "Unable to determine whether the image tag already exists" in inspect_step["run"]
    assert publish_step["if"] == "steps.image.outputs.push == 'true'"
