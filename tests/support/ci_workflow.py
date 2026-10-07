"""Inspect extracted CI actions without losing their calling job's contracts."""

from __future__ import annotations

import copy
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
PREFIX = "./.github/actions/ci-job-"


def expand_ci_job_actions(workflow: dict, root: Path = ROOT) -> dict:
    """Expand only the bounded, in-tree job actions, retaining symbolic contexts.

    Other actions remain normal uses steps so their existing dedicated contract
    tests still inspect their public inputs. No expression or shell is executed.
    """
    result = copy.deepcopy(workflow)
    for job in result.get("jobs", {}).values():
        expanded = []
        for step in job.get("steps", []):
            uses = step.get("uses", "")
            if not uses.startswith(PREFIX):
                expanded.append(step)
                continue
            suffix = uses.removeprefix(PREFIX)
            if not re.fullmatch(r"[a-z0-9-]+", suffix):
                raise ValueError("invalid CI job action path")
            action = yaml.safe_load((root / uses[2:] / "action.yml").read_text())
            if action["runs"]["using"] != "composite":
                raise ValueError("CI job action must be composite")
            supplied = step.get("with", {})
            definitions = action.get("inputs", {})
            if set(supplied) != set(definitions):
                raise ValueError("CI job action inputs must be explicit and complete")

            def substitute(value, bindings=supplied):
                """Resolve declared action inputs while leaving other GitHub expressions symbolic."""
                if isinstance(value, dict):
                    return {key: substitute(item) for key, item in value.items()}
                if isinstance(value, list):
                    return [substitute(item) for item in value]
                if not isinstance(value, str):
                    return value
                for key, binding in bindings.items():
                    value = value.replace("${{ inputs." + key + " }}", str(binding))
                    expression = str(binding)
                    if expression.startswith("${{ ") and expression.endswith(" }}"):
                        expression = expression[4:-3]
                    else:
                        expression = repr(binding)
                    value = re.sub(r"\binputs\." + re.escape(key) + r"(?![a-zA-Z0-9_-])", expression, value)
                if re.search(r"\binputs\.[a-zA-Z0-9_-]+", value):
                    raise ValueError("unbound CI job action input")
                return value

            expanded.extend(substitute(action["runs"]["steps"]))
        if "steps" in job:
            job["steps"] = expanded
    return result
