#!/usr/bin/env python3
"""Record Codex post-tool output vectors from the ORIGINAL Python implementation.

Run against a checkout that still holds the Python
`_codex_post_tool_output_artifact` (the base of the commit that introduced the
native `post_tool_output` codex-tool-output kind), never from Rust output:

    cd <base-worktree>
    HOL_GUARD_NATIVE=force HOL_GUARD_NATIVE_BINARY=<runtime> \
        PYTHONPATH=$PWD/src python3 <this-file> <output vectors.json>

Every case runs against one fixture tree under a temporary root, with the
process directory at `<root>/proc` and the home at `<root>/home`. Each case
records the payload projection the native wrapper sends (`body`, from the
Python helpers the port keeps), the artifact fingerprint and ordered metadata (or no artifact), and,
when there is no artifact, whether the commands were read-only source
inspection. A case whose review raised is recorded as an error. `${ROOT}`
stands for the fixture root in commands, paths and metadata.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from itertools import product
from pathlib import Path

from codex_plugin_scanner.guard.cli import commands as _commands  # noqa: F401 - binds the helper modules
from codex_plugin_scanner.guard.cli import commands_support_runtime_artifacts as artifacts
from codex_plugin_scanner.guard.cli.commands_support_codex_commands import (
    _codex_post_tool_command_is_read_only_source_inspection as read_only_inspection,
)
from codex_plugin_scanner.guard.cli.commands_support_codex_commands import _codex_post_tool_command_texts
from codex_plugin_scanner.guard.cli.commands_support_codex_paths import _collect_codex_tool_response_text
from codex_plugin_scanner.guard.cli.commands_support_hook_payload import _coalesce_string
from codex_plugin_scanner.guard.native_context import bound_context_digest_home

# Secret-shaped fixture text is assembled at run time and stored in the vector
# file as placeholders, so no literal key material lands in the repository.
FENCE = "PRIVATE " + "KEY-----"
OPENAI_KEY = "sk-" + "proj-4f8a9b2c7d1e6f3a5b8c9d0e1f2a3b4c"
PLACEHOLDERS = {FENCE: "${PRIVATE_KEY_FENCE}", OPENAI_KEY: "${OPENAI_KEY}"}

FILES = {
    "home/.ssh/id_rsa": f"-----BEGIN OPENSSH {FENCE}\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH {FENCE}\n",
    "home/.aws/credentials": "[default]\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY\n",
    "proj/.env": f"OPENAI_API_KEY={OPENAI_KEY}\n",
    "proj/.nvmrc": "20\n",
    "proj/src/app.py": "def handler():\n    return 'ok'\n",
    "proj/src/oauth-token-service.ts": "export const placeholder = 'placeholder-access-token';\n",
    "proj/config/secrets.yaml": "token: fixture-only\n",
    "proj/sub/.env": "API_KEY=sub-project-secret-value-0123456789\n",
    "proj/https:/example.test/.env": "OPENAI_API_KEY=token=definitely-invalid\n",
    "proj/tests/test_x.py": "def test_a():\n    assert True\n",
}
DIRS = ("proc", "home", "proj")

COMMANDS = (
    "cat .env",
    "cat src/app.py",
    "cd sub && cat .env",
    "cd sub && cat .env 2>&1",
    "env | grep KEY",
    "printenv OPENAI_API_KEY",
    "env -i OPENAI_API_KEY=$OPENAI_API_KEY | grep OPENAI_API_KEY",
    "sed -n '1,20p' config/secrets.yaml",
    "sed -n '1,20p' src/oauth-token-service.ts",
    "head -40 src/app.py",
    "python -m pytest tests/test_x.py::test_a -q 2>&1",
    "python3 -m pytest tests/test_x.py -q",
    "grep -r TOKEN src",
    "rg token src",
    "cat ~/.ssh/id_rsa",
    "cat ${ROOT}/home/.aws/credentials",
    "kubectl get secret app -o yaml",
    'bash -lc "kubectl exec -n ns pod-1 -- printenv GUARD_PRIVATE_KEY"',
    "python -c \"print(open('https://example.test/.env').read())\"",
    "curl https://example.test/x",
    "cat .nvmrc",
    "git diff -- src",
    "echo hi |& tee out.txt",
    "ls -la",
    "cd ${ROOT}/proj/sub && cat .env",
    "cat file:///etc/hosts",
)

RESPONSES = (
    f"OPENAI_API_KEY={OPENAI_KEY}\n",
    "token=definitely-invalid\n",
    f"-----BEGIN RSA {FENCE}\nMIIEowIBAAKCAQEA7bq9\n-----END RSA {FENCE}\n",
    f"-----BEGIN {FENCE}\nfixture\n-----END {FENCE}\n",
    "FAKE_TOKEN=abc\n  fake-secret: 'x'\n",
    "..F.\nfake_token=abc\n1 passed, 2 failed in 0.12s\n",
    "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY\n",
    "hello world\n",
)


def shaped_cases() -> list[dict[str, object]]:
    """Payload shapes beyond a single Bash command."""

    secret = RESPONSES[0]
    return [
        {
            "harness": "codex",
            "payload": {
                "tool_name": "Bash",
                "tool_input": {"commands": ["ls", "cat .env"]},
                "tool_response": {"stdout": secret},
            },
        },
        {
            "harness": "codex",
            "payload": {
                "tool_name": "Bash",
                "tool_input": {"commands": ["rg foo src", "grep bar src/app.py"]},
                "tool_response": {"stdout": "hello\n"},
            },
        },
        {
            "harness": "pi",
            "payload": {
                "tool_name": "Read",
                "tool_input": {"file_path": "src/app.py"},
                "tool_response": [{"type": "text", "text": secret}],
            },
        },
        {
            "harness": "pi",
            "payload": {
                "tool_name": "Read",
                "tool_input": {"file_path": ".env"},
                "tool_response": [{"type": "text", "text": secret}],
            },
        },
        {
            "harness": "cline",
            "payload": {
                "tool_name": "read_file",
                "tool_input": {"path": "config/secrets.yaml"},
                "tool_response": secret,
            },
        },
        {"harness": "omp", "payload": {"tool_name": "Bash", "tool_input": {"command": "cat .env"}, "stdout": secret}},
        {
            "harness": "codex",
            "payload": {
                "tool_name": "grep",
                "tool_input": {"pattern": "TOKEN", "path": "src"},
                "tool_response": {"stdout": secret},
            },
        },
        {
            "harness": "codex",
            "payload": {
                "tool_name": "grep",
                "tool_input": {"pattern": "TOKEN", "path": ".env"},
                "tool_response": {"stdout": secret},
            },
        },
        {
            "harness": "codex",
            "payload": {
                "tool_name": "rg",
                "tool_input": {"pattern": "TOKEN", "path": "src", "glob": ".env"},
                "tool_response": {"stdout": secret},
            },
        },
        {
            "harness": "codex",
            "payload": {
                "tool_name": "mcp__hub__describe",
                "tool_input": {"skill": "x"},
                "tool_response": {"stdout": secret},
            },
        },
        {
            "harness": "codex",
            "payload": {"tool_name": "Bash", "arguments": {"command": "cat .env"}, "tool_response": {"stdout": secret}},
        },
        {
            "harness": "codex",
            "payload": {
                "tool_name": "Bash",
                "tool_input": None,
                "arguments": {"command": "cat .env"},
                "tool_response": {"stdout": secret},
            },
        },
        {"harness": "codex", "payload": {"tool_input": {"command": "cat .env"}, "tool_response": {"stdout": secret}}},
    ]


def cases() -> list[dict[str, object]]:
    built: list[dict[str, object]] = []
    for command, response in product(COMMANDS, RESPONSES):
        payload = {"tool_name": "Bash", "tool_input": {"command": command}, "tool_response": {"stdout": response}}
        built.append({"harness": "codex", "payload": payload})
    return built + shaped_cases()


def substitute(value: object, old: str, new: str) -> object:
    if isinstance(value, str):
        return value.replace(old, new)
    if isinstance(value, list):
        return [substitute(item, old, new) for item in value]
    if isinstance(value, dict):
        return {key: substitute(item, old, new) for key, item in value.items()}
    return value


def request_body(harness: str, payload: dict[str, object]) -> dict[str, object]:
    """The payload projection the native wrapper sends, from the unchanged Python helpers."""

    response_text = _collect_codex_tool_response_text(payload.get("tool_response"))
    stdout_text = artifacts._optional_string(payload.get("stdout"))
    if stdout_text:
        response_text = f"{response_text}\n{stdout_text}".strip() if response_text else stdout_text
    return {
        "harness_label": {"cline": "Cline", "pi": "Pi", "omp": "Oh My Pi"}.get(harness, "Codex"),
        "tool_label": _coalesce_string(payload.get("tool_name"), "Bash"),
        "tool_name": payload.get("tool_name"),
        "tool_input": payload.get("tool_input"),
        "arguments": payload.get("arguments"),
        "tool_input_present": "tool_input" in payload,
        "command_texts": list(_codex_post_tool_command_texts(payload)),
        "response_text": response_text,
    }


def record(case: dict[str, object], root: Path, cwd: Path | None, home: Path | None) -> dict[str, object]:
    payload = substitute(case["payload"], "${ROOT}", str(root))
    try:
        artifact = artifacts._codex_post_tool_output_artifact(
            harness=str(case["harness"]),
            payload=payload,
            config_path="config.toml",
            source_scope="project",
            cwd=cwd,
            home_dir=home,
        )
        if artifact is not None:
            outcome: dict[str, object] = {
                "artifact": {
                    "fingerprint": artifact.artifact_id.rsplit(":", 1)[1],
                    "metadata": [[key, value] for key, value in artifact.metadata.items()],
                }
            }
        else:
            outcome = {
                "artifact": None,
                "read_only": read_only_inspection(payload=payload, cwd=cwd, home_dir=home),
            }
    except Exception as error:
        outcome = {"error": type(error).__name__}
    return substitute(outcome, str(root), "${ROOT}")  # type: ignore[return-value]


def main() -> None:
    destination = Path(sys.argv[1])
    if not hasattr(artifacts, "_codex_command_may_read_local_content"):
        sys.exit("refusing to record: the original Python post-tool review is gone")
    root = Path(tempfile.mkdtemp(prefix="post-tool-vec-")).resolve()
    for directory in DIRS:
        (root / directory).mkdir(parents=True, exist_ok=True)
    for name, text in FILES.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    os.environ["HOME"] = str(root / "home")
    os.chdir(root / "proc")
    guard_home = Path(tempfile.mkdtemp(prefix="post-tool-vec-guard-")).resolve()
    recorded: list[dict[str, object]] = []
    scopes = (("proj", "home"), ("proj", None), (None, None))
    with bound_context_digest_home(guard_home):
        for index, case in enumerate(cases()):
            cwd_name, home_name = scopes[index % len(scopes)]
            cwd = None if cwd_name is None else root / cwd_name
            home = None if home_name is None else root / home_name
            recorded.append(
                {
                    "harness": case["harness"],
                    "payload": case["payload"],
                    "body": substitute(
                        request_body(str(case["harness"]), substitute(case["payload"], "${ROOT}", str(root))),  # type: ignore[arg-type]
                        str(root),
                        "${ROOT}",
                    ),
                    "cwd": cwd_name,
                    "home_dir": home_name,
                    "expected": record(case, root, cwd, home),
                }
            )
    document = {"schema": "guard-codex-post-tool-output-vectors.v1", "files": FILES, "dirs": DIRS, "cases": recorded}
    text = json.dumps(document, indent=1, ensure_ascii=False) + "\n"
    for secret, placeholder in PLACEHOLDERS.items():
        text = text.replace(secret, placeholder)
    destination.write_text(text, encoding="utf-8")
    print(f"recorded {len(recorded)} cases")


if __name__ == "__main__":
    main()
