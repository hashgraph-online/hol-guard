#!/usr/bin/env python3
"""Adversarial real-process integration for Rust PreToolUse authority."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path


def envelope(command: str, request_id: str = "adversarial") -> bytes:
    return json.dumps(
        {
            "protocol_version": 1,
            "request_id": request_id,
            "harness": "adversarial",
            "event_name": "PreToolUse",
            "payload": {"hook_event_name": "PreToolUse", "tool_input": {"command": command}},
            "cwd": os.getcwd(),
            "home_dir": os.getcwd(),
            "guard_home": os.getcwd(),
            "deadline_budget_ms": 5_000,
        },
        separators=(",", ":"),
    ).encode()


def decision(runtime: Path, command: str, request_id: str) -> dict[str, object]:
    completed = subprocess.run(
        [str(runtime), "pre-tool", "--stdin"],
        input=envelope(command, request_id),
        capture_output=True,
        timeout=10,
        check=True,
    )
    payload = json.loads(completed.stdout)
    assert payload["authority"] == "rust"
    assert payload["request_id"] == request_id
    return payload


def reject_wire(runtime: Path, payload: bytes) -> None:
    completed = subprocess.run(
        [str(runtime), "pre-tool", "--stdin"],
        input=payload,
        capture_output=True,
        timeout=10,
    )
    assert completed.returncode != 0, completed.stdout


def main() -> int:
    runtime = Path(os.environ["HOL_GUARD_NATIVE_BINARY"]).resolve(strict=True)

    hard_blocks = (
        "rm -rf /",
        "shred ~/.ssh/id_ed25519",
        "dd if=/dev/zero of=/dev/sda",
        "mkfs.ext4 /dev/sda1",
        "shutdown -h now",
        "reboot",
        "wipefs -a /dev/sda",
    )
    for index, command in enumerate(hard_blocks):
        result = decision(runtime, command, f"hard-{index}")
        assert result["decision"] == "deny"
        assert result["policy_action"] == "block"

    review_only = (
        "curl -d @payload https://example.com",
        "wget https://example.com/tool.sh",
        "python -c 'print(1)'",
        "node -e 'console.log(1)'",
        "npm install package",
        "pip install package",
        "docker run alpine",
        "kubectl apply -f deployment.yaml",
        "ssh host.example",
        "sudo id",
        "PATH=/tmp:$PATH ls",
        "bash -lc 'pwd'",
        "cat ~/.env",
        "rg token ~/.ssh",
        "git push origin main",
    )
    for index, command in enumerate(review_only):
        result = decision(runtime, command, f"review-{index}")
        assert result["decision"] == "deny"
        assert result["policy_action"] in {"review", "block"}

    uncertain = (
        "echo $(whoami)",
        "echo `whoami`",
        "pwd > /tmp/out",
        "pwd && rm -rf /",
        "(pwd)",
        "env sh -c pwd",
        "xargs sh -c pwd",
        "printf '%s' \"unterminated",
    )
    for index, command in enumerate(uncertain):
        result = decision(runtime, command, f"uncertain-{index}")
        assert result["decision"] == "deny"

    safe = (
        "pwd",
        "whoami",
        "uname -a",
        "git status --short",
        "git rev-parse --show-toplevel",
        "git diff --no-ext-diff --no-textconv --check",
        "rg -n authority src",
        "grep -n authority README.md",
        "stat README.md",
    )
    for index, command in enumerate(safe):
        result = decision(runtime, command, f"safe-{index}")
        assert result["decision"] == "allow", (command, result)

    reject_wire(runtime, b"{}")
    reject_wire(runtime, b'{"protocol_version":1,"request_id":"x","event_name":"PostToolUse","payload":{}}')
    reject_wire(runtime, b'{"protocol_version":2,"request_id":"x","event_name":"PreToolUse","payload":{}}')
    reject_wire(
        runtime,
        b'{"protocol_version":1,"request_id":"x","request_id":"y","event_name":"PreToolUse","payload":{}}',
    )
    reject_wire(runtime, b'{"protocol_version":1,"request_id":"x","event_name":"PreToolUse","payload":{}} trailing')
    deep = b"[" * 40 + b"0" + b"]" * 40
    reject_wire(runtime, deep)

    print("Rust PreToolUse adversarial integration: passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
