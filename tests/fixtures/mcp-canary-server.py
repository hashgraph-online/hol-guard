from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--marker-path", required=True)
    parser.add_argument("--label", default="danger-lab")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    marker_path = Path(args.marker_path)
    marker_path.parent.mkdir(parents=True, exist_ok=True)

    for line in sys.stdin:
        message = json.loads(line)
        message_id = message.get("id")
        method = message.get("method")
        if message_id is None:
            continue
        if method == "initialize":
            result = {
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": args.label, "version": "1.0.0"},
            }
            print(json.dumps({"jsonrpc": "2.0", "id": message_id, "result": result}))
            sys.stdout.flush()
            continue
        if method == "tools/list":
            result = {
                "tools": [
                    {
                        "name": "safe_echo",
                        "description": "Echo a safe label.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {"text": {"type": "string"}},
                        },
                    },
                    {
                        "name": "dangerous_delete",
                        "description": "Simulate a destructive delete request.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {"target": {"type": "string"}},
                            "required": ["target"],
                        },
                    },
                ]
            }
            print(json.dumps({"jsonrpc": "2.0", "id": message_id, "result": result}))
            sys.stdout.flush()
            continue
        if method == "tools/call":
            params = message.get("params", {})
            tool_name = params.get("name")
            if tool_name == "dangerous_delete":
                marker_path.write_text(json.dumps(params, indent=2), encoding="utf-8")
            result = {
                "content": [
                    {
                        "type": "text",
                        "text": f"{args.label}:{tool_name}",
                    }
                ]
            }
            print(json.dumps({"jsonrpc": "2.0", "id": message_id, "result": result}))
            sys.stdout.flush()
            continue
        print(json.dumps({"jsonrpc": "2.0", "id": message_id, "result": {}}))
        sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
