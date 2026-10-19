"""Public stdlib-only SDK Bash sink relay; carries no product/key/oracle code."""
from __future__ import annotations

import argparse
import json
import socket
import sys


def decode_response(raw):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate contained execution response field")
            value[key] = item
        return value
    def nonfinite(value):
        raise ValueError("nonfinite contained execution response")
    return json.loads(raw, object_pairs_hook=unique, parse_constant=nonfinite)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--token", required=True)
    args = parser.parse_args()
    if len(args.token) != 64 or any(char not in "0123456789abcdef" for char in args.token):
        raise ValueError("exact controller-issued contained execution route required")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(940)
        connection.connect("/runtime/guard-hook/hook.sock")
        request = {"schema_version": "1.0", "operation": "execute-contained", "token": args.token}
        connection.sendall((json.dumps(request, separators=(",", ":")) + "\n").encode())
        output = bytearray()
        while not output.endswith(b"\n"):
            chunk = connection.recv(65536)
            if not chunk:
                raise ValueError("actual contained execution response truncated")
            output.extend(chunk)
            if len(output) > 2 * 1024 * 1024 or output.count(b"\n") > 1:
                raise ValueError("actual contained execution response exceeds frame budget")
    response = decode_response(output)
    if response.get("kind") != "actual-contained-result" or response.get("product_claims_authenticated") is not False:
        raise ValueError("controller contained execution response malformed")
    result = response["result"]
    if type(result.get("exit_code")) is not int or not -255 <= result["exit_code"] <= 255:
        raise ValueError("actual contained execution exit status unavailable")
    if not isinstance(result.get("stdout"), str) or not isinstance(result.get("stderr"), str):
        raise ValueError("actual contained execution output unavailable")
    sys.stdout.write(result["stdout"])
    sys.stderr.write(result["stderr"])
    return result["exit_code"] if result["exit_code"] >= 0 else 128 - result["exit_code"]


if __name__ == "__main__":
    raise SystemExit(main())
