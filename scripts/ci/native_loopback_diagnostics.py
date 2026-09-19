"""Read-only evidence for whether macOS selected the exact PTR fixture.

Never export another resolver's names, addresses, or raw scutil output. The
direct UDP probe proves the private responder independently of system lookup;
its packet is counted separately from actual resolver traffic.
"""

from __future__ import annotations

import hashlib
import os
import re
import socket
import stat
import struct
import subprocess
from pathlib import Path

if __package__:
    from .native_loopback_dns import RESOLVER_DIRECTORY, REVERSE_NAME, ptr_response, resolver_configuration
else:
    from native_loopback_dns import RESOLVER_DIRECTORY, REVERSE_NAME, ptr_response, resolver_configuration

_MAX_CONFIGURATION_BYTES = 256 * 1024


def owned_configuration(port: int, owner: str, *, directory: Path = RESOLVER_DIRECTORY) -> dict[str, object]:
    expected = resolver_configuration(port, owner)
    try:
        fd = os.open(directory / REVERSE_NAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as handle:
            metadata = os.fstat(handle.fileno())
            if not stat.S_ISREG(metadata.st_mode):
                return {"status": "not_regular", "owned_bytes_match": False}
            content = handle.read(len(expected) + 1)
    except FileNotFoundError:
        return {"status": "absent", "owned_bytes_match": False}
    except OSError:
        return {"status": "unavailable", "owned_bytes_match": False}
    return {
        "status": "read",
        "owned_bytes_match": content == expected and metadata.st_size == len(expected),
        "configuration_sha256": hashlib.sha256(content).hexdigest(),
        "root_owned": metadata.st_uid == 0,
        "group_world_writable": bool(metadata.st_mode & 0o022),
    }


def selected_configuration(text: str, port: int) -> dict[str, object]:
    if len(text.encode("utf-8")) > _MAX_CONFIGURATION_BYTES:
        return {"status": "size_limit", "zone_present": False, "exact_resolver_selected": False}
    matching = selected = 0
    for block in re.split(r"(?m)^resolver #\d+\s*$", text)[1:]:
        domains = re.findall(r"(?m)^\s*domain\s*:\s*(\S+)\s*$", block)
        if domains != [REVERSE_NAME]:
            continue
        matching += 1
        addresses = re.findall(r"(?m)^\s*nameserver\[\d+\]\s*:\s*(\S+)\s*$", block)
        ports = re.findall(r"(?m)^\s*port\s*:\s*(\d+)\s*$", block)
        if addresses == ["127.0.0.1"] and ports == [str(port)]:
            selected += 1
    return {
        "status": "parsed",
        "zone_present": matching > 0,
        "matching_zone_count": matching,
        "exact_resolver_selected": selected > 0,
        "selected_zone_count": selected,
    }


def system_configuration(port: int) -> dict[str, object]:
    try:
        result = subprocess.run(["/usr/sbin/scutil", "--dns"], capture_output=True, timeout=5, check=False)
        if result.returncode == 0:
            return selected_configuration(result.stdout.decode("utf-8", errors="strict"), port)
    except subprocess.TimeoutExpired:
        return {"status": "deadline_exceeded", "zone_present": False, "exact_resolver_selected": False}
    except (OSError, UnicodeError):
        pass
    return {"status": "unavailable", "zone_present": False, "exact_resolver_selected": False}


def responder_probe(port: int) -> dict[str, object]:
    labels = b"".join(bytes((len(label),)) + label.encode("ascii") for label in REVERSE_NAME.split(".")) + b"\0"
    packet = struct.pack("!6H", 317, 0x0100, 1, 0, 0, 0) + labels + struct.pack("!HH", 12, 1)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(1)
            client.sendto(packet, ("127.0.0.1", port))
            response, peer = client.recvfrom(513)
            passed = peer == ("127.0.0.1", port) and response == ptr_response(packet)
        return {"passed": passed, "status": "completed", "requests": 1}
    except OSError:
        return {"passed": False, "status": "unavailable", "requests": 1}
