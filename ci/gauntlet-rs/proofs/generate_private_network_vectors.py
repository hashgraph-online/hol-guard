"""Freeze Python's loopback-only private-cell topology reader."""

from __future__ import annotations

import ast
import hashlib
import ipaddress
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / "ci/gauntlet/benchmark/product_vm_network.py"
OUTPUT = ROOT / "ci/gauntlet-rs/crates/gauntlet-evidence/tests/fixtures/private_network_v1.json"


def source_function():
    tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
    function = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                    and node.name == "validate_topology")
    scope = {"ipaddress": ipaddress}
    exec(compile(ast.fix_missing_locations(ast.Module(body=[function], type_ignores=[])),
                 str(SOURCE), "exec"), scope)
    return scope["validate_topology"]


def route4(destination="0000007F", gateway="00000000", mask="00FFFFFF", interface="lo"):
    return f"{interface} {destination} {gateway} 0001 0 0 0 {mask} 0 0 0"


def route6(destination="00000000000000000000000000000001", prefix="80", flags="00000001",
           interface="lo", nexthop="00000000000000000000000000000000"):
    return f"{destination} {prefix} {'0' * 32} 00 {nexthop} 00000000 00000000 00000001 {flags} {interface}"


def address6(address="00000000000000000000000000000001", interface="lo"):
    return f"{address} 01 80 10 80 {interface}"


def base():
    return {"devices": "lo: 0\n", "routes4": "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n"
            + route4() + "\n", "routes6": route6() + "\n", "addresses6": address6() + "\n"}


def cases():
    root = base()
    yield "valid-loopback", root

    def altered(name, **changes):
        return name, {**root, **changes}

    yield altered("valid-empty-routes", routes4="Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n",
                  routes6="", addresses6="")
    yield altered("valid-ipv6-reject-stub", routes6=route6(
        destination="0" * 32, prefix="00", flags="00000200") + "\n")
    yield altered("valid-crlf-devices", devices="lo: 0\r\n")
    yield altered("extra-interface", devices="lo: 0\neth0: 1\n")
    yield altered("missing-interface", devices="")
    yield altered("duplicate-loopback", devices="lo: 0\nlo: 1\n")
    yield altered("ipv4-wrong-interface", routes4=root["routes4"].replace("lo 0000007F", "eth0 0000007F"))
    yield altered("ipv4-nonloopback", routes4=root["routes4"].replace("0000007F", "0000000A"))
    yield altered("ipv4-gateway", routes4=root["routes4"].replace("00000000 0001", "0100007F 0001"))
    yield altered("ipv4-zero-mask", routes4=root["routes4"].replace("00FFFFFF", "00000000"))
    yield altered("ipv4-missing-field", routes4=root["routes4"].replace("0 0 0 00FFFFFF", "0 0 00FFFFFF"))
    yield altered("ipv6-wrong-interface", routes6=route6(interface="eth0") + "\n")
    yield altered("ipv6-next-hop", routes6=route6(nexthop="0" * 31 + "1") + "\n")
    yield altered("ipv6-unmarked-default", routes6=route6(destination="0" * 32, prefix="00") + "\n")
    yield altered("ipv6-nonloopback", routes6=route6(destination="0" * 31 + "2") + "\n")
    yield altered("ipv6-wrong-loopback-prefix", routes6=route6(prefix="40") + "\n")
    yield altered("ipv6-nonloopback-address", addresses6=address6(address="0" * 31 + "2") + "\n")
    yield altered("ipv6-address-wrong-interface", addresses6=address6(interface="eth0") + "\n")
    yield altered("ipv6-address-missing-field", addresses6="0" * 32 + " 01 80 10 lo\n")


def main():
    validate = source_function()
    rows = []
    for name, row in cases():
        try:
            result = validate(row["devices"], row["routes4"], row["routes6"], row["addresses6"])
            accepted, reason = True, None
        except ValueError as error:
            result, accepted, reason = None, False, str(error)
        rows.append({"name": name, **row, "accepted": accepted, "reason": reason, "result": result})
    OUTPUT.write_text(json.dumps({"schema": "gauntlet-python-private-network.v1",
                                  "source_sha256": hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
                                  "cases": rows}, sort_keys=True, separators=(",", ":")) + "\n",
                      encoding="utf-8")
    print(f"frozen {len(rows)} Python network cases: "
          f"{sum(row['accepted'] for row in rows)} accepted")


if __name__ == "__main__":
    main()
