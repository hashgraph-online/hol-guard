"""Dashboard-session authorization cases for the daemon route vector recorder."""

from __future__ import annotations

import itertools

_SC_ACTIONS = {
    "/v1/supply-chain/package-shims": "package_shims_status",
    "/v1/supply-chain/entitlement": "supply_chain_entitlement",
    "/v1/supply-chain/bundle": "supply_chain_bundle",
    "/v1/supply-chain/repair": "package_shims_repair_all",
    "/v1/supply-chain/package-shims/activate": "package_shims_activate",
    "/v1/supply-chain/package-shims/install": "package_shims_install",
    "/v1/supply-chain/package-shims/repair": "package_shims_repair",
    "/v1/supply-chain/package-shims/test": "package_shims_test",
    "/v1/supply-chain/package-shims/uninstall": "package_shims_remove",
    "/v1/supply-chain/package-shims/remove": "package_shims_remove",
    "/v1/supply-chain/package-shims/open-shell": "package_shims_open-shell",
    "/v1/supply-chain/package-shims/connect": "package_shims_connect",
    "/v1/supply-chain/audit": "package_shims_audit",
    "/v1/supply-chain/sync": "package_shims_sync",
    "/v1/supply-chain/bogus": "package_shims_bogus",
    "/v1/supply-chain": "package_shims_none",
    "/v1/supply-chain/package-shims/install/extra": "package_shims_extra",
}


def session_cases(pr_surface: str) -> list[dict]:
    cases: list[dict] = []

    def add(name: str, method: str, path: str, claims: dict, payload: dict | None = None, **extra: str | None) -> None:
        raw = {"method": method, "path": path, "claims": claims, "payload": payload}
        raw["nonce_header"] = extra.get("nonce_header")
        raw["origin_header"] = extra.get("origin_header")
        cases.append({"kind": "session_authorize", "name": name, "raw": raw})

    pr_paths = [
        "/v1/runtime",
        "/v1/settings",
        "/v1/extension-controls/effective",
        "/v1/update/status",
        "/v1/initialize",
        "/v1/extension-controls/recover-authority",
        "/v1/policy",
        "/v1/settings/import",
        "/v1/hooks/codex/pre",
    ]
    for method, path in itertools.product(["GET", "POST", "DELETE"], pr_paths):
        add(
            f"session.protection_repair.{method}.{path}",
            method,
            path,
            {"surface": pr_surface},
            {} if method == "POST" else None,
        )
    s_paths = [
        "/v1/runtime",
        "/v1/capabilities",
        "/v1/policy",
        "/v1/settings/import",
        "/v1/requests",
        "/v1/requests/r1",
        "/v1/requests/r1/approve",
        "/v1/requests/r1/live-decision",
        "/v1/receipts/r1",
        "/v1/operations/o1/items",
        "/v1/sessions/s1/resume",
        "/v1/mcp-policy/requests/r/decision",
        "/v1/apps/connect",
        "/v1/apps/bogus",
        "/v1/supply-chain/package-shims",
        "/v1/extension-controls/inspect",
        "/v1/extension-controls/apply",
        "/v1/local-clis/apply",
        "/v1/hooks/codex/pre",
        "/v1/update",
        "/v1/artifacts/a/diff",
        "/",
        "/v1/unknown",
    ]
    for surface, method, path in itertools.product(
        ["approval-center", "dashboard", "cloud-dashboard"], ["GET", "POST"], s_paths
    ):
        add(f"session.local_surface.{surface}.{method}.{path}", method, path, {"surface": surface})
    for claims in [
        {},
        {"surface": "other"},
        {"surface": None},
        {"action_path": "  "},
        {"action_path": 5},
        {"surface": 7},
    ]:
        for path in ["/v1/runtime", "/v1/receipts", "/v1/apps/connect", "/v1/supply-chain/package-shims"]:
            add(f"session.local_surface.no_action_path.{path}.{sorted(claims.items())}", "GET", path, claims)
    for odd in ([5], "/v1/receipts", []):
        claims = {"action_path": "read", "allowed_read_paths": odd}
        add(f"session.scoped_read.odd.{odd}", "GET", "/v1/receipts", claims)
    allow = [None, ["/v1/receipts"], ["/v1/other"], ["/v1/receipts", 5]]
    for rp, nonce, header, body in itertools.product(
        allow,
        [None, "n1", "  "],
        [None, "n1", " n1 ", "bad", ""],
        [
            None,
            {},
            {"dashboard_session_nonce": "n1"},
            {"dashboard_session_nonce": "zz"},
            {"dashboard_session_nonce": 5},
        ],
    ):
        claims = {"action_path": "read", "allowed_read_paths": rp, "nonce": nonce}
        add(
            f"session.scoped_read.{rp}.{nonce!r}.{header!r}.{body}",
            "GET",
            "/v1/receipts",
            claims,
            body,
            nonce_header=header,
        )
    for method in ["POST", "DELETE"]:
        add(
            f"session.scoped_read.non_get.{method}",
            method,
            "/v1/receipts",
            {"action_path": "read", "allowed_read_paths": ["/v1/receipts"]},
            {},
        )
    full = {"action_path": "connect", "harness": "codex", "location_id": "loc1", "workspace_id": "ws1"}
    pay_full = {"harness": "codex", "location_id": "loc1", "workspace_id": "ws1"}
    payloads = [
        None,
        pay_full,
        {**pay_full, "harness": "other"},
        {k: v for k, v in pay_full.items() if k != "harness"},
        {**{k: v for k, v in pay_full.items() if k != "location_id"}, "locationId": "loc1"},
        {k: v for k, v in pay_full.items() if k != "location_id"},
        {**pay_full, "workspace_id": "ws2"},
        {k: v for k, v in pay_full.items() if k != "workspace_id"},
        {**pay_full, "harness": "  codex "},
        {**pay_full, "workspace_id": 5},
        {**pay_full, "workspaceId": "ws1", "workspace_id": ""},
    ]
    for app, action in itertools.product(
        ["connect", "repair", "status", "test", "disconnect"],
        ["connect", "repair", "status", "test", "disconnect", "other"],
    ):
        for index, body in enumerate(payloads):
            if index > 3 and app != action and action != "other":
                continue
            add(
                f"session.cloud_app.{app}.{action}.{index}",
                "POST",
                f"/v1/apps/{app}",
                {**full, "action_path": action},
                body,
            )
    for label, claims in {
        "no_loc": {k: v for k, v in full.items() if k != "location_id"},
        "no_ws": {k: v for k, v in full.items() if k != "workspace_id"},
        "no_harness": {k: v for k, v in full.items() if k != "harness"},
        "blank_harness": {**full, "harness": "  "},
    }.items():
        for index, body in enumerate(payloads):
            add(f"session.cloud_app.claims_{label}.{index}", "POST", "/v1/apps/connect", claims, body)
    add("session.cloud_app.get", "GET", "/v1/apps/connect", full, pay_full)
    for path, action in _SC_ACTIONS.items():
        for label, claims in {
            "action_path": {"action_path": action},
            "allowed_list": {"action_path": "zzz", "allowed_action_paths": [action]},
            "other_list": {"action_path": "zzz", "allowed_action_paths": ["zzz"]},
            "nonce": {"action_path": action, "nonce": "n1"},
            "bad_list": {"action_path": "zzz", "allowed_action_paths": action},
            "mixed_list": {"action_path": "zzz", "allowed_action_paths": [5, action]},
        }.items():
            for body in (None, {}):
                add(f"session.supply_chain.scope.{path}.{label}.{body}", "POST", path, claims, body)
    base = {"action_path": "package_shims_install"}
    path = "/v1/supply-chain/package-shims/install"

    def grid(snake: str, camel: str, values: list[str | None], tag: str) -> None:
        claim_opts = [{}, {snake: values[0]}, {camel: values[0]}, {snake: f" {values[0]} "}, {snake: "  "}]
        pay_opts = [
            {},
            {snake: values[0]},
            {camel: values[0]},
            {snake: values[1]},
            {snake: 5},
            {snake: "", camel: values[0]},
        ]
        for ci, cl in enumerate(claim_opts):
            for pi, pl in enumerate(pay_opts):
                for nonce in (None, "n1"):
                    claims = {**base, **cl, **({"nonce": nonce} if nonce else {})}
                    add(f"session.supply_chain.{tag}.c{ci}.p{pi}.{nonce}", "POST", path, claims, pl)

    grid("workspace_id", "workspaceId", ["ws1", "ws2"], "workspace")
    grid("location_id", "locationId", ["loc1", "loc2"], "location")
    origin = "http://127.0.0.1:5000"
    other = "http://127.0.0.1:6000"
    for ci, cl in enumerate(
        [
            {},
            {"daemon_origin": origin},
            {"daemonOrigin": origin},
            {"daemon_origin": f" {origin} "},
            {"daemon_origin": "  "},
        ]
    ):
        for pi, pl in enumerate(
            [{}, {"daemon_origin": origin}, {"daemonOrigin": origin}, {"daemon_origin": other}, {"daemon_origin": 5}]
        ):
            for oi, request_origin in enumerate([None, origin, other]):
                add(
                    f"session.supply_chain.daemon_origin.c{ci}.p{pi}.o{oi}",
                    "POST",
                    path,
                    {**base, **cl},
                    pl,
                    origin_header=request_origin,
                )
    for cl, body in itertools.product(
        [None, "str", [], ["npm"], ["npm", "pip"], ["npm", 5]],
        [
            ("absent", {}),
            ("null", {"managers": None}),
            ("str", {"managers": "npm"}),
            ("empty", {"managers": []}),
            ("npm", {"managers": ["npm"]}),
            ("pip", {"managers": ["pip"]}),
            ("both", {"managers": ["npm", "pip"]}),
            ("mixed", {"managers": ["npm", 5]}),
        ],
    ):
        claims = dict(base) if cl is None else {**base, "managers": cl}
        add(f"session.supply_chain.managers.{cl}.{body[0]}", "POST", path, claims, body[1])
    for name in ("package_shims_status", "supply_chain_bundle", "supply_chain_entitlement"):
        p = next(key for key, value in _SC_ACTIONS.items() if value == name)
        for body in (None, {}):
            add(f"session.supply_chain.bodyless.{name}.{body}", "GET", p, {"action_path": name}, body)
    return cases
