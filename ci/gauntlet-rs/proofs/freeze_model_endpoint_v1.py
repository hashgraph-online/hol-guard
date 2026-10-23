"""Freeze local-route and model-advertisement outcomes from pinned Python."""

from __future__ import annotations

import hashlib
import json
import re
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
OUTPUT = ROOT / "ci/gauntlet-rs/crates/gauntlet-evidence/tests/fixtures/python_model_endpoint_v1.json"
MODEL_SOURCE_SHA256 = "82cf4f951340e0c9cc65315b31f042aef235d378a661d4b5246f36db29d3f302"
PREFLIGHT_SOURCE_SHA256 = "69f5d0368f5c763a047c554b2d9a31a63f169fd2bc8d13a14aa96d8a38a274d7"


def checked_source(path: Path, expected: str) -> None:
    if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
        raise SystemExit(f"pinned source changed: {path}")


def main() -> None:
    sys.path.insert(0, str(ROOT))
    # The cases exercise only the route and one-model condition. Supply small
    # import stubs for unrelated schema/asset code so the frozen source runs
    # without installing the full benchmark dependency set on the host.
    config_stub = types.ModuleType("ci.gauntlet.benchmark.ci_runner_config")
    config_stub.SHA = re.compile(r"[0-9a-f]{64}")
    config_stub.verify_assets = lambda _: None
    contracts_stub = types.ModuleType("ci.gauntlet.benchmark.contracts")
    contracts_stub.strict_json_loads = json.loads
    sys.modules[config_stub.__name__] = config_stub
    sys.modules[contracts_stub.__name__] = contracts_stub
    from ci.gauntlet.benchmark import ci_runner_preflight, model_endpoint

    checked_source(Path(model_endpoint.__file__), MODEL_SOURCE_SHA256)
    checked_source(Path(ci_runner_preflight.__file__), PREFLIGHT_SOURCE_SHA256)

    routes = []
    valid = [
        f"http://{host}:{port}/v1"
        for host in ("host.lima.internal", "localhost", "127.0.0.1", "192.168.5.2")
        for port in (8001, 8002)
    ]
    invalid = [
        "https://host.lima.internal:8001/v1",
        "http://host.lima.internal:8003/v1",
        "http://host.lima.internal.evil:8001/v1",
        "http://HOST.LIMA.INTERNAL:8001/v1",
        "http://localhost:8001/v1/",
        "http://localhost:8001/v1/models",
        "http://localhost:8001/v1?next=/v1",
        "http://user@localhost:8001/v1",
        "http://[::1]:8001/v1",
        "http://localhost/v1",
        "http://localhost:08001/v1",
    ]
    for url in valid + invalid:
        try:
            routes.append({"base_url": url, "route": model_endpoint.model_endpoint(url)})
        except ValueError as error:
            routes.append({"base_url": url, "python_refusal": str(error)})

    observed = []
    declarations = [
        ("legacy-default", valid[0], None),
        ("legacy-nondefault", valid[1], None),
        ("exact", valid[1], model_endpoint.model_endpoint(valid[1])),
        ("wrong-port", valid[1], {**model_endpoint.model_endpoint(valid[1]), "port": 8001}),
        ("extra-field", valid[1], {**model_endpoint.model_endpoint(valid[1]), "extra": 1}),
        ("wrong-kind", valid[1], "http://localhost:8002/v1"),
    ]
    for name, url, metadata in declarations:
        try:
            observed.append({"name": name, "base_url": url, "observed": metadata,
                             "route": model_endpoint.verify_model_endpoint(metadata, url)})
        except ValueError as error:
            observed.append({"name": name, "base_url": url, "observed": metadata,
                             "python_refusal": str(error)})

    model_id = "Qwen/Qwen3-Gauntlet-Synthetic"
    model_rows = [
        ("exact", {"data": [{"id": model_id}]}),
        ("extra-model-fields", {"data": [{"id": model_id, "object": "model"}], "object": "list"}),
        ("empty", {"data": []}),
        ("duplicate", {"data": [{"id": model_id}, {"id": model_id}]}),
        ("wrong-id", {"data": [{"id": "other"}]}),
        ("nonobject-row", {"data": [model_id]}),
        ("missing-data", {"object": "list"}),
        ("wrong-data-kind", {"data": {"id": model_id}}),
    ]
    models = []
    original_connection = ci_runner_preflight.http.client.HTTPConnection

    class FakeResponse:
        status = 200

        def __init__(self, body: bytes):
            self.body = body

        def read(self, limit: int) -> bytes:
            return self.body[:limit]

    class FakeConnection:
        def __init__(self, host: str, port: int, timeout: int):
            if (host, port, timeout) != ("192.168.5.2", 8001, 5):
                raise AssertionError("Python observer used an unexpected route")
            self.path = ""

        def request(self, method: str, path: str, headers: dict):
            if method != "GET" or headers != {"Connection": "close"}:
                raise AssertionError("Python observer used an unexpected request")
            self.path = path

        def getresponse(self):
            body = (current_model if self.path == "/v1/models" else {}).copy()
            return FakeResponse(json.dumps(body, sort_keys=True).encode())

        def close(self):
            pass

    try:
        ci_runner_preflight.http.client.HTTPConnection = FakeConnection
        for name, current_model in model_rows:
            try:
                result = ci_runner_preflight.observe_provider(
                    {"runtime": {"base_url": model_endpoint.DEFAULT_BASE_URL,
                                 "model_id": model_id}}, validate=False)
                models.append({"name": name, "models": current_model, "model_id": model_id,
                               "route": result["route"]})
            except ValueError as error:
                models.append({"name": name, "models": current_model, "model_id": model_id,
                               "python_refusal": str(error)})
    finally:
        ci_runner_preflight.http.client.HTTPConnection = original_connection

    OUTPUT.write_text(json.dumps({
        "schema": "gauntlet-model-endpoint-fixtures.v1",
        "model_endpoint_source_sha256": MODEL_SOURCE_SHA256,
        "preflight_source_sha256": PREFLIGHT_SOURCE_SHA256,
        "routes": routes,
        "observed": observed,
        "models": models,
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {len(routes)} routes, {len(observed)} observations, {len(models)} model cases")


if __name__ == "__main__":
    main()
