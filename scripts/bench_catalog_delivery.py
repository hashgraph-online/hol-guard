"""Measure catalog delivery end to end and compare codecs on identical data.

Run with::

    HOL_GUARD_NATIVE_BINARY=rust/target/release/hol-guard-runtime \\
      uv run --no-sync python scripts/bench_catalog_delivery.py OUT.json \\
      [--protobuf-path DIR_WITH_PROTOBUF_RUNTIME]

A disposable Guard home and a loopback daemon are created for the run; no
installed Guard state is read or written. Workflows go through the real
daemon, resident and Rust read model. The codec comparison re-encodes the
exact v2 pages the daemon served, so every codec carries the same semantic
data; it never compares a smaller projection against a larger one.
Protobuf numbers come from ``scripts/catalog_delivery_bench.proto``, compiled
with ``protoc`` into a temporary directory. When ``protoc`` or the Python
protobuf runtime is unavailable the codec row is recorded as unverified.
"""

from __future__ import annotations

import argparse
import gzip
import importlib
import json
import os
import platform
import resource
import shutil
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from codex_plugin_scanner.guard.cli import extension_catalog_reads as reads
from codex_plugin_scanner.guard.daemon import catalog_v2_client
from codex_plugin_scanner.guard.daemon.catalog_v2_client import CatalogV2Client, extension_route
from codex_plugin_scanner.guard.daemon.client import GuardSurfaceDaemonClient
from codex_plugin_scanner.guard.daemon.manager import load_guard_daemon_auth_token
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.native_resident_client import close_native_residents
from codex_plugin_scanner.guard.store import GuardStore

PROTO = Path(__file__).with_name("catalog_delivery_bench.proto")


def _summary(samples: list[float]) -> dict[str, float]:
    ordered = sorted(samples)
    return {
        "n": len(ordered),
        "median_ms": round(statistics.median(ordered), 3),
        "p95_ms": round(ordered[min(len(ordered) - 1, int(len(ordered) * 0.95))], 3),
        "max_ms": round(ordered[-1], 3),
    }


def _timed(fn: Callable[[], object], iterations: int) -> tuple[list[float], object]:
    samples: list[float] = []
    result: object = None
    for _ in range(iterations):
        started = time.perf_counter()
        result = fn()
        samples.append((time.perf_counter() - started) * 1000)
    return samples, result


class _Meter:
    """Counts requests and response bytes through ``CatalogV2Client``."""

    def __init__(self) -> None:
        self.requests = 0
        self.bytes = 0
        self.not_modified = 0
        self._original = CatalogV2Client._request

    @contextmanager
    def measuring(self) -> Iterator[_Meter]:
        meter = self
        original = self._original

        def wrapped(client: CatalogV2Client, route: str, query: str, *, if_none_match: str | None):
            response = original(client, route, query, if_none_match=if_none_match)
            meter.requests += 1
            meter.bytes += response.size
            meter.not_modified += response.status == 304
            return response

        CatalogV2Client._request = wrapped  # type: ignore[method-assign]
        try:
            yield self
        finally:
            CatalogV2Client._request = original  # type: ignore[method-assign]


def _require_v2(meter: _Meter, row: str) -> None:
    """Fail the run when a CLI read fell back to v1 instead of the v2 client."""

    if meter.requests <= 0:
        raise RuntimeError(f"{row} made no v2 requests; the CLI fell back to v1")


def _process_rss() -> list[dict[str, object]]:
    """RSS of every descendant process, named, so resident memory is attributable."""

    completed = subprocess.run(["ps", "-axo", "pid=,ppid=,rss=,comm="], capture_output=True, text=True, check=False)
    rows = [line.split(None, 3) for line in completed.stdout.splitlines()]
    children: dict[int, list[tuple[int, int, str]]] = {}
    for pid, ppid, rss, comm in (row for row in rows if len(row) == 4):
        children.setdefault(int(ppid), []).append((int(pid), int(rss), Path(comm).name))
    found: list[dict[str, object]] = []
    pending = [os.getpid()]
    while pending:
        for pid, rss, name in children.get(pending.pop(), []):
            found.append({"pid": pid, "rss_kib": rss, "command": name})
            pending.append(pid)
    return found


def workflows(client: GuardSurfaceDaemonClient, iterations: int) -> dict[str, Any]:
    results: dict[str, Any] = {}
    started = time.perf_counter()
    cold = CatalogV2Client(client, timeout=30.0).get("index", "limit=50")
    results["cold_first_index_page_ms"] = round((time.perf_counter() - started) * 1000, 3)
    assert isinstance(cold.get("items"), list)

    samples, v1 = _timed(client.extension_control_catalog, iterations)
    v1_bytes = len(json.dumps(v1, separators=(",", ":")).encode())
    results["v1_full_catalog"] = {"approx_bytes": v1_bytes, **_summary(samples)}

    reader = CatalogV2Client(client)
    samples, _ = _timed(lambda: CatalogV2Client(client).get("index", "limit=50"), iterations)
    with _Meter().measuring() as meter:
        reader.get("index", "limit=50")
    results["v2_first_index_page"] = {"bytes": meter.bytes, **_summary(samples)}
    samples, _ = _timed(lambda: reader.get("index", "limit=50"), iterations)
    with _Meter().measuring() as meter:
        reader.get("index", "limit=50")
    results["v2_revalidate_unchanged"] = {"bytes": meter.bytes, "status_304": meter.not_modified, **_summary(samples)}

    samples, listing = _timed(lambda: reads.catalog_list(client), iterations)
    with _Meter().measuring() as meter:
        reads.catalog_list(client)
    _require_v2(meter, "cli_list_v2")
    results["cli_list_v2"] = {"requests": meter.requests, "bytes": meter.bytes, **_summary(samples)}

    extensions = listing["extensions"]  # type: ignore[index]
    largest = max(extensions, key=lambda item: item["rule_count"] + item["permission_count"])["extension_id"]
    samples, _ = _timed(lambda: reads.catalog_show(client, largest), iterations)
    with _Meter().measuring() as meter:
        reads.catalog_show(client, largest)
    _require_v2(meter, "cli_show_largest_v2")
    results["cli_show_largest_v2"] = {
        "extension_id": largest,
        "requests": meter.requests,
        "bytes": meter.bytes,
        **_summary(samples),
    }

    samples, _ = _timed(lambda: reads.pattern_extensions(client, None), max(3, iterations // 4))
    with _Meter().measuring() as meter:
        reads.pattern_extensions(client, None)
    _require_v2(meter, "cli_patterns_all_v2")
    results["cli_patterns_all_v2"] = {"requests": meter.requests, "bytes": meter.bytes, **_summary(samples)}
    samples, _ = _timed(lambda: reads.pattern_extensions(client, None, "git push"), iterations)
    with _Meter().measuring() as meter:
        reads.pattern_extensions(client, None, "git push")
    _require_v2(meter, "cli_patterns_query_git_push_v2")
    results["cli_patterns_query_git_push_v2"] = {"requests": meter.requests, "bytes": meter.bytes, **_summary(samples)}

    def export() -> list[dict[str, object]]:
        export_reader = CatalogV2Client(client)
        return [catalog_v2_client.v1_extension_from_v2(export_reader, item["extension_id"]) for item in extensions]

    samples, exported = _timed(export, max(3, iterations // 4))
    with _Meter().measuring() as meter:
        export()
    _require_v2(meter, "full_export_v2_cold_cache")
    results["full_export_v2_cold_cache"] = {
        "extensions": len(exported),  # type: ignore[arg-type]
        "requests": meter.requests,
        "bytes": meter.bytes,
        **_summary(samples),
    }

    threads, per_thread = 8, max(10, iterations)
    concurrent: list[float] = []
    lock = threading.Lock()

    def worker() -> None:
        local = CatalogV2Client(client)
        timings, _ = _timed(lambda: local._request("index", "limit=50", if_none_match=None), per_thread)
        with lock:
            concurrent.extend(timings)

    started = time.perf_counter()
    pool = [threading.Thread(target=worker) for _ in range(threads)]
    for thread in pool:
        thread.start()
    for thread in pool:
        thread.join()
    wall = time.perf_counter() - started
    results["concurrent_first_page"] = {
        "threads": threads,
        "requests": len(concurrent),
        "requests_per_second": round(len(concurrent) / wall, 1),
        **_summary(concurrent),
    }
    return results


def collect_pages(client: GuardSurfaceDaemonClient) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """The exact v2 index and permission pages the daemon served."""

    reader = CatalogV2Client(client)
    index_pages: list[dict[str, Any]] = []
    cursor: str | None = None
    while True:
        query = "limit=100" + (f"&cursor={cursor}" if cursor else "")
        page = reader.get("index", query)
        index_pages.append(page)
        cursor = page.get("next_cursor")  # type: ignore[assignment]
        if cursor is None:
            break
    permission_pages: list[dict[str, Any]] = []
    for page in index_pages:
        for item in page["items"]:
            cursor = None
            while True:
                query = "limit=100" + (f"&cursor={cursor}" if cursor else "")
                body = reader.get(extension_route(item["extension_id"], "permissions"), query)
                permission_pages.append(body)
                cursor = body.get("next_cursor")  # type: ignore[assignment]
                if cursor is None:
                    break
    return index_pages, permission_pages


def _load_protobuf(protobuf_path: Path | None, scratch: Path) -> tuple[Any | None, str | None]:
    protoc = shutil.which("protoc")
    if protoc is None:
        return None, "protoc not found"
    if protobuf_path is not None:
        sys.path.insert(0, str(protobuf_path))
    try:
        protobuf = importlib.import_module("google.protobuf")
    except ImportError:
        return None, "python protobuf runtime not importable"
    subprocess.run(
        [protoc, f"--proto_path={PROTO.parent}", f"--python_out={scratch}", str(PROTO)],
        check=True,
    )
    sys.path.insert(0, str(scratch))
    module = importlib.import_module("catalog_delivery_bench_pb2")
    module.__dict__["_runtime_version"] = protobuf.__version__
    return module, None


_PAGE_SCALARS = ("schema_version", "snapshot_id", "native_catalog_digest", "limit", "total_count")
_SUMMARY_LISTS = ("action_classes", "aliases", "ecosystem_ids", "executables")


def _summary_to_pb(pb: Any, item: dict[str, Any]) -> Any:
    message = pb.ExtensionSummary(
        extension_id=item["extension_id"],
        name=item["name"],
        permission_count=item["permission_count"],
        required=item["required"],
        risk_classes=item["risk_classes"],
        rule_count=item["rule_count"],
        source=item["source"],
        trust_class=item["trust_class"],
        version=item["version"],
        content_revision=item["content_revision"],
        description=item["description"],
        **{key: item[key] for key in _SUMMARY_LISTS},
        icon=pb.Icon(**item["icon"]),
        catalog_defaults=pb.CatalogDefaults(**item["catalog_defaults"]),
        publisher=pb.Publisher(
            id=item["publisher"]["id"],
            display_name=item["publisher"]["displayName"],
            **({"url": item["publisher"]["url"]} if "url" in item["publisher"] else {}),
        ),
    )
    if "surface" in item:
        message.surface = item["surface"]
    return message


def _summary_from_pb(message: Any) -> dict[str, Any]:
    icon: dict[str, Any] = {"kind": message.icon.kind}
    for key in ("name", "background"):
        if message.icon.HasField(key):
            icon[key] = getattr(message.icon, key)
    publisher: dict[str, Any] = {"displayName": message.publisher.display_name, "id": message.publisher.id}
    if message.publisher.HasField("url"):
        publisher["url"] = message.publisher.url
    item: dict[str, Any] = {
        "catalog_defaults": {
            "activation": message.catalog_defaults.activation,
            "enabled": message.catalog_defaults.enabled,
        },
        "content_revision": message.content_revision,
        "description": message.description,
        "extension_id": message.extension_id,
        "icon": icon,
        "name": message.name,
        "permission_count": message.permission_count,
        "publisher": publisher,
        "required": message.required,
        "risk_classes": list(message.risk_classes),
        "rule_count": message.rule_count,
        "source": message.source,
        "trust_class": message.trust_class,
        "version": message.version,
        **{key: list(getattr(message, key)) for key in _SUMMARY_LISTS},
    }
    if message.HasField("surface"):
        item["surface"] = message.surface
    return item


_PERMISSION_OPTIONAL = ("family", "fixed_reason", "replacement_permission_id")


def _permission_to_pb(pb: Any, item: dict[str, Any]) -> Any:
    fields = {key: value for key, value in item.items() if key not in _PERMISSION_OPTIONAL}
    message = pb.Permission(**fields)
    for key in _PERMISSION_OPTIONAL:
        if item.get(key) is not None:
            setattr(message, key, item[key])
    return message


def _permission_from_pb(message: Any) -> dict[str, Any]:
    item: dict[str, Any] = {}
    for field in message.DESCRIPTOR.fields:
        value = getattr(message, field.name)
        if field.name in _PERMISSION_OPTIONAL:
            item[field.name] = value if message.HasField(field.name) else None
        elif field.is_repeated:
            item[field.name] = list(value)
        else:
            item[field.name] = value
    return item


def _page_to_pb(pb: Any, page: dict[str, Any], *, permissions: bool) -> Any:
    message = (pb.PermissionPage if permissions else pb.IndexPage)(**{key: page[key] for key in _PAGE_SCALARS})
    if permissions:
        message.extension_id = page["extension_id"]
        message.items.extend(_permission_to_pb(pb, item) for item in page["items"])
    else:
        message.items.extend(_summary_to_pb(pb, item) for item in page["items"])
    if page["next_cursor"] is not None:
        message.next_cursor = page["next_cursor"]
    return message


def _page_from_pb(message: Any, *, permissions: bool) -> dict[str, Any]:
    page: dict[str, Any] = {key: getattr(message, key) for key in _PAGE_SCALARS}
    if permissions:
        page["extension_id"] = message.extension_id
        page["items"] = [_permission_from_pb(item) for item in message.items]
    else:
        page["items"] = [_summary_from_pb(item) for item in message.items]
    page["next_cursor"] = message.next_cursor if message.HasField("next_cursor") else None
    return page


def _validate(page: dict[str, Any]) -> None:
    catalog_v2_client._page_fields(page)


def _codec_row(
    name: str,
    pages: list[dict[str, Any]],
    *,
    permissions: bool,
    pb: Any | None,
    unavailable: str | None,
    iterations: int,
) -> dict[str, Any]:
    compact = [json.dumps(page, separators=(",", ":"), sort_keys=True).encode() for page in pages]
    pretty = [json.dumps(page, indent=2, sort_keys=True).encode() for page in pages]
    row: dict[str, Any] = {
        "pages": len(pages),
        "items": sum(len(page["items"]) for page in pages),
        "json_pretty_bytes": sum(map(len, pretty)),
        "json_compact_bytes": sum(map(len, compact)),
        "gzip6_compact_bytes": sum(len(gzip.compress(body, 6)) for body in compact),
    }
    samples, _ = _timed(lambda: [json.dumps(p, separators=(",", ":"), sort_keys=True) for p in pages], iterations)
    row["json_encode"] = _summary(samples)
    samples, _ = _timed(lambda: [json.loads(body) for body in compact], iterations)
    row["json_decode"] = _summary(samples)
    samples, _ = _timed(lambda: [_validate(json.loads(body)) for body in compact], iterations)
    row["json_decode_validate"] = _summary(samples)
    samples, _ = _timed(lambda: [gzip.decompress(gzip.compress(body, 6)) for body in compact], iterations)
    row["gzip6_compress_decompress"] = _summary(samples)
    if pb is None:
        row["protobuf"] = {"verified": False, "reason": unavailable}
        return row
    messages = [_page_to_pb(pb, page, permissions=permissions) for page in pages]
    encoded = [message.SerializeToString(deterministic=True) for message in messages]
    page_type = pb.PermissionPage if permissions else pb.IndexPage
    roundtrip = [_page_from_pb(page_type.FromString(body), permissions=permissions) for body in encoded]
    assert roundtrip == pages, f"{name}: protobuf round trip lost semantic data"
    encode, _ = _timed(lambda: [message.SerializeToString(deterministic=True) for message in messages], iterations)
    decode, _ = _timed(lambda: [page_type.FromString(body) for body in encoded], iterations)
    convert, _ = _timed(
        lambda: [_validate(_page_from_pb(page_type.FromString(body), permissions=permissions)) for body in encoded],
        iterations,
    )
    row["protobuf"] = {
        "verified": True,
        "semantic_round_trip_equal": True,
        "bytes": sum(map(len, encoded)),
        "gzip6_bytes": sum(len(gzip.compress(body, 6)) for body in encoded),
        "encode": _summary(encode),
        "decode": _summary(decode),
        "decode_convert_validate": _summary(convert),
    }
    return row


def codecs(
    index_pages: list[dict[str, Any]],
    permission_pages: list[dict[str, Any]],
    protobuf_path: Path | None,
    iterations: int,
) -> dict[str, Any]:
    results: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="catalog-bench-pb-") as scratch:
        pb, unavailable = _load_protobuf(protobuf_path, Path(scratch))
        if pb is not None:
            results["protobuf_toolchain"] = {
                "runtime": pb.__dict__["_runtime_version"],
                "generated_module_bytes": Path(scratch, "catalog_delivery_bench_pb2.py").stat().st_size,
                "requires": "protoc at build time, protobuf runtime in every consumer",
            }
        for name, pages, permissions in (
            ("index_pages", index_pages, False),
            ("permission_pages", permission_pages, True),
        ):
            results[name] = _codec_row(
                name, pages, permissions=permissions, pb=pb, unavailable=unavailable, iterations=iterations
            )
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("output", type=Path)
    parser.add_argument("--iterations", type=int, default=20)
    parser.add_argument("--protobuf-path", type=Path)
    args = parser.parse_args()
    binary = os.environ.get("HOL_GUARD_NATIVE_BINARY")
    if not binary or not Path(binary).is_file():
        raise SystemExit("set HOL_GUARD_NATIVE_BINARY to a built hol-guard-runtime")
    os.environ["HOL_GUARD_NATIVE"] = "force"
    report: dict[str, Any] = {
        "environment": {
            "platform": platform.platform(),
            "machine": platform.machine(),
            "python": platform.python_version(),
            "cpu_count": os.cpu_count(),
            "native_binary": Path(binary).name,
            "native_binary_bytes": Path(binary).stat().st_size,
        },
        "iterations": args.iterations,
    }
    with tempfile.TemporaryDirectory(prefix="catalog-bench-home-") as home:
        store = GuardStore(Path(home) / "guard-home")
        started = time.perf_counter()
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()
        report["daemon_start_ms"] = round((time.perf_counter() - started) * 1000, 3)
        try:
            token = load_guard_daemon_auth_token(store.guard_home)
            assert token is not None
            client = GuardSurfaceDaemonClient(f"http://127.0.0.1:{daemon.port}", token)
            report["workflows"] = workflows(client, args.iterations)
            report["memory_kib"] = {
                "bench_process_max_rss": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss // 1024,
                "descendants": _process_rss(),
            }
            index_pages, permission_pages = collect_pages(client)
            report["codecs"] = codecs(index_pages, permission_pages, args.protobuf_path, args.iterations)
        finally:
            daemon.stop()
            close_native_residents(store.guard_home)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
