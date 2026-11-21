"""Measure fresh-process native reuse of known offline compiler output.

This unsigned fixture supplies its own compiler-produced root for comparison.
It is not publication authentication, runtime activation or hook qualification.
Production builds instead obtain reuse through VerifiedCompilerReuse.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import resource
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import build_native_command_packs as packs
from benchmark_extension_delivery import source_tree
from command_pack_store import PackReader, publish_object
from extension_delivery_objects import encoded


def worker(compiler, source, cache, reuse):
    objects = cache / "objects"
    objects.mkdir(parents=True, exist_ok=True)
    identities = set()
    started = time.perf_counter()
    with tempfile.TemporaryFile() as input_data, tempfile.TemporaryFile() as errors:
        count = packs.input_stream(source, input_data, identities)
        arguments = [str(compiler), "compile-packs"]
        if reuse:
            digest = hashlib.sha256((cache / "release.json").read_bytes()).hexdigest()
            arguments = [str(compiler), "compile-packs-reuse", str(cache), digest]
        process = subprocess.Popen(arguments, stdin=input_data, stdout=subprocess.PIPE, stderr=errors)
        root = stats = None
        stream_digest = hashlib.sha256()
        try:
            while line := process.stdout.readline(packs.MAX_OUTPUT_LINE + 1):
                if len(line) > packs.MAX_OUTPUT_LINE or not line.endswith(b"\n"):
                    raise ValueError("compiler output exceeds record budget")
                row = json.loads(line)
                if row.get("kind") == "compilation":
                    if stats is not None:
                        raise ValueError("duplicate compilation report")
                    stats = row["stats"]
                    continue
                if root is not None:
                    raise ValueError("output follows completed release")
                stream_digest.update(line)
                if row.get("kind") == "root":
                    root = row
                elif row.get("kind") == "object":
                    data = base64.b64decode(row["data"], validate=True)
                    if not 0 < len(data) <= 65536 or len(data) != row["length"]:
                        raise ValueError("invalid object size")
                    digest = hashlib.sha256(data).hexdigest()
                    if digest != row["sha256"]:
                        raise ValueError("invalid object digest")
                    publish_object(objects, digest, data)
                else:
                    raise ValueError("native compiler rejected fixture")
            status = process.wait()
            if status or root is None:
                errors.seek(0)
                raise ValueError(errors.read(2048).decode(errors="replace"))
        finally:
            process.stdout.close()
            if process.poll() is None:
                process.terminate()
                process.wait()
    elapsed = time.perf_counter() - started
    peak = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss * (1 if sys.platform == "darwin" else 1024)
    PackReader(objects).verify_release(root, packs.legacy.implementation_digest(), identities)
    if not reuse:
        (cache / "release.json").write_bytes(encoded(root))
    return {
        "extensions": count,
        "engine": root["engine"],
        "seconds": elapsed,
        "compiler_peak_rss_bytes": peak,
        "stream_sha256": stream_digest.hexdigest(),
        "root": root,
        "compilation": stats or {"compiled": count, "reused": 0, "retained_encoded_bytes": 0},
    }


def run_worker(compiler, source, cache, reuse=False):
    result = subprocess.run(
        [
            sys.executable,
            str(Path(__file__).resolve()),
            "--worker",
            "--compiler",
            str(compiler),
            "--source",
            str(source),
            "--cache",
            str(cache),
            *(["--reuse"] if reuse else []),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode:
        raise ValueError("offline compiler benchmark worker failed: " + result.stderr[-4096:])
    return json.loads(result.stdout)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compiler", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--factors", type=int, nargs="+", default=[1, 10, 100])
    parser.add_argument("--worker", action="store_true")
    parser.add_argument("--source", type=Path)
    parser.add_argument("--cache", type=Path)
    parser.add_argument("--reuse", action="store_true")
    args = parser.parse_args()
    if args.worker:
        print(json.dumps(worker(args.compiler, args.source, args.cache, args.reuse)))
        return
    if args.output is None or any(factor not in {1, 10, 100} for factor in args.factors):
        parser.error("provide a fresh output file and factors from 1, 10, 100")
    baseline = sum(
        len(tuple((packs.legacy.ROOT / "contributions" / name).glob(pattern)))
        for name, pattern in [("command-sources", "command.*.json"), ("mcp-servers", "mcp.*.json")]
    )
    results = []
    for factor in args.factors:
        with tempfile.TemporaryDirectory(prefix="pack-reuse-benchmark-") as temporary:
            source, cache = Path(temporary).resolve() / "source", Path(temporary).resolve() / "cache"
            source_tree(packs.legacy.ROOT, source, baseline * factor)
            cold = run_worker(args.compiler, source, cache)
            warm = run_worker(args.compiler, source, cache, True)
            assert cold["stream_sha256"] == warm["stream_sha256"] and cold["root"] == warm["root"]
            assert warm["compilation"] == {"compiled": 0, "reused": baseline * factor, "retained_encoded_bytes": 0}
            path = source / "contributions/command-sources/command.agentbridge.json"
            value = json.loads(path.read_bytes())
            value["extension"]["description"] += " Offline compiler reuse measurement."
            path.write_bytes(encoded(value))
            changed = run_worker(args.compiler, source, cache, True)
            assert changed["compilation"] == {
                "compiled": 1,
                "reused": baseline * factor - 1,
                "retained_encoded_bytes": 0,
            }
            clean = run_worker(args.compiler, source, Path(temporary).resolve() / "clean")
            assert clean["stream_sha256"] == changed["stream_sha256"] and clean["root"] == changed["root"]
            for report in (cold, warm, changed, clean):
                report.pop("root")
            row = {
                "factor": factor,
                "cold": cold,
                "warm_fresh_process": warm,
                "one_edit": changed,
                "changed_clean": clean,
            }
            results.append(row)
            print(json.dumps(row), flush=True)
    with args.output.open("x") as output:
        json.dump({"scope": __doc__, "results": results}, output, indent=2)


if __name__ == "__main__":
    main()
