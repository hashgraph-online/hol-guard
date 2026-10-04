"""Real protected Vitest workers, using the CI-installed locked dependency fixture."""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.restricted_vitest import prepare_restricted_vitest, run_restricted_vitest


@pytest.mark.parametrize("pool", ["forks", "threads"])
def test_workers_inherit_localhost_preload_and_cannot_replace_transform_image(tmp_path, monkeypatch, pool):
    fixture = Path(os.environ["GUARD_VITEST_FIXTURE"]).resolve(strict=True)
    workspace = tmp_path / "workspace"
    shutil.copytree(fixture, workspace, symlinks=True)
    # setup-node's hosted toolcache is not an implicit trusted runtime root.
    # Validate a copied native image inside the readonly workspace instead.
    runtime = shutil.which("node")
    assert runtime is not None, "The provisioned containment job requires Node"
    node = workspace / "bin/node"
    node.parent.mkdir()
    shutil.copyfile(Path(runtime).resolve(strict=True), node)
    node.chmod(0o500)
    monkeypatch.setenv("PATH", str(node.parent) + os.pathsep + os.environ.get("PATH", ""))
    # Exercise the credential denial deliberately in the worker, not during
    # Vite's automatic root-level dotenv loading.
    credentials = workspace / "credentials"
    credentials.mkdir()
    (credentials / ".env").write_text("SYNTHETIC_ONLY=worker-regression\n")
    source = workspace / "worker.test.ts"
    source.write_text(
        r"""
import { test, expect } from 'vitest';
import { transformSync } from 'esbuild';
import dns from 'node:dns';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

test('fixed resolution reaches the real worker without wider permissions', async () => {
  expect(process.env.VITEST_WORKER_ID).toBeDefined();
  expect(transformSync('const value: number = 7', {loader: 'ts'}).code).toContain('7');
  // NODE_OPTIONS preloads are inherited but are not listed in process.execArgv.
  expect(process.env.NODE_OPTIONS).toContain('localhost-resolution.cjs');
  expect(await dns.promises.lookup('localhost')).toEqual({address: '127.0.0.1', family: 4});
  expect(await dns.promises.lookup('localhost', 6)).toEqual({address: '::1', family: 6});
  expect(await dns.promises.lookup('localhost.', {all: true})).toEqual([{address: '127.0.0.1', family: 4}]);
  expect(await dns.promises.lookup('127.0.0.2')).toEqual({address: '127.0.0.2', family: 4});
  await expect(dns.promises.lookup('guard-worker-test.invalid')).rejects.toBeDefined();
  await new Promise<void>((resolve, reject) => dns.lookup('localhost', (error, address, family) => {
    try {
      expect(error).toBeNull(); expect(address).toBe('127.0.0.1'); expect(family).toBe(4); resolve();
    } catch (error) { reject(error); }
  }));
  const image = process.env.ESBUILD_BINARY_PATH;
  expect(image).toBeDefined();
  const parent = path.dirname(image!);
  const scratch = path.dirname(os.tmpdir());
  expect(parent).not.toBe(scratch);
  const before = fs.readFileSync(image!);
  const denied = (action: () => void) => {
    try { action(); throw new Error('sandbox unexpectedly allowed mutation'); }
    catch (error: any) { expect(['EACCES', 'EPERM', 'EROFS']).toContain(error.code); }
  };
  denied(() => fs.chmodSync(image!, 0o700));
  denied(() => fs.writeFileSync(image!, 'replacement'));
  denied(() => fs.unlinkSync(image!));
  denied(() => fs.renameSync(parent, path.join(scratch, 'moved-images')));
  denied(() => fs.mkdirSync(path.join(parent, 'new-child')));
  expect(fs.readFileSync(image!)).toEqual(before);
  denied(() => fs.readFileSync('credentials/.env'));
  denied(() => fs.writeFileSync('worker.test.ts', 'replacement'));
  fs.writeFileSync(path.join(os.tmpdir(), 'ordinary-scratch.txt'), 'allowed');
});
""".lstrip()
    )
    command = [
        str(node),
        "--max-old-space-size=256",
        str(workspace / "node_modules/vitest/vitest.mjs"),
        "run",
        "worker.test.ts",
        "--pool",
        pool,
        "--maxWorkers",
        "1",
        "--reporter=dot",
    ]
    plan = prepare_restricted_vitest(command, workspace=workspace)
    version = json.loads((workspace / "node_modules/esbuild/package.json").read_text())["version"]
    transform = next((workspace / "node_modules/@esbuild").glob("*/bin/esbuild")).resolve(strict=True)
    approved = {(str(node), "--help"), (str(transform), f"--service={version}", "--ping")}
    checked = []

    def authorize_capability(argv):
        assert argv in approved, f"Unexpected protected capability: {argv}"
        checked.append(argv)

    assert (
        run_restricted_vitest(
            command,
            env={},
            workspace=workspace,
            timeout_seconds=90,
            prepared_plan=plan,
            authorize_capability=authorize_capability,
        )
        == 0
    )
    assert (str(transform), f"--service={version}", "--ping") in checked
    assert (credentials / ".env").read_text() == "SYNTHETIC_ONLY=worker-regression\n"
    assert "fixed resolution reaches the real worker" in source.read_text()
