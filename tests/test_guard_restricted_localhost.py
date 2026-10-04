"""A fixed local DNS answer never delegates external names to a new resolver."""

import shutil
import subprocess
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.restricted_localhost import _SOURCE


def test_callback_and_promise_localhost_answers_preserve_external_resolver(tmp_path: Path):
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node runtime not available")
    script = tmp_path / "test.cjs"
    script.write_text(
        """
const assert = require('node:assert/strict');
const dns = require('node:dns');
dns.lookup = (hostname, options, callback) => callback(new Error('original:' + hostname));
dns.promises.lookup = async hostname => { throw new Error('original:' + hostname); };
"""
        + _SOURCE.replace("const dns = require('node:dns');", "")
        + """
(async () => {
  assert.deepEqual(await dns.promises.lookup('localhost'), {address:'127.0.0.1', family:4});
  assert.deepEqual(await dns.promises.lookup('localhost', 6), {address:'::1', family:6});
  assert.deepEqual(await dns.promises.lookup('localhost.', {all:true}), [{address:'127.0.0.1', family:4}]);
  await assert.rejects(dns.promises.lookup('external.invalid'), /original:external.invalid/);
  await new Promise((resolve, reject) => dns.lookup('localhost', (error, address, family) => {
    try { assert.equal(error, null); assert.equal(address, '127.0.0.1'); assert.equal(family, 4); resolve(); }
    catch (error) { reject(error); }
  }));
  await new Promise(resolve => dns.lookup('external.invalid', {}, error => {
    assert.match(error.message, /original:external.invalid/); resolve();
  }));
})().catch(error => {console.error(error); process.exitCode = 1;});
"""
    )
    result = subprocess.run([node, str(script)], capture_output=True, text=True, timeout=20, check=False)
    assert result.returncode == 0, result.stderr


def test_worker_explicit_arguments_keep_fixed_preload(tmp_path: Path):
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node runtime not available")
    preload = tmp_path / "localhost-resolution.cjs"
    preload.write_text(_SOURCE)
    script = """
import assert from 'node:assert/strict';
import { Worker } from 'node:worker_threads';
import { lookup } from 'node:dns';
await new Promise((resolve, reject) => lookup('localhost', (error, address) => {
  try { assert.equal(error, null); assert.equal(address, '127.0.0.1'); resolve(); }
  catch (error) { reject(error); }
}));
const worker = new Worker(`
  const { parentPort } = require('node:worker_threads');
  require('node:dns').promises.lookup('localhost').then(result => parentPort.postMessage(result));
`, {eval: true, execArgv: [], env: {NODE_OPTIONS: ''}});
await new Promise((resolve, reject) => {
  worker.once('error', reject);
  worker.once('message', result => {
    try { assert.deepEqual(result, {address:'127.0.0.1', family:4}); resolve(); }
    catch (error) { reject(error); }
  });
});
await worker.terminate();
"""
    result = subprocess.run(
        [node, "--require", str(preload), "--input-type=module", "-e", script],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert result.returncode == 0, result.stderr
