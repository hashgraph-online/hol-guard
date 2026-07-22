#!/usr/bin/env bun

import { createHash, randomBytes } from "node:crypto";
import { lstat, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const SHA256 = /^[0-9a-f]{64}$/;
const VERSION = /^(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*))*(?:(?:a|b|rc)[0-9]+)?(?:\.post[0-9]+)?(?:\.dev[0-9]+)?(?:\+[0-9A-Za-z]+(?:[._-][0-9A-Za-z]+)*)?$/;
const TESTPYPI_WHEEL = /^\/packages\/[0-9a-f]{2}\/[0-9a-f]{2}\/[0-9a-f]{32,64}\/[^/]+\.whl$/;
const WHEEL_FILENAME = /^hol_guard-[0-9A-Za-z][0-9A-Za-z._+-]*-[0-9A-Za-z_.]+-[0-9A-Za-z_.]+-[0-9A-Za-z_.]+\.whl$/;
const MAX_WHEEL_BYTES = 100 * 1024 * 1024;
const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));

export function parseProofArgs(argv) {
  const values = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index];
    const value = argv[index + 1];
    if (!key?.startsWith("--") || value === undefined || value.startsWith("--")) {
      throw new Error("Arguments must be exact --name value pairs");
    }
    if (values.has(key)) throw new Error(`Duplicate argument: ${key}`);
    values.set(key, value);
  }
  const version = values.get("--version");
  const sha256 = values.get("--sha256");
  const wheel = values.get("--wheel");
  const testpypiWheelUrl = values.get("--testpypi-wheel-url");
  if (!version || !VERSION.test(version)) throw new Error("--version must be one exact version");
  if (!sha256 || !SHA256.test(sha256)) throw new Error("--sha256 must be one lowercase SHA-256");
  if (Boolean(wheel) === Boolean(testpypiWheelUrl)) {
    throw new Error("Select exactly one of --wheel or --testpypi-wheel-url");
  }
  const supported = new Set(["--version", "--sha256", "--wheel", "--testpypi-wheel-url"]);
  for (const key of values.keys()) {
    if (!supported.has(key)) throw new Error(`Unsupported argument: ${key}`);
  }
  if (wheel) validateWheelFilename(basename(wheel));
  if (testpypiWheelUrl) validateTestPypiWheelUrl(testpypiWheelUrl);
  return { version, sha256, wheel: wheel ? resolve(wheel) : null, testpypiWheelUrl: testpypiWheelUrl ?? null };
}

function validateWheelFilename(filename) {
  if (!WHEEL_FILENAME.test(filename)) throw new Error("Input must use a valid hol_guard wheel filename");
  return filename;
}

export function validateTestPypiWheelUrl(rawUrl) {
  let url;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new Error("TestPyPI wheel URL is invalid");
  }
  if (
    url.protocol !== "https:" ||
    url.hostname !== "test-files.pythonhosted.org" ||
    url.username ||
    url.password ||
    url.port ||
    url.search ||
    url.hash ||
    !TESTPYPI_WHEEL.test(url.pathname)
  ) {
    throw new Error("TestPyPI input must be one immutable test-files wheel URL");
  }
  validateWheelFilename(basename(url.pathname));
  return url;
}

export async function loadVerifiedWheel(config, fetchImplementation = fetch) {
  let bytes;
  let filename;
  let source;
  if (config.wheel) {
    const metadata = await lstat(config.wheel);
    if (!metadata.isFile() || metadata.isSymbolicLink()) throw new Error("Local wheel must be a regular file");
    if (metadata.size > MAX_WHEEL_BYTES) throw new Error("Wheel exceeds the Dockerlab size limit");
    bytes = new Uint8Array(await readFile(config.wheel));
    filename = validateWheelFilename(basename(config.wheel));
    source = `local:${filename}`;
  } else {
    const url = validateTestPypiWheelUrl(config.testpypiWheelUrl);
    const response = await fetchImplementation(url, { redirect: "error" });
    if (!response.ok || response.url !== url.href) throw new Error("Exact TestPyPI wheel download failed");
    const contentLengthHeader = response.headers.get("content-length");
    if (contentLengthHeader !== null) {
      const contentLength = Number(contentLengthHeader);
      if (!Number.isSafeInteger(contentLength) || contentLength < 0 || contentLength > MAX_WHEEL_BYTES) {
        throw new Error("Wheel content length is invalid or exceeds the Dockerlab size limit");
      }
    }
    bytes = new Uint8Array(await response.arrayBuffer());
    if (bytes.byteLength > MAX_WHEEL_BYTES) throw new Error("Wheel exceeds the Dockerlab size limit");
    filename = validateWheelFilename(basename(url.pathname));
    source = `testpypi:${filename}`;
  }
  const observedSha256 = createHash("sha256").update(bytes).digest("hex");
  if (observedSha256 !== config.sha256) throw new Error("Wheel SHA-256 mismatch");
  return { bytes, filename, source };
}

function run(command, options = {}) {
  const result = Bun.spawnSync(command, {
    cwd: options.cwd,
    env: options.env ?? process.env,
    stdout: "pipe",
    stderr: "pipe",
  });
  const stdout = result.stdout.toString().trim();
  const stderr = result.stderr.toString().trim();
  if (result.exitCode !== 0 && !options.allowFailure) {
    throw new Error(`${command[0]} failed (${result.exitCode}): ${stderr.slice(0, 4000)}`);
  }
  return { exitCode: result.exitCode, stdout, stderr };
}

async function teardownDocker(runId, imageTag, containerName, runner = run) {
  runner(["docker", "rm", "--force", containerName], { allowFailure: true });
  runner(["docker", "image", "rm", "--force", imageTag], { allowFailure: true });
  const label = `hol.guard.dockerlab=${runId}`;
  const containers = runner(["docker", "ps", "-aq", "--filter", `label=${label}`]);
  const images = runner(["docker", "images", "-q", "--filter", `label=${label}`]);
  const volumes = runner(["docker", "volume", "ls", "-q", "--filter", `label=${label}`]);
  if (containers.stdout || images.stdout || volumes.stdout) throw new Error("Dockerlab teardown left owned state behind");
}

export async function runInstalledPackageProof(config, dependencies = {}) {
  const runner = dependencies.runner ?? run;
  const wheelLoader = dependencies.wheelLoader ?? loadVerifiedWheel;
  const runId = randomBytes(8).toString("hex");
  const imageTag = `hol-guard-installed-proof:${runId}`;
  const containerName = `hol-guard-installed-proof-${runId}`;
  const context = await mkdtemp(join(tmpdir(), "hol-guard-installed-proof-"));
  let primaryError;
  try {
    const wheel = await wheelLoader(config);
    await writeFile(join(context, wheel.filename), wheel.bytes, { mode: 0o600 });
    await writeFile(
      join(context, "installed_guard_package_origin.py"),
      await readFile(join(SCRIPT_DIR, "installed_guard_package_origin.py")),
      { mode: 0o600 },
    );
    await writeFile(
      join(context, "Dockerfile"),
      await readFile(join(SCRIPT_DIR, "installed-guard-package.Dockerfile")),
      { mode: 0o600 },
    );
    runner([
      "docker",
      "build",
      "--label",
      `hol.guard.dockerlab=${runId}`,
      "--tag",
      imageTag,
      context,
    ]);
    const result = runner([
      "docker",
      "run",
      "--rm",
      "--name",
      containerName,
      "--label",
      `hol.guard.dockerlab=${runId}`,
      imageTag,
      "--expected-version",
      config.version,
      "--expected-wheel-sha256",
      config.sha256,
      "--wheel-path",
      `/opt/guard-proof/${wheel.filename}`,
    ]);
    const proof = JSON.parse(result.stdout);
    if (proof.status !== "verified" || proof.version !== config.version || proof.wheel_sha256 !== config.sha256) {
      throw new Error("Installed-package proof returned inconsistent evidence");
    }
    return { ...proof, source: wheel.source };
  } catch (error) {
    primaryError = error;
    throw error;
  } finally {
    let cleanupError;
    try {
      await teardownDocker(runId, imageTag, containerName, runner);
    } catch (teardownError) {
      cleanupError = teardownError;
    }
    try {
      await rm(context, { recursive: true, force: true });
    } catch (filesystemError) {
      cleanupError = cleanupError
        ? new AggregateError([cleanupError, filesystemError], "Docker and temporary-file teardown failed")
        : filesystemError;
    }
    if (cleanupError) {
      if (primaryError) {
        throw new AggregateError([primaryError, cleanupError], "Dockerlab execution and teardown failed");
      }
      throw cleanupError;
    }
  }
}

async function main() {
  const config = parseProofArgs(Bun.argv.slice(2));
  const result = await runInstalledPackageProof(config);
  console.log(JSON.stringify(result));
}

if (import.meta.main) {
  await main();
}
