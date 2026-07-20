import { createHash } from "node:crypto";
import { describe, expect, test } from "bun:test";

import {
  loadVerifiedWheel,
  parseProofArgs,
  runInstalledPackageProof,
  validateTestPypiWheelUrl,
} from "../../scripts/dockerlabs/installed-guard-package-proof.mjs";

const SHA = "a".repeat(64);
const URL = `https://test-files.pythonhosted.org/packages/aa/bb/${"c".repeat(64)}/hol_guard-2.2.0a1-py3-none-any.whl`;

describe("installed Guard package proof", () => {
  test("accepts one exact local wheel", () => {
    expect(
      parseProofArgs(["--wheel", "dist/hol_guard-2.2.0a1-py3-none-any.whl", "--version", "2.2.0a1", "--sha256", SHA]),
    ).toMatchObject({ version: "2.2.0a1", sha256: SHA, testpypiWheelUrl: null });
  });

  test("accepts only immutable TestPyPI wheel URLs", () => {
    expect(validateTestPypiWheelUrl(URL).href).toBe(URL);
    for (const value of [
      "https://test.pypi.org/simple/hol-guard/",
      "https://files.pythonhosted.org/packages/aa/bb/file.whl",
      `${URL}?download=1`,
      "http://test-files.pythonhosted.org/packages/aa/bb/file.whl",
    ]) {
      expect(() => validateTestPypiWheelUrl(value)).toThrow();
    }
  });

  test("rejects ranges, ambiguous sources, and uppercase hashes", () => {
    expect(() => parseProofArgs(["--wheel", "x.whl", "--version", ">=2.2", "--sha256", SHA])).toThrow();
    expect(() => parseProofArgs(["--wheel", "x.whl", "--version", "latest", "--sha256", SHA])).toThrow();
    expect(() => parseProofArgs(["--wheel", "other-2.2-py3-none-any.whl", "--version", "2.2", "--sha256", SHA])).toThrow();
    expect(() =>
      parseProofArgs([
        "--wheel",
        "x.whl",
        "--testpypi-wheel-url",
        URL,
        "--version",
        "2.2.0a1",
        "--sha256",
        SHA,
      ]),
    ).toThrow();
    expect(() => parseProofArgs(["--wheel", "x.whl", "--version", "2.2.0a1", "--sha256", SHA.toUpperCase()])).toThrow();
  });

  test("verifies fetched bytes and rejects redirects or hash drift", async () => {
    const bytes = new TextEncoder().encode("exact-wheel");
    const sha256 = createHash("sha256").update(bytes).digest("hex");
    const config = { wheel: null, testpypiWheelUrl: URL, version: "2.2.0a1", sha256 };
    const exactResponse = () => ({
      ok: true,
      url: URL,
      headers: new Headers(),
      arrayBuffer: async () => bytes.buffer,
    });
    let redirectPolicy;
    const loaded = await loadVerifiedWheel(config, async (_url, options) => {
      redirectPolicy = options.redirect;
      return exactResponse();
    });
    expect(loaded.bytes).toEqual(bytes);
    expect(redirectPolicy).toBe("error");
    await expect(
      loadVerifiedWheel(config, async () => ({ ...exactResponse(), url: "https://example.invalid/redirected.whl" })),
    ).rejects.toThrow("download failed");
    await expect(loadVerifiedWheel({ ...config, sha256: SHA }, async () => exactResponse())).rejects.toThrow(
      "SHA-256 mismatch",
    );
  });

  test("tears down owned Docker state when execution fails", async () => {
    const commands = [];
    const runner = (command, options = {}) => {
      commands.push(command);
      if (command[1] === "build") throw new Error("synthetic build failure");
      return { exitCode: options.allowFailure ? 1 : 0, stdout: "", stderr: "" };
    };
    const wheelLoader = async () => ({
      bytes: new Uint8Array([1, 2, 3]),
      filename: "hol_guard-2.2.0a1-py3-none-any.whl",
      source: "test",
    });
    await expect(
      runInstalledPackageProof(
        { wheel: "unused.whl", testpypiWheelUrl: null, version: "2.2.0a1", sha256: SHA },
        { runner, wheelLoader },
      ),
    ).rejects.toThrow("synthetic build failure");
    expect(commands.some((command) => command[1] === "rm" && command.includes("--force"))).toBeTrue();
    expect(commands.some((command) => command[1] === "image" && command[2] === "rm")).toBeTrue();
    expect(commands.some((command) => command[1] === "images" && command[2] === "-q")).toBeTrue();
    expect(commands.some((command) => command[1] === "volume" && command[2] === "ls")).toBeTrue();
  });

  test("fails closed when Docker inventory cannot prove zero residue", async () => {
    const runner = (command) => {
      if (command[1] === "build") throw new Error("synthetic build failure");
      if (command[1] === "ps") throw new Error("synthetic inventory failure");
      return { exitCode: 0, stdout: "", stderr: "" };
    };
    const wheelLoader = async () => ({
      bytes: new Uint8Array([1, 2, 3]),
      filename: "hol_guard-2.2.0a1-py3-none-any.whl",
      source: "test",
    });

    await expect(
      runInstalledPackageProof(
        { wheel: "unused.whl", testpypiWheelUrl: null, version: "2.2.0a1", sha256: SHA },
        { runner, wheelLoader },
      ),
    ).rejects.toThrow("Dockerlab execution and teardown failed");
  });
});
