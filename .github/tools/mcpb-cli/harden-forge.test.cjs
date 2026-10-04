"use strict";

const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

for (const [name, version, reason] of [
  ["unrecognized version", "1.4.1", "Review the backport"],
  ["modified source", "1.4.0", "Refuse a different or modified Forge source"],
]) {
  test("reject " + name + " without emitting VEX", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "mcpb-forge-check-"));
    try {
      const packageRoot = path.join(root, "node_modules", "node-forge");
      fs.mkdirSync(path.join(packageRoot, "lib"), { recursive: true });
      fs.writeFileSync(path.join(packageRoot, "package.json"), JSON.stringify({ version }));
      const rsa = path.join(packageRoot, "lib", "rsa.js");
      fs.writeFileSync(rsa, "unrecognized RSA implementation");
      const script = path.join(root, "harden-forge.cjs");
      fs.copyFileSync(path.join(__dirname, "harden-forge.cjs"), script);
      const vex = path.join(root, "proof.json");
      const result = spawnSync(process.execPath, [script, "--vex-output", vex], { encoding: "utf8" });
      assert.notEqual(result.status, 0);
      assert(result.stderr.includes(reason));
      assert.equal(fs.existsSync(vex), false);
      assert.equal(fs.readFileSync(rsa, "utf8"), "unrecognized RSA implementation");
    } finally {
      fs.rmSync(root, { recursive: true });
    }
  });
}
