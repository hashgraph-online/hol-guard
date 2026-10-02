"use strict";

const assert = require("node:assert/strict");
const { createHash } = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const originalSha256 = "fd4740238145ec26470eb3f06a627c72039538ce1307dbdce40521f94dfd0a50";
const originalCondition = "            obj.value.length !== 2) {";
const fixedCondition = `            obj.value.length !== 2 ||
            obj.value[0].value.length < 1 || obj.value[0].value.length > 2 ||
            (obj.value[0].value.length === 2 &&
              (obj.value[0].value[1].tagClass !== asn1.Class.UNIVERSAL ||
                obj.value[0].value[1].type !== asn1.Type.NULL ||
                obj.value[0].value[1].constructed ||
                obj.value[0].value[1].value !== ''))) {`;
const sha256 = (text) => createHash("sha256").update(text).digest("hex");

function hardenForge() {
  const packageRoot = path.join(__dirname, "node_modules", "node-forge");
  const packageMetadata = JSON.parse(fs.readFileSync(path.join(packageRoot, "package.json"), "utf8"));
  assert.equal(packageMetadata.version, "1.4.0", "Review the backport when the locked Forge version changes.");
  const target = path.join(packageRoot, "lib", "rsa.js");
  const current = fs.readFileSync(target, "utf8");
  const original = current.includes(fixedCondition) ? current.replace(fixedCondition, originalCondition) : current;
  assert.equal(sha256(original), originalSha256, "Refuse a different or modified Forge source file.");
  assert.equal(original.split(originalCondition).length, 2, "Expected exactly one RSA verification condition.");
  const patched = original.replace(originalCondition, fixedCondition);
  if (current !== patched) fs.writeFileSync(target, patched);
  assert.equal(sha256(fs.readFileSync(target)), sha256(patched));
  require("./verify-forge.cjs")();
  return sha256(patched);
}

if (require.main === module) {
  const args = process.argv.slice(2);
  assert(args.length === 0 || (args.length === 2 && args[0] === "--vex-output"), "Invalid hardening arguments.");
  const patchedSha256 = hardenForge();
  if (args.length) {
    const vex = {
      "@context": "https://openvex.dev/ns/v0.2.0",
      "@id": "https://github.com/hashgraph-online/hol-guard/blob/main/.github/tools/mcpb-cli/harden-forge.cjs",
      author: "HOL Guard maintainers",
      timestamp: "2026-10-02T00:00:00Z",
      version: 1,
      statements: [{
        vulnerability: { name: "CVE-2026-85393" },
        products: [{ "@id": "pkg:npm/node-forge@1.4.0" }],
        status: "fixed",
        impact_statement: `The locked MCPB build tool applies and tests a strict AlgorithmIdentifier backport before CLI use. Patched rsa.js SHA-256: ${patchedSha256}.`,
      }],
    };
    fs.writeFileSync(args[1], JSON.stringify(vex, null, 2) + "\n");
  }
  console.log("Verified MCPB Forge backport SHA-256: " + patchedSha256);
}

module.exports = hardenForge;
