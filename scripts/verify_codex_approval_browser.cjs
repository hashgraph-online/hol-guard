#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
let stage = "arguments";

function rejectSymlink(target, label) {
  try {
    if (fs.lstatSync(target).isSymbolicLink()) {
      throw new Error(`${label} must not be a symbolic link`);
    }
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
}

function rejectSymlinkedPathComponents(target, label) {
  const resolved = path.resolve(target);
  const root = path.parse(resolved).root;
  let current = root;
  for (const component of path.relative(root, resolved).split(path.sep).filter(Boolean)) {
    current = path.join(current, component);
    rejectSymlink(current, label);
  }
}

function prepareOutputDirectory(value) {
  const directory = path.resolve(value);
  rejectSymlinkedPathComponents(directory, "Output directory path");
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  rejectSymlinkedPathComponents(directory, "Output directory path");
  if (!fs.statSync(directory).isDirectory()) throw new Error("Output path is not a directory");
  fs.chmodSync(directory, 0o700);
  return directory;
}

function outputArtifact(directory, name) {
  const target = path.join(directory, name);
  rejectSymlink(target, `Output artifact ${name}`);
  if (fs.existsSync(target) && !fs.statSync(target).isFile()) {
    throw new Error(`Output artifact ${name} is not a regular file`);
  }
  return target;
}

function writePrivateFile(target, content) {
  const noFollow = fs.constants.O_NOFOLLOW || 0;
  const fd = fs.openSync(target, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_TRUNC | noFollow, 0o600);
  try {
    fs.fchmodSync(fd, 0o600);
    fs.writeFileSync(fd, content, "utf8");
  } finally {
    fs.closeSync(fd);
  }
}

async function screenshotPrivate(page, target, options = {}) {
  const screenshot = await page.screenshot(options);
  writePrivateFile(target, screenshot);
}

function option(name) {
  const index = process.argv.indexOf(name);
  return index < 0 ? undefined : process.argv[index + 1];
}

async function main() {
  const messageFile = option("--message-file");
  const outputDir = option("--output-dir");
  if (!messageFile || !outputDir) {
    throw new Error("Required: --message-file FILE --output-dir DIRECTORY");
  }
  rejectSymlink(messageFile, "Message file");
  const message = fs.readFileSync(messageFile, "utf8");
  stage = "extract-signed-link";
  const candidates = message.match(/https?:\/\/[^\s<>"`]+/g) || [];
  const links = candidates.map((candidate) => {
    try {
      return new URL(candidate.replace(/[).,;]+$/, ""));
    } catch {
      return null;
    }
  }).filter((url) => url && ["127.0.0.1", "localhost", "[::1]"].includes(url.hostname)
    && /^\/requests\/[A-Za-z0-9_-]+$/.test(url.pathname));
  const signed = links.find((url) => new URLSearchParams(url.hash.slice(1)).has("guard-token"));
  if (!signed) {
    throw new Error("Codex final message did not contain a complete signed local approval URL");
  }
  if (links.some((url) => !new URLSearchParams(url.hash.slice(1)).has("guard-token"))) {
    throw new Error("Codex final message also contained an unsigned approval URL");
  }
  const raw = new URL(signed);
  raw.hash = "";
  const requestId = raw.pathname.split("/").pop();
  const apiPath = `/v1/requests/${requestId}`;
  const { chromium } = require(option("--playwright-module") || "@playwright/test");
  const artifacts = prepareOutputDirectory(outputDir);
  const unsignedScreenshot = outputArtifact(artifacts, "unsigned.png");
  const signedLoadedScreenshot = outputArtifact(artifacts, "signed-loaded.png");
  const signedScreenshot = outputArtifact(artifacts, "signed.png");
  const signedPage = outputArtifact(artifacts, "signed-page.txt");
  const browserSummary = outputArtifact(artifacts, "browser-summary.json");
  stage = "launch-browser";
  const browser = await chromium.launch({ headless: true });
  const summary = {
    request_fingerprint: crypto.createHash("sha256").update(requestId).digest("hex").slice(0, 16),
    raw_rejected: false,
    signed_request_loaded: false,
    verification_scope: "load-only; does not approve or execute the request",
    approval_clicked: false,
  };
  try {
    const rawContext = await browser.newContext();
    try {
      stage = "unsigned-api";
      const response = await rawContext.request.get(`${raw.origin}${apiPath}`);
      summary.raw_rejected = response.status() === 401;
      if (!summary.raw_rejected) throw new Error("Unsigned request was not rejected with 401");
      const page = await rawContext.newPage();
      stage = "unsigned-page";
      await page.goto(raw.href, { waitUntil: "domcontentloaded" });
      await page.getByText("This approval link needs a signed local session", { exact: false }).waitFor();
      await screenshotPrivate(page, unsignedScreenshot, { fullPage: true });
    } finally {
      await rawContext.close();
    }

    const signedContext = await browser.newContext();
    try {
      stage = "signed-api";
      const page = await signedContext.newPage();
      const loaded = page.waitForResponse((response) => {
        const url = new URL(response.url());
        return url.origin === signed.origin && url.pathname === apiPath && response.status() === 200;
      }, { timeout: 30000 });
      await page.goto(signed.href, { waitUntil: "domcontentloaded" });
      const response = await loaded;
      const request = await response.json();
      summary.signed_request_loaded = request.request_id === requestId;
      if (!summary.signed_request_loaded) throw new Error("Signed link loaded an unexpected request");
      stage = "approval-ui";
      await screenshotPrivate(page, signedLoadedScreenshot, { fullPage: true });
      let verificationError;
      try {
        const approve = page.getByRole("button", {
          name: /^(approve once|allow once|allow just this once|allow and remember for this project)$/i,
        }).first();
        await approve.waitFor({ timeout: 30000 });
        if (!await approve.isEnabled()) throw new Error("Approval control is disabled");
        await page.getByRole("button", { name: "Keep blocked", exact: true }).waitFor();
      } catch (error) {
        verificationError = error;
      } finally {
        let artifactError;
        try {
          await screenshotPrivate(page, signedScreenshot, { fullPage: true });
        } catch (error) {
          artifactError = error;
        }
        try {
          writePrivateFile(signedPage, await page.locator("body").innerText());
        } catch (error) {
          artifactError ||= error;
        }
        if (!verificationError && artifactError) throw artifactError;
      }
      if (verificationError) throw verificationError;
    } finally {
      await signedContext.close();
    }
    writePrivateFile(browserSummary, JSON.stringify(summary, null, 2) + "\n");
    process.stdout.write(JSON.stringify(summary) + "\n");
  } finally {
    await browser.close();
  }
}

main().catch(() => {
  // Browser errors may contain the signed URL. Keep diagnostics credential-free.
  process.stderr.write(`Approval browser verification failed at ${stage}; inspect private artifacts and daemon state.\n`);
  process.exitCode = 1;
});
