// Isolated fixture-backed browser checks. Never connects to a live Guard or SDK.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createServer } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { chromium } from "playwright";
const dashboard = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const repository = path.dirname(dashboard);
const executable = process.argv[2] || chromium.executablePath();
assert.ok(existsSync(executable), "Supply an installed browser executable; this check never downloads one.");
const output = process.argv[3] || await mkdtemp(path.join(os.tmpdir(), "cigar-versions-browser-"));
if (process.argv[3]) await mkdir(output);
const fixtureRoot = await mkdtemp(path.join(os.tmpdir(), "cigar-versions-fixture-"));
const receipt = JSON.parse(await readFile(path.join(dashboard, "src/context-assistance/fixtures/intent-state.json"), "utf8"));
const document = JSON.parse(await readFile(path.join(repository, "integrations/cigar/release-catalog.v1.json"), "utf8"));
const initialState = { ...receipt.native_test.ready_observation, generation: "9007199254740993" };
const installed = (runtime_id, build_id) => ({ runtime_id, build_id, qualification: "guard_qualified", sdk_version: "0.14.1", core_version: "0.14.1",
  adapter_id: "fixture_adapter", adapter_revision: 1,
  python_version: [3, 14, 7], platform: "darwin-arm64", worker_fingerprint: initialState.runtime.worker_fingerprint, managed: true });
const installations = [installed(initialState.preferences.runtime_id, "fixture:source"), installed("fixture:target", "fixture:target-build")];
const preferences = { mode: "manual", allow_preview: false, retain_last_good: true };
const updateSettings = { schema: "guard-cigar-update-preferences.v1", requested: preferences, effective: preferences,
  revision: "sha256:" + "a".repeat(64), diagnostic: null, locked_settings: [],
  capabilities: { modes: ["manual", "notify"], automatic_preparation: false, automatic_selection: false, retention_reduction: false } };
const releases = { schema: "guard-cigar-releases.v1", host_platform: "darwin-arm64", builds: document.builds, interpreter_builds: document.interpreters,
  catalog: { source: "bundled", fresh_for_preparation: true, diagnostic: null, trust_configured: false, trust_diagnostic: null,
    remote_feed_configured: false, feed_diagnostic: null, activation_granted: false } };
function selection(state, off = false) {
  return { schema: "guard-cigar-switch-job.v1", job_id: off ? "fixture:initial" : "fixture:switch", operation: off ? "select" : "switch", phase: "ready", code: "ready",
    target_runtime_id: "fixture:target", source_runtime_id: off ? null : state.preferences.runtime_id, expected_generation: state.generation,
    can_commit: true, keeps_disabled: off, reconnect_required: !off, initial_selection: off, cleanup_pending: false,
    authority_restored: false, recovery_attempt: null, created_at_ms: Date.now(), updated_at_ms: Date.now(), deadline_at_ms: Date.now() + 120000,
    worker_live: true, cancel_requested: false, recovery_available: false };
}
let state = structuredClone(initialState), jobs = [selection(state)], proof = false, commitMode = "normal", delayedCommit = null, metadataOrder = false;
const calls = [], checks = [], browserErrors = [];
const pass = description => { checks.push(description); console.log(JSON.stringify({ check: description, passed: true })); };
const moduleUrl = (name) => JSON.stringify("/@fs" + path.join(dashboard, "src", name));
const entry = `import React, {useCallback,useRef,useState} from "react";
import {createRoot} from "react-dom/client";
import {ContextAssistanceSettings} from ${moduleUrl("context-assistance/settings-panel.tsx")};
import {withCigarSelection} from ${moduleUrl("context-assistance/selection-settings.ts")};
import "./fixture.css";
import ${moduleUrl("context-assistance/workspace.css")};
import ${moduleUrl("context-assistance/tutorials.css")};
const fixture=await fetch('/__cigar_fixture').then(r=>r.json());
function Harness(){
 const [saved,setSaved]=useState(fixture.state.preferences), [draft,setDraft]=useState(fixture.state.preferences), [busy,setBusy]=useState(false), [unrelated,setUnrelated]=useState('unchanged');
 const savedRef=useRef(saved); savedRef.current=saved;
 const stopped=useCallback(config=>{savedRef.current=config;setSaved(config);setDraft(current=>({...current,enabled:false}));},[]);
 const changed=useCallback((config,previous)=>{
  const old=savedRef.current, next=withCigarSelection({context_assistance:old},config,previous).context_assistance;
  if(next===old)return; savedRef.current=next;setSaved(next);
  setDraft(current=>withCigarSelection({context_assistance:current},config,previous,true).context_assistance);
 },[]);
 return <><button type='button' onClick={()=>setUnrelated('pending protection edit')}>Edit unrelated preference</button>
 <output data-testid='selection' style={{display:'none'}}>{JSON.stringify({saved,draft,unrelated,busy})}</output>
 <ContextAssistanceSettings workspace value={draft} savedValue={saved} gate={fixture.proof?{enabled:true,totp_enabled:false}:null}
 locked={false} disabled={false} onChange={setDraft} onStopped={stopped} onSelectionChanged={changed} onBusyChange={setBusy}/></>;
}
createRoot(document.getElementById('root')).render(<Harness/>);`;
await writeFile(path.join(fixtureRoot, "entry.tsx"), entry, { flag: "wx" });
await writeFile(path.join(fixtureRoot, "fixture.css"), '@import ' + JSON.stringify(path.join(dashboard, "src/tailwind-root.css")) + ';\n@source ' + JSON.stringify(path.join(dashboard, "src")) + ';\n', { flag: "wx" });
await writeFile(path.join(fixtureRoot, "index.html"), "<!doctype html><html><head><title>CIGAR Versions fixture</title></head><body style='padding:16px'><div id='root'></div><script type='module' src='/entry.tsx'></script></body></html>", { flag: "wx" });
const server = await createServer({ configFile: false, root: fixtureRoot, cacheDir: path.join(fixtureRoot, "vite-cache"),
  plugins: [react(), tailwindcss()], resolve: { alias: { "react-dom": path.join(dashboard,"node_modules/react-dom"), react: path.join(dashboard,"node_modules/react") } },
  server: { host: "127.0.0.1", port: 0, strictPort: true, fs: { allow: [fixtureRoot, dashboard] } } });
let browser;
const summary = { schema: "guard-cigar-versions-browser.v1", scope: "Isolated browser with HTTP fixtures only; no live Guard, native process, SDK or installed/frozen workflow qualification.",
  calls, executable, executable_sha256: createHash("sha256").update(await readFile(executable)).digest("hex"), checks, browser_errors: browserErrors };
try {
  await server.listen();
  const address = server.httpServer.address();
  const origin = "http://127.0.0.1:" + address.port;
  browser = await chromium.launch({ executablePath: executable, headless: true });
  summary.browser_version = browser.version();
  const context = await browser.newContext({ viewport: { width: 1280, height: 1000 } });
  const page = await context.newPage();
  page.on("pageerror", error => browserErrors.push(error.message));
  await page.route("**/*", async route => {
    const request = route.request(), url = new URL(request.url());
    if (url.origin !== origin) return route.abort("blockedbyclient");
    if (url.pathname === "/__cigar_fixture") return route.fulfill({ json: { state, proof } });
    if (!url.pathname.startsWith("/v1/")) return route.continue();
    const body = request.method() === "POST" ? request.postDataJSON() : null;
    const action = body?.input?.action;
    calls.push({ path: url.pathname, method: request.method(), action: action ?? null, input: body?.input ?? null,
      proof_present: Boolean(body?.approval_password || body?.approval_totp_code) });
    const reply = (result) => route.fulfill({ json: { schema: "guard-cigar-versions-result.v1", result, state } });
    if (url.pathname === "/v1/context-assistance/installations") return route.fulfill({ json: { ...state,
      preferences: metadataOrder ? { ...Object.fromEntries(Object.entries(state.preferences).reverse()), features: { ...state.preferences.features, execution_context: false } } : state.preferences,
      installation_options: installations } });
    if (url.pathname === "/v1/context-assistance") return route.fulfill({ json: state });
    if (url.pathname === "/v1/context-assistance/stop") {
      state = { ...state, availability: "off", diagnostic: null, requested_enabled: false, effective_enabled: false, runtime: null, last_check: null, job: null, qualification: null,
        generation: String(BigInt(state.generation) + 1n), preferences: { ...state.preferences, enabled: false }, effective_preferences: { ...state.effective_preferences, enabled: false } };
      return route.fulfill({ json: state });
    }
    if (url.pathname === "/v1/context-assistance/versions" && request.method() === "GET") return reply(releases);
    if (url.pathname === "/v1/context-assistance/interpreters") return reply({ interpreters: [] });
    if (url.pathname === "/v1/context-assistance/jobs") return reply({ jobs });
    if (action === "preferences" || action === "set_preferences") return reply(updateSettings);
    if (action === "commit") {
      if (commitMode === "unknown") return route.abort("failed");
      const target = jobs.find(job => job.job_id === body.input.job_id);
      assert.ok(target); assert.equal(body.input.expected_generation, target.expected_generation);
      assert.equal(body.input.reconnect, target.reconnect_required);
      state = { ...state, generation: String(BigInt(state.generation) + 1n), preferences: { ...state.preferences, runtime_id: target.target_runtime_id },
        effective_preferences: { ...state.effective_preferences, runtime_id: target.target_runtime_id } };
      jobs = jobs.map(job => ({ ...job, phase: "completed", can_commit: false, worker_live: false, code: "completed" }));
      if (commitMode === "delay") {
        const captured = structuredClone(state);
        await new Promise(resolve => { delayedCommit = () => route.fulfill({ json: { schema: "guard-cigar-versions-result.v1", result: jobs[0], state: captured } }).then(resolve); });
        return;
      }
      return reply(jobs[0]);
    }
    if (action === "recover") {
      assert.equal(body.input.expected_generation, state.generation);
      jobs = jobs.map(job => ({ ...job, phase: "completed", code: "recovered", worker_live: false, recovery_available: false, can_commit: false }));
      return reply(jobs[0]);
    }
    if (action === "cancel") { jobs = jobs.map(job => ({ ...job, can_commit: false, phase: "cancelled", code: "cancelled", worker_live: false, cancel_requested: true })); return reply(jobs[0]); }
    if (action === "prepare_switch" || action === "prepare_rollback") return reply(jobs[0]);
    throw new Error("Unexpected fixture request: " + url.pathname + " " + action);
  });
  const open = async (versions = true) => {
    await page.goto(origin + "/?guard-token=cigar-browser-fixture");
    await page.getByRole("tab", { name: "Updates", exact: true }).waitFor();
    if (versions) {
      await page.getByRole("tab", { name: "Updates", exact: true }).click();
      await page.getByRole("heading", { name: "Registered installations", exact: true }).waitFor();
      await page.getByRole("button", { name: "Refresh versions & jobs", exact: true }).waitFor({ state: "visible" });
    }
  };
  const expect = (await import("@playwright/test")).expect;
  await open(false);
  assert.ok(calls.every(call => call.method === "GET" && call.path.endsWith("installations")), "opening the workspace must not prepare or select an SDK");
  pass("Workspace opening reads registered metadata without SDK effects");
  await page.getByRole("tab", { name: "Settings", exact: true }).click();
  await expect(page.getByRole("combobox", { name: "Local runtime", exact: true })).toHaveCount(0);
  await page.getByRole("button", { name: "Choose or switch runtime", exact: true }).click();
  await expect(page.getByRole("tab", { name: "Updates", exact: true })).toHaveAttribute("aria-selected", "true");
  await page.getByRole("heading", { name: "Registered installations", exact: true }).waitFor();
  pass("Runtime preferences route selection to Versions without drafting or starting a replacement");
  await page.getByRole("tab", { name: "Settings", exact: true }).focus();
  await page.keyboard.press("ArrowRight");
  await expect(page.getByRole("tab", { name: "Updates", exact: true })).toBeFocused();
  await page.getByRole("heading", { name: "Registered installations", exact: true }).waitFor();
  await expect(page.getByRole("button", { name: "Switch now", exact: true })).toBeDisabled();
  assert.ok(calls.every(call => !["install","setup_interpreter","prepare_switch","commit"].includes(call.action)));
  pass("Keyboard tab navigation opens Versions; metadata never submits preparation or commit");
  const effectsBeforeKeyboard = calls.filter(call => call.action && call.action !== "preferences").length;
  await expect(page.getByRole("article", { name: /CIGAR 0\.14\.1.*selected.*running/ })).toBeVisible();
  await expect(page.getByRole("button", { name: "Prepare this build", exact: true })).toHaveAccessibleDescription(/Guard qualification/);
  const previewChoice = page.getByRole("checkbox", { name: "Allow preview selections", exact: true });
  await previewChoice.focus(); await page.keyboard.press("Space");
  await expect(previewChoice).toBeChecked(); await expect(previewChoice).toBeFocused();
  await expect(page.getByRole("button", { name: "Save update preferences", exact: true })).toBeEnabled();
  await page.keyboard.press("Space"); await expect(previewChoice).not.toBeChecked();
  assert.equal(calls.filter(call => call.action && call.action !== "preferences").length, effectsBeforeKeyboard);
  pass("Build cards expose version names and unavailable reasons; keyboard preference edits preserve focus without submitting updates");
  await page.getByRole("button", { name: "Edit unrelated preference", exact: true }).click();
  await page.getByLabel("I am ready to reconnect context sources and apps.").check();
  await page.getByRole("button", { name: "Switch now", exact: true }).click();
  await expect(page.getByTestId("selection")).toContainText('"runtime_id":"fixture:target"');
  await expect(page.getByTestId("selection")).toContainText("pending protection edit");
  const firstCommit = calls.find(call => call.action === "commit");
  assert.equal(firstCommit.input.expected_generation, "9007199254740993"); assert.equal(firstCommit.input.reconnect, true);
  pass("Live switch requires reconnect consent, preserves full generation precision and unrelated draft state");
  state = structuredClone(initialState); jobs = [selection(state)]; commitMode = "delay";
  await open();
  await page.getByLabel("I am ready to reconnect context sources and apps.").check();
  await page.getByRole("button", { name: "Switch now", exact: true }).click();
  await expect.poll(() => Boolean(delayedCommit)).toBe(true);
  await page.getByRole("button", { name: "Turn off CIGAR", exact: true }).click();
  await expect(page.getByTestId("selection")).toContainText('"enabled":false');
  await delayedCommit(); delayedCommit = null;
  await expect(page.getByRole("button", { name: "Refresh versions & jobs", exact: true })).toBeEnabled();
  const stopped = JSON.parse(await page.getByTestId("selection").textContent());
  assert.equal(stopped.saved.enabled, false); assert.equal(stopped.draft.enabled, false);
  pass("Delayed selection reply cannot undo a later successful Stop");
  state = structuredClone(initialState); jobs = [selection(state)]; commitMode = "unknown";
  await open(); const before = calls.filter(call => call.action === "commit").length;
  await page.getByLabel("I am ready to reconnect context sources and apps.").check();
  await page.getByRole("button", { name: "Switch now", exact: true }).click();
  await expect(page.getByRole("alert")).toContainText("Refresh versions and jobs");
  assert.equal(calls.filter(call => call.action === "commit").length, before + 1);
  await expect(page.getByText("Last submitted job:", { exact: false })).toContainText("fixture:switch");
  pass("Unknown transport outcome is not retried; stable native job ID remains visible");
  state = { ...structuredClone(initialState), availability: "off", requested_enabled: false, effective_enabled: false, runtime: null, last_check: null, diagnostic: null, qualification: null,
    preferences: { ...initialState.preferences, enabled: false, runtime_id: "" }, effective_preferences: { ...initialState.effective_preferences, enabled: false, runtime_id: "" } };
  jobs = [selection(state, true)]; commitMode = "normal";
  await open();
  await expect(page.getByLabel("I am ready to reconnect context sources and apps.")).toHaveCount(0);
  await page.getByRole("button", { name: "Select & keep CIGAR off", exact: true }).click();
  await expect(page.getByTestId("selection")).toContainText('"runtime_id":"fixture:target"');
  const off = JSON.parse(await page.getByTestId("selection").textContent());
  assert.equal(off.saved.enabled, false); assert.equal(off.draft.enabled, false);
  assert.equal(calls.filter(call => call.action === "commit").at(-1).input.reconnect, false);
  pass("Initial selection commits with reconnect false and keeps saved and draft CIGAR preferences off");
  state = structuredClone(initialState); jobs = [selection(state)]; proof = true;
  await open();
  await page.getByLabel("I am ready to reconnect context sources and apps.").check();
  const beforeProof = calls.filter(call => call.action === "commit").length;
  await page.getByRole("button", { name: "Switch now", exact: true }).click();
  await expect(page.getByRole("dialog")).toBeVisible();
  assert.equal(calls.filter(call => call.action === "commit").length, beforeProof);
  await page.getByLabel("Approval password", { exact: true }).fill("fixture-proof-only");
  await page.getByRole("button", { name: "Confirm change", exact: true }).click();
  await expect(page.getByTestId("selection")).toContainText('"runtime_id":"fixture:target"');
  const proved = calls.filter(call => call.action === "commit").at(-1);
  assert.equal(proved.proof_present, true); assert.ok(!Object.hasOwn(proved.input, "approval_password"));
  pass("Existing settings proof modal gates the explicit action and keeps proof outside SDK input");
  state = structuredClone(initialState); jobs = [selection(state)]; proof = true;
  await open();
  const beforeCancel = calls.filter(call => call.action === "cancel").length;
  await page.getByRole("button", { name: "Cancel job", exact: true }).click();
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await expect(page.getByRole("status").filter({ hasText: /^cancelled/ })).toBeVisible();
  assert.equal(calls.filter(call => call.action === "cancel").length, beforeCancel + 1);
  assert.equal(calls.filter(call => call.action === "cancel").at(-1).proof_present, false);
  pass("Explicit cancellation remains available without settings proof and never commits a selection");
  state = { ...structuredClone(initialState), generation: "9007199254740994" }; jobs = [selection(initialState)]; proof = false;
  await open();
  await expect(page.getByRole("button", { name: "Switch now", exact: true })).toBeDisabled();
  await expect(page.getByText("The live selection changed.", { exact: false })).toBeVisible();
  pass("A stale job generation cannot enable a browser switch");
  state = structuredClone(initialState); jobs = [{ ...selection(state), phase: "recovery_required", code: "recovery_required", can_commit: false, worker_live: false, recovery_available: true }];
  await open();
  const beforeRecover = calls.filter(call => call.action === "recover").length;
  await page.getByRole("button", { name: "Recover job", exact: true }).click();
  await expect(page.getByRole("status").filter({ hasText: /^completed/ })).toBeVisible();
  assert.equal(calls.filter(call => call.action === "recover").length, beforeRecover + 1);
  pass("Interrupted work exposes one explicit recovery request bound to the current native generation");
  const recoveryStart = Date.now(), recoveryEnd = recoveryStart + 120000;
  state = { ...structuredClone(initialState), availability: "off", requested_enabled: false, effective_enabled: false,
    runtime: null, last_check: null, diagnostic: null, qualification: null,
    preferences: { ...initialState.preferences, enabled: false, runtime_id: "fixture:target" },
    effective_preferences: { ...initialState.effective_preferences, enabled: false, runtime_id: "fixture:target" } };
  jobs = [{ ...selection(initialState), operation: "recover", phase: "preparing_recovery", code: "verifying_disabled_recovery",
    can_commit: false, keeps_disabled: true, reconnect_required: false,
    created_at_ms: recoveryStart - 3600000, updated_at_ms: recoveryStart, deadline_at_ms: recoveryStart - 3480000,
    recovery_attempt: { id: "a".repeat(32), expected_generation: state.generation, started_at_ms: recoveryStart, deadline_at_ms: recoveryEnd } }];
  const effectsBeforeRecoveryRead = calls.filter(call => call.action && call.action !== "preferences").length;
  await open();
  const recovering = page.getByRole("article", { name: "Recover selection fixture:switch", exact: true });
  await recovering.getByText("Job details", { exact: true }).click();
  await expect(recovering.locator("p").filter({ hasText: /^Recovery deadline:/ }).locator("time")).toHaveAttribute("datetime", new Date(recoveryEnd).toISOString());
  await expect(recovering.locator("p").filter({ hasText: /^Original preparation deadline:/ }).locator("time")).toHaveAttribute("datetime", new Date(recoveryStart - 3480000).toISOString());
  await expect(recovering.getByText("Recovery keeps CIGAR off.", { exact: false })).toBeVisible();
  await expect(recovering.getByRole("button", { name: /Switch now|Select & keep/ })).toHaveCount(0);
  assert.equal(calls.filter(call => call.action && call.action !== "preferences").length, effectsBeforeRecoveryRead);
  pass("Recovery shows its renewed deadline separately from expired preparation and never exposes a commit or starts CIGAR");
  const effectsBeforeLesson = calls.filter(call => call.action && call.action !== "preferences").length;
  await page.getByRole("tab", { name: "Tutorials", exact: true }).click();
  await page.getByRole("button", { name: /^Start walkthrough.*Update CIGAR with less interruption/ }).click();
  await expect(page.getByRole("heading", { name: "Update CIGAR with less interruption", exact: true })).toBeVisible();
  await expect(page.getByRole("tab", { name: "Updates", exact: true })).toHaveAttribute("aria-selected", "true");
  await page.getByRole("button", { name: "Next step", exact: true }).click();
  await expect(page.getByText("Step 2 of 6", { exact: false })).toBeVisible();
  await page.getByRole("button", { name: "Exit walkthrough", exact: true }).click();
  await page.getByRole("button", { name: /^Resume walkthrough.*Update CIGAR with less interruption/ }).click();
  await expect(page.getByText("Step 2 of 6", { exact: false })).toBeVisible();
  const learning = await page.evaluate(() => JSON.parse(sessionStorage.getItem("hol-guard:cigar-tutorial:v1")));
  assert.deepEqual(learning, { schema: 1, tutorial: "cigar-updates", step: 1 });
  assert.equal(calls.filter(call => call.action && call.action !== "preferences").length, effectsBeforeLesson);
  await page.getByRole("button", { name: "Exit walkthrough", exact: true }).click();
  await page.getByRole("tab", { name: "Updates", exact: true }).click();
  await page.getByRole("heading", { name: "Registered installations", exact: true }).waitFor();
  pass("Update walkthrough resumes its step, navigates Versions and never performs a native effect");
  state = { ...structuredClone(initialState), availability: "off", requested_enabled: false, effective_enabled: false,
    runtime: null, last_check: null, diagnostic: null, qualification: null, execution_ready: false,
    preferences: { ...initialState.preferences, enabled: false }, effective_preferences: { ...initialState.effective_preferences, enabled: false } };
  jobs = []; proof = false; metadataOrder = true;
  await open(false);
  await page.getByRole("tab", { name: "Settings", exact: true }).click();
  await page.getByRole("switch", { name: "Use CIGAR on this machine", exact: true }).click();
  await expect.poll(async () => JSON.parse(await page.getByTestId("selection").textContent()).draft.enabled).toBe(true);
  await page.getByRole("tab", { name: "Updates", exact: true }).click();
  await page.getByRole("heading", { name: "Registered installations", exact: true }).waitFor();
  await expect(page.getByRole("button", { name: "Refresh versions & jobs", exact: true })).toBeEnabled();
  const unchanged = JSON.parse(await page.getByTestId("selection").textContent());
  assert.equal(unchanged.saved.enabled, false); assert.equal(unchanged.draft.enabled, true);
  pass("Metadata key order and optional false defaults cannot overwrite a pending CIGAR opt-in");
  await page.setViewportSize({ width: 390, height: 844 });
  await page.getByRole("tab", { name: "Updates", exact: true }).scrollIntoViewIfNeeded();
  summary.utility_styles = await page.getByRole("region", { name: "CIGAR release catalog", exact: true }).evaluate(element => {
    const style = getComputedStyle(element); return { padding: style.paddingTop, radius: style.borderTopLeftRadius };
  });
  assert.equal(summary.utility_styles.padding, "16px", "Browser fixture must load the dashboard's generated utilities");
  assert.equal(summary.utility_styles.radius, "12px");
  summary.mobile_layout = await page.evaluate(() => ({ viewport: innerWidth, content: document.documentElement.scrollWidth }));
  assert.ok(summary.mobile_layout.content <= summary.mobile_layout.viewport, "Versions must not create horizontal page overflow");
  await page.screenshot({ path: path.join(output, "versions-mobile.png"), fullPage: true });
  pass("Versions controls remain navigable at a 390px mobile viewport");
  assert.deepEqual(browserErrors, []);
  summary.calls = calls; summary.passed = true;
  console.log(JSON.stringify({ passed: true, browser_version: summary.browser_version, checks, output }));
} catch (error) {
  summary.passed = false; summary.failure = error.stack ?? String(error);
  console.error(summary.failure); process.exitCode = 1;
} finally {
  summary.completed_at_utc = new Date().toISOString();
  await writeFile(path.join(output, "receipt.json"), JSON.stringify(summary, null, 2) + "\n", { flag: "wx" });
  await browser?.close(); await server.close();
}
