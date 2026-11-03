import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { renderToStaticMarkup } from "react-dom/server";
import { ContextHomeStatusView } from "./home-status";
import { parseContextAssistanceStatus } from "./status";

const native = JSON.parse(readFileSync(new URL("./fixtures/intent-state.json", import.meta.url), "utf8")).native_test;
const ready = parseContextAssistanceStatus(native.ready_observation);
const off = parseContextAssistanceStatus({ ...ready, availability: "off", requested_enabled: false, effective_enabled: false,
  preferences: { ...ready.preferences, enabled: false }, effective_preferences: { ...ready.effective_preferences, enabled: false },
  runtime: null, last_check: null, qualification: null, job: null });
const render = (status: typeof ready | null, extra: { loading?: boolean; stopping?: boolean; error?: boolean; stopAvailable?: boolean } = {}) =>
  renderToStaticMarkup(<ContextHomeStatusView status={status} loading={false} stopping={false} error={false}
    onRefresh={() => {}} onStop={() => {}} onOpenSettings={() => {}} {...extra} />);
assert.match(render(ready), /Ready/);
assert.match(render(ready), /Turn off CIGAR/);
assert.match(render(ready), /CIGAR is on/);
assert.doesNotMatch(render(ready), /authorize|execution|context assistance/i);
assert.doesNotMatch(render(ready), /Try again/);
assert.match(render(off), />Off</);
assert.match(render(off), /CIGAR is off/);
assert.doesNotMatch(render(off), /Turn off CIGAR/);
assert.match(render(null, { loading: true }), /Checking CIGAR/);
assert.match(render(null, { error: true }), /role="alert"/);
assert.match(render(null, { error: true }), /Protection keeps working/);
assert.match(render(null, { error: true }), /Try again/);
assert.doesNotMatch(render(null, { error: true }), /Turn off CIGAR/);
assert.match(render(null, { error: true, stopAvailable: true }), /Turn off CIGAR/);
assert.match(render(ready, { stopping: true }), />Stopping</);
console.log("Home context status, opt-out visibility and independent failure rendering passed.");
