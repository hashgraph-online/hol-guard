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
assert.match(render(ready), /Turn off context assistance/);
assert.match(render(ready), /does not approve or confirm execution/);
assert.match(render(off), />Off</);
assert.doesNotMatch(render(off), /Turn off context assistance/);
assert.match(render(null, { loading: true }), /Checking status/);
assert.match(render(null, { error: true }), /role="alert"/);
assert.match(render(null, { error: true }), /existing approvals remain available/);
assert.doesNotMatch(render(null, { error: true }), /Turn off context assistance/);
assert.match(render(null, { error: true, stopAvailable: true }), /Turn off context assistance/);
assert.match(render(ready, { stopping: true }), />Stopping</);
console.log("Home context status, opt-out visibility and independent failure rendering passed.");
