import assert from "node:assert/strict";
import { createRequire } from "node:module";
import test from "node:test";

const { JSDOM } = createRequire(import.meta.url)("jsdom");
const dom = new JSDOM("<!doctype html><div id='root'></div>", {
  url: "http://127.0.0.1:4781/?guard-token=synthetic-local-token",
});
Object.assign(globalThis, {
  window: dom.window,
  document: dom.window.document,
  HTMLElement: dom.window.HTMLElement,
  HTMLInputElement: dom.window.HTMLInputElement,
  IS_REACT_ACT_ENVIRONMENT: true,
});

const React = await import("react");
const { createRoot } = await import("react-dom/client");
const { CloudReviewSettings } = await import("./cloud-review-settings");
type Status = import("../guard-api").CloudReviewSettingsStatus;

const baseStatus = {
  enabled: true,
  connected: true,
  reason: null,
  expires_at: "2026-10-17T00:00:00Z",
  workspace_id: "workspace-1",
  source: "default",
  pending_uploads: 0,
  held_events: 0,
  isolated_events: 0,
  last_synced_at: null,
  delivery_state: "idle",
  approval_gate: { enabled: false, totp_enabled: false },
} as Status;

async function mounted(status: Status = baseStatus) {
  const container = document.getElementById("root")!;
  const root = createRoot(container);
  const previousFetch = globalThis.fetch;
  const writes: Record<string, unknown>[] = [];
  globalThis.fetch = async (_url, options) => {
    if (options?.method === "POST") writes.push(JSON.parse(String(options.body)));
    return new Response(JSON.stringify(status), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  };
  await React.act(async () => root.render(React.createElement(CloudReviewSettings)));
  return {
    writes,
    async close() {
      await React.act(async () => root.unmount());
      globalThis.fetch = previousFetch;
    },
  };
}

function button(label: string): HTMLButtonElement {
  const found = Array.from(document.querySelectorAll("button"))
    .find((element) => element.textContent?.trim() === label);
  assert.ok(found, `Expected visible button: ${label}`);
  return found;
}

async function click(label: string) {
  await React.act(async () => button(label).click());
}

test("explicit renewal requires local proof and sends the renewal intent", async () => {
  const ui = await mounted({
    ...baseStatus,
    approval_gate: { ...baseStatus.approval_gate, enabled: true },
  });
  try {
    await click("Renew authorization");
    assert.match(document.querySelector('[role="dialog"]')!.textContent!, /30 days/);
    assert.equal(button("Renew for 30 days").disabled, true);
    assert.equal(ui.writes.length, 0);
    const input = document.querySelector<HTMLInputElement>('input[type="password"]')!;
    await React.act(async () => {
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!.call(
        input, "synthetic-proof",
      );
      input.dispatchEvent(new dom.window.Event("input", { bubbles: true }));
    });
    assert.equal(button("Renew for 30 days").disabled, false);
    await click("Renew for 30 days");
    assert.deepEqual(ui.writes, [{
      action: "enable",
      workspace_id: "workspace-1",
      source: "default",
      include_held_requests: false,
      renew_consent: true,
      approval_password: "synthetic-proof",
      confirm: "cloud-review.enable",
    }]);
    assert.equal(document.querySelector('[role="dialog"]'), null);
  } finally {
    await ui.close();
  }
});

test("delivery recovery preserves authorization and does not request renewal", async () => {
  const ui = await mounted({ ...baseStatus, activation_error: "worker_restart_required" });
  try {
    await click("Restore Cloud Review");
    assert.match(document.querySelector('[role="dialog"]')!.textContent!, /existing authorization and expiry/);
    await click("Authorize this device");
    assert.equal(ui.writes.length, 1);
    assert.equal(ui.writes[0].action, "enable");
    assert.equal(ui.writes[0].renew_consent, undefined);
    assert.equal(ui.writes[0].include_held_requests, false);
  } finally {
    await ui.close();
  }
});

test("cancelled renewal cannot leak renewal intent or include held requests into recovery", async () => {
  const ui = await mounted({ ...baseStatus, held_events: 1 });
  try {
    await click("Renew authorization");
    const includeHeld = document.querySelector<HTMLInputElement>('input[type="checkbox"]')!;
    await React.act(async () => includeHeld.click());
    assert.equal(includeHeld.checked, true);
    await click("Cancel");
    assert.equal(ui.writes.length, 0);
    await click("Restore Cloud Review");
    await click("Authorize this device");
    assert.equal(ui.writes.length, 1);
    assert.equal(ui.writes[0].renew_consent, undefined);
    assert.equal(ui.writes[0].include_held_requests, false);
  } finally {
    await ui.close();
  }
});
