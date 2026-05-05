import { buildDemoRuntimeSnapshot } from "./guard-api";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

const snapshot = buildDemoRuntimeSnapshot();

assert(snapshot.cloud_pairing_state.state === "paired_waiting", "demo snapshot exposes paired waiting state");
assert(snapshot.cloud_pairing_state.label === snapshot.cloud_state_label, "demo pairing label matches legacy label");
assert(snapshot.cloud_pairing_state.detail === snapshot.cloud_state_detail, "demo pairing detail matches legacy detail");
assert(snapshot.cloud_pairing_state.sync_configured === true, "demo pairing state marks sync configured");
assert(snapshot.cloud_pairing_state.dashboard_url === snapshot.dashboard_url, "demo dashboard URL is preserved");
assert(snapshot.cloud_pairing_state.inbox_url === snapshot.inbox_url, "demo inbox URL is preserved");
assert(snapshot.cloud_pairing_state.fleet_url === snapshot.fleet_url, "demo fleet URL is preserved");
assert(snapshot.cloud_pairing_state.connect_url === snapshot.connect_url, "demo connect URL is preserved");
