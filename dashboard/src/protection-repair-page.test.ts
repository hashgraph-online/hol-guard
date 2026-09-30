import { readFileSync } from "node:fs";

import { PROTECTION_REPAIR_ROUTE, protectionRepairView } from "./protection-repair-page";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

assert(PROTECTION_REPAIR_ROUTE === "/protection/repair", "the repair page has one stable local route");

const repair = protectionRepairView("tampered", true);
assert(repair.action === "repair", "a tampered policy offers the repair button");
assert(repair.actionLabel === "Repair protection", "the button name matches the hook instruction");
assert(repair.title === "Trusted protection needs repair", "the heading states the situation");
assert(repair.body.includes("then retry the blocked action"), "repair copy tells the user to retry after approval");

const recovery = protectionRepairView("recovery-required", true);
assert(recovery.actionLabel === "Repair protection", "recovery-required uses the same repair button");

const setup = protectionRepairView("tampered", false);
assert(setup.action === "setup", "a missing approval gate sends the user to set it up");
assert(setup.actionLabel === "Set up approval", "the setup button names the next action");

const repaired = protectionRepairView("protected", true);
assert(repaired.action === "home", "a protected policy does not offer another repair");
assert(repaired.title === "Protection is repaired", "success says the repair finished");
assert(repaired.body === "Retry the blocked action.", "success tells the user to retry the blocked action");

const other = protectionRepairView("degraded-unacknowledged", true);
assert(other.action === "extensions", "other protection states leave this page");

const source = readFileSync(new URL("./protection-repair-page.tsx", import.meta.url), "utf8");
assert((source.match(/type="button"/g) ?? []).length === 2, "the page has one button in each finished state");
assert(!/uppercase|tracking-widest|eyebrow|kicker/i.test(source), "the repair page does not add a kicker");
assert(!source.includes("bg-gradient-to"), "the repair page does not introduce gradient text or fills");
