import { renderToStaticMarkup } from "react-dom/server";
import { normalizeApprovalRequest } from "./guard-api";
import { normalizeRuntimeUpgradeAdvice, RUNTIME_UPGRADE_ADVICE_SCHEMA } from "./runtime-upgrade-advice";
import { RuntimeUpgradeError } from "./runtime-upgrade-api";
import { RuntimeUpgradeCard } from "./runtime-upgrade-card";

function assert(condition: boolean, message: string): void {
  if (!condition) throw new Error(message);
}

const nvmAdvice = {
  schema: RUNTIME_UPGRADE_ADVICE_SCHEMA,
  family: "node",
  current_version: "25.2.1",
  current_path: "/opt/runtimes/nvm/versions/node/v25.2.1/bin/node",
  advisory_id: "CVE-0000-0001",
  severity: "high",
  known_exploited: false,
  manager: "nvm",
  patched_version: "26.12.1",
  installed_version: "24.22.1",
  switch_version: "24.22.1",
  switched: false,
  command: "nvm alias default 24.22.1",
  download_url: "https://nodejs.org/en/download",
};

{
  const advice = normalizeRuntimeUpgradeAdvice(nvmAdvice);
  assert(advice !== null, "valid advice normalizes");
  assert(advice?.switch_version === "24.22.1", "nvm advice keeps its switch");
  assert(normalizeRuntimeUpgradeAdvice({ ...nvmAdvice, schema: "guard.other.v1" }) === null, "another schema is ignored");
  assert(normalizeRuntimeUpgradeAdvice({ ...nvmAdvice, family: "bun" }) === null, "another family is ignored");
  assert(normalizeRuntimeUpgradeAdvice({ ...nvmAdvice, advisory_id: "" }) === null, "advice must name the advisory");
  const brew = normalizeRuntimeUpgradeAdvice({ ...nvmAdvice, manager: "homebrew", switch_version: "24.22.1" });
  assert(brew?.switch_version === null, "only nvm advice can offer the one-click switch");
  const link = normalizeRuntimeUpgradeAdvice({ ...nvmAdvice, download_url: "https://downloads.example.test/node" });
  assert(link?.download_url === "https://nodejs.org/en/download", "the download link is always the official page");
  const unknown = normalizeRuntimeUpgradeAdvice({ ...nvmAdvice, manager: "volta" });
  assert(unknown?.manager === "other" && unknown.switch_version === null, "an unknown manager offers no switch");
}

{
  const item = normalizeApprovalRequest({
    request_id: "runtime-upgrade-request",
    status: "pending",
    runtime_upgrade: nvmAdvice,
  } as unknown as Parameters<typeof normalizeApprovalRequest>[0]);
  assert(item.runtime_upgrade?.installed_version === "24.22.1", "the approval request carries its advice");
  const plain = normalizeApprovalRequest({
    request_id: "plain-request",
    status: "pending",
    runtime_upgrade: { schema: "guard.other.v1" },
  } as unknown as Parameters<typeof normalizeApprovalRequest>[0]);
  assert(plain.runtime_upgrade === undefined, "malformed advice is dropped");
}

{
  const advice = normalizeRuntimeUpgradeAdvice(nvmAdvice) ?? undefined;
  const markup = renderToStaticMarkup(<RuntimeUpgradeCard requestId="r1" advice={advice} />);
  assert(markup.includes("Update Node.js to stop these reviews"), "the card explains why the command is paused");
  assert(markup.includes("Node.js 25.2.1") && markup.includes("CVE-0000-0001"), "the card names the version and advisory");
  assert(markup.includes("Use Node.js 24.22.1"), "nvm with a clean version installed gets the one-click switch");
  assert(markup.includes("nvm alias default 24.22.1"), "the card shows the matching terminal command");
  assert(markup.includes("https://nodejs.org/en/download"), "the card links the official download page");
}

{
  const advice = normalizeRuntimeUpgradeAdvice({ ...nvmAdvice, switch_version: null, switched: true }) ?? undefined;
  const markup = renderToStaticMarkup(<RuntimeUpgradeCard requestId="r1" advice={advice} />);
  assert(!markup.includes("Use Node.js"), "a finished switch offers no button");
  assert(markup.includes("nvm now defaults to Node.js 24.22.1"), "a finished switch says what nvm now starts");
  assert(markup.includes("Restart the agent"), "a finished switch says running agents need a restart");
}

{
  const advice =
    normalizeRuntimeUpgradeAdvice({
      ...nvmAdvice,
      manager: "homebrew",
      installed_version: null,
      switch_version: null,
      command: "brew upgrade node",
    }) ?? undefined;
  const markup = renderToStaticMarkup(<RuntimeUpgradeCard requestId="r1" advice={advice} />);
  assert(!markup.includes("Use Node.js"), "Homebrew gets no one-click switch");
  assert(markup.includes("brew upgrade node"), "Homebrew gets its upgrade command");
  assert(markup.includes("Node.js 26.12.1 or later fixes it."), "without an installed version the card names the fix");
}

{
  assert(renderToStaticMarkup(<RuntimeUpgradeCard requestId="r1" advice={undefined} />) === "", "no advice renders nothing");
}

{
  const stale = new RuntimeUpgradeError(409, "runtime_upgrade_version_mismatch");
  assert(stale.message.includes("Reload the review"), "a stale card asks for a reload");
  const failed = new RuntimeUpgradeError(409, "runtime_upgrade_failed");
  assert(failed.message.includes("terminal"), "a failed write points at the terminal command");
}

console.log("runtime-upgrade-advice tests passed");
