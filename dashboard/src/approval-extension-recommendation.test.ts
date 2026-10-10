import { readFileSync } from "node:fs";
import {
  approvalExtensionRecommendationCopy,
  normalizeApprovalExtensionRecommendation,
} from "./approval-extension-recommendation";
import {
  approveWithExtensionAllow,
  extensionAllowFailureMessage,
  ExtensionAllowUncertainError,
  type ExtensionAllowDeps,
} from "./approve-with-extension-allow";
import { ExtensionControlApiError, type EffectiveExtensionControls } from "./extension-controls-api";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(`Assertion failed: ${message}`);
  }
}

const DIGEST = "a".repeat(64);

function rawRecommendation(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    schema: "guard.approval-extension-recommendation.v1",
    status: "available",
    caution: false,
    revision: 4,
    catalog_digest: DIGEST,
    permissions: [
      {
        permission_id: "command.git.permission.add",
        label: "Git add",
        description: "Stage files.",
        example_command: "git add",
        extension_id: "command.git",
        extension_name: "Git protection",
        rule_id: "command.git.add",
        risk_tier: "high",
        caution: false,
        caution_reason: null,
        caution_detail: null,
        cli_command: "hol-guard command controls set command.git.permission.add --state allow; rm -rf /",
      },
    ],
    ...overrides,
  };
}

const normalized = normalizeApprovalExtensionRecommendation(rawRecommendation());
assert(normalized !== null, "valid recommendation normalizes");
assert(normalized!.permissions[0]!.permission_id === "command.git.permission.add", "keeps permission id");
assert(
  normalized!.permissions[0]!.cli_command === "hol-guard command controls set command.git.permission.add --state allow",
  "CLI line is rebuilt from the validated id, never echoed from the daemon",
);
assert(normalizeApprovalExtensionRecommendation(rawRecommendation({ schema: "other" })) === null, "rejects schema");
assert(normalizeApprovalExtensionRecommendation(rawRecommendation({ status: "maybe" })) === null, "rejects status");
assert(normalizeApprovalExtensionRecommendation(rawRecommendation({ permissions: [] })) === null, "rejects empty");
assert(normalizeApprovalExtensionRecommendation(rawRecommendation({ catalog_digest: "x" })) === null, "rejects digest");
assert(
  normalizeApprovalExtensionRecommendation(
    rawRecommendation({ permissions: [{ ...(rawRecommendation().permissions as object[])[0], permission_id: "git add a.txt" }] }),
  ) === null,
  "rejects non-catalog permission ids",
);
assert(normalizeApprovalExtensionRecommendation(null) === null, "absent recommendation is null");

const copy = approvalExtensionRecommendationCopy(normalized!);
assert(copy.title === "Git protection covers git add", `title: ${copy.title}`);
assert(copy.primaryLabel === "Approve & always allow git add", `primary: ${copy.primaryLabel}`);
assert(copy.configureLabel === "Configure in Git protection", `configure: ${copy.configureLabel}`);
assert(copy.cautionLines.length === 0, "no caution for git add");
assert(copy.successMessage.includes("now allows git add automatically"), "success copy");

const caution = normalizeApprovalExtensionRecommendation(
  rawRecommendation({
    caution: true,
    permissions: [
      {
        ...(rawRecommendation().permissions as Record<string, unknown>[])[0],
        permission_id: "command.git.permission.force-push",
        label: "Forced Git push",
        example_command: "git push --force",
        rule_id: "command.git.push-force",
        caution: true,
        caution_reason: "destructive",
        caution_detail: "Rewrites remote history.",
      },
    ],
  }),
);
assert(caution !== null && caution.caution, "caution recommendation normalizes");
const cautionCopy = approvalExtensionRecommendationCopy(caution!);
assert(
  cautionCopy.cautionLines[0] === "git push --force can destroy work or history. Rewrites remote history.",
  `caution line: ${cautionCopy.cautionLines[0]}`,
);

const hrefSource = readFileSync(new URL("./extension-pattern-href.ts", import.meta.url), "utf8");
assert(
  hrefSource.includes("`/extensions/${extensionId}`") &&
    hrefSource.includes('params.set("rule", ruleId)') &&
    hrefSource.includes('url.searchParams.set("tab", "permissions")'),
  "deep link carries only catalog ids",
);

function effective(revision: number, enabled: string[] = []): EffectiveExtensionControls {
  return {
    schema_version: "1",
    health: "protected",
    revision,
    catalog_digest: DIGEST,
    global_lockdown: false,
    controls: [],
    failures: [],
    layers: [
      {
        schema_version: "1.0.0",
        kind: "local-admin",
        catalog_digest: DIGEST,
        global_lockdown: false,
        controls: enabled.map((id) => ({ target_kind: "permission" as const, target_id: id, state: "enabled" as const })),
      },
    ],
  };
}

function fakeDeps(overrides: Partial<ExtensionAllowDeps> & { calls: string[] }): ExtensionAllowDeps {
  const { calls } = overrides;
  return {
    fetchEffective: async () => {
      calls.push("effective");
      return effective(4);
    },
    preview: async (payload) => {
      calls.push(`preview:${payload.approval_password ?? ""}:${payload.layers[0]!.controls.map((c) => c.target_id).join(",")}`);
      return { proof_id: "proof-1" } as never;
    },
    apply: async (payload) => {
      calls.push(`apply:${payload.proof_id}`);
      return { schema_version: "1", status: "applied", revision: 5, catalog_digest: DIGEST };
    },
    resolve: async (credentials) => {
      calls.push(`resolve:${credentials.approval_password ?? ""}`);
    },
    sessionNonce: () => "nonce",
    ...overrides,
  };
}

async function run(): Promise<void> {
  const ids = ["command.git.permission.add"];
  const credentials = { approval_password: "pw" };

  const calls: string[] = [];
  const outcome = await approveWithExtensionAllow(fakeDeps({ calls }), ids, credentials);
  assert(outcome.status === "approved", "happy path approves");
  assert(
    calls.join("|") === "effective|preview:pw:command.git.permission.add|apply:proof-1|resolve:pw",
    `order: ${calls.join("|")}`,
  );

  const conflictCalls: string[] = [];
  let attempts = 0;
  const retried = await approveWithExtensionAllow(
    fakeDeps({
      calls: conflictCalls,
      apply: async (payload) => {
        attempts += 1;
        conflictCalls.push(`apply:${payload.proof_id}`);
        if (attempts === 1) throw new ExtensionControlApiError("stale", 409, "authority_conflict");
        return { schema_version: "1", status: "applied", revision: 6, catalog_digest: DIGEST };
      },
    }),
    ids,
    credentials,
  );
  assert(retried.status === "approved" && attempts === 2, "apply authority_conflict retries once");

  const uncertainCalls: string[] = [];
  let uncertain: unknown = null;
  try {
    await approveWithExtensionAllow(
      fakeDeps({
        calls: uncertainCalls,
        apply: async () => {
          throw new TypeError("Failed to fetch");
        },
      }),
      ids,
      credentials,
    );
  } catch (caught) {
    uncertain = caught;
  }
  assert(uncertain instanceof ExtensionAllowUncertainError, "network failure during apply is uncertain");
  assert(!extensionAllowFailureMessage(uncertain).includes("Nothing was changed"), "uncertain apply never claims no change");
  assert(!uncertainCalls.some((call) => call.startsWith("resolve")), "uncertain apply never resolves the request");
  assert(
    extensionAllowFailureMessage(new ExtensionControlApiError("wrong password", 403)).endsWith("Nothing was changed."),
    "clean rejection says nothing changed",
  );

  const failCalls: string[] = [];
  let rejected = false;
  try {
    await approveWithExtensionAllow(
      fakeDeps({
        calls: failCalls,
        preview: async () => {
          throw new ExtensionControlApiError("wrong password", 403, "approval_gate_password_invalid");
        },
      }),
      ids,
      credentials,
    );
  } catch {
    rejected = true;
  }
  assert(rejected, "proof failure rejects");
  assert(!failCalls.some((call) => call.startsWith("resolve")), "proof failure never resolves the request");

  const partialCalls: string[] = [];
  const partial = await approveWithExtensionAllow(
    fakeDeps({
      calls: partialCalls,
      resolve: async () => {
        throw new Error("Request already resolved.");
      },
    }),
    ids,
    credentials,
  );
  assert(partial.status === "saved_only", "resolve failure after apply reports saved-only");
  assert(partial.status === "saved_only" && partial.message.includes("still needs a decision"), "saved-only copy");

  const alreadyCalls: string[] = [];
  const already = await approveWithExtensionAllow(
    fakeDeps({ calls: alreadyCalls, fetchEffective: async () => effective(9, ids) }),
    ids,
    credentials,
  );
  assert(already.status === "approved" && already.revision === 9, "already-allowed permission skips mutation");
  assert(!alreadyCalls.some((call) => call.startsWith("preview")), "no preview when nothing changes");

  let unhealthy = false;
  try {
    await approveWithExtensionAllow(
      fakeDeps({ calls: [], fetchEffective: async () => ({ ...effective(4), health: "tampered" }) }),
      ids,
      credentials,
    );
  } catch {
    unhealthy = true;
  }
  assert(unhealthy, "unhealthy authority refuses before any mutation");

  const cardSource = readFileSync(new URL("./review-decision-card.tsx", import.meta.url), "utf8");
  assert(cardSource.includes("<ApprovalExtensionRecommendationCard"), "review card renders the recommendation");
  assert(
    /<ApprovalExtensionRecommendationCard\s+key=\{item\.request_id\}/.test(cardSource),
    "recommendation card state resets when the reviewed request changes",
  );
  assert(
    cardSource.includes("onDialogActiveChange={setExtensionDialogActive}") && cardSource.includes("extensionDialogActive ||"),
    "decision shortcuts pause while the always-allow dialog is open",
  );
  const recommendationCardSource = readFileSync(new URL("./approval-extension-recommendation-card.tsx", import.meta.url), "utf8");
  assert(
    recommendationCardSource.includes("inFlight.current) return;") && recommendationCardSource.includes("inFlight.current = false;"),
    "a second confirm cannot start while a save is in flight",
  );
  console.log("approval-extension-recommendation tests passed");
}

void run().catch((error: unknown) => {
  console.error(error);
  process.exitCode = 1;
});
