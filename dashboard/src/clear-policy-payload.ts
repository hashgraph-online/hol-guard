import type { DecisionScope } from "./guard-types";

export type ClearPolicyPayload = {
  harness?: string;
  all?: boolean;
  scope?: DecisionScope;
  artifact_id?: string;
  artifact_hash?: string;
  artifact_id_is_null?: boolean;
  artifact_hash_is_null?: boolean;
  workspace?: string;
  publisher?: string;
};

export type ClearPolicyInput = {
  scope: DecisionScope;
  harness: string;
  artifact_id?: string | null;
  artifact_hash?: string | null;
  workspace?: string | null;
  publisher?: string | null;
};

export type ClearPolicyKeyInput = ClearPolicyInput & {
  action?: string | null;
  reason?: string | null;
  updated_at?: string | null;
};

function fieldIsNull(value: string | null | undefined): boolean {
  return value === null || value === undefined || value === "";
}

/**
 * Builds an exact `clearPolicy` payload for the given remembered-decision scope.
 * Artifact scope targets by artifact_id; workspace scope by workspace path;
 * publisher scope by publisher name; harness scope by harness name; global clears all.
 */
export function buildClearPayload(input: ClearPolicyInput): ClearPolicyPayload {
  switch (input.scope) {
    case "artifact":
      return {
        harness: input.harness,
        scope: "artifact",
        artifact_id: input.artifact_id ?? undefined,
        artifact_hash: input.artifact_hash ?? undefined,
      };
    case "workspace":
      return {
        harness: input.harness,
        scope: "workspace",
        artifact_id: input.artifact_id ?? undefined,
        artifact_hash: input.artifact_hash ?? undefined,
        workspace: input.workspace ?? undefined,
      };
    case "publisher":
      return {
        harness: input.harness,
        scope: "publisher",
        publisher: input.publisher ?? undefined,
      };
    case "harness":
      return {
        scope: "harness",
        harness: input.harness,
        artifact_id: input.artifact_id ?? undefined,
        artifact_hash: input.artifact_hash ?? undefined,
        artifact_id_is_null: fieldIsNull(input.artifact_id) ? true : undefined,
        artifact_hash_is_null: fieldIsNull(input.artifact_hash) ? true : undefined,
      };
    case "global":
      return { scope: "global", all: true };
  }
}

export function policyIdentityKey(input: ClearPolicyKeyInput): string {
  return JSON.stringify([
    input.harness,
    input.scope,
    input.artifact_id ?? null,
    input.artifact_hash ?? null,
    input.workspace ?? null,
    input.publisher ?? null,
    input.action ?? null,
    input.reason ?? null,
    input.updated_at ?? null,
  ]);
}

/**
 * Returns the clear button label for the given decision scope.
 * Labels follow the GR119 copy spec exactly.
 */
export function clearLabelForScope(scope: DecisionScope): string {
  switch (scope) {
    case "artifact":
      return "Clear exact decision";
    case "workspace":
      return "Clear project decision";
    case "publisher":
      return "Clear publisher decision";
    case "harness":
      return "Clear app decision";
    case "global":
      return "Clear global decision";
  }
}
