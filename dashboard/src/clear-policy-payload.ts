import type { DecisionScope } from "./guard-types";

export type ClearPolicyPayload = {
  harness?: string;
  all?: boolean;
  scope?: DecisionScope;
  artifact_id?: string;
  artifact_hash?: string;
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

/**
 * Builds the minimal `clearPolicy` payload for the given remembered-decision scope.
 * Artifact scope targets by artifact_id; workspace scope by workspace path;
 * publisher scope by publisher name; harness scope by harness name; global clears all.
 */
export function buildClearPayload(input: ClearPolicyInput): ClearPolicyPayload {
  switch (input.scope) {
    case "artifact":
      return {
        scope: "artifact",
        artifact_id: input.artifact_id ?? undefined,
        artifact_hash: input.artifact_hash ?? undefined,
      };
    case "workspace":
      return { scope: "workspace", workspace: input.workspace ?? undefined };
    case "publisher":
      return { scope: "publisher", publisher: input.publisher ?? undefined };
    case "harness":
      return {
        scope: "harness",
        harness: input.harness,
        artifact_id: input.artifact_id ?? undefined,
        artifact_hash: input.artifact_hash ?? undefined,
      };
    case "global":
      return { scope: "global", all: true };
  }
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
