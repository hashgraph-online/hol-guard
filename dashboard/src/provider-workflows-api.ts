import { fetchLocalCliApi } from "./guard-api";

export type ProviderWorkflow = {
  proposalId: string; guidancePresent: boolean;
  requirements: { slug: string; role: "primary" | "supporting";
    state: "ask" | "saved-deny" | "unresolved"; schemaObserved: boolean }[];
};

function object(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

export async function fetchProviderWorkflows(cliId: string, offset: number, signal: AbortSignal): Promise<{
  proposals: ProviderWorkflow[]; nextOffset: number | null;
}> {
  const response = await fetchLocalCliApi("/v1/local-clis/provider-workflows", {
    method: "POST", signal, headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ cli_id: cliId, offset }),
  });
  const body: unknown = await response.json();
  if (!response.ok) throw new Error(object(body) && typeof body.message === "string" ? body.message : "Could not load workflow suggestions.");
  if (!object(body) || body.cli_id !== cliId || !Array.isArray(body.proposals) || body.proposals.length > 10
    || (body.next_offset !== null && body.next_offset !== offset + 10)) throw new Error("Invalid workflow suggestions");
  const proposals = body.proposals.map((entry): ProviderWorkflow => {
    if (!object(entry) || typeof entry.proposal_id !== "string" || !/^[a-f0-9]{64}$/.test(entry.proposal_id)
      || entry.source !== "composio-search-guidance" || entry.permissions_granted !== false
      || entry.requirements_complete !== false || entry.account_binding !== "unverified"
      || typeof entry.guidance_present !== "boolean" || !Array.isArray(entry.requirements)
      || entry.requirements.length > 50) throw new Error("Invalid workflow provenance");
    const requirements = entry.requirements.map((part): ProviderWorkflow["requirements"][number] => {
      if (!object(part) || typeof part.tool_slug !== "string" || !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(part.tool_slug)
        || !["primary", "supporting"].includes(String(part.role))
        || !["ask", "saved-deny", "unresolved"].includes(String(part.state))
        || typeof part.schema_observed !== "boolean") throw new Error("Invalid workflow dependency");
      return { slug: part.tool_slug, role: part.role as "primary" | "supporting",
        state: part.state as "ask" | "saved-deny" | "unresolved", schemaObserved: part.schema_observed };
    });
    return { proposalId: entry.proposal_id, guidancePresent: entry.guidance_present, requirements };
  });
  return { proposals, nextOffset: body.next_offset as number | null };
}
