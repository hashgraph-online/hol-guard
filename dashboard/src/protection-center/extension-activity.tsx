import { HiMiniArrowTopRightOnSquare } from "react-icons/hi2";

import type { ExtensionCatalogItem } from "../extension-controls-api";
import type { GuardReceipt } from "../guard-types";

function receiptMatchesExtension(receipt: GuardReceipt, extension: ExtensionCatalogItem): boolean {
  const identities = new Set([
    extension.extension_id,
    ...extension.permissions.map((permission) => permission.permission_id),
    ...extension.rules.map((rule) => rule.rule_id),
  ]);
  if (identities.has(receipt.artifact_id)) return true;
  if (receipt.changed_capabilities.some((capability) => identities.has(capability))) return true;
  const envelope = receipt.action_envelope_json;
  if (!envelope) return false;
  if (envelope.command_category === extension.extension_id) return true;
  const toolName = envelope.tool_name?.trim().toLowerCase();
  return Boolean(toolName && extension.executables.some((executable) => executable.toLowerCase() === toolName));
}

export function recentExtensionReceipts(
  receipts: readonly GuardReceipt[],
  extension: ExtensionCatalogItem,
  limit = 8,
): GuardReceipt[] {
  return receipts
    .filter((receipt) => receiptMatchesExtension(receipt, extension))
    .sort((left, right) => Date.parse(right.timestamp) - Date.parse(left.timestamp))
    .slice(0, limit);
}

function receiptDecisionLabel(receipt: GuardReceipt): string {
  if (receipt.policy_decision === "allow") return "Allowed";
  if (receipt.policy_decision === "block") return "Blocked";
  return "Reviewed";
}

export function ExtensionActivity(props: {
  extension: ExtensionCatalogItem;
  receipts: readonly GuardReceipt[];
}) {
  const receipts = recentExtensionReceipts(props.receipts, props.extension);
  return (
    <article className="rounded-3xl border border-slate-200 bg-white p-5 shadow-sm">
      <h2 className="text-lg font-semibold text-brand-dark">Recent Extension decisions</h2>
      <p className="mt-2 text-sm leading-6 text-brand-dark/75">
        Receipt-backed decisions mapped to this canonical Extension. Guard does not synthesize activity.
      </p>
      {receipts.length ? (
        <ul className="mt-4 divide-y divide-slate-100" aria-label="Recent Extension receipts">
          {receipts.map((receipt) => (
            <li key={receipt.receipt_id} className="flex flex-col gap-2 py-3 sm:flex-row sm:items-center sm:justify-between">
              <div>
                <p className="text-sm font-semibold text-brand-dark">{receiptDecisionLabel(receipt)} · {receipt.harness}</p>
                <p className="mt-1 text-xs text-brand-dark/60">{receipt.capabilities_summary} · {new Date(receipt.timestamp).toLocaleString()}</p>
              </div>
              <a href={`/evidence?view=actions&selected=${encodeURIComponent(receipt.receipt_id)}&search=${encodeURIComponent(receipt.receipt_id)}`} className="inline-flex min-h-11 items-center gap-2 text-sm font-semibold text-brand-blue hover:underline">
                Open receipt <HiMiniArrowTopRightOnSquare className="size-4" aria-hidden="true" />
              </a>
            </li>
          ))}
        </ul>
      ) : (
        <p className="mt-4 rounded-2xl bg-slate-50 p-4 text-sm text-brand-dark/70">No matching receipts are available on this device yet.</p>
      )}
      <a href={`/evidence?view=actions&search=${encodeURIComponent(props.extension.extension_id)}`} className="mt-4 inline-flex min-h-11 items-center gap-2 rounded-xl border border-slate-300 px-4 text-sm font-semibold text-brand-dark">
        View matching Evidence <HiMiniArrowTopRightOnSquare className="size-4" aria-hidden="true" />
      </a>
    </article>
  );
}
