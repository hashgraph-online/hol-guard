import type { ReactNode } from "react";

/**
 * One ruled section below the manager roster. Wide screens set the heading
 * beside its content, so the details read as a ledger of facts about this
 * device rather than a stack of same-size cards.
 */
export function SupplyChainDetailSection({
  id,
  title,
  lead,
  action,
  children,
  ...sectionProps
}: {
  id: string;
  title: string;
  lead: string;
  action?: ReactNode;
  children: ReactNode;
  "aria-label"?: string;
  "data-testid"?: string;
}) {
  const labelled = sectionProps["aria-label"] === undefined ? { "aria-labelledby": id } : {};
  return (
    <section
      {...labelled}
      {...sectionProps}
      className="grid min-w-0 gap-x-10 gap-y-3 py-5 md:grid-cols-[minmax(0,13rem)_minmax(0,1fr)]"
    >
      <div className="min-w-0">
        <h3 id={id} className="text-sm font-semibold text-brand-dark">
          {title}
        </h3>
        <p className="mt-0.5 text-sm leading-6 text-slate-600">{lead}</p>
        {action ? <div className="mt-2">{action}</div> : null}
      </div>
      <div className="min-w-0">{children}</div>
    </section>
  );
}
