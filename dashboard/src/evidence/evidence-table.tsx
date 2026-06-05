import type { ReactNode } from "react";

interface EvidenceTableProps {
  children: ReactNode;
  label: string;
}

export function EvidenceTable({ children, label }: EvidenceTableProps) {
  return (
    <div className="rounded-2xl border border-slate-100 bg-white overflow-hidden shadow-sm">
      <div className="overflow-x-auto">
        <table className="w-full text-sm" aria-label={label}>
          {children}
        </table>
      </div>
    </div>
  );
}

interface EvidenceTableHeadProps {
  children: ReactNode;
}

export function EvidenceTableHead({ children }: EvidenceTableHeadProps) {
  return (
    <thead>
      <tr className="border-b border-slate-100 bg-slate-50/80">
        {children}
      </tr>
    </thead>
  );
}

interface EvidenceTableHeaderProps {
  children: ReactNode;
  className?: string;
}

export function EvidenceTableHeader({ children, className = "" }: EvidenceTableHeaderProps) {
  return (
    <th
      scope="col"
      className={`px-3 py-2.5 text-left text-[11px] font-semibold uppercase tracking-wider text-slate-500 ${className}`}
    >
      {children}
    </th>
  );
}

interface EvidenceTableBodyProps {
  children: ReactNode;
}

export function EvidenceTableBody({ children }: EvidenceTableBodyProps) {
  return <tbody>{children}</tbody>;
}

interface EvidenceTableRowProps {
  children: ReactNode;
  onClick?: () => void;
  isSelected?: boolean;
}

export function EvidenceTableRow({ children, onClick, isSelected }: EvidenceTableRowProps) {
  return (
    <tr
      onClick={onClick}
      className={`border-b border-slate-100 last:border-0 transition-colors ${
        isSelected ? "bg-brand-blue/[0.04]" : onClick ? "hover:bg-slate-50 cursor-pointer" : ""
      }`}
    >
      {children}
    </tr>
  );
}

interface EvidenceTableCellProps {
  children: ReactNode;
  className?: string;
}

export function EvidenceTableCell({ children, className = "" }: EvidenceTableCellProps) {
  return (
    <td className={`px-3 py-2.5 ${className}`}>
      {children}
    </td>
  );
}
