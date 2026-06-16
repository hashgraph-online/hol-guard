import { GITHUB_ISSUE_BUTTON_LABEL, GITHUB_ISSUE_LINK } from "./github-issue-link";

export const SHELL_FOOTER_LICENSE_HREF =
  "https://github.com/hashgraph-online/hol-guard/blob/main/LICENSE";

export const SHELL_FOOTER_RESOURCE_LINKS = [
  { href: "https://hol.org/guard/docs", label: "Docs" },
  { href: "https://hol.org/guard", label: "Guard Cloud" },
  { href: "https://github.com/hashgraph-online/hol-guard", label: "GitHub" },
  { href: GITHUB_ISSUE_LINK, label: GITHUB_ISSUE_BUTTON_LABEL },
  { href: "https://hol.org/points/legal/privacy", label: "Privacy" },
  { href: "https://hol.org/points/legal/terms", label: "Terms" },
] as const;

export function ShellFooter() {
  return (
    <footer className="mt-auto border-t border-slate-200 bg-[#f8fafc]">
      <div className="mx-auto flex max-w-6xl flex-col gap-3 px-4 py-5 sm:flex-row sm:items-center sm:justify-between sm:px-6 lg:px-8">
        <p className="text-[11px] font-medium text-slate-400">
          HOL Guard is open source under{" "}
          <a
            href={SHELL_FOOTER_LICENSE_HREF}
            target="_blank"
            rel="noreferrer"
            className="rounded-sm text-slate-500 no-underline transition-colors hover:text-brand-blue focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/30"
          >
            Apache-2.0
          </a>
          . Built by Hashgraph Online.
        </p>
        <nav aria-label="Guard resources" className="flex flex-wrap gap-x-4 gap-y-1">
          {SHELL_FOOTER_RESOURCE_LINKS.map((link) => (
            <a
              key={link.href}
              href={link.href}
              target="_blank"
              rel="noreferrer"
              className="rounded-sm text-[11px] font-medium text-slate-500 no-underline transition-colors hover:text-brand-blue focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/30"
            >
              {link.label}
            </a>
          ))}
        </nav>
      </div>
    </footer>
  );
}
