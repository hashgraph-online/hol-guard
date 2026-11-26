import { LoggedActionPanel } from "../logged-action-panel";

/** The command that prints an anonymized case skeleton for one stored browser approval (BP-T172). */
export function browserReportCommand(requestId: string): string {
  return `hol-guard browser report-prompt ${requestId}`;
}

/**
 * "This should not have asked": the way to report a browser review as a false positive. Guard sends
 * nothing; the command prints a case skeleton with every value replaced, for the user to read and paste
 * into a public issue.
 */
export function BrowserReportPrompt({ requestId }: { requestId: string }) {
  return (
    <details className="border-t border-slate-100 px-4 py-3 sm:px-5">
      <summary className="cursor-pointer select-none text-sm font-medium text-brand-dark/80 focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/30">
        This should not have asked
      </summary>
      <p className="mt-2 text-sm text-muted-foreground">
        Run this command to print the call as an anonymized case: every value is replaced and every site becomes
        site-a.example.test. Read it, then paste it into a public issue. Guard does not send anything.
      </p>
      <div className="mt-3">
        <LoggedActionPanel
          key={`${requestId}-report`}
          label="Command"
          text={browserReportCommand(requestId)}
          copyAriaLabel="Copy the report command to clipboard"
          expandAriaLabel="Expand the report command"
          collapseAriaLabel="Collapse the report command"
        />
      </div>
    </details>
  );
}
